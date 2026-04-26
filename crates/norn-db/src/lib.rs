use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use norn_core::{
    Exposure, IgnoredFinding, InventoryItem, InventoryKind, NotificationEvent, RiskEvaluation,
    RiskLevel, ScanRecord, ScannerError, ServiceSummary, Summary, VulnerabilityFinding,
    VulnerabilitySummary,
};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

const INIT_SQL: &str = include_str!("migrations/001_init.sql");

#[derive(Clone)]
pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn open_url(url: &str) -> Result<Self> {
        let path = sqlite_path_from_url(url)?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create database directory {}", parent.display())
            })?;
        }
        let conn = Connection::open(&path)
            .with_context(|| format!("failed to open SQLite database {}", path.display()))?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_memory() -> Result<Self> {
        let db = Self {
            conn: Arc::new(Mutex::new(Connection::open_in_memory()?)),
        };
        db.migrate()?;
        Ok(db)
    }

    pub fn migrate(&self) -> Result<()> {
        self.conn
            .lock()
            .expect("database mutex poisoned")
            .execute_batch(INIT_SQL)
            .context("failed to run SQLite migrations")
    }

    pub fn create_scan(&self, host: &str) -> Result<ScanRecord> {
        let now = Utc::now();
        let scan = ScanRecord {
            id: Uuid::new_v4().to_string(),
            host: host.to_string(),
            started_at: now,
            completed_at: None,
            status: "running".to_string(),
            inventory_count: 0,
            finding_count: 0,
            scanner_errors: Vec::new(),
        };
        let conn = self.conn.lock().expect("database mutex poisoned");
        conn.execute(
            "INSERT INTO hosts (id, name, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(name) DO UPDATE SET last_seen = excluded.last_seen",
            params![Uuid::new_v4().to_string(), host, now.to_rfc3339()],
        )?;
        conn.execute(
            "INSERT INTO scans
             (id, host, started_at, status, inventory_count, finding_count, scanner_errors_json)
             VALUES (?1, ?2, ?3, ?4, 0, 0, '[]')",
            params![
                scan.id,
                scan.host,
                scan.started_at.to_rfc3339(),
                scan.status
            ],
        )?;
        Ok(scan)
    }

    pub fn finish_scan(
        &self,
        scan_id: &str,
        status: &str,
        inventory_count: usize,
        finding_count: usize,
        scanner_errors: &[ScannerError],
    ) -> Result<()> {
        let errors_json = serde_json::to_string(scanner_errors)?;
        self.conn.lock().expect("database mutex poisoned").execute(
            "UPDATE scans
             SET completed_at = ?2, status = ?3, inventory_count = ?4, finding_count = ?5,
                 scanner_errors_json = ?6
             WHERE id = ?1",
            params![
                scan_id,
                Utc::now().to_rfc3339(),
                status,
                inventory_count as i64,
                finding_count as i64,
                errors_json
            ],
        )?;
        Ok(())
    }

    pub fn insert_inventory(&self, scan_id: &str, items: &[InventoryItem]) -> Result<()> {
        let mut conn = self.conn.lock().expect("database mutex poisoned");
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO inventory_items
                 (scan_id, item_id, name, source, kind, status, exposure, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for item in items {
                stmt.execute(params![
                    scan_id,
                    item.id,
                    item.name,
                    serde_json::to_string(&item.source)?,
                    serde_json::to_string(&item.kind)?,
                    serde_json::to_string(&item.status)?,
                    serde_json::to_string(&item.exposure)?,
                    serde_json::to_string(item)?
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn insert_findings(&self, scan_id: &str, findings: &[VulnerabilityFinding]) -> Result<()> {
        let mut conn = self.conn.lock().expect("database mutex poisoned");
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO vulnerability_findings
                 (scan_id, finding_id, inventory_item_id, vulnerability_id, severity, fix_available, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for finding in findings {
                stmt.execute(params![
                    scan_id,
                    finding.id,
                    finding.inventory_item_id,
                    finding.vulnerability_id,
                    serde_json::to_string(&finding.severity)?,
                    serde_json::to_string(&finding.fix_available)?,
                    serde_json::to_string(finding)?
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn insert_risks(&self, scan_id: &str, risks: &[RiskEvaluation]) -> Result<()> {
        let mut conn = self.conn.lock().expect("database mutex poisoned");
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO risk_evaluations
                 (scan_id, risk_id, finding_id, inventory_item_id, service_name, vulnerability_id, risk, exposure, data_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            )?;
            for risk in risks {
                stmt.execute(params![
                    scan_id,
                    risk.id,
                    risk.finding_id,
                    risk.inventory_item_id,
                    risk.service_name,
                    risk.vulnerability_id,
                    serde_json::to_string(&risk.risk)?,
                    serde_json::to_string(&risk.exposure)?,
                    serde_json::to_string(risk)?
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn add_ignore(&self, ignore: &IgnoredFinding) -> Result<()> {
        self.conn.lock().expect("database mutex poisoned").execute(
            "INSERT INTO ignored_findings (vulnerability_id, service, expires_at, reason, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                ignore.vulnerability_id,
                ignore.service,
                ignore.expires_at.map(|value| value.to_rfc3339()),
                ignore.reason,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn active_ignores(&self) -> Result<Vec<IgnoredFinding>> {
        let now = Utc::now().to_rfc3339();
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT vulnerability_id, service, expires_at, reason
             FROM ignored_findings
             WHERE expires_at IS NULL OR expires_at > ?1",
        )?;
        let rows = stmt.query_map(params![now], |row| {
            let expires_at: Option<String> = row.get(2)?;
            Ok(IgnoredFinding {
                vulnerability_id: row.get(0)?,
                service: row.get(1)?,
                expires_at: expires_at.and_then(|value| parse_datetime(&value).ok()),
                reason: row.get(3)?,
            })
        })?;
        collect_rows(rows)
    }

    pub fn insert_notification(
        &self,
        scan_id: Option<&str>,
        event_type: &str,
        event: &NotificationEvent,
    ) -> Result<()> {
        self.conn.lock().expect("database mutex poisoned").execute(
            "INSERT INTO notification_events
             (scan_id, event_type, service_name, vulnerability_id, risk, data_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                scan_id,
                event_type,
                event.service,
                event.vulnerability_id,
                serde_json::to_string(&event.runtime_risk)?,
                serde_json::to_string(event)?,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    pub fn has_prior_risk(
        &self,
        scan_id: &str,
        vulnerability_id: &str,
        service: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM risk_evaluations
             WHERE scan_id != ?1 AND vulnerability_id = ?2 AND service_name = ?3",
            params![scan_id, vulnerability_id, service],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn latest_inventory(&self) -> Result<Vec<InventoryItem>> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(Vec::new());
        };
        self.inventory_for_scan(&scan_id)
    }

    pub fn inventory_for_scan(&self, scan_id: &str) -> Result<Vec<InventoryItem>> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT data_json FROM inventory_items WHERE scan_id = ?1 ORDER BY source, name",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| row.get::<_, String>(0))?;
        let json_rows = collect_rows(rows)?;
        json_rows
            .into_iter()
            .map(|json| serde_json::from_str(&json).context("failed to parse inventory JSON"))
            .collect()
    }

    pub fn latest_risks(&self) -> Result<Vec<RiskEvaluation>> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(Vec::new());
        };
        self.risks_for_scan(&scan_id)
    }

    pub fn risks_for_scan(&self, scan_id: &str) -> Result<Vec<RiskEvaluation>> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT data_json FROM risk_evaluations WHERE scan_id = ?1 ORDER BY risk, service_name",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| row.get::<_, String>(0))?;
        let json_rows = collect_rows(rows)?;
        json_rows
            .into_iter()
            .map(|json| serde_json::from_str(&json).context("failed to parse risk JSON"))
            .collect()
    }

    pub fn latest_findings(&self) -> Result<Vec<VulnerabilityFinding>> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(Vec::new());
        };
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT data_json FROM vulnerability_findings WHERE scan_id = ?1 ORDER BY severity, vulnerability_id",
        )?;
        let rows = stmt.query_map(params![scan_id], |row| row.get::<_, String>(0))?;
        let json_rows = collect_rows(rows)?;
        json_rows
            .into_iter()
            .map(|json| serde_json::from_str(&json).context("failed to parse finding JSON"))
            .collect()
    }

    pub fn summary(&self) -> Result<Summary> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(Summary::default());
        };
        let inventory = self.inventory_for_scan(&scan_id)?;
        let risks = self.risks_for_scan(&scan_id)?;
        let scan = self.scan_by_id(&scan_id)?;
        let mut summary = Summary {
            last_scan_time: scan.completed_at.or(Some(scan.started_at)),
            ..Summary::default()
        };

        for item in &inventory {
            if item.kind == InventoryKind::Container && item.is_running() {
                summary.running_containers += 1;
            } else if item.is_running() {
                summary.running_services += 1;
            }
            if item.exposure == Exposure::Public {
                summary.public_services += 1;
            }
        }

        for risk in &risks {
            match risk.risk {
                RiskLevel::Critical => summary.critical_risks += 1,
                RiskLevel::High => summary.high_risks += 1,
                RiskLevel::Medium => summary.medium_risks += 1,
                RiskLevel::Low => summary.low_risks += 1,
                RiskLevel::Informational => {}
            }
        }

        Ok(summary)
    }

    pub fn service_summaries(&self) -> Result<Vec<ServiceSummary>> {
        let inventory = self.latest_inventory()?;
        let risks = self.latest_risks()?;
        Ok(inventory
            .into_iter()
            .map(|item| {
                let related = risks
                    .iter()
                    .filter(|risk| risk.inventory_item_id == item.id)
                    .collect::<Vec<_>>();
                let highest_risk = related
                    .iter()
                    .map(|risk| risk.risk)
                    .max_by_key(|risk| risk.score());
                ServiceSummary {
                    name: item.name,
                    source: item.source,
                    status: item.status,
                    exposure: item.exposure,
                    highest_risk,
                    vulnerability_count: related.len(),
                }
            })
            .collect())
    }

    pub fn vulnerability_summaries(&self) -> Result<Vec<VulnerabilitySummary>> {
        let risks = self.latest_risks()?;
        let findings = self.latest_findings()?;
        let mut summaries = risks
            .into_iter()
            .filter_map(|risk| {
                let finding = findings
                    .iter()
                    .find(|finding| finding.id == risk.finding_id)?;
                Some(VulnerabilitySummary {
                    vulnerability_id: risk.vulnerability_id,
                    severity: risk.severity,
                    runtime_risk: risk.risk,
                    affected_service: risk.service_name,
                    exposed: risk.exposure,
                    fix_available: finding.fix_available,
                    first_seen: finding.first_seen,
                    last_seen: finding.last_seen,
                    package_name: finding.package_name.clone(),
                    installed_version: finding.installed_version.clone(),
                    fixed_version: finding.fixed_version.clone(),
                })
            })
            .collect::<Vec<_>>();
        summaries.sort_by_key(|summary| std::cmp::Reverse(summary.runtime_risk.score()));
        Ok(summaries)
    }

    pub fn list_scans(&self) -> Result<Vec<ScanRecord>> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, host, started_at, completed_at, status, inventory_count, finding_count, scanner_errors_json
             FROM scans ORDER BY started_at DESC LIMIT 100",
        )?;
        let rows = stmt.query_map([], scan_from_row)?;
        collect_rows(rows)
    }

    fn latest_scan_id(&self) -> Result<Option<String>> {
        self.conn
            .lock()
            .expect("database mutex poisoned")
            .query_row(
                "SELECT id FROM scans WHERE status != 'running' ORDER BY started_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("failed to load latest scan id")
    }

    fn scan_by_id(&self, scan_id: &str) -> Result<ScanRecord> {
        self.conn
            .lock()
            .expect("database mutex poisoned")
            .query_row(
                "SELECT id, host, started_at, completed_at, status, inventory_count, finding_count, scanner_errors_json
                 FROM scans WHERE id = ?1",
                params![scan_id],
                scan_from_row,
            )
            .context("failed to load scan")
    }
}

fn sqlite_path_from_url(url: &str) -> Result<PathBuf> {
    if url == "sqlite::memory:" {
        return Ok(PathBuf::from(":memory:"));
    }
    let path = url
        .strip_prefix("sqlite://")
        .ok_or_else(|| anyhow::anyhow!("database.url must start with sqlite://"))?;
    Ok(Path::new(path).to_path_buf())
}

fn scan_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanRecord> {
    let started_at: String = row.get(2)?;
    let completed_at: Option<String> = row.get(3)?;
    let errors_json: String = row.get(7)?;
    Ok(ScanRecord {
        id: row.get(0)?,
        host: row.get(1)?,
        started_at: parse_datetime_sql(&started_at)?,
        completed_at: completed_at
            .as_deref()
            .map(parse_datetime_sql)
            .transpose()?,
        status: row.get(4)?,
        inventory_count: row.get::<_, i64>(5)? as usize,
        finding_count: row.get::<_, i64>(6)? as usize,
        scanner_errors: serde_json::from_str(&errors_json)
            .map_err(|error| json_sql_error(7, error))?,
    })
}

fn json_sql_error(column: usize, error: serde_json::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, Box::new(error))
}

fn parse_datetime(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)?.with_timezone(&Utc))
}

fn parse_datetime_sql(value: &str) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>> {
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to collect SQLite rows")
}

#[cfg(test)]
mod tests {
    use norn_core::{Exposure, FixAvailability, InventorySource, RuntimeStatus, Severity};

    use super::*;

    #[test]
    fn stores_scan_history_and_summary() {
        let db = Database::open_memory().unwrap();
        let scan = db.create_scan("test-host").unwrap();
        let mut item = InventoryItem::new(
            "docker:abc",
            "nginx",
            InventorySource::Docker,
            InventoryKind::Container,
        );
        item.status = RuntimeStatus::Running;
        item.exposure = Exposure::Public;
        db.insert_inventory(&scan.id, &[item.clone()]).unwrap();

        let finding = VulnerabilityFinding {
            id: "finding-1".to_string(),
            scanner: "grype".to_string(),
            target_id: "target-1".to_string(),
            inventory_item_id: item.id.clone(),
            vulnerability_id: "CVE-2026-0001".to_string(),
            package_name: Some("nginx".to_string()),
            installed_version: Some("1.25.3".to_string()),
            fixed_version: Some("1.25.4".to_string()),
            severity: Severity::Critical,
            cvss: None,
            fix_available: FixAvailability::Available,
            description: None,
            references: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        };
        db.insert_findings(&scan.id, std::slice::from_ref(&finding))
            .unwrap();
        let risk = RiskEvaluation {
            id: "risk-1".to_string(),
            finding_id: finding.id,
            inventory_item_id: item.id,
            service_name: "nginx".to_string(),
            vulnerability_id: "CVE-2026-0001".to_string(),
            severity: Severity::Critical,
            risk: RiskLevel::Critical,
            exposure: Exposure::Public,
            reason: "critical public".to_string(),
            recommended_action: None,
            evaluated_at: Utc::now(),
        };
        db.insert_risks(&scan.id, &[risk]).unwrap();
        db.finish_scan(&scan.id, "completed", 1, 1, &[]).unwrap();

        let summary = db.summary().unwrap();
        assert_eq!(summary.running_containers, 1);
        assert_eq!(summary.public_services, 1);
        assert_eq!(summary.critical_risks, 1);
        assert_eq!(db.list_scans().unwrap().len(), 1);
    }
}
