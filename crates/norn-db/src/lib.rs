use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use norn_core::{
    Exposure, IgnoredFinding, InventoryItem, InventoryKind, InventorySource, NotificationEvent,
    RiskEvaluation, RiskLevel, RuntimeStatus, ScanRecord, ScannerError, ServiceSummary, Summary,
    VulnerabilityFinding, VulnerabilitySummary,
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
        configure_connection(&conn)
            .with_context(|| format!("failed to configure SQLite connection {}", path.display()))?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.migrate()?;
        Ok(db)
    }

    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        // WAL is not meaningful for in-memory DBs, but busy_timeout still is.
        conn.execute_batch("PRAGMA busy_timeout = 5000;")
            .context("failed to configure in-memory SQLite connection")?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
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
        let superseded_errors = serde_json::to_string(&[ScannerError {
            scanner: "norn".to_string(),
            target: "scan".to_string(),
            message: "Scan was superseded by a newer run before it completed.".to_string(),
        }])?;
        conn.execute(
            "UPDATE scans
             SET completed_at = ?2, status = 'abandoned', scanner_errors_json = ?3
             WHERE host = ?1 AND status = 'running'",
            params![host, now.to_rfc3339(), superseded_errors],
        )?;
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
        let conn = self.conn.lock().expect("database mutex poisoned");
        conn.execute(
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
        // Checkpoint the WAL so it doesn't grow unboundedly between scans.
        // TRUNCATE resets the WAL file to zero bytes after a successful checkpoint.
        // We ignore errors here: a failed checkpoint is not fatal, and WAL mode
        // will continue to function correctly even without explicit checkpoints.
        let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        Ok(())
    }

    pub fn prune_old_scans(&self, retention_days: u32) -> Result<usize> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff = cutoff.to_rfc3339();
        let conn = self.conn.lock().expect("database mutex poisoned");
        let deleted_scans = conn.execute(
            "DELETE FROM scans WHERE started_at < ?1 AND status != 'running'",
            params![&cutoff],
        )?;
        let deleted_notifications = conn.execute(
            "DELETE FROM notification_events WHERE created_at < ?1",
            params![&cutoff],
        )?;
        Ok(deleted_scans + deleted_notifications)
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

    pub fn has_prior_notification_event(
        &self,
        scan_id: &str,
        event_type: &str,
        vulnerability_id: Option<&str>,
        service: &str,
    ) -> Result<bool> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let count: i64 = conn.query_row(
            "SELECT COUNT(*)
             FROM notification_events
             WHERE (scan_id IS NULL OR scan_id != ?1)
               AND event_type = ?2
               AND ((vulnerability_id IS NULL AND ?3 IS NULL) OR vulnerability_id = ?3)
               AND service_name = ?4",
            params![scan_id, event_type, vulnerability_id, service],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn prior_notification_keys(
        &self,
        event_type: &str,
    ) -> Result<HashSet<(Option<String>, String)>> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT vulnerability_id, service_name
             FROM notification_events
             WHERE event_type = ?1",
        )?;
        let rows = stmt.query_map(params![event_type], |row| {
            Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.collect::<std::result::Result<HashSet<_>, _>>()
            .context("failed to collect notification dedupe keys")
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

    pub fn summary(&self) -> Result<Summary> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(Summary::default());
        };
        self.summary_for_scan(&scan_id)
    }

    pub fn summary_for_scan(&self, scan_id: &str) -> Result<Summary> {
        let scan = self.scan_by_id(scan_id)?;
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut summary = Summary {
            last_scan_time: scan.completed_at.or(Some(scan.started_at)),
            ..Summary::default()
        };

        {
            let mut stmt = conn.prepare(
                "SELECT kind, status, exposure, COUNT(*)
                 FROM inventory_items
                 WHERE scan_id = ?1
                 GROUP BY kind, status, exposure",
            )?;
            let rows = stmt.query_map(params![&scan_id], |row| {
                let kind_json: String = row.get(0)?;
                let status_json: String = row.get(1)?;
                let exposure_json: String = row.get(2)?;
                Ok((
                    inventory_kind_from_json(0, &kind_json)?,
                    runtime_status_from_json(1, &status_json)?,
                    exposure_from_json(2, &exposure_json)?,
                    row.get::<_, i64>(3)? as usize,
                ))
            })?;

            for row in rows {
                let (kind, status, exposure, count) = row?;
                if status_is_running(status) {
                    match kind {
                        InventoryKind::Container => summary.running_containers += count,
                        InventoryKind::Service => summary.running_services += count,
                        InventoryKind::ListeningPort => summary.listening_ports += count,
                        InventoryKind::Package | InventoryKind::Host => {}
                    }
                }
                if exposure == Exposure::Public {
                    summary.public_services += count;
                }
            }
        }

        {
            let mut stmt = conn.prepare(
                "SELECT risk, COUNT(*)
                 FROM risk_evaluations
                 WHERE scan_id = ?1
                 GROUP BY risk",
            )?;
            let rows = stmt.query_map(params![&scan_id], |row| {
                let risk_json: String = row.get(0)?;
                Ok((
                    risk_level_from_json(0, &risk_json)?,
                    row.get::<_, i64>(1)? as usize,
                ))
            })?;

            for row in rows {
                let (risk, count) = row?;
                match risk {
                    RiskLevel::Critical => summary.critical_risks += count,
                    RiskLevel::High => summary.high_risks += count,
                    RiskLevel::Medium => summary.medium_risks += count,
                    RiskLevel::Low => summary.low_risks += count,
                    RiskLevel::Informational => summary.informational_risks += count,
                }
            }
        }

        Ok(summary)
    }

    pub fn service_summaries(&self) -> Result<Vec<ServiceSummary>> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(Vec::new());
        };
        self.service_summaries_for_scan(&scan_id)
    }

    pub fn service_summaries_for_scan(&self, scan_id: &str) -> Result<Vec<ServiceSummary>> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let mut stmt = conn.prepare(
            r#"
            SELECT
                i.name,
                i.source,
                i.status,
                i.exposure,
                COUNT(r.row_id) AS vulnerability_count,
                MAX(CASE r.risk
                    WHEN '"critical"' THEN 5
                    WHEN '"high"' THEN 4
                    WHEN '"medium"' THEN 3
                    WHEN '"low"' THEN 2
                    WHEN '"informational"' THEN 1
                    ELSE NULL
                END) AS max_risk_score
            FROM inventory_items i
            LEFT JOIN risk_evaluations r
              ON r.scan_id = i.scan_id AND r.inventory_item_id = i.item_id
            WHERE i.scan_id = ?1
            GROUP BY i.row_id, i.name, i.source, i.status, i.exposure
            ORDER BY COALESCE(max_risk_score, 0) DESC, vulnerability_count DESC, i.name
            "#,
        )?;
        let rows = stmt.query_map(params![&scan_id], |row| {
            let source_json: String = row.get(1)?;
            let status_json: String = row.get(2)?;
            let exposure_json: String = row.get(3)?;
            let max_risk_score: Option<i64> = row.get(5)?;

            Ok(ServiceSummary {
                name: row.get(0)?,
                source: inventory_source_from_json(1, &source_json)?,
                status: runtime_status_from_json(2, &status_json)?,
                exposure: exposure_from_json(3, &exposure_json)?,
                highest_risk: max_risk_score.and_then(risk_from_score),
                vulnerability_count: row.get::<_, i64>(4)? as usize,
            })
        })?;
        collect_rows(rows)
    }

    pub fn vulnerability_summaries(&self) -> Result<Vec<VulnerabilitySummary>> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(Vec::new());
        };
        self.vulnerability_summaries_for_scan_with_limit(&scan_id, None)
    }

    pub fn vulnerability_summaries_limited(
        &self,
        limit: usize,
    ) -> Result<Vec<VulnerabilitySummary>> {
        let Some(scan_id) = self.latest_scan_id()? else {
            return Ok(Vec::new());
        };
        self.vulnerability_summaries_for_scan_with_limit(&scan_id, Some(limit))
    }

    pub fn vulnerability_summaries_for_scan(
        &self,
        scan_id: &str,
    ) -> Result<Vec<VulnerabilitySummary>> {
        self.vulnerability_summaries_for_scan_with_limit(scan_id, None)
    }

    fn vulnerability_summaries_for_scan_with_limit(
        &self,
        scan_id: &str,
        limit: Option<usize>,
    ) -> Result<Vec<VulnerabilitySummary>> {
        let conn = self.conn.lock().expect("database mutex poisoned");
        let base_query = r#"
            WITH ranked AS (
                SELECT
                    r.data_json AS risk_json,
                    f.data_json AS finding_json,
                    r.service_name,
                    r.vulnerability_id,
                    CASE r.risk
                        WHEN '"critical"' THEN 5
                        WHEN '"high"' THEN 4
                        WHEN '"medium"' THEN 3
                        WHEN '"low"' THEN 2
                        WHEN '"informational"' THEN 1
                        ELSE 0
                    END AS risk_score,
                    ROW_NUMBER() OVER (
                        PARTITION BY r.service_name, r.vulnerability_id
                        ORDER BY
                            CASE r.risk
                                WHEN '"critical"' THEN 5
                                WHEN '"high"' THEN 4
                                WHEN '"medium"' THEN 3
                                WHEN '"low"' THEN 2
                                WHEN '"informational"' THEN 1
                                ELSE 0
                            END DESC,
                            r.row_id ASC
                    ) AS row_rank
                FROM risk_evaluations r
                JOIN vulnerability_findings f
                  ON f.scan_id = r.scan_id AND f.finding_id = r.finding_id
                WHERE r.scan_id = ?1
            )
            SELECT risk_json, finding_json
            FROM ranked
            WHERE row_rank = 1
            ORDER BY risk_score DESC, service_name, vulnerability_id
        "#;
        let query = if limit.is_some() {
            format!("{base_query} LIMIT ?2")
        } else {
            base_query.to_string()
        };
        let mut stmt = conn.prepare(&query)?;
        if let Some(limit) = limit {
            let rows = stmt.query_map(
                params![&scan_id, limit as i64],
                vulnerability_summary_from_row,
            )?;
            collect_rows(rows)
        } else {
            let rows = stmt.query_map(params![&scan_id], vulnerability_summary_from_row)?;
            collect_rows(rows)
        }
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
                "SELECT id FROM scans WHERE status IN ('completed', 'completed_with_errors') ORDER BY started_at DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("failed to load latest scan id")
    }

    pub fn scan_by_id(&self, scan_id: &str) -> Result<ScanRecord> {
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

/// Apply connection-level PRAGMAs that must be set on every open.
///
/// - `journal_mode=WAL`: readers never block writers and writers never block
///   readers, which matters in `serve` mode where the API polls the DB while
///   long scan inserts are in flight.
/// - `synchronous=NORMAL`: safe with WAL (a crash can only lose the last
///   un-checkpointed frames, not corrupt the database), and meaningfully
///   faster than the default FULL mode.
/// - `busy_timeout=5000`: instead of returning SQLITE_BUSY immediately when
///   another connection holds a lock, wait up to 5 s before giving up.
fn configure_connection(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous  = NORMAL;
        PRAGMA busy_timeout = 5000;
        ",
    )
    .context("failed to apply SQLite connection PRAGMAs")
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

fn inventory_kind_from_json(column: usize, value: &str) -> rusqlite::Result<InventoryKind> {
    serde_json::from_str(value).map_err(|error| json_sql_error(column, error))
}

fn inventory_source_from_json(column: usize, value: &str) -> rusqlite::Result<InventorySource> {
    serde_json::from_str(value).map_err(|error| json_sql_error(column, error))
}

fn runtime_status_from_json(column: usize, value: &str) -> rusqlite::Result<RuntimeStatus> {
    serde_json::from_str(value).map_err(|error| json_sql_error(column, error))
}

fn exposure_from_json(column: usize, value: &str) -> rusqlite::Result<Exposure> {
    serde_json::from_str(value).map_err(|error| json_sql_error(column, error))
}

fn risk_level_from_json(column: usize, value: &str) -> rusqlite::Result<RiskLevel> {
    serde_json::from_str(value).map_err(|error| json_sql_error(column, error))
}

fn risk_evaluation_from_json(column: usize, value: &str) -> rusqlite::Result<RiskEvaluation> {
    serde_json::from_str(value).map_err(|error| json_sql_error(column, error))
}

fn vulnerability_finding_from_json(
    column: usize,
    value: &str,
) -> rusqlite::Result<VulnerabilityFinding> {
    serde_json::from_str(value).map_err(|error| json_sql_error(column, error))
}

fn status_is_running(status: RuntimeStatus) -> bool {
    matches!(status, RuntimeStatus::Running | RuntimeStatus::Active)
}

fn risk_from_score(score: i64) -> Option<RiskLevel> {
    match score {
        5 => Some(RiskLevel::Critical),
        4 => Some(RiskLevel::High),
        3 => Some(RiskLevel::Medium),
        2 => Some(RiskLevel::Low),
        1 => Some(RiskLevel::Informational),
        _ => None,
    }
}

fn vulnerability_summary_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<VulnerabilitySummary> {
    let risk_json: String = row.get(0)?;
    let finding_json: String = row.get(1)?;
    let risk = risk_evaluation_from_json(0, &risk_json)?;
    let finding = vulnerability_finding_from_json(1, &finding_json)?;

    Ok(VulnerabilitySummary {
        vulnerability_id: risk.vulnerability_id,
        severity: risk.severity,
        runtime_risk: risk.risk,
        affected_service: risk.service_name,
        exposed: risk.exposure,
        fix_available: finding.fix_available,
        first_seen: finding.first_seen,
        last_seen: finding.last_seen,
        package_name: finding.package_name,
        installed_version: finding.installed_version,
        fixed_version: finding.fixed_version,
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

    #[test]
    fn prune_old_scans_removes_old_completed_scans() {
        let db = Database::open_memory().unwrap();

        // Insert an old scan and finish it.
        let old_scan = db.create_scan("test-host").unwrap();
        db.finish_scan(&old_scan.id, "completed", 0, 0, &[])
            .unwrap();
        // Back-date the scan's started_at to 200 days ago so it falls outside the 90-day window.
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE scans SET started_at = ?2 WHERE id = ?1",
                params![
                    old_scan.id,
                    (Utc::now() - chrono::Duration::days(200)).to_rfc3339(),
                ],
            )
            .unwrap();

        // Insert a recent scan and finish it.
        let recent_scan = db.create_scan("test-host").unwrap();
        db.finish_scan(&recent_scan.id, "completed", 0, 0, &[])
            .unwrap();

        // Pruning with retention_days = 90 should remove only the old scan.
        let deleted = db.prune_old_scans(90).unwrap();
        assert_eq!(deleted, 1);
        let remaining = db.list_scans().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, recent_scan.id);
    }

    #[test]
    fn prune_old_scans_retention_zero_keeps_everything() {
        let db = Database::open_memory().unwrap();

        let scan = db.create_scan("test-host").unwrap();
        db.finish_scan(&scan.id, "completed", 0, 0, &[]).unwrap();
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE scans SET started_at = ?2 WHERE id = ?1",
                params![
                    scan.id,
                    (Utc::now() - chrono::Duration::days(500)).to_rfc3339(),
                ],
            )
            .unwrap();

        // retention_days = 0 means retain forever.
        let deleted = db.prune_old_scans(0).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(db.list_scans().unwrap().len(), 1);
    }

    #[test]
    fn prune_old_scans_does_not_remove_running_scans() {
        let db = Database::open_memory().unwrap();

        // A running scan that is also old should NOT be pruned.
        let running_scan = db.create_scan("test-host").unwrap();
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE scans SET started_at = ?2 WHERE id = ?1",
                params![
                    running_scan.id,
                    (Utc::now() - chrono::Duration::days(200)).to_rfc3339(),
                ],
            )
            .unwrap();

        let deleted = db.prune_old_scans(90).unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(db.list_scans().unwrap().len(), 1);
    }

    #[test]
    fn prune_old_scans_removes_old_notification_events() {
        let db = Database::open_memory().unwrap();
        let old_scan = db.create_scan("test-host").unwrap();
        let recent_scan = db.create_scan("test-host").unwrap();
        let event = notification_event("nginx", Some("CVE-2026-0001"));

        db.insert_notification(Some(&old_scan.id), "risk", &event)
            .unwrap();
        db.insert_notification(Some(&recent_scan.id), "risk", &event)
            .unwrap();
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE notification_events SET created_at = ?1 WHERE scan_id = ?2",
                params![
                    (Utc::now() - chrono::Duration::days(200)).to_rfc3339(),
                    old_scan.id,
                ],
            )
            .unwrap();

        let deleted = db.prune_old_scans(90).unwrap();

        assert_eq!(deleted, 1);
        assert!(db
            .has_prior_notification_event("new-scan", "risk", Some("CVE-2026-0001"), "nginx",)
            .unwrap());
        let count: i64 = db
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM notification_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn prune_old_scans_retention_zero_keeps_notification_events() {
        let db = Database::open_memory().unwrap();
        let scan = db.create_scan("test-host").unwrap();
        let event = notification_event("nginx", Some("CVE-2026-0001"));
        db.insert_notification(Some(&scan.id), "risk", &event)
            .unwrap();
        db.conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE notification_events SET created_at = ?1 WHERE scan_id = ?2",
                params![
                    (Utc::now() - chrono::Duration::days(500)).to_rfc3339(),
                    scan.id,
                ],
            )
            .unwrap();

        let deleted = db.prune_old_scans(0).unwrap();

        assert_eq!(deleted, 0);
        assert!(db
            .has_prior_notification_event("new-scan", "risk", Some("CVE-2026-0001"), "nginx",)
            .unwrap());
    }

    fn notification_event(service: &str, vulnerability_id: Option<&str>) -> NotificationEvent {
        NotificationEvent {
            project: "Norn".to_string(),
            host: "test-host".to_string(),
            service: service.to_string(),
            artifact: Some("nginx:latest".to_string()),
            vulnerability_id: vulnerability_id.map(str::to_string),
            severity: Some(Severity::Critical),
            runtime_risk: RiskLevel::Critical,
            exposure: Exposure::Public,
            reason: "critical public".to_string(),
            recommended_action: Some("Patch".to_string()),
        }
    }
}
