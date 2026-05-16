use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventorySource {
    Docker,
    Systemd,
    PackageManager,
    Ports,
    Host,
}

impl std::fmt::Display for InventorySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Docker => "docker",
            Self::Systemd => "systemd",
            Self::PackageManager => "packages",
            Self::Ports => "ports",
            Self::Host => "host",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryKind {
    Container,
    Service,
    Package,
    ListeningPort,
    Host,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeStatus {
    Running,
    Active,
    Installed,
    Stopped,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exposure {
    Public,
    Internal,
    Localhost,
    Unknown,
}

impl Exposure {
    pub fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

impl std::fmt::Display for Exposure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Localhost => "localhost",
            Self::Unknown => "unknown",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Negligible,
    Unknown,
}

impl Severity {
    pub fn from_grype(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            "negligible" => Self::Negligible,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Negligible => "Negligible",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl RiskLevel {
    pub fn score(self) -> u8 {
        match self {
            Self::Critical => 5,
            Self::High => 4,
            Self::Medium => 3,
            Self::Low => 2,
            Self::Informational => 1,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "Critical",
            Self::High => "High",
            Self::Medium => "Medium",
            Self::Low => "Low",
            Self::Informational => "Informational",
        }
    }

    pub fn at_least(self, minimum: Self) -> bool {
        self.score() >= minimum.score()
    }

    pub fn raised_one(self) -> Self {
        match self {
            Self::Informational => Self::Low,
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
            Self::High | Self::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixAvailability {
    Available,
    NotAvailable,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEndpoint {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub exposure: Exposure,
    pub process: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DockerMetadata {
    pub container_id: String,
    pub image: String,
    pub image_id: Option<String>,
    pub privileged: bool,
    pub docker_socket_mounted: bool,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryItem {
    pub id: String,
    pub name: String,
    pub source: InventorySource,
    pub kind: InventoryKind,
    pub status: RuntimeStatus,
    pub image: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub binary_path: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub endpoints: Vec<NetworkEndpoint>,
    pub exposure: Exposure,
    pub docker: Option<DockerMetadata>,
    pub collected_at: DateTime<Utc>,
}

impl InventoryItem {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        source: InventorySource,
        kind: InventoryKind,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            source,
            kind,
            status: RuntimeStatus::Unknown,
            image: None,
            package_name: None,
            package_version: None,
            binary_path: None,
            labels: BTreeMap::new(),
            endpoints: Vec::new(),
            exposure: Exposure::Unknown,
            docker: None,
            collected_at: Utc::now(),
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self.status, RuntimeStatus::Running | RuntimeStatus::Active)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTargetType {
    ContainerImage,
    HostFilesystem,
    Package,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanTarget {
    pub id: String,
    pub inventory_item_id: String,
    pub name: String,
    pub target_type: ScanTargetType,
    pub reference: String,
    pub exposure: Exposure,
    pub docker: Option<DockerMetadata>,
}

impl ScanTarget {
    pub fn from_inventory(item: &InventoryItem, reference: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            inventory_item_id: item.id.clone(),
            name: item.name.clone(),
            target_type: match item.kind {
                InventoryKind::Container => ScanTargetType::ContainerImage,
                InventoryKind::Package => ScanTargetType::Package,
                _ => ScanTargetType::HostFilesystem,
            },
            reference: reference.into(),
            exposure: item.exposure,
            docker: item.docker.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnerabilityFinding {
    pub id: String,
    pub scanner: String,
    pub target_id: String,
    pub inventory_item_id: String,
    pub vulnerability_id: String,
    pub package_name: Option<String>,
    pub installed_version: Option<String>,
    pub fixed_version: Option<String>,
    pub severity: Severity,
    pub cvss: Option<f32>,
    pub fix_available: FixAvailability,
    pub description: Option<String>,
    pub references: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskEvaluation {
    pub id: String,
    pub finding_id: String,
    pub inventory_item_id: String,
    pub service_name: String,
    pub vulnerability_id: String,
    pub severity: Severity,
    pub risk: RiskLevel,
    pub exposure: Exposure,
    pub reason: String,
    pub recommended_action: Option<String>,
    pub evaluated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnoredFinding {
    pub vulnerability_id: String,
    pub service: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
}

impl IgnoredFinding {
    pub fn matches(&self, vulnerability_id: &str, service: &str, now: DateTime<Utc>) -> bool {
        if self.vulnerability_id != vulnerability_id {
            return false;
        }
        if let Some(expires_at) = self.expires_at {
            if expires_at <= now {
                return false;
            }
        }
        self.service
            .as_deref()
            .map(|expected| expected == service)
            .unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerError {
    pub scanner: String,
    pub target: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub host: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: String,
    pub inventory_count: usize,
    pub finding_count: usize,
    pub scanner_errors: Vec<ScannerError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Summary {
    pub running_services: usize,
    pub running_containers: usize,
    pub listening_ports: usize,
    pub public_services: usize,
    pub critical_risks: usize,
    pub high_risks: usize,
    pub medium_risks: usize,
    pub low_risks: usize,
    pub informational_risks: usize,
    pub last_scan_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceSummary {
    pub name: String,
    pub source: InventorySource,
    pub status: RuntimeStatus,
    pub exposure: Exposure,
    pub highest_risk: Option<RiskLevel>,
    pub vulnerability_count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    pub vulnerability_id: String,
    pub severity: Severity,
    pub runtime_risk: RiskLevel,
    pub affected_service: String,
    pub exposed: Exposure,
    pub fix_available: FixAvailability,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub package_name: Option<String>,
    pub installed_version: Option<String>,
    pub fixed_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationItem {
    pub service: String,
    pub highest_risk: RiskLevel,
    pub exposure: Exposure,
    pub vulnerability_count: usize,
    pub fixable_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub informational_count: usize,
    pub top_vulnerabilities: Vec<String>,
    pub affected_packages: Vec<RemediationPackage>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub recommended_action: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationPackage {
    pub package_name: String,
    pub installed_version: Option<String>,
    pub fixed_version: Option<String>,
    pub vulnerability_count: usize,
    pub fixable_count: usize,
    pub highest_risk: RiskLevel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanOutcome {
    pub scan: ScanRecord,
    pub summary: Summary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationEvent {
    pub project: String,
    pub host: String,
    pub service: String,
    pub artifact: Option<String>,
    pub vulnerability_id: Option<String>,
    pub severity: Option<Severity>,
    pub runtime_risk: RiskLevel,
    pub exposure: Exposure,
    pub reason: String,
    pub recommended_action: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_rule_matches_service_and_expiry() {
        let now = Utc::now();
        let rule = IgnoredFinding {
            vulnerability_id: "CVE-2026-0001".to_string(),
            service: Some("nginx".to_string()),
            expires_at: Some(now + chrono::Duration::days(1)),
            reason: None,
        };

        assert!(rule.matches("CVE-2026-0001", "nginx", now));
        assert!(!rule.matches("CVE-2026-0001", "postgres", now));
        assert!(!rule.matches("CVE-2026-0002", "nginx", now));
        assert!(!rule.matches("CVE-2026-0001", "nginx", now + chrono::Duration::days(2)));
    }
}
