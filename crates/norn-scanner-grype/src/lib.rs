use std::{fs, path::PathBuf, time::Duration};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use norn_core::{
    FixAvailability, ScanTarget, Severity, VulnerabilityFinding, VulnerabilityScanner,
};
use serde::Deserialize;
use tokio::{process::Command, time::timeout};

#[derive(Debug, Clone)]
pub struct GrypeScanner {
    binary: String,
    timeout: Duration,
    fixture_path: Option<PathBuf>,
}

impl GrypeScanner {
    pub fn new(binary: impl Into<String>, timeout: Duration) -> Self {
        Self {
            binary: binary.into(),
            timeout,
            fixture_path: None,
        }
    }

    pub fn with_fixture(
        binary: impl Into<String>,
        timeout: Duration,
        fixture_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            binary: binary.into(),
            timeout,
            fixture_path: Some(fixture_path.into()),
        }
    }
}

#[async_trait]
impl VulnerabilityScanner for GrypeScanner {
    fn name(&self) -> &'static str {
        "grype"
    }

    async fn scan(&self, target: ScanTarget) -> Result<Vec<VulnerabilityFinding>> {
        if let Some(path) = &self.fixture_path {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read Grype fixture {}", path.display()))?;
            return parse_grype_json(&content, &target);
        }

        let mut command = Command::new(&self.binary);
        command.args(["-o", "json", &target.reference]);
        let output = timeout(self.timeout, command.output())
            .await
            .map_err(|_| anyhow!("Grype scan timed out after {}s", self.timeout.as_secs()))?
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    anyhow!(
                        "Grype binary '{}' was not found; install Grype or set scanner.grype.binary",
                        self.binary
                    )
                } else {
                    anyhow!("failed to execute Grype: {error}")
                }
            })?;

        if !output.status.success() {
            return Err(anyhow!(
                "Grype exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        parse_grype_json(&String::from_utf8_lossy(&output.stdout), &target)
    }
}

pub fn parse_grype_json(input: &str, target: &ScanTarget) -> Result<Vec<VulnerabilityFinding>> {
    let document: GrypeDocument =
        serde_json::from_str(input).context("failed to parse Grype JSON output")?;
    let now = Utc::now();

    Ok(document
        .matches
        .into_iter()
        .map(|entry| {
            let fix_available = fix_availability(entry.vulnerability.fix.as_ref());
            let fixed_version = entry
                .vulnerability
                .fix
                .as_ref()
                .and_then(|fix| fix.versions.first())
                .cloned();
            VulnerabilityFinding {
                id: format!(
                    "{}:{}:{}",
                    target.id, entry.vulnerability.id, entry.artifact.name
                ),
                scanner: "grype".to_string(),
                target_id: target.id.clone(),
                inventory_item_id: target.inventory_item_id.clone(),
                vulnerability_id: entry.vulnerability.id,
                package_name: Some(entry.artifact.name),
                installed_version: Some(entry.artifact.version),
                fixed_version,
                severity: Severity::from_grype(&entry.vulnerability.severity),
                cvss: entry
                    .vulnerability
                    .cvss
                    .as_ref()
                    .and_then(|scores| scores.first())
                    .and_then(|score| score.metrics.base_score),
                fix_available,
                description: entry.vulnerability.description,
                references: entry.vulnerability.urls.unwrap_or_default(),
                first_seen: now,
                last_seen: now,
            }
        })
        .collect())
}

fn fix_availability(fix: Option<&GrypeFix>) -> FixAvailability {
    match fix {
        Some(fix) if !fix.versions.is_empty() => FixAvailability::Available,
        Some(fix) if fix.state.as_deref() == Some("fixed") => FixAvailability::Available,
        Some(_) => FixAvailability::NotAvailable,
        None => FixAvailability::Unknown,
    }
}

#[derive(Debug, Deserialize)]
struct GrypeDocument {
    #[serde(default)]
    matches: Vec<GrypeMatch>,
}

#[derive(Debug, Deserialize)]
struct GrypeMatch {
    vulnerability: GrypeVulnerability,
    artifact: GrypeArtifact,
}

#[derive(Debug, Deserialize)]
struct GrypeVulnerability {
    id: String,
    severity: String,
    description: Option<String>,
    fix: Option<GrypeFix>,
    urls: Option<Vec<String>>,
    cvss: Option<Vec<GrypeCvss>>,
}

#[derive(Debug, Deserialize)]
struct GrypeFix {
    #[serde(default)]
    versions: Vec<String>,
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GrypeCvss {
    metrics: GrypeCvssMetrics,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrypeCvssMetrics {
    base_score: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct GrypeArtifact {
    name: String,
    version: String,
}

#[cfg(test)]
mod tests {
    use norn_core::{Exposure, ScanTarget, ScanTargetType};

    use super::*;

    const FIXTURE: &str = include_str!("../../../fixtures/grype/output.json");

    fn target() -> ScanTarget {
        ScanTarget {
            id: "target-1".to_string(),
            inventory_item_id: "docker:abc".to_string(),
            name: "norn-nginx".to_string(),
            target_type: ScanTargetType::ContainerImage,
            reference: "docker:nginx:1.25.3".to_string(),
            exposure: Exposure::Public,
            docker: None,
        }
    }

    #[test]
    fn parses_grype_json_fixture() {
        let findings = parse_grype_json(FIXTURE, &target()).unwrap();

        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].vulnerability_id, "CVE-2026-0001");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].fix_available, FixAvailability::Available);
        assert_eq!(findings[1].fix_available, FixAvailability::NotAvailable);
        assert_eq!(findings[0].cvss, Some(9.8));
    }
}
