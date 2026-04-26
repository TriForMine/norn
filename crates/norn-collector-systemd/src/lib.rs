use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use norn_core::{
    Collector, Exposure, InventoryItem, InventoryKind, InventorySource, RuntimeStatus,
};
use tokio::process::Command;

#[derive(Debug, Clone, Default)]
pub struct SystemdCollector {
    fixture_path: Option<PathBuf>,
}

impl SystemdCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_fixture(path: impl Into<PathBuf>) -> Self {
        Self {
            fixture_path: Some(path.into()),
        }
    }
}

#[async_trait]
impl Collector for SystemdCollector {
    fn name(&self) -> &'static str {
        "systemd"
    }

    async fn collect(&self) -> Result<Vec<InventoryItem>> {
        if let Some(path) = &self.fixture_path {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read systemd fixture {}", path.display()))?;
            return Ok(parse_systemd_units(&content));
        }

        let output = Command::new("systemctl")
            .args([
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--no-pager",
            ])
            .output()
            .await
            .context("failed to execute systemctl")?;
        if !output.status.success() {
            anyhow::bail!(
                "systemctl failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(parse_systemd_units(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }
}

pub fn parse_systemd_units(input: &str) -> Vec<InventoryItem> {
    input
        .lines()
        .filter_map(parse_systemd_line)
        .filter(|item| item.status == RuntimeStatus::Active)
        .collect()
}

fn parse_systemd_line(line: &str) -> Option<InventoryItem> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("UNIT ") || !trimmed.contains(".service") {
        return None;
    }

    let parts = trimmed.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 4 {
        return None;
    }

    let unit = parts[0];
    let active = parts[2];
    let mut item = InventoryItem::new(
        format!("systemd:{unit}"),
        unit.trim_end_matches(".service"),
        InventorySource::Systemd,
        InventoryKind::Service,
    );
    item.status = if active == "active" {
        RuntimeStatus::Active
    } else {
        RuntimeStatus::Stopped
    };
    item.exposure = Exposure::Unknown;
    item.collected_at = Utc::now();
    Some(item)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../../fixtures/systemd/list-units.txt");

    #[test]
    fn parses_active_systemd_services() {
        let services = parse_systemd_units(FIXTURE);

        assert_eq!(services.len(), 4);
        assert!(services.iter().any(|service| service.name == "nginx"));
        assert!(!services
            .iter()
            .any(|service| service.name == "inactive-example"));
    }
}
