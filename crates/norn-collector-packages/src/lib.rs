use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use norn_core::{
    Collector, Exposure, InventoryItem, InventoryKind, InventorySource, RuntimeStatus,
};
use tokio::process::Command;

#[derive(Debug, Clone, Default)]
pub struct PackageCollector {
    fixture_path: Option<PathBuf>,
}

impl PackageCollector {
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
impl Collector for PackageCollector {
    fn name(&self) -> &'static str {
        "packages"
    }

    async fn collect(&self) -> Result<Vec<InventoryItem>> {
        if let Some(path) = &self.fixture_path {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read package fixture {}", path.display()))?;
            return Ok(parse_dpkg_list(&content));
        }

        let output = Command::new("dpkg-query")
            .args([
                "-W",
                "-f=${binary:Package}\\t${Version}\\t${Architecture}\\n",
            ])
            .output()
            .await
            .context("failed to execute dpkg-query")?;
        if !output.status.success() {
            anyhow::bail!(
                "dpkg-query failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(parse_dpkg_query(&String::from_utf8_lossy(&output.stdout)))
    }
}

pub fn parse_dpkg_list(input: &str) -> Vec<InventoryItem> {
    input.lines().filter_map(parse_dpkg_status_line).collect()
}

pub fn parse_dpkg_query(input: &str) -> Vec<InventoryItem> {
    input
        .lines()
        .filter_map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            if fields.len() < 2 {
                return None;
            }
            Some(package_item(fields[0], fields[1]))
        })
        .collect()
}

fn parse_dpkg_status_line(line: &str) -> Option<InventoryItem> {
    let trimmed = line.trim();
    if !trimmed.starts_with("ii ") {
        return None;
    }
    let fields = trimmed.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 3 {
        return None;
    }
    Some(package_item(fields[1], fields[2]))
}

fn package_item(name: &str, version: &str) -> InventoryItem {
    let mut item = InventoryItem::new(
        format!("package:{name}"),
        name,
        InventorySource::PackageManager,
        InventoryKind::Package,
    );
    item.status = RuntimeStatus::Installed;
    item.package_name = Some(name.to_string());
    item.package_version = Some(version.to_string());
    item.exposure = Exposure::Unknown;
    item.collected_at = Utc::now();
    item
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../../fixtures/packages/dpkg-status.txt");

    #[test]
    fn parses_installed_dpkg_packages() {
        let packages = parse_dpkg_list(FIXTURE);

        assert_eq!(packages.len(), 3);
        assert!(packages.iter().any(|package| {
            package.package_name.as_deref() == Some("openssl")
                && package.package_version.as_deref() == Some("3.0.11-1~deb12u2")
        }));
        assert!(!packages
            .iter()
            .any(|package| package.package_name.as_deref() == Some("oldpkg")));
    }
}
