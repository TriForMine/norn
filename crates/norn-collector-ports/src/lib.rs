use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use norn_core::{
    Collector, Exposure, InventoryItem, InventoryKind, InventorySource, NetworkEndpoint,
    RuntimeStatus,
};
use tokio::process::Command;

#[derive(Debug, Clone, Default)]
pub struct PortCollector {
    fixture_path: Option<PathBuf>,
}

impl PortCollector {
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
impl Collector for PortCollector {
    fn name(&self) -> &'static str {
        "ports"
    }

    async fn collect(&self) -> Result<Vec<InventoryItem>> {
        if let Some(path) = &self.fixture_path {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read ports fixture {}", path.display()))?;
            return Ok(parse_ss_listening(&content));
        }

        let output = Command::new("ss")
            .args(["-ltnup"])
            .output()
            .await
            .context("failed to execute ss")?;
        if !output.status.success() {
            anyhow::bail!(
                "ss failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(parse_ss_listening(&String::from_utf8_lossy(&output.stdout)))
    }
}

pub fn parse_ss_listening(input: &str) -> Vec<InventoryItem> {
    input.lines().filter_map(parse_ss_line).collect()
}

fn parse_ss_line(line: &str) -> Option<InventoryItem> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("Netid") {
        return None;
    }
    let parts = trimmed.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 5 {
        return None;
    }
    let protocol = parts[0];
    let state = parts[1];
    if state != "LISTEN" && state != "UNCONN" {
        return None;
    }
    let local = parts[4];
    let (address, port) = split_address_port(local)?;
    let process = extract_process(trimmed);
    let exposure = exposure_for_address(&address);
    let name = process
        .clone()
        .unwrap_or_else(|| format!("{}:{}", protocol, port));

    let mut item = InventoryItem::new(
        format!("port:{protocol}:{address}:{port}"),
        name.clone(),
        InventorySource::Ports,
        InventoryKind::ListeningPort,
    );
    item.status = RuntimeStatus::Running;
    item.exposure = exposure;
    item.endpoints.push(NetworkEndpoint {
        protocol: protocol.to_string(),
        address,
        port,
        exposure,
        process,
    });
    item.collected_at = Utc::now();
    Some(item)
}

fn split_address_port(local: &str) -> Option<(String, u16)> {
    let normalized = local.trim();
    if let Some(stripped) = normalized.strip_prefix('[') {
        let (address, rest) = stripped.split_once("]:")?;
        let port = rest.parse().ok()?;
        return Some((address.to_string(), port));
    }
    let (address, port) = normalized.rsplit_once(':')?;
    Some((address.to_string(), port.parse().ok()?))
}

fn extract_process(line: &str) -> Option<String> {
    let start = line.find("((\"")? + 3;
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn exposure_for_address(address: &str) -> Exposure {
    match address {
        "0.0.0.0" | "::" | "*" => Exposure::Public,
        "127.0.0.1" | "::1" | "localhost" => Exposure::Localhost,
        _ => Exposure::Internal,
    }
}

#[cfg(test)]
mod tests {
    use norn_core::Exposure;

    use super::*;

    const FIXTURE: &str = include_str!("../../../fixtures/ports/ss-listening.txt");

    #[test]
    fn parses_listening_ports() {
        let ports = parse_ss_listening(FIXTURE);

        assert_eq!(ports.len(), 4);
        assert!(ports
            .iter()
            .any(|item| item.name == "nginx" && item.exposure == Exposure::Public));
        assert!(ports
            .iter()
            .any(|item| item.name == "postgres" && item.exposure == Exposure::Localhost));
        assert!(ports
            .iter()
            .any(|item| item.name == "mdns" && item.exposure == Exposure::Internal));
    }
}
