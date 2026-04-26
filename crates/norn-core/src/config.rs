use std::{env, fs, path::Path, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};

use crate::RiskLevel;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/norn/config.toml";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NornConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub scan: ScanConfig,
    pub collectors: CollectorsConfig,
    pub scanner: ScannerConfig,
    pub notifications: NotificationsConfig,
    pub risk: RiskConfig,
}

impl NornConfig {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let selected = path.unwrap_or_else(|| Path::new(DEFAULT_CONFIG_PATH));
        let mut config = if selected.exists() {
            let content = fs::read_to_string(selected)
                .with_context(|| format!("failed to read {}", selected.display()))?;
            toml::from_str(&content)
                .with_context(|| format!("failed to parse {}", selected.display()))?
        } else {
            Self::default()
        };
        config.apply_env_overrides();
        Ok(config)
    }

    pub fn load_from_str(input: &str) -> Result<Self> {
        let mut config: Self = toml::from_str(input).context("failed to parse config TOML")?;
        config.apply_env_overrides();
        Ok(config)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(value) = env::var("NORN_SERVER_BIND") {
            self.server.bind = value;
        }
        if let Ok(value) = env::var("NORN_DATABASE_URL") {
            self.database.url = value;
        }
        if let Ok(value) = env::var("NORN_SCAN_INTERVAL") {
            self.scan.interval = value;
        }
        if let Ok(value) = env::var("NORN_GRYPE_BINARY") {
            self.scanner.grype.binary = value;
        }
        if let Ok(value) = env::var("NORN_SCANNER_PARALLELISM") {
            if let Ok(parallelism) = value.parse::<usize>() {
                self.scanner.parallelism = parallelism.max(1);
            }
        }
        if let Ok(value) = env::var("NORN_DISCORD_WEBHOOK_URL") {
            self.notifications.discord.webhook_url = value;
        }
        if let Ok(value) = env::var("NORN_DISCORD_ENABLED") {
            self.notifications.discord.enabled = parse_bool(&value);
        }
        if let Ok(value) = env::var("NORN_RISK_NOTIFY_MINIMUM") {
            self.risk.notify_minimum = parse_risk(&value).unwrap_or(self.risk.notify_minimum);
        }
        if let Ok(value) = env::var("NORN_RISK_MAX_NOTIFICATIONS_PER_SCAN") {
            if let Ok(limit) = value.parse::<usize>() {
                self.risk.max_notifications_per_scan = limit;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub bind: String,
    pub static_dir: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: "0.0.0.0:8787".to_string(),
            static_dir: "apps/web/dist".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    pub url: String,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite:///var/lib/norn/norn.db".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub interval: String,
    pub run_on_start: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            interval: "6h".to_string(),
            run_on_start: true,
        }
    }
}

impl ScanConfig {
    pub fn interval_duration(&self) -> Result<Duration> {
        humantime_serde::re::humantime::parse_duration(&self.interval)
            .with_context(|| format!("invalid scan interval {}", self.interval))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CollectorsConfig {
    pub docker: DockerCollectorConfig,
    pub systemd: BasicCollectorConfig,
    pub packages: BasicCollectorConfig,
    pub ports: BasicCollectorConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DockerCollectorConfig {
    pub enabled: bool,
    pub socket: String,
    pub fixture_path: Option<String>,
}

impl Default for DockerCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket: "/var/run/docker.sock".to_string(),
            fixture_path: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BasicCollectorConfig {
    pub enabled: bool,
    pub fixture_path: Option<String>,
}

impl BasicCollectorConfig {
    pub fn default_enabled() -> Self {
        Self {
            enabled: true,
            fixture_path: None,
        }
    }
}

impl Default for BasicCollectorConfig {
    fn default() -> Self {
        Self::default_enabled()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScannerConfig {
    pub parallelism: usize,
    pub grype: GrypeConfig,
}

impl ScannerConfig {
    pub fn parallelism(&self) -> usize {
        self.parallelism.max(1)
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            parallelism: 4,
            grype: GrypeConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GrypeConfig {
    pub enabled: bool,
    pub binary: String,
    pub timeout_seconds: u64,
    pub fixture_path: Option<String>,
}

impl Default for GrypeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            binary: "grype".to_string(),
            timeout_seconds: 300,
            fixture_path: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationsConfig {
    pub discord: DiscordConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscordConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RiskConfig {
    #[serde(
        default = "default_notify_minimum",
        deserialize_with = "deserialize_risk_level"
    )]
    pub notify_minimum: RiskLevel,
    #[serde(default = "default_max_notifications_per_scan")]
    pub max_notifications_per_scan: usize,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            notify_minimum: RiskLevel::High,
            max_notifications_per_scan: default_max_notifications_per_scan(),
        }
    }
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_risk(value: &str) -> Option<RiskLevel> {
    match value.to_ascii_lowercase().as_str() {
        "critical" => Some(RiskLevel::Critical),
        "high" => Some(RiskLevel::High),
        "medium" => Some(RiskLevel::Medium),
        "low" => Some(RiskLevel::Low),
        "informational" | "info" => Some(RiskLevel::Informational),
        _ => None,
    }
}

fn default_notify_minimum() -> RiskLevel {
    RiskLevel::High
}

fn default_max_notifications_per_scan() -> usize {
    50
}

fn deserialize_risk_level<'de, D>(deserializer: D) -> std::result::Result<RiskLevel, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    parse_risk(&value)
        .ok_or_else(|| serde::de::Error::custom(format!("invalid risk level '{value}'")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_config_and_applies_env_override() {
        env::set_var("NORN_SERVER_BIND", "127.0.0.1:9000");
        env::set_var("NORN_SCANNER_PARALLELISM", "12");
        env::set_var("NORN_RISK_NOTIFY_MINIMUM", "Critical");
        env::set_var("NORN_RISK_MAX_NOTIFICATIONS_PER_SCAN", "7");
        let cfg = NornConfig::load_from_str(
            r#"
            [server]
            bind = "0.0.0.0:8787"

            [database]
            url = "sqlite://./norn.db"
            "#,
        )
        .unwrap();
        env::remove_var("NORN_SERVER_BIND");
        env::remove_var("NORN_SCANNER_PARALLELISM");
        env::remove_var("NORN_RISK_NOTIFY_MINIMUM");
        env::remove_var("NORN_RISK_MAX_NOTIFICATIONS_PER_SCAN");

        assert_eq!(cfg.server.bind, "127.0.0.1:9000");
        assert_eq!(cfg.database.url, "sqlite://./norn.db");
        assert_eq!(cfg.scanner.parallelism(), 12);
        assert_eq!(cfg.risk.notify_minimum, RiskLevel::Critical);
        assert_eq!(cfg.risk.max_notifications_per_scan, 7);
    }

    #[test]
    fn parses_scan_interval() {
        let cfg = ScanConfig {
            interval: "15m".to_string(),
            run_on_start: true,
        };
        assert_eq!(cfg.interval_duration().unwrap(), Duration::from_secs(900));
    }
}
