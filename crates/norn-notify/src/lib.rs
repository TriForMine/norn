use anyhow::{anyhow, Result};
use async_trait::async_trait;
use norn_core::{NotificationEvent, Notifier};
use serde_json::{json, Value};

#[derive(Clone)]
pub struct DiscordNotifier {
    webhook_url: String,
    client: reqwest::Client,
}

impl DiscordNotifier {
    pub fn new(webhook_url: impl Into<String>) -> Self {
        Self {
            webhook_url: webhook_url.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Notifier for DiscordNotifier {
    fn name(&self) -> &'static str {
        "discord"
    }

    async fn send(&self, event: NotificationEvent) -> Result<()> {
        if self.webhook_url.trim().is_empty() {
            return Err(anyhow!("Discord webhook URL is empty"));
        }

        let response = self
            .client
            .post(&self.webhook_url)
            .json(&discord_payload(&event))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(anyhow!("Discord webhook returned {}", response.status()));
        }
        Ok(())
    }
}

pub fn discord_payload(event: &NotificationEvent) -> Value {
    let title = match &event.vulnerability_id {
        Some(id) => format!("{} runtime risk: {}", event.runtime_risk.as_str(), id),
        None => format!("{} runtime risk", event.runtime_risk.as_str()),
    };
    let artifact = event.artifact.as_deref().unwrap_or("unknown");
    let severity = event
        .severity
        .map(|severity| severity.as_str())
        .unwrap_or("N/A");
    let action = event
        .recommended_action
        .as_deref()
        .unwrap_or("Review the affected runtime asset and reduce exposure where possible.");

    json!({
        "username": "Norn",
        "embeds": [{
            "title": title,
            "description": event.reason,
            "color": color_for_risk(event.runtime_risk.score()),
            "fields": [
                {"name": "Project", "value": event.project, "inline": true},
                {"name": "Host", "value": event.host, "inline": true},
                {"name": "Service", "value": event.service, "inline": true},
                {"name": "Artifact", "value": artifact, "inline": true},
                {"name": "Severity", "value": severity, "inline": true},
                {"name": "Runtime risk", "value": event.runtime_risk.as_str(), "inline": true},
                {"name": "Exposure", "value": event.exposure.to_string(), "inline": true},
                {"name": "Recommended action", "value": action, "inline": false}
            ]
        }]
    })
}

fn color_for_risk(score: u8) -> u32 {
    match score {
        5 => 0xd7263d,
        4 => 0xf46036,
        3 => 0xf4b942,
        2 => 0x2e86ab,
        _ => 0x6c757d,
    }
}

#[cfg(test)]
mod tests {
    use norn_core::{Exposure, RiskLevel, Severity};

    use super::*;

    #[test]
    fn formats_discord_payload() {
        let payload = discord_payload(&NotificationEvent {
            project: "Norn".to_string(),
            host: "homelab".to_string(),
            service: "nginx".to_string(),
            artifact: Some("nginx:1.25.3".to_string()),
            vulnerability_id: Some("CVE-2026-0001".to_string()),
            severity: Some(Severity::Critical),
            runtime_risk: RiskLevel::Critical,
            exposure: Exposure::Public,
            reason: "Critical vulnerability on public service".to_string(),
            recommended_action: Some("Patch now.".to_string()),
        });

        assert_eq!(payload["username"], "Norn");
        assert!(payload["embeds"][0]["title"]
            .as_str()
            .unwrap()
            .contains("CVE-2026-0001"));
        assert_eq!(payload["embeds"][0]["fields"][2]["value"], "nginx");
    }
}
