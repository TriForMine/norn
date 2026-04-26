use chrono::Utc;
use norn_core::{
    Exposure, FixAvailability, InventoryItem, RiskEvaluation, RiskLevel, Severity,
    VulnerabilityFinding,
};
use uuid::Uuid;

pub fn evaluate_finding(
    finding: &VulnerabilityFinding,
    inventory_item: &InventoryItem,
) -> RiskEvaluation {
    let mut risk = base_risk(finding.severity, inventory_item.exposure);
    let mut reasons = vec![format!(
        "{} vulnerability on {} service",
        finding.severity.as_str(),
        inventory_item.exposure
    )];

    if inventory_item.exposure == Exposure::Unknown {
        reasons.push("Unknown exposure; finding is retained for review".to_string());
    }

    if let Some(docker) = &inventory_item.docker {
        if docker.privileged {
            risk = risk.raised_one();
            reasons.push("Container is running privileged".to_string());
        }
        if docker.docker_socket_mounted {
            risk = risk.raised_one();
            reasons.push("Container mounts the Docker socket".to_string());
        }
    }

    let recommended_action = recommended_action(finding.fix_available, risk);

    RiskEvaluation {
        id: Uuid::new_v4().to_string(),
        finding_id: finding.id.clone(),
        inventory_item_id: inventory_item.id.clone(),
        service_name: inventory_item.name.clone(),
        vulnerability_id: finding.vulnerability_id.clone(),
        severity: finding.severity,
        risk,
        exposure: inventory_item.exposure,
        reason: reasons.join("; "),
        recommended_action,
        evaluated_at: Utc::now(),
    }
}

pub fn base_risk(severity: Severity, exposure: Exposure) -> RiskLevel {
    match (severity, exposure) {
        (Severity::Critical, Exposure::Public) => RiskLevel::Critical,
        (Severity::High, Exposure::Public) => RiskLevel::High,
        (Severity::Medium, Exposure::Public) => RiskLevel::Medium,
        (Severity::Low, Exposure::Public) => RiskLevel::Low,
        (Severity::Critical, Exposure::Internal | Exposure::Localhost | Exposure::Unknown) => {
            RiskLevel::High
        }
        (Severity::High, Exposure::Internal | Exposure::Localhost | Exposure::Unknown) => {
            RiskLevel::Medium
        }
        (Severity::Medium, Exposure::Internal | Exposure::Localhost | Exposure::Unknown) => {
            RiskLevel::Medium
        }
        (Severity::Low, Exposure::Internal | Exposure::Localhost | Exposure::Unknown) => {
            RiskLevel::Low
        }
        _ => RiskLevel::Informational,
    }
}

fn recommended_action(fix_available: FixAvailability, risk: RiskLevel) -> Option<String> {
    match (fix_available, risk) {
        (FixAvailability::Available, RiskLevel::Critical | RiskLevel::High) => {
            Some("Patch or redeploy the affected service as soon as possible.".to_string())
        }
        (FixAvailability::Available, _) => {
            Some("Plan an update for the affected package or image.".to_string())
        }
        (FixAvailability::NotAvailable, RiskLevel::Critical | RiskLevel::High) => Some(
            "No fix is known; reduce exposure, add compensating controls, or replace the component."
                .to_string(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use norn_core::{
        DockerMetadata, FixAvailability, InventoryKind, InventorySource, RuntimeStatus,
    };

    use super::*;

    fn item(exposure: Exposure) -> InventoryItem {
        let mut item = InventoryItem::new(
            "docker:abc",
            "nginx",
            InventorySource::Docker,
            InventoryKind::Container,
        );
        item.status = RuntimeStatus::Running;
        item.exposure = exposure;
        item
    }

    fn finding(severity: Severity) -> VulnerabilityFinding {
        VulnerabilityFinding {
            id: "finding-1".to_string(),
            scanner: "grype".to_string(),
            target_id: "target-1".to_string(),
            inventory_item_id: "docker:abc".to_string(),
            vulnerability_id: "CVE-2026-0001".to_string(),
            package_name: Some("nginx".to_string()),
            installed_version: Some("1.25.3".to_string()),
            fixed_version: Some("1.25.4".to_string()),
            severity,
            cvss: None,
            fix_available: FixAvailability::Available,
            description: None,
            references: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    #[test]
    fn critical_public_service_is_critical_runtime_risk() {
        let risk = evaluate_finding(&finding(Severity::Critical), &item(Exposure::Public));

        assert_eq!(risk.risk, RiskLevel::Critical);
    }

    #[test]
    fn critical_internal_service_is_high_runtime_risk() {
        let risk = evaluate_finding(&finding(Severity::Critical), &item(Exposure::Internal));

        assert_eq!(risk.risk, RiskLevel::High);
    }

    #[test]
    fn medium_internal_service_stays_medium() {
        let risk = evaluate_finding(&finding(Severity::Medium), &item(Exposure::Internal));

        assert_eq!(risk.risk, RiskLevel::Medium);
    }

    #[test]
    fn privileged_container_increases_risk() {
        let mut item = item(Exposure::Internal);
        item.docker = Some(DockerMetadata {
            container_id: "abc".to_string(),
            image: "nginx".to_string(),
            image_id: None,
            privileged: true,
            docker_socket_mounted: false,
            labels: Default::default(),
        });

        let risk = evaluate_finding(&finding(Severity::High), &item);

        assert_eq!(risk.risk, RiskLevel::High);
        assert!(risk.reason.contains("privileged"));
    }

    #[test]
    fn docker_socket_mount_increases_risk() {
        let mut item = item(Exposure::Internal);
        item.docker = Some(DockerMetadata {
            container_id: "abc".to_string(),
            image: "nginx".to_string(),
            image_id: None,
            privileged: false,
            docker_socket_mounted: true,
            labels: Default::default(),
        });

        let risk = evaluate_finding(&finding(Severity::High), &item);

        assert_eq!(risk.risk, RiskLevel::High);
        assert!(risk.reason.contains("Docker socket"));
    }

    #[test]
    fn unknown_exposure_is_marked_for_review() {
        let risk = evaluate_finding(&finding(Severity::High), &item(Exposure::Unknown));

        assert_eq!(risk.risk, RiskLevel::Medium);
        assert!(risk.reason.contains("Unknown exposure"));
    }
}
