use norn_core::{
    Collector, InventoryItem, InventoryKind, ScanTarget, ScannerError, VulnerabilityFinding,
};
use tracing::{debug, warn};

#[derive(Default)]
pub struct CollectorRegistry {
    collectors: Vec<Box<dyn Collector>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push<C>(&mut self, collector: C)
    where
        C: Collector + 'static,
    {
        self.collectors.push(Box::new(collector));
    }

    pub async fn collect(&self) -> (Vec<InventoryItem>, Vec<ScannerError>) {
        let mut items = Vec::new();
        let mut errors = Vec::new();

        for collector in &self.collectors {
            debug!(collector = collector.name(), "running collector");
            match collector.collect().await {
                Ok(mut collected) => items.append(&mut collected),
                Err(error) => {
                    warn!(collector = collector.name(), error = %error, "collector failed");
                    errors.push(ScannerError {
                        scanner: collector.name().to_string(),
                        target: "inventory".to_string(),
                        message: error.to_string(),
                    });
                }
            }
        }

        (items, errors)
    }
}

pub fn scan_targets_from_inventory(items: &[InventoryItem]) -> Vec<ScanTarget> {
    items
        .iter()
        .filter_map(|item| match item.kind {
            InventoryKind::Container if item.is_running() => container_scan_reference(item)
                .map(|reference| ScanTarget::from_inventory(item, reference)),
            InventoryKind::Host => Some(ScanTarget::from_inventory(item, "dir:/")),
            _ => None,
        })
        .collect()
}

fn container_scan_reference(item: &InventoryItem) -> Option<String> {
    let image = item
        .docker
        .as_ref()
        .and_then(|docker| docker.image_id.as_deref())
        .filter(|image_id| !image_id.trim().is_empty())
        .or(item.image.as_deref())?;
    Some(format!("docker:{image}"))
}

#[derive(Debug, Clone)]
pub struct ScanTargetGroup {
    pub representative: ScanTarget,
    pub targets: Vec<ScanTarget>,
}

pub fn unique_scan_target_groups(targets: &[ScanTarget]) -> Vec<ScanTargetGroup> {
    let mut groups = Vec::<ScanTargetGroup>::new();

    for target in targets {
        if let Some(group) = groups
            .iter_mut()
            .find(|group| group.representative.reference == target.reference)
        {
            group.targets.push(target.clone());
        } else {
            groups.push(ScanTargetGroup {
                representative: target.clone(),
                targets: vec![target.clone()],
            });
        }
    }

    groups
}

pub fn expand_findings_to_targets(
    findings: &[VulnerabilityFinding],
    targets: &[ScanTarget],
) -> Vec<VulnerabilityFinding> {
    let mut expanded = Vec::with_capacity(findings.len().saturating_mul(targets.len()));
    for target in targets {
        for finding in findings {
            expanded.push(finding_for_target(finding, target));
        }
    }
    expanded
}

fn finding_for_target(finding: &VulnerabilityFinding, target: &ScanTarget) -> VulnerabilityFinding {
    if finding.target_id == target.id && finding.inventory_item_id == target.inventory_item_id {
        return finding.clone();
    }

    let mut finding = finding.clone();
    finding.id = format!("{}:{}", target.id, finding.id);
    finding.target_id = target.id.clone();
    finding.inventory_item_id = target.inventory_item_id.clone();
    finding
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use norn_core::{
        DockerMetadata, Exposure, FixAvailability, InventoryItem, InventoryKind, InventorySource,
        RuntimeStatus, ScanTargetType, Severity, VulnerabilityFinding,
    };

    use super::*;

    #[test]
    fn creates_container_scan_targets() {
        let mut item = InventoryItem::new(
            "docker:abc",
            "nginx",
            InventorySource::Docker,
            InventoryKind::Container,
        );
        item.status = RuntimeStatus::Running;
        item.image = Some("nginx:1.25".to_string());
        item.exposure = Exposure::Public;
        item.docker = Some(DockerMetadata {
            container_id: "abc".to_string(),
            image: "nginx:1.25".to_string(),
            image_id: None,
            privileged: false,
            docker_socket_mounted: false,
            labels: Default::default(),
        });
        item.collected_at = Utc::now();

        let targets = scan_targets_from_inventory(&[item]);

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].reference, "docker:nginx:1.25");
        assert_eq!(targets[0].exposure, Exposure::Public);
    }

    #[test]
    fn prefers_docker_image_id_for_container_scan_targets() {
        let mut item = InventoryItem::new(
            "docker:abc",
            "nginx",
            InventorySource::Docker,
            InventoryKind::Container,
        );
        item.status = RuntimeStatus::Running;
        item.image = Some("private/nginx:latest".to_string());
        item.docker = Some(DockerMetadata {
            container_id: "abc".to_string(),
            image: "private/nginx:latest".to_string(),
            image_id: Some("sha256:abc123".to_string()),
            privileged: false,
            docker_socket_mounted: false,
            labels: Default::default(),
        });

        let targets = scan_targets_from_inventory(&[item]);

        assert_eq!(targets[0].reference, "docker:sha256:abc123");
    }

    #[test]
    fn groups_duplicate_scan_references() {
        let first = scan_target("target-1", "item-1", "web-1", "docker:sha256:abc");
        let second = scan_target("target-2", "item-2", "web-2", "docker:sha256:abc");
        let third = scan_target("target-3", "item-3", "db", "docker:sha256:def");

        let groups = unique_scan_target_groups(&[first, second, third]);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].targets.len(), 2);
        assert_eq!(groups[1].targets.len(), 1);
    }

    #[test]
    fn expands_findings_to_all_targets_in_group() {
        let first = scan_target("target-1", "item-1", "web-1", "docker:sha256:abc");
        let second = scan_target("target-2", "item-2", "web-2", "docker:sha256:abc");
        let finding = VulnerabilityFinding {
            id: "finding-1".to_string(),
            scanner: "grype".to_string(),
            target_id: first.id.clone(),
            inventory_item_id: first.inventory_item_id.clone(),
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

        let expanded = expand_findings_to_targets(&[finding], &[first, second]);

        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0].inventory_item_id, "item-1");
        assert_eq!(expanded[1].inventory_item_id, "item-2");
        assert_eq!(expanded[1].target_id, "target-2");
    }

    fn scan_target(
        id: impl Into<String>,
        inventory_item_id: impl Into<String>,
        name: impl Into<String>,
        reference: impl Into<String>,
    ) -> ScanTarget {
        ScanTarget {
            id: id.into(),
            inventory_item_id: inventory_item_id.into(),
            name: name.into(),
            target_type: ScanTargetType::ContainerImage,
            reference: reference.into(),
            exposure: Exposure::Public,
            docker: None,
        }
    }
}
