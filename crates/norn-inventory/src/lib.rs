use norn_core::{
    Collector, InventoryItem, InventoryKind, ScanTarget, ScannerError, VulnerabilityFinding,
    VulnerabilityScanner,
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
            InventoryKind::Container if item.is_running() => item
                .image
                .as_ref()
                .map(|image| ScanTarget::from_inventory(item, format!("docker:{image}"))),
            InventoryKind::Host => Some(ScanTarget::from_inventory(item, "dir:/")),
            _ => None,
        })
        .collect()
}

pub async fn scan_targets(
    scanners: &[Box<dyn VulnerabilityScanner>],
    targets: &[ScanTarget],
) -> (Vec<VulnerabilityFinding>, Vec<ScannerError>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    for target in targets {
        for scanner in scanners {
            debug!(
                scanner = scanner.name(),
                target = target.reference,
                "running vulnerability scanner"
            );
            match scanner.scan(target.clone()).await {
                Ok(mut target_findings) => findings.append(&mut target_findings),
                Err(error) => {
                    warn!(
                        scanner = scanner.name(),
                        target = target.reference,
                        error = %error,
                        "scanner failed for target"
                    );
                    errors.push(ScannerError {
                        scanner: scanner.name().to_string(),
                        target: target.reference.clone(),
                        message: error.to_string(),
                    });
                }
            }
        }
    }

    (findings, errors)
}

pub fn scanner_vec<S>(scanner: S) -> Vec<Box<dyn VulnerabilityScanner>>
where
    S: VulnerabilityScanner + 'static,
{
    vec![Box::new(scanner)]
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use norn_core::{
        DockerMetadata, Exposure, InventoryItem, InventoryKind, InventorySource, RuntimeStatus,
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
}
