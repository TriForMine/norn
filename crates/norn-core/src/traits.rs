use anyhow::Result;
use async_trait::async_trait;

use crate::{InventoryItem, NotificationEvent, ScanOutcome, ScanTarget, VulnerabilityFinding};

#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn collect(&self) -> Result<Vec<InventoryItem>>;
}

#[async_trait]
pub trait VulnerabilityScanner: Send + Sync {
    fn name(&self) -> &'static str;
    async fn scan(&self, target: ScanTarget) -> Result<Vec<VulnerabilityFinding>>;
}

#[async_trait]
pub trait Notifier: Send + Sync {
    fn name(&self) -> &'static str;
    async fn send(&self, event: NotificationEvent) -> Result<()>;
}

#[async_trait]
pub trait ScanRunner: Send + Sync {
    async fn run_scan(&self) -> Result<ScanOutcome>;
}
