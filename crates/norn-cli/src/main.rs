use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use norn_api::{serve, ApiState};
use norn_collector_docker::DockerCollector;
use norn_collector_packages::PackageCollector;
use norn_collector_ports::PortCollector;
use norn_collector_systemd::SystemdCollector;
use norn_core::{
    Exposure, IgnoredFinding, InventoryItem, NornConfig, NotificationEvent, Notifier, RiskLevel,
    ScanOutcome, ScanRecord, ScanRunner, ScannerError, VulnerabilityScanner, DEFAULT_CONFIG_PATH,
};
use norn_db::Database;
use norn_inventory::{scan_targets, scan_targets_from_inventory, CollectorRegistry};
use norn_notify::DiscordNotifier;
use norn_risk::evaluate_finding;
use norn_scanner_grype::GrypeScanner;
use tracing::{error, info, warn};

#[derive(Debug, Parser)]
#[command(name = "norn")]
#[command(about = "Runtime vulnerability monitoring for Linux servers")]
struct Cli {
    #[arg(long, global = true, env = "NORN_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run inventory collection and vulnerability scanning once.
    Scan,
    /// Start the scheduler, API, and dashboard server.
    Serve,
    /// Print current inventory without storing a scan.
    Inventory {
        #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
        output: OutputFormat,
    },
    /// Print a markdown report for the latest stored scan.
    Report,
    /// Send notification commands.
    Notify {
        #[command(subcommand)]
        command: NotifyCommand,
    },
    /// Ignore a vulnerability for an optional service and duration.
    Ignore {
        vulnerability_id: String,
        #[arg(long)]
        service: Option<String>,
        #[arg(long, default_value_t = 30)]
        days: i64,
        #[arg(long)]
        reason: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum NotifyCommand {
    /// Send a test Discord notification.
    Test,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Json,
    Table,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "norn=info,tower_http=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config = NornConfig::load(Some(&cli.config))
        .with_context(|| format!("failed to load config {}", cli.config.display()))?;
    let db = Database::open_url(&config.database.url)?;
    let host = hostname::get()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown-host".to_string());
    let notifier = build_notifier(&config);

    match cli.command {
        Commands::Scan => {
            let runner = LocalScanRunner::new(config, db, host, notifier);
            let outcome = runner.run_scan().await?;
            print_scan_summary(&outcome);
        }
        Commands::Serve => {
            let runner = Arc::new(LocalScanRunner::new(
                config.clone(),
                db.clone(),
                host,
                notifier.clone(),
            ));
            if config.scan.run_on_start {
                match runner.run_scan().await {
                    Ok(outcome) => print_scan_summary(&outcome),
                    Err(error) => warn!(error = %error, "startup scan failed"),
                }
            }
            spawn_scheduler(runner.clone(), config.scan.interval_duration()?);

            let mut state = ApiState::new(db);
            state.runner = Some(runner);
            state.notifier = notifier;
            serve(&config.server.bind, &config.server.static_dir, state).await?;
        }
        Commands::Inventory { output } => {
            let registry = build_collectors(&config);
            let (items, errors) = registry.collect().await;
            for error in errors {
                warn!(
                    scanner = error.scanner,
                    target = error.target,
                    message = error.message,
                    "inventory collector failed"
                );
            }
            print_inventory(&items, output)?;
        }
        Commands::Report => print_report(&db)?,
        Commands::Notify {
            command: NotifyCommand::Test,
        } => {
            let notifier = notifier.context(
                "Discord notifications are disabled or notifications.discord.webhook_url is empty",
            )?;
            notifier
                .send(NotificationEvent {
                    project: "Norn".to_string(),
                    host,
                    service: "notification-test".to_string(),
                    artifact: Some("norn".to_string()),
                    vulnerability_id: Some("TEST-NOTIFICATION".to_string()),
                    severity: None,
                    runtime_risk: RiskLevel::High,
                    exposure: Exposure::Unknown,
                    reason: "Discord webhook test from Norn".to_string(),
                    recommended_action: Some("No action required.".to_string()),
                })
                .await?;
            println!("Sent Discord test notification");
        }
        Commands::Ignore {
            vulnerability_id,
            service,
            days,
            reason,
        } => {
            let ignore = IgnoredFinding {
                vulnerability_id,
                service,
                expires_at: Some(Utc::now() + chrono::Duration::days(days)),
                reason,
            };
            db.add_ignore(&ignore)?;
            println!("Ignore rule added");
        }
    }

    Ok(())
}

#[derive(Clone)]
struct LocalScanRunner {
    config: NornConfig,
    db: Database,
    host: String,
    notifier: Option<Arc<dyn Notifier>>,
}

impl LocalScanRunner {
    fn new(
        config: NornConfig,
        db: Database,
        host: String,
        notifier: Option<Arc<dyn Notifier>>,
    ) -> Self {
        Self {
            config,
            db,
            host,
            notifier,
        }
    }
}

#[async_trait]
impl ScanRunner for LocalScanRunner {
    async fn run_scan(&self) -> Result<ScanOutcome> {
        let scan = self.db.create_scan(&self.host)?;
        info!(scan_id = scan.id, host = self.host, "scan started");

        let registry = build_collectors(&self.config);
        let (inventory, mut errors) = registry.collect().await;
        let targets = scan_targets_from_inventory(&inventory);
        let scanners = build_scanners(&self.config);
        let (findings, scanner_errors) = scan_targets(&scanners, &targets).await;
        errors.extend(scanner_errors);

        let inventory_by_id = inventory
            .iter()
            .map(|item| (item.id.clone(), item))
            .collect::<HashMap<_, _>>();
        let ignores = self.db.active_ignores()?;
        let now = Utc::now();
        let mut risks = Vec::new();
        for finding in &findings {
            let Some(item) = inventory_by_id.get(&finding.inventory_item_id) else {
                continue;
            };
            if ignores
                .iter()
                .any(|ignore| ignore.matches(&finding.vulnerability_id, &item.name, now))
            {
                continue;
            }
            risks.push(evaluate_finding(finding, item));
        }

        let risk_events = self.notification_events_for_risks(&scan, &inventory_by_id, &risks)?;
        let container_events =
            self.notification_events_for_sensitive_containers(&scan, &inventory)?;

        self.db.insert_inventory(&scan.id, &inventory)?;
        self.db.insert_findings(&scan.id, &findings)?;
        self.db.insert_risks(&scan.id, &risks)?;

        for event in risk_events.into_iter().chain(container_events) {
            self.send_notification(&scan.id, event).await;
        }

        let status = if errors.is_empty() {
            "completed"
        } else {
            "completed_with_errors"
        };
        self.db
            .finish_scan(&scan.id, status, inventory.len(), findings.len(), &errors)?;
        let summary = self.db.summary()?;
        let completed = self
            .db
            .list_scans()?
            .into_iter()
            .find(|stored| stored.id == scan.id)
            .unwrap_or_else(|| {
                scan_record_with_errors(scan, status, inventory.len(), findings.len(), errors)
            });

        info!(scan_id = completed.id, status, "scan completed");
        Ok(ScanOutcome {
            scan: completed,
            summary,
        })
    }
}

impl LocalScanRunner {
    fn notification_events_for_risks(
        &self,
        scan: &ScanRecord,
        inventory_by_id: &HashMap<String, &InventoryItem>,
        risks: &[norn_core::RiskEvaluation],
    ) -> Result<Vec<NotificationEvent>> {
        let mut events = Vec::new();
        for risk in risks {
            if !risk.risk.at_least(self.config.risk.notify_minimum) {
                continue;
            }
            if self
                .db
                .has_prior_risk(&scan.id, &risk.vulnerability_id, &risk.service_name)?
            {
                continue;
            }
            let artifact = inventory_by_id
                .get(&risk.inventory_item_id)
                .and_then(|item| item.image.clone().or_else(|| item.package_name.clone()));
            events.push(NotificationEvent {
                project: "Norn".to_string(),
                host: self.host.clone(),
                service: risk.service_name.clone(),
                artifact,
                vulnerability_id: Some(risk.vulnerability_id.clone()),
                severity: Some(risk.severity),
                runtime_risk: risk.risk,
                exposure: risk.exposure,
                reason: risk.reason.clone(),
                recommended_action: risk.recommended_action.clone(),
            });
        }
        Ok(events)
    }

    fn notification_events_for_sensitive_containers(
        &self,
        scan: &ScanRecord,
        inventory: &[InventoryItem],
    ) -> Result<Vec<NotificationEvent>> {
        let mut events = Vec::new();
        for item in inventory {
            let Some(docker) = &item.docker else {
                continue;
            };
            if docker.privileged {
                let key = "NORN-PRIVILEGED-CONTAINER";
                if !self.db.has_prior_risk(&scan.id, key, &item.name)? {
                    events.push(NotificationEvent {
                        project: "Norn".to_string(),
                        host: self.host.clone(),
                        service: item.name.clone(),
                        artifact: item.image.clone(),
                        vulnerability_id: Some(key.to_string()),
                        severity: None,
                        runtime_risk: RiskLevel::High,
                        exposure: item.exposure,
                        reason: "Container is running with privileged=true".to_string(),
                        recommended_action: Some(
                            "Remove privileged mode or isolate this workload.".to_string(),
                        ),
                    });
                }
            }
            if docker.docker_socket_mounted {
                let key = "NORN-DOCKER-SOCKET-MOUNT";
                if !self.db.has_prior_risk(&scan.id, key, &item.name)? {
                    events.push(NotificationEvent {
                        project: "Norn".to_string(),
                        host: self.host.clone(),
                        service: item.name.clone(),
                        artifact: item.image.clone(),
                        vulnerability_id: Some(key.to_string()),
                        severity: None,
                        runtime_risk: RiskLevel::Critical,
                        exposure: item.exposure,
                        reason: "Container mounts /var/run/docker.sock".to_string(),
                        recommended_action: Some(
                            "Remove the Docker socket mount or place it behind a restricted socket proxy."
                                .to_string(),
                        ),
                    });
                }
            }
        }
        Ok(events)
    }

    async fn send_notification(&self, scan_id: &str, event: NotificationEvent) {
        let Some(notifier) = &self.notifier else {
            return;
        };
        match notifier.send(event.clone()).await {
            Ok(()) => {
                if let Err(error) = self.db.insert_notification(Some(scan_id), "risk", &event) {
                    warn!(error = %error, "failed to store notification event");
                }
            }
            Err(error) => warn!(error = %error, notifier = notifier.name(), "notification failed"),
        }
    }
}

fn build_collectors(config: &NornConfig) -> CollectorRegistry {
    let mut registry = CollectorRegistry::new();

    if config.collectors.docker.enabled {
        if let Some(path) = &config.collectors.docker.fixture_path {
            registry.push(DockerCollector::with_fixture(
                &config.collectors.docker.socket,
                path,
            ));
        } else {
            registry.push(DockerCollector::new(&config.collectors.docker.socket));
        }
    }
    if config.collectors.systemd.enabled {
        if let Some(path) = &config.collectors.systemd.fixture_path {
            registry.push(SystemdCollector::with_fixture(path));
        } else {
            registry.push(SystemdCollector::new());
        }
    }
    if config.collectors.packages.enabled {
        if let Some(path) = &config.collectors.packages.fixture_path {
            registry.push(PackageCollector::with_fixture(path));
        } else {
            registry.push(PackageCollector::new());
        }
    }
    if config.collectors.ports.enabled {
        if let Some(path) = &config.collectors.ports.fixture_path {
            registry.push(PortCollector::with_fixture(path));
        } else {
            registry.push(PortCollector::new());
        }
    }

    registry
}

fn build_scanners(config: &NornConfig) -> Vec<Box<dyn VulnerabilityScanner>> {
    let mut scanners: Vec<Box<dyn VulnerabilityScanner>> = Vec::new();
    if config.scanner.grype.enabled {
        let timeout = Duration::from_secs(config.scanner.grype.timeout_seconds);
        if let Some(path) = &config.scanner.grype.fixture_path {
            scanners.push(Box::new(GrypeScanner::with_fixture(
                &config.scanner.grype.binary,
                timeout,
                path,
            )));
        } else {
            scanners.push(Box::new(GrypeScanner::new(
                &config.scanner.grype.binary,
                timeout,
            )));
        }
    }
    scanners
}

fn build_notifier(config: &NornConfig) -> Option<Arc<dyn Notifier>> {
    if config.notifications.discord.enabled
        && !config.notifications.discord.webhook_url.trim().is_empty()
    {
        Some(Arc::new(DiscordNotifier::new(
            config.notifications.discord.webhook_url.clone(),
        )))
    } else {
        None
    }
}

fn spawn_scheduler(runner: Arc<LocalScanRunner>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            ticker.tick().await;
            if let Err(error) = runner.run_scan().await {
                error!(error = %error, "scheduled scan failed");
            }
        }
    });
}

fn scan_record_with_errors(
    mut scan: ScanRecord,
    status: &str,
    inventory_count: usize,
    finding_count: usize,
    scanner_errors: Vec<ScannerError>,
) -> ScanRecord {
    scan.completed_at = Some(Utc::now());
    scan.status = status.to_string();
    scan.inventory_count = inventory_count;
    scan.finding_count = finding_count;
    scan.scanner_errors = scanner_errors;
    scan
}

fn print_scan_summary(outcome: &ScanOutcome) {
    println!("Host: {}", outcome.scan.host);
    println!("Running containers: {}", outcome.summary.running_containers);
    println!("Active services: {}", outcome.summary.running_services);
    println!("Public services: {}", outcome.summary.public_services);
    println!("Critical runtime risks: {}", outcome.summary.critical_risks);
    println!("High runtime risks: {}", outcome.summary.high_risks);
    println!("Medium runtime risks: {}", outcome.summary.medium_risks);
    println!("Low runtime risks: {}", outcome.summary.low_risks);
    if !outcome.scan.scanner_errors.is_empty() {
        println!(
            "Scanner/collector errors: {}",
            outcome.scan.scanner_errors.len()
        );
    }
}

fn print_inventory(items: &[InventoryItem], output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(items)?),
        OutputFormat::Table => {
            println!(
                "{:<28} {:<12} {:<12} {:<10}",
                "NAME", "SOURCE", "STATUS", "EXPOSURE"
            );
            for item in items {
                println!(
                    "{:<28} {:<12} {:<12?} {:<10}",
                    item.name,
                    item.source.to_string(),
                    item.status,
                    item.exposure
                );
            }
        }
    }
    Ok(())
}

fn print_report(db: &Database) -> Result<()> {
    let scans = db.list_scans()?;
    let Some(scan) = scans.first() else {
        println!("# Norn Runtime Security Report\n\nNo scans have been stored yet.");
        return Ok(());
    };
    let vulnerabilities = db.vulnerability_summaries()?;
    let summary = db.summary()?;

    println!("# Norn Runtime Security Report");
    println!();
    println!("Generated at: {}", Utc::now().to_rfc3339());
    println!("Host: {}", scan.host);
    println!();
    println!("## Summary");
    println!();
    println!("- Running containers: {}", summary.running_containers);
    println!("- Active services: {}", summary.running_services);
    println!("- Public services: {}", summary.public_services);
    println!("- Critical runtime risks: {}", summary.critical_risks);
    println!("- High runtime risks: {}", summary.high_risks);
    println!();
    println!("## Urgent");
    print_report_group(
        vulnerabilities
            .iter()
            .filter(|finding| finding.runtime_risk == RiskLevel::Critical),
    );
    println!();
    println!("## Important");
    print_report_group(
        vulnerabilities
            .iter()
            .filter(|finding| finding.runtime_risk == RiskLevel::High),
    );
    println!();
    println!("## Low priority");
    print_report_group(
        vulnerabilities
            .iter()
            .filter(|finding| !finding.runtime_risk.at_least(RiskLevel::High)),
    );
    Ok(())
}

fn print_report_group<'a>(items: impl Iterator<Item = &'a norn_core::VulnerabilitySummary>) {
    let mut printed = false;
    for item in items {
        printed = true;
        println!(
            "- **{}** on `{}`: {} risk, {} exposure, fix {:?}",
            item.vulnerability_id,
            item.affected_service,
            item.runtime_risk.as_str(),
            item.exposed,
            item.fix_available
        );
    }
    if !printed {
        println!("- None");
    }
}
