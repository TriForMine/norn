use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    io::{self, Stdout},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand, ValueEnum};
use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table as ComfyTable};
use console::{style as console_style, Term};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use norn_api::{serve, ApiState, ScanLock, ScanProgressState};
use norn_collector_docker::DockerCollector;
use norn_collector_packages::PackageCollector;
use norn_collector_ports::PortCollector;
use norn_collector_systemd::SystemdCollector;
use norn_core::{
    Exposure, IgnoredFinding, InventoryItem, NornConfig, NotificationEvent, Notifier, RiskLevel,
    ScanOutcome, ScanRecord, ScanRunner, ScanTarget, ScannerError, ServiceSummary, Summary,
    VulnerabilityFinding, VulnerabilityScanner, VulnerabilitySummary, DEFAULT_CONFIG_PATH,
};
use norn_db::Database;
use norn_inventory::{
    expand_findings_to_targets, scan_targets_from_inventory_with_options,
    unique_scan_target_groups, CollectorRegistry, ScanTargetOptions,
};
use norn_notify::DiscordNotifier;
use norn_risk::evaluate_finding;
use norn_scanner_grype::GrypeScanner;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table as TuiTable},
    Frame, Terminal,
};
use tracing::{debug, error, info, warn};

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
    Scan {
        /// Disable interactive progress bars.
        #[arg(long)]
        no_progress: bool,
        /// Override scanner concurrency for this run.
        #[arg(long, value_parser = parse_positive_usize)]
        jobs: Option<usize>,
    },
    /// Start the scheduler, API, and dashboard server.
    Serve,
    /// Open the terminal dashboard.
    Tui,
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

const TUI_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const TUI_VULNERABILITY_LIMIT: usize = 200;

#[derive(Debug, Default)]
struct NotificationBatch {
    events: Vec<NotificationEvent>,
    suppressed: usize,
}

fn parse_positive_usize(value: &str) -> std::result::Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|error| format!("invalid number '{value}': {error}"))?;
    if parsed == 0 {
        Err("value must be at least 1".to_string())
    } else {
        Ok(parsed)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "norn=info,tower_http=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let mut config = NornConfig::load(Some(&cli.config))
        .with_context(|| format!("failed to load config {}", cli.config.display()))?;
    let db = Database::open_url(&config.database.url)?;
    let host = hostname::get()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown-host".to_string());
    let notifier = build_notifier(&config);

    match cli.command {
        Commands::Scan { no_progress, jobs } => {
            if let Some(jobs) = jobs {
                config.scanner.parallelism = jobs;
            }
            let runner = LocalScanRunner::new(config, db, host, notifier, None);
            let outcome = runner.run_scan_interactive(!no_progress).await?;
            print_scan_summary(&outcome);
        }
        Commands::Serve => {
            let mut state = ApiState::new(db.clone());
            let runner = Arc::new(LocalScanRunner::new(
                config.clone(),
                db.clone(),
                host,
                notifier.clone(),
                Some(state.scan_progress.clone()),
            ));
            if config.scan.run_on_start {
                match runner.run_scan().await {
                    Ok(outcome) => print_scan_summary(&outcome),
                    Err(error) => warn!(error = %error, "startup scan failed"),
                }
            }
            state.runner = Some(runner.clone());
            state.notifier = notifier;
            spawn_scheduler(
                runner,
                config.scan.interval_duration()?,
                state.scan_lock.clone(),
            );
            serve(&config.server.bind, &config.server.static_dir, state).await?;
        }
        Commands::Tui => {
            let runner = LocalScanRunner::new(config, db.clone(), host, notifier, None);
            run_tui(db, runner).await?;
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
    scan_progress: Option<ScanProgressState>,
}

impl LocalScanRunner {
    fn new(
        config: NornConfig,
        db: Database,
        host: String,
        notifier: Option<Arc<dyn Notifier>>,
        scan_progress: Option<ScanProgressState>,
    ) -> Self {
        Self {
            config,
            db,
            host,
            notifier,
            scan_progress,
        }
    }
}

#[async_trait]
impl ScanRunner for LocalScanRunner {
    async fn run_scan(&self) -> Result<ScanOutcome> {
        self.run_scan_internal(ScanProgress::disabled()).await
    }
}

impl LocalScanRunner {
    async fn run_scan_interactive(&self, show_progress: bool) -> Result<ScanOutcome> {
        self.run_scan_internal(ScanProgress::new(show_progress))
            .await
    }

    async fn run_scan_internal(&self, progress: ScanProgress) -> Result<ScanOutcome> {
        let scan = self.db.create_scan(&self.host)?;
        info!(scan_id = scan.id, host = self.host, "scan started");
        if let Some(scan_progress) = &self.scan_progress {
            scan_progress.start(scan.id.clone(), self.host.clone());
        }

        let outcome = self.run_scan_steps(scan, progress).await;
        if outcome.is_err() {
            if let Some(scan_progress) = &self.scan_progress {
                scan_progress.finish("Scan failed");
            }
        }
        outcome
    }

    async fn run_scan_steps(
        &self,
        scan: ScanRecord,
        progress: ScanProgress,
    ) -> Result<ScanOutcome> {
        if let Some(scan_progress) = &self.scan_progress {
            scan_progress.set_phase("collecting_inventory", "Collecting inventory", None);
        }
        let registry = build_collectors(&self.config);
        let inventory_progress = progress.spinner("Collecting runtime inventory");
        let (inventory, mut errors) = registry.collect().await;
        inventory_progress
            .finish_with_message(format!("Collected {} inventory items", inventory.len()));

        if let Some(scan_progress) = &self.scan_progress {
            scan_progress.set_phase(
                "preparing_targets",
                "Preparing vulnerability targets",
                Some(format!("Collected {} inventory items", inventory.len())),
            );
        }
        let targets = scan_targets_from_inventory_with_options(
            &inventory,
            ScanTargetOptions {
                scan_host_filesystem: self.config.scanner.scan_host_filesystem,
            },
        );
        let scanners = build_scanners(&self.config);
        let (findings, scanner_errors) = scan_targets_with_progress(
            &scanners,
            &targets,
            self.config.scanner.parallelism(),
            &progress,
            self.scan_progress.clone(),
        )
        .await;
        errors.extend(scanner_errors);

        if let Some(scan_progress) = &self.scan_progress {
            scan_progress.set_phase(
                "evaluating_risk",
                "Evaluating runtime risk",
                Some(format!("Found {} vulnerability findings", findings.len())),
            );
        }
        let risk_progress = progress.spinner("Evaluating runtime risk");
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
        risk_progress.finish_with_message(format!("Evaluated {} runtime risks", risks.len()));

        if let Some(scan_progress) = &self.scan_progress {
            scan_progress.set_phase(
                "preparing_notifications",
                "Preparing notifications",
                Some(format!("Evaluated {} runtime risks", risks.len())),
            );
        }
        let notification_progress = progress.spinner("Preparing notifications");
        let notification_batch = if self.notifier.is_some() {
            self.prepare_notification_batch(&inventory_by_id, &risks, &inventory)?
        } else {
            NotificationBatch::default()
        };
        if self.notifier.is_some() {
            let prepared = notification_batch.events.len();
            let suppressed = notification_batch.suppressed;
            if suppressed > 0 && self.config.risk.max_notifications_per_scan == 0 {
                notification_progress.finish_with_message(format!(
                    "Suppressed {suppressed} notifications (cap is 0)"
                ));
            } else if suppressed > 0 {
                notification_progress.finish_with_message(format!(
                    "Prepared {prepared} notifications ({suppressed} summarized)"
                ));
            } else {
                notification_progress
                    .finish_with_message(format!("Prepared {prepared} notifications"));
            }
        } else {
            notification_progress.finish_with_message("Skipped notifications (notifier disabled)");
        }

        if let Some(scan_progress) = &self.scan_progress {
            scan_progress.set_phase("storing_results", "Storing scan results", None);
        }
        let storage_progress = progress.spinner("Storing scan results");
        self.db.insert_inventory(&scan.id, &inventory)?;
        self.db.insert_findings(&scan.id, &findings)?;
        self.db.insert_risks(&scan.id, &risks)?;
        storage_progress.finish_with_message("Stored scan results");

        if let Err(error) = self.db.prune_old_scans(self.config.database.retention_days) {
            warn!(error = %error, "failed to prune old scan data");
        } else {
            debug!(
                retention_days = self.config.database.retention_days,
                "pruned old scan data"
            );
        }

        for event in notification_batch.events {
            self.send_notification(&scan.id, event).await;
        }

        let status = if errors.is_empty() {
            "completed"
        } else {
            "completed_with_errors"
        };
        self.db
            .finish_scan(&scan.id, status, inventory.len(), findings.len(), &errors)?;
        if let Some(scan_progress) = &self.scan_progress {
            scan_progress.finish("Scan complete");
        }
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

    fn prepare_notification_batch(
        &self,
        inventory_by_id: &HashMap<String, &InventoryItem>,
        risks: &[norn_core::RiskEvaluation],
        inventory: &[InventoryItem],
    ) -> Result<NotificationBatch> {
        let prior_notifications = self.db.prior_notification_keys("risk")?;
        let mut events =
            self.notification_events_for_risks(inventory_by_id, risks, &prior_notifications)?;
        events.extend(
            self.notification_events_for_sensitive_containers(inventory, &prior_notifications)?,
        );
        events.sort_by_key(|event| {
            (
                Reverse(event.runtime_risk.score()),
                event.service.clone(),
                event.vulnerability_id.clone(),
            )
        });

        let limit = self.config.risk.max_notifications_per_scan;
        let total_candidates = events.len();
        if total_candidates <= limit {
            return Ok(NotificationBatch {
                events,
                suppressed: 0,
            });
        }

        if limit == 0 {
            return Ok(NotificationBatch {
                events: Vec::new(),
                suppressed: total_candidates,
            });
        }

        let individual_limit = limit.saturating_sub(1);
        events.truncate(individual_limit);
        let suppressed = total_candidates.saturating_sub(events.len());
        events.push(self.notification_summary_event(events.len(), suppressed));

        Ok(NotificationBatch { events, suppressed })
    }

    fn notification_events_for_risks(
        &self,
        inventory_by_id: &HashMap<String, &InventoryItem>,
        risks: &[norn_core::RiskEvaluation],
        prior_notifications: &HashSet<(Option<String>, String)>,
    ) -> Result<Vec<NotificationEvent>> {
        let mut events = Vec::new();
        let mut seen = HashSet::new();
        let mut candidates = risks
            .iter()
            .filter(|risk| risk.risk.at_least(self.config.risk.notify_minimum))
            .collect::<Vec<_>>();
        candidates.sort_by_key(|risk| {
            (
                Reverse(risk.risk.score()),
                risk.service_name.clone(),
                risk.vulnerability_id.clone(),
            )
        });

        for risk in candidates {
            let key = (risk.service_name.clone(), risk.vulnerability_id.clone());
            if !seen.insert(key) {
                continue;
            }
            if prior_notifications.contains(&(
                Some(risk.vulnerability_id.clone()),
                risk.service_name.clone(),
            )) {
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
        inventory: &[InventoryItem],
        prior_notifications: &HashSet<(Option<String>, String)>,
    ) -> Result<Vec<NotificationEvent>> {
        let mut events = Vec::new();
        for item in inventory {
            let Some(docker) = &item.docker else {
                continue;
            };
            if docker.privileged {
                let key = "NORN-PRIVILEGED-CONTAINER";
                if !prior_notifications.contains(&(Some(key.to_string()), item.name.clone())) {
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
                if !prior_notifications.contains(&(Some(key.to_string()), item.name.clone())) {
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

    fn notification_summary_event(&self, sent: usize, suppressed: usize) -> NotificationEvent {
        NotificationEvent {
            project: "Norn".to_string(),
            host: self.host.clone(),
            service: "scan-summary".to_string(),
            artifact: None,
            vulnerability_id: Some("NORN-NOTIFICATION-SUMMARY".to_string()),
            severity: None,
            runtime_risk: RiskLevel::High,
            exposure: Exposure::Unknown,
            reason: format!(
                "Norn found more new notification candidates than the configured per-scan cap. Sent {sent} individual notifications and summarized {suppressed} additional candidates."
            ),
            recommended_action: Some(format!(
                "Review the dashboard or report for the full scan. Increase risk.max_notifications_per_scan above {} if you want more individual alerts.",
                self.config.risk.max_notifications_per_scan
            )),
        }
    }

    async fn send_notification(&self, scan_id: &str, event: NotificationEvent) {
        let Some(notifier) = &self.notifier else {
            return;
        };
        let event_type = if event.vulnerability_id.as_deref() == Some("NORN-NOTIFICATION-SUMMARY") {
            "summary"
        } else {
            "risk"
        };
        match notifier.send(event.clone()).await {
            Ok(()) => {
                if let Err(error) = self
                    .db
                    .insert_notification(Some(scan_id), event_type, &event)
                {
                    warn!(error = %error, "failed to store notification event");
                }
            }
            Err(error) => warn!(error = %error, notifier = notifier.name(), "notification failed"),
        }
    }
}

struct ScanProgress {
    multi: MultiProgress,
}

impl ScanProgress {
    fn new(show_progress: bool) -> Self {
        let draw_target = if show_progress && Term::stderr().is_term() {
            ProgressDrawTarget::stderr()
        } else {
            ProgressDrawTarget::hidden()
        };
        Self {
            multi: MultiProgress::with_draw_target(draw_target),
        }
    }

    fn disabled() -> Self {
        Self {
            multi: MultiProgress::with_draw_target(ProgressDrawTarget::hidden()),
        }
    }

    fn spinner(&self, message: impl Into<String>) -> ProgressBar {
        let progress = self.multi.add(ProgressBar::new_spinner());
        progress.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .expect("progress spinner template is valid"),
        );
        progress.set_message(message.into());
        progress.enable_steady_tick(Duration::from_millis(100));
        progress
    }

    fn bar(&self, length: u64, message: impl Into<String>) -> ProgressBar {
        let progress = self.multi.add(ProgressBar::new(length));
        progress.set_style(
            ProgressStyle::with_template(
                "{msg} [{bar:40.cyan/blue}] {pos}/{len} {elapsed_precise}",
            )
            .expect("progress bar template is valid")
            .progress_chars("=> "),
        );
        progress.set_message(message.into());
        progress
    }
}

async fn scan_targets_with_progress(
    scanners: &[Arc<dyn VulnerabilityScanner>],
    targets: &[ScanTarget],
    parallelism: usize,
    progress: &ScanProgress,
    api_progress: Option<ScanProgressState>,
) -> (Vec<VulnerabilityFinding>, Vec<ScannerError>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let groups = unique_scan_target_groups(targets);
    let total = groups.len().saturating_mul(scanners.len()) as u64;
    let container_checks = targets.len().saturating_mul(scanners.len());
    let duplicate_checks = container_checks.saturating_sub(total as usize);
    let parallelism = parallelism.max(1);
    debug!(
        target_checks = container_checks,
        unique_checks = total,
        duplicate_checks,
        parallelism,
        "deduplicated vulnerability scan targets"
    );
    let scan_progress = progress.bar(
        total,
        format!(
            "Scanning vulnerability targets ({parallelism} jobs, {duplicate_checks} duplicates skipped)"
        ),
    );
    if let Some(api_progress) = &api_progress {
        api_progress.set_vulnerability_scan(total, parallelism);
    }

    if total == 0 {
        scan_progress.finish_with_message("No vulnerability targets");
        return (findings, errors);
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(parallelism));
    let mut tasks = tokio::task::JoinSet::new();

    for group in groups {
        for scanner in scanners {
            let permit = semaphore
                .clone()
                .acquire_owned()
                .await
                .expect("scanner semaphore is not closed");
            let scanner = Arc::clone(scanner);
            let target = group.representative.clone();
            let target_count = group.targets.len();
            let targets = group.targets.clone();
            let scan_progress = scan_progress.clone();
            let api_progress = api_progress.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let scanner_name = scanner.name();
                scan_progress.set_message(format!(
                    "Scanning {} with {} ({target_count} containers)",
                    target.name, scanner_name
                ));
                if let Some(api_progress) = &api_progress {
                    api_progress.target_started(format!("{} ({scanner_name})", target.name));
                }
                debug!(
                    scanner = scanner_name,
                    target = %target.reference,
                    target_count,
                    "running vulnerability scanner"
                );
                let result = match scanner.scan(target.clone()).await {
                    Ok(findings) => ScanJobResult {
                        findings: expand_findings_to_targets(&findings, &targets),
                        error: None,
                    },
                    Err(error) => {
                        warn!(
                            scanner = scanner_name,
                            target = %target.reference,
                            error = %error,
                            "scanner failed for target"
                        );
                        ScanJobResult {
                            findings: Vec::new(),
                            error: Some(ScannerError {
                                scanner: scanner_name.to_string(),
                                target: target.reference,
                                message: error.to_string(),
                            }),
                        }
                    }
                };
                scan_progress.inc(1);
                if let Some(api_progress) = &api_progress {
                    api_progress.target_completed();
                }
                result
            });
        }
    }

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(mut scan_result) => {
                findings.append(&mut scan_result.findings);
                if let Some(error) = scan_result.error {
                    errors.push(error);
                }
            }
            Err(error) => errors.push(ScannerError {
                scanner: "scanner-task".to_string(),
                target: "unknown".to_string(),
                message: error.to_string(),
            }),
        }
    }

    scan_progress.finish_with_message(format!("Scanned {total} target checks"));
    (findings, errors)
}

struct ScanJobResult {
    findings: Vec<VulnerabilityFinding>,
    error: Option<ScannerError>,
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

fn build_scanners(config: &NornConfig) -> Vec<Arc<dyn VulnerabilityScanner>> {
    let mut scanners: Vec<Arc<dyn VulnerabilityScanner>> = Vec::new();
    if config.scanner.grype.enabled {
        let timeout = Duration::from_secs(config.scanner.grype.timeout_seconds);
        if let Some(path) = &config.scanner.grype.fixture_path {
            scanners.push(Arc::new(GrypeScanner::with_fixture(
                &config.scanner.grype.binary,
                timeout,
                path,
            )));
        } else {
            scanners.push(Arc::new(GrypeScanner::new(
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

fn spawn_scheduler(runner: Arc<LocalScanRunner>, interval: Duration, scan_lock: ScanLock) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // consume the first immediate tick so the scheduler doesn't fire right
        // after the startup scan already ran
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match scan_lock.clone().try_lock_owned() {
                Ok(_permit) => {
                    if let Err(error) = runner.run_scan().await {
                        error!(error = %error, "scheduled scan failed");
                    }
                    // _permit dropped here, after run_scan completes
                }
                Err(_) => {
                    info!("scheduled scan skipped: a scan is already in progress");
                }
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

struct TuiSnapshot {
    summary: Summary,
    services: Vec<ServiceSummary>,
    vulnerabilities: Vec<VulnerabilitySummary>,
    scans: Vec<ScanRecord>,
}

async fn run_tui(db: Database, runner: LocalScanRunner) -> Result<()> {
    let (mut terminal, _guard) = enter_tui()?;
    let mut status = "q quit | r run scan | R refresh".to_string();
    let mut snapshot = load_tui_snapshot(&db)?;
    let mut last_refresh = Instant::now();

    loop {
        terminal.draw(|frame| draw_tui(frame, &snapshot, &status))?;

        if !event::poll(Duration::from_millis(250))? {
            if last_refresh.elapsed() >= TUI_REFRESH_INTERVAL {
                snapshot = load_tui_snapshot(&db)?;
                last_refresh = Instant::now();
            }
            continue;
        }

        let Event::Key(key) = event::read()? else {
            continue;
        };

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => break,
            KeyCode::Char('r') => {
                status = "Running scan...".to_string();
                terminal.draw(|frame| draw_tui(frame, &snapshot, &status))?;
                status = match runner.run_scan().await {
                    Ok(outcome) => {
                        snapshot = load_tui_snapshot(&db)?;
                        last_refresh = Instant::now();
                        format!(
                            "Scan completed: {} inventory, {} findings, {} errors",
                            outcome.scan.inventory_count,
                            outcome.scan.finding_count,
                            outcome.scan.scanner_errors.len()
                        )
                    }
                    Err(error) => format!("Scan failed: {error}"),
                };
            }
            KeyCode::Char('R') => {
                snapshot = load_tui_snapshot(&db)?;
                last_refresh = Instant::now();
                status = "Dashboard refreshed".to_string();
            }
            _ => {}
        }
    }

    terminal.show_cursor()?;
    Ok(())
}

fn enter_tui() -> Result<(Terminal<CrosstermBackend<Stdout>>, TerminalGuard)> {
    enable_raw_mode().context("failed to enable terminal raw mode")?;
    let mut stdout = io::stdout();
    if let Err(error) = execute!(stdout, EnterAlternateScreen) {
        let _ = disable_raw_mode();
        return Err(error).context("failed to enter terminal alternate screen");
    }

    let backend = CrosstermBackend::new(stdout);
    match Terminal::new(backend) {
        Ok(terminal) => Ok((terminal, TerminalGuard)),
        Err(error) => {
            restore_terminal();
            Err(error).context("failed to initialize terminal UI")
        }
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let mut stdout = io::stdout();
    let _ = execute!(stdout, LeaveAlternateScreen);
}

fn load_tui_snapshot(db: &Database) -> Result<TuiSnapshot> {
    let mut services = db.service_summaries()?;
    services.sort_by_key(|service| {
        (
            Reverse(service.highest_risk.map(|risk| risk.score()).unwrap_or(0)),
            Reverse(service.vulnerability_count),
            service.name.clone(),
        )
    });

    let vulnerabilities = db.vulnerability_summaries_limited(TUI_VULNERABILITY_LIMIT)?;

    Ok(TuiSnapshot {
        summary: db.summary()?,
        services,
        vulnerabilities,
        scans: db.list_scans()?,
    })
}

fn draw_tui(frame: &mut Frame<'_>, snapshot: &TuiSnapshot, status: &str) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),
            Constraint::Min(10),
            Constraint::Length(7),
            Constraint::Length(3),
        ])
        .split(frame.area());

    frame.render_widget(overview_widget(&snapshot.summary), rows[0]);

    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[1]);
    frame.render_widget(services_widget(&snapshot.services), main[0]);
    frame.render_widget(vulnerabilities_widget(&snapshot.vulnerabilities), main[1]);

    frame.render_widget(scans_widget(&snapshot.scans), rows[2]);
    frame.render_widget(footer_widget(status), rows[3]);
}

fn overview_widget(summary: &Summary) -> Paragraph<'_> {
    let last_scan = summary
        .last_scan_time
        .map(format_tui_time)
        .unwrap_or_else(|| "never".to_string());
    Paragraph::new(vec![
        Line::from(vec![
            Span::styled(
                "Norn",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" | Last scan: {last_scan}")),
        ]),
        Line::from(format!(
            "Running containers: {} | Active services: {} | Listening ports: {} | Publicly bound: {}",
            summary.running_containers,
            summary.running_services,
            summary.listening_ports,
            summary.public_services
        )),
        Line::from(vec![
            risk_count_span("Critical", summary.critical_risks, Color::Red),
            Span::raw("  "),
            risk_count_span("High", summary.high_risks, Color::LightRed),
            Span::raw("  "),
            risk_count_span("Medium", summary.medium_risks, Color::Yellow),
            Span::raw("  "),
            risk_count_span("Low", summary.low_risks, Color::Blue),
            Span::raw("  "),
            risk_count_span("Info", summary.informational_risks, Color::Gray),
        ]),
    ])
    .block(Block::default().title("Overview").borders(Borders::ALL))
    .alignment(Alignment::Left)
}

fn services_widget(services: &[ServiceSummary]) -> List<'_> {
    let items = services
        .iter()
        .take(12)
        .map(|service| {
            let risk = service
                .highest_risk
                .map(|risk| risk.as_str().to_string())
                .unwrap_or_else(|| "None".to_string());
            ListItem::new(Line::from(vec![
                Span::styled(&service.name, risk_style_option(service.highest_risk)),
                Span::raw(format!(
                    " | {} | {:?} | {} vuln | {}",
                    service.source, service.status, service.vulnerability_count, risk
                )),
            ]))
        })
        .collect::<Vec<_>>();

    empty_list_fallback(items, "No services from a completed scan").block(
        Block::default()
            .title("Services")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    )
}

fn vulnerabilities_widget(vulnerabilities: &[VulnerabilitySummary]) -> List<'_> {
    let items = vulnerabilities
        .iter()
        .take(12)
        .map(|vulnerability| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    &vulnerability.vulnerability_id,
                    risk_style(vulnerability.runtime_risk),
                ),
                Span::raw(format!(
                    " | {} | {} | fix {:?}",
                    vulnerability.affected_service,
                    vulnerability.exposed,
                    vulnerability.fix_available
                )),
            ]))
        })
        .collect::<Vec<_>>();

    empty_list_fallback(items, "No runtime risks from a completed scan").block(
        Block::default()
            .title("Vulnerabilities")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    )
}

fn scans_widget(scans: &[ScanRecord]) -> TuiTable<'_> {
    let rows = scans.iter().take(4).map(|scan| {
        Row::new(vec![
            short_id(&scan.id),
            scan.status.clone(),
            scan.inventory_count.to_string(),
            scan.finding_count.to_string(),
            scan.scanner_errors.len().to_string(),
            scan.completed_at
                .or(Some(scan.started_at))
                .map(format_tui_time)
                .unwrap_or_else(|| "unknown".to_string()),
        ])
    });

    TuiTable::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(22),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(16),
        ],
    )
    .header(
        Row::new(vec![
            "Scan",
            "Status",
            "Inventory",
            "Findings",
            "Errors",
            "Time",
        ])
        .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title("Scan History").borders(Borders::ALL))
}

fn footer_widget(status: &str) -> Paragraph<'_> {
    Paragraph::new(status.to_string())
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Center)
}

fn empty_list_fallback<'a>(items: Vec<ListItem<'a>>, fallback: &'a str) -> List<'a> {
    if items.is_empty() {
        List::new(vec![ListItem::new(fallback)])
    } else {
        List::new(items)
    }
}

fn risk_count_span(label: &'static str, count: usize, color: Color) -> Span<'static> {
    Span::styled(
        format!("{label}: {count}"),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

fn risk_style(risk: RiskLevel) -> Style {
    let color = match risk {
        RiskLevel::Critical => Color::Red,
        RiskLevel::High => Color::LightRed,
        RiskLevel::Medium => Color::Yellow,
        RiskLevel::Low => Color::Blue,
        RiskLevel::Informational => Color::Gray,
    };
    Style::default().fg(color).add_modifier(Modifier::BOLD)
}

fn risk_style_option(risk: Option<RiskLevel>) -> Style {
    risk.map(risk_style)
        .unwrap_or_else(|| Style::default().fg(Color::Gray))
}

fn short_id(id: &str) -> String {
    id.chars().take(8).collect()
}

fn format_tui_time(time: DateTime<Utc>) -> String {
    time.format("%Y-%m-%d %H:%M:%S UTC").to_string()
}

fn print_scan_summary(outcome: &ScanOutcome) {
    println!("{}", console_style("Scan summary").bold());
    println!("Host: {}", console_style(&outcome.scan.host).cyan());
    println!("Running containers: {}", outcome.summary.running_containers);
    println!("Active services: {}", outcome.summary.running_services);
    println!("Listening ports: {}", outcome.summary.listening_ports);
    println!(
        "Publicly bound inventory items: {}",
        outcome.summary.public_services
    );
    println!("Critical runtime risks: {}", outcome.summary.critical_risks);
    println!("High runtime risks: {}", outcome.summary.high_risks);
    println!("Medium runtime risks: {}", outcome.summary.medium_risks);
    println!("Low runtime risks: {}", outcome.summary.low_risks);
    println!(
        "Informational runtime risks: {}",
        outcome.summary.informational_risks
    );
    if !outcome.scan.scanner_errors.is_empty() {
        println!(
            "{}",
            console_style(format!(
                "Scanner/collector errors: {}",
                outcome.scan.scanner_errors.len()
            ))
            .yellow()
        );
    }
}

fn print_inventory(items: &[InventoryItem], output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(items)?),
        OutputFormat::Table => {
            let mut table = ComfyTable::new();
            table
                .load_preset(UTF8_FULL)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec!["Name", "Source", "Status", "Exposure"]);
            for item in items {
                table.add_row(vec![
                    item.name.clone(),
                    item.source.to_string(),
                    format!("{:?}", item.status),
                    item.exposure.to_string(),
                ]);
            }
            println!("{table}");
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
    println!("- Listening ports: {}", summary.listening_ports);
    println!(
        "- Publicly bound inventory items: {}",
        summary.public_services
    );
    println!("- Critical runtime risks: {}", summary.critical_risks);
    println!("- High runtime risks: {}", summary.high_risks);
    println!("- Medium runtime risks: {}", summary.medium_risks);
    println!("- Low runtime risks: {}", summary.low_risks);
    println!(
        "- Informational runtime risks: {}",
        summary.informational_risks
    );
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
