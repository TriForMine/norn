import {
  Bug,
  LayoutDashboard,
  Loader2,
  RefreshCcw,
  Rows3,
  Settings,
  Shield,
  ShieldAlert,
  Timer,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { IgnoreRules } from "./components/IgnoreRules";
import { NotificationSettings } from "./components/NotificationSettings";
import { RemediationQueue } from "./components/RemediationQueue";
import { ScanHistory } from "./components/ScanHistory";
import { ServicesTable } from "./components/ServicesTable";
import { SummaryCards } from "./components/SummaryCards";
import { ThemeToggle } from "./components/ThemeToggle";
import { VulnerabilitiesTable } from "./components/VulnerabilitiesTable";
import { api } from "./lib/api";
import type {
  RemediationItem,
  ScanRecord,
  ScanStatus,
  ServiceSummary,
  Summary,
  VulnerabilitySummary,
} from "./types";

type Tab =
  | "dashboard"
  | "remediation"
  | "services"
  | "vulnerabilities"
  | "scans"
  | "notifications"
  | "ignore";

const emptySummary: Summary = {
  running_services: 0,
  running_containers: 0,
  listening_ports: 0,
  public_services: 0,
  critical_risks: 0,
  high_risks: 0,
  medium_risks: 0,
  low_risks: 0,
  informational_risks: 0,
  last_scan_time: null,
};

const SCAN_POLL_INTERVAL_MS = 2000;

export function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [summary, setSummary] = useState<Summary>(emptySummary);
  const [services, setServices] = useState<ServiceSummary[]>([]);
  const [remediation, setRemediation] = useState<RemediationItem[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<
    VulnerabilitySummary[]
  >([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<string | null>(null);
  const [scanRunning, setScanRunning] = useState(false);
  const [scanElapsed, setScanElapsed] = useState(0);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const scanStartRef = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [
        nextSummary,
        nextServices,
        nextRemediation,
        nextVulnerabilities,
        nextScans
      ] =
        await Promise.all([
          api.summary(),
          api.services(),
          api.remediation(),
          api.vulnerabilities(),
          api.scans(),
        ]);
      setSummary(nextSummary);
      setServices(nextServices);
      setRemediation(nextRemediation);
      setVulnerabilities(nextVulnerabilities);
      setScans(nextScans);
      setStatus(null);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to load data");
    } finally {
      setLoading(false);
    }
  }, []);

  // Poll scan status. When a scan transitions from running → done, refresh data.
  useEffect(() => {
    let wasRunning = false;

    const poll = async () => {
      try {
        const nextStatus = await api.scanStatus();
        const { running } = nextStatus;
        setScanStatus(nextStatus);
        setScanRunning(running);

        if (running && !wasRunning) {
          // scan just started (externally, e.g. scheduler)
          scanStartRef.current = nextStatus.started_at
            ? new Date(nextStatus.started_at).getTime()
            : Date.now();
        }
        if (!running && wasRunning) {
          // scan just finished — refresh data
          setScanElapsed(0);
          scanStartRef.current = null;
          setScanStatus(null);
          await refresh();
        }
        wasRunning = running;
      } catch {
        // status endpoint unreachable, ignore
      }
    };

    void poll();
    const id = setInterval(() => void poll(), SCAN_POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  // Tick the elapsed counter every second while a scan is running.
  useEffect(() => {
    if (!scanRunning) return;
    const id = setInterval(() => {
      if (scanStartRef.current !== null) {
        setScanElapsed(Math.floor((Date.now() - scanStartRef.current) / 1000));
      }
    }, 1000);
    return () => clearInterval(id);
  }, [scanRunning]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function runScan() {
    setScanRunning(true);
    setScanStatus({
      running: true,
      phase: "starting",
      phase_label: "Starting scan",
      completed_target_checks: 0,
      total_target_checks: 0,
      parallelism: 0,
    });
    scanStartRef.current = Date.now();
    setScanElapsed(0);
    setStatus(null);
    try {
      await api.runScan();
      await refresh();
      setStatus("Scan complete");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Scan failed");
    } finally {
      setScanRunning(false);
      setScanStatus(null);
      scanStartRef.current = null;
      setScanElapsed(0);
    }
  }

  const scanPercent =
    scanStatus && scanStatus.total_target_checks > 0
      ? Math.round(
          (scanStatus.completed_target_checks / scanStatus.total_target_checks) *
            100,
        )
      : null;

  const nav = useMemo(
    () => [
      { id: "dashboard" as const, label: "Dashboard", icon: LayoutDashboard },
      { id: "remediation" as const, label: "Remediation", icon: ShieldAlert },
      { id: "services" as const, label: "Services", icon: Rows3 },
      { id: "vulnerabilities" as const, label: "Vulnerabilities", icon: Bug },
      { id: "scans" as const, label: "Scans", icon: Timer },
      { id: "notifications" as const, label: "Notifications", icon: Settings },
      { id: "ignore" as const, label: "Ignore", icon: Shield },
    ],
    [],
  );

  return (
    <div className="min-h-screen bg-page">
      <header className="border-b border-line bg-panel">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-4 lg:px-6">
          <div>
            <h1 className="text-xl font-semibold text-ink">Norn</h1>
            <p className="text-sm text-muted">Runtime risk monitor</p>
          </div>
          <div className="flex items-center gap-2">
            {status ? (
              <p className="max-w-96 truncate text-sm text-muted">{status}</p>
            ) : null}
            <ThemeToggle />
            <button
              className="focus-ring inline-flex items-center gap-2 rounded border border-line bg-panel px-3 py-2 text-sm font-semibold text-ink shadow-surface hover:bg-slate-50 dark:hover:bg-slate-800"
              onClick={() => void refresh()}
              type="button"
            >
              <RefreshCcw className="h-4 w-4" aria-hidden="true" />
              Refresh
            </button>
            <button
              className="focus-ring inline-flex items-center gap-2 rounded bg-brand px-3 py-2 text-sm font-semibold text-white shadow-surface dark:text-slate-950 disabled:cursor-not-allowed disabled:opacity-50"
              onClick={() => void runScan()}
              disabled={scanRunning}
              type="button"
            >
              {scanRunning ? (
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              ) : (
                <Shield className="h-4 w-4" aria-hidden="true" />
              )}
              {scanRunning ? "Scanning…" : "Scan"}
            </button>
          </div>
        </div>
      </header>

      {scanRunning ? (
        <div className="border-b border-amber-200 bg-amber-50 dark:border-amber-900 dark:bg-amber-950/40">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-3 px-4 py-2 lg:px-6">
            <Loader2
              className="h-4 w-4 shrink-0 animate-spin text-amber-600 dark:text-amber-400"
              aria-hidden="true"
            />
            <p className="text-sm font-medium text-amber-800 dark:text-amber-300">
              {scanStatus?.phase_label ?? "Scan in progress"}
              {scanElapsed > 0
                ? ` - ${Math.floor(scanElapsed / 60)}m ${scanElapsed % 60}s elapsed`
                : ""}
            </p>
            {scanPercent !== null ? (
              <div className="flex min-w-52 items-center gap-2">
                <div className="h-2 w-32 overflow-hidden rounded bg-amber-200 dark:bg-amber-900">
                  <div
                    className="h-full bg-amber-600 dark:bg-amber-400"
                    style={{ width: `${scanPercent}%` }}
                  />
                </div>
                <span className="text-xs font-semibold text-amber-700 dark:text-amber-300">
                  {scanStatus?.completed_target_checks ?? 0}/
                  {scanStatus?.total_target_checks ?? 0}
                </span>
              </div>
            ) : null}
            {scanStatus?.current_target ? (
              <p className="max-w-xl truncate text-sm text-amber-600 dark:text-amber-500">
                {scanStatus.current_target}
              </p>
            ) : scanStatus?.message ? (
              <p className="max-w-xl truncate text-sm text-amber-600 dark:text-amber-500">
                {scanStatus.message}
              </p>
            ) : (
              <p className="text-sm text-amber-600 dark:text-amber-500">
                Dashboard will refresh automatically when complete.
              </p>
            )}
          </div>
        </div>
      ) : null}

      <div className="mx-auto grid max-w-7xl gap-5 px-4 py-5 lg:grid-cols-[220px_minmax(0,1fr)] lg:px-6">
        <nav className="flex gap-2 overflow-x-auto lg:block lg:space-y-1">
          {nav.map((item) => {
            const Icon = item.icon;
            const active = item.id === tab;
            return (
              <button
                key={item.id}
                className={`focus-ring inline-flex min-w-fit items-center gap-2 rounded px-3 py-2 text-sm font-semibold lg:w-full ${
                  active
                    ? "bg-ink text-white dark:bg-brand dark:text-slate-950"
                    : "text-slate-700 hover:bg-panel dark:text-slate-300 dark:hover:bg-slate-800"
                }`}
                onClick={() => setTab(item.id)}
                type="button"
              >
                <Icon className="h-4 w-4" aria-hidden="true" />
                {item.label}
              </button>
            );
          })}
        </nav>

        <main className="min-w-0 space-y-5">
          {loading ? <p className="text-sm text-muted">Loading</p> : null}
          {tab === "dashboard" ? (
            <>
              <SummaryCards summary={summary} />
              <section>
                <h2 className="mb-3 text-base font-semibold text-ink">
                  Remediation queue
                </h2>
                <RemediationQueue items={remediation.slice(0, 8)} />
              </section>
            </>
          ) : null}
          {tab === "remediation" ? (
            <RemediationQueue items={remediation} />
          ) : null}
          {tab === "services" ? <ServicesTable services={services} /> : null}
          {tab === "vulnerabilities" ? (
            <VulnerabilitiesTable vulnerabilities={vulnerabilities} />
          ) : null}
          {tab === "scans" ? <ScanHistory scans={scans} /> : null}
          {tab === "notifications" ? <NotificationSettings /> : null}
          {tab === "ignore" ? <IgnoreRules /> : null}
        </main>
      </div>
    </div>
  );
}
