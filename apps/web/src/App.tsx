import { Bug, LayoutDashboard, RefreshCcw, Rows3, Settings, Shield, Timer } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { IgnoreRules } from "./components/IgnoreRules";
import { NotificationSettings } from "./components/NotificationSettings";
import { ScanHistory } from "./components/ScanHistory";
import { ServicesTable } from "./components/ServicesTable";
import { SummaryCards } from "./components/SummaryCards";
import { ThemeToggle } from "./components/ThemeToggle";
import { VulnerabilitiesTable } from "./components/VulnerabilitiesTable";
import { api } from "./lib/api";
import type { ScanRecord, ServiceSummary, Summary, VulnerabilitySummary } from "./types";

type Tab = "dashboard" | "services" | "vulnerabilities" | "scans" | "notifications" | "ignore";

const emptySummary: Summary = {
  running_services: 0,
  running_containers: 0,
  public_services: 0,
  critical_risks: 0,
  high_risks: 0,
  medium_risks: 0,
  low_risks: 0,
  last_scan_time: null
};

export function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [summary, setSummary] = useState<Summary>(emptySummary);
  const [services, setServices] = useState<ServiceSummary[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilitySummary[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [nextSummary, nextServices, nextVulnerabilities, nextScans] = await Promise.all([
        api.summary(),
        api.services(),
        api.vulnerabilities(),
        api.scans()
      ]);
      setSummary(nextSummary);
      setServices(nextServices);
      setVulnerabilities(nextVulnerabilities);
      setScans(nextScans);
      setStatus(null);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Unable to load data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function runScan() {
    setStatus("Scan running");
    try {
      await api.runScan();
      await refresh();
      setStatus("Scan complete");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Scan failed");
    }
  }

  const nav = useMemo(
    () => [
      { id: "dashboard" as const, label: "Dashboard", icon: LayoutDashboard },
      { id: "services" as const, label: "Services", icon: Rows3 },
      { id: "vulnerabilities" as const, label: "Vulnerabilities", icon: Bug },
      { id: "scans" as const, label: "Scans", icon: Timer },
      { id: "notifications" as const, label: "Notifications", icon: Settings },
      { id: "ignore" as const, label: "Ignore", icon: Shield }
    ],
    []
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
            {status ? <p className="max-w-96 truncate text-sm text-muted">{status}</p> : null}
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
              className="focus-ring inline-flex items-center gap-2 rounded bg-brand px-3 py-2 text-sm font-semibold text-white shadow-surface dark:text-slate-950"
              onClick={() => void runScan()}
              type="button"
            >
              <Shield className="h-4 w-4" aria-hidden="true" />
              Scan
            </button>
          </div>
        </div>
      </header>

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
                <h2 className="mb-3 text-base font-semibold text-ink">Top runtime risks</h2>
                <VulnerabilitiesTable vulnerabilities={vulnerabilities.slice(0, 8)} />
              </section>
            </>
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
