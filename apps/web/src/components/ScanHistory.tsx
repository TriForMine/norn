import type { ScanRecord } from "../types";

const statusStyles: Record<string, string> = {
  completed:
    "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300",
  completed_with_errors:
    "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300",
  running: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300",
  abandoned:
    "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400",
};

const statusLabel: Record<string, string> = {
  completed: "Completed",
  completed_with_errors: "Completed with errors",
  running: "Running",
  abandoned: "Abandoned",
};

function StatusBadge({ status }: { status: string }) {
  const style =
    statusStyles[status] ??
    "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400";
  const label = statusLabel[status] ?? status;
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold ${style}`}
    >
      {label}
    </span>
  );
}

export function ScanHistory({ scans }: { scans: ScanRecord[] }) {
  return (
    <div className="overflow-hidden rounded-md border border-line bg-panel shadow-surface">
      <table className="min-w-full divide-y divide-line text-sm">
        <thead className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wide text-muted dark:bg-slate-900/60">
          <tr>
            <th className="px-4 py-3">Started</th>
            <th className="px-4 py-3">Host</th>
            <th className="px-4 py-3">Status</th>
            <th className="px-4 py-3 text-right">Inventory</th>
            <th className="px-4 py-3 text-right">Findings</th>
            <th className="px-4 py-3 text-right">Errors</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {scans.map((scan) => (
            <tr
              key={scan.id}
              className="hover:bg-slate-50 dark:hover:bg-slate-900/50"
            >
              <td className="px-4 py-3">
                {new Date(scan.started_at).toLocaleString()}
              </td>
              <td className="px-4 py-3">{scan.host}</td>
              <td className="px-4 py-3">
                <StatusBadge status={scan.status} />
              </td>
              <td className="px-4 py-3 text-right">{scan.inventory_count}</td>
              <td className="px-4 py-3 text-right">{scan.finding_count}</td>
              <td className="px-4 py-3 text-right">
                {scan.scanner_errors.length > 0 ? (
                  <span className="font-semibold text-amber-600 dark:text-amber-400">
                    {scan.scanner_errors.length}
                  </span>
                ) : (
                  scan.scanner_errors.length
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
