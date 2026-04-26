import type { ScanRecord } from "../types";

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
            <tr key={scan.id} className="hover:bg-slate-50 dark:hover:bg-slate-900/50">
              <td className="px-4 py-3">{new Date(scan.started_at).toLocaleString()}</td>
              <td className="px-4 py-3">{scan.host}</td>
              <td className="px-4 py-3">{scan.status}</td>
              <td className="px-4 py-3 text-right">{scan.inventory_count}</td>
              <td className="px-4 py-3 text-right">{scan.finding_count}</td>
              <td className="px-4 py-3 text-right">{scan.scanner_errors.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
