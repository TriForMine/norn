import type { RemediationItem } from "../types";
import { Badge } from "./Badge";

const date = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit"
});

export function RemediationQueue({ items }: { items: RemediationItem[] }) {
  return (
    <div className="overflow-hidden rounded-md border border-line bg-panel shadow-surface">
      <table className="min-w-full divide-y divide-line text-sm">
        <thead className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wide text-muted dark:bg-slate-900/60">
          <tr>
            <th className="px-4 py-3">Service</th>
            <th className="px-4 py-3">Risk</th>
            <th className="px-4 py-3">Exposure</th>
            <th className="px-4 py-3">Findings</th>
            <th className="px-4 py-3">Fixable</th>
            <th className="px-4 py-3">Top IDs</th>
            <th className="px-4 py-3">Action</th>
            <th className="px-4 py-3">Last seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {items.map((item) => (
            <tr
              key={item.service}
              className="hover:bg-slate-50 dark:hover:bg-slate-900/50"
            >
              <td className="max-w-64 truncate px-4 py-3 font-semibold text-ink">
                {item.service}
              </td>
              <td className="px-4 py-3">
                <Badge value={item.highest_risk} />
              </td>
              <td className="px-4 py-3">
                <Badge value={item.exposure} />
              </td>
              <td className="px-4 py-3 font-mono text-xs">
                {item.vulnerability_count}
                <span className="ml-2 text-muted">
                  C {item.critical_count} / H {item.high_count} / M{" "}
                  {item.medium_count}
                </span>
              </td>
              <td className="px-4 py-3 font-mono text-xs">
                {item.fixable_count}
              </td>
              <td className="max-w-72 truncate px-4 py-3 font-mono text-xs text-muted">
                {item.top_vulnerabilities.slice(0, 5).join(", ") || "none"}
              </td>
              <td className="max-w-80 px-4 py-3 text-muted">
                {item.recommended_action}
              </td>
              <td className="px-4 py-3 text-muted">
                {date.format(new Date(item.last_seen))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
