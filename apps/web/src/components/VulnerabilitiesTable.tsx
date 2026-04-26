import type { VulnerabilitySummary } from "../types";
import { Badge } from "./Badge";

const date = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit"
});

export function VulnerabilitiesTable({
  vulnerabilities
}: {
  vulnerabilities: VulnerabilitySummary[];
}) {
  return (
    <div className="overflow-hidden rounded-md border border-line bg-panel shadow-surface">
      <table className="min-w-full divide-y divide-line text-sm">
        <thead className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wide text-muted dark:bg-slate-900/60">
          <tr>
            <th className="px-4 py-3">CVE / ID</th>
            <th className="px-4 py-3">Severity</th>
            <th className="px-4 py-3">Runtime risk</th>
            <th className="px-4 py-3">Affected service</th>
            <th className="px-4 py-3">Exposed</th>
            <th className="px-4 py-3">Fix</th>
            <th className="px-4 py-3">First seen</th>
            <th className="px-4 py-3">Last seen</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {vulnerabilities.map((vulnerability) => (
            <tr
              key={`${vulnerability.affected_service}:${vulnerability.vulnerability_id}`}
              className="hover:bg-slate-50 dark:hover:bg-slate-900/50"
            >
              <td className="px-4 py-3 font-mono text-xs font-semibold text-ink">
                {vulnerability.vulnerability_id}
              </td>
              <td className="px-4 py-3">
                <Badge value={vulnerability.severity} />
              </td>
              <td className="px-4 py-3">
                <Badge value={vulnerability.runtime_risk} />
              </td>
              <td className="max-w-56 truncate px-4 py-3">{vulnerability.affected_service}</td>
              <td className="px-4 py-3">
                <Badge value={vulnerability.exposed} />
              </td>
              <td className="px-4 py-3">
                <Badge value={vulnerability.fix_available} />
              </td>
              <td className="px-4 py-3 text-muted">
                {date.format(new Date(vulnerability.first_seen))}
              </td>
              <td className="px-4 py-3 text-muted">
                {date.format(new Date(vulnerability.last_seen))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
