import type { ServiceSummary } from "../types";
import { Badge } from "./Badge";

export function ServicesTable({ services }: { services: ServiceSummary[] }) {
  return (
    <div className="overflow-hidden rounded-md border border-line bg-panel shadow-surface">
      <table className="min-w-full divide-y divide-line text-sm">
        <thead className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wide text-muted dark:bg-slate-900/60">
          <tr>
            <th className="px-4 py-3">Name</th>
            <th className="px-4 py-3">Source</th>
            <th className="px-4 py-3">Status</th>
            <th className="px-4 py-3">Exposure</th>
            <th className="px-4 py-3">Highest risk</th>
            <th className="px-4 py-3 text-right">Vulnerabilities</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {services.map((service) => (
            <tr
              key={`${service.source}:${service.name}`}
              className="hover:bg-slate-50 dark:hover:bg-slate-900/50"
            >
              <td className="max-w-64 truncate px-4 py-3 font-medium text-ink">{service.name}</td>
              <td className="px-4 py-3 text-muted">{service.source}</td>
              <td className="px-4 py-3 text-muted">{service.status}</td>
              <td className="px-4 py-3">
                <Badge value={service.exposure} />
              </td>
              <td className="px-4 py-3">
                <Badge value={service.highest_risk} />
              </td>
              <td className="px-4 py-3 text-right font-medium">{service.vulnerability_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
