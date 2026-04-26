import {
  Activity,
  AlertTriangle,
  Box,
  Clock,
  Globe,
  Server,
  ShieldAlert,
} from "lucide-react";
import type { Summary } from "../types";

const formatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

export function SummaryCards({ summary }: { summary: Summary }) {
  const cards = [
    {
      label: "Active services",
      value: summary.running_services,
      icon: Server,
    },
    {
      label: "Running containers",
      value: summary.running_containers,
      icon: Box,
    },
    {
      label: "Listening ports",
      value: summary.listening_ports,
      icon: Activity,
    },
    {
      label: "Publicly bound",
      value: summary.public_services,
      icon: Globe,
    },
    {
      label: "Critical risks",
      value: summary.critical_risks,
      icon: ShieldAlert,
    },
    {
      label: "High risks",
      value: summary.high_risks,
      icon: AlertTriangle,
    },
    {
      label: "Informational risks",
      value: summary.informational_risks,
      icon: Activity,
    },
    {
      label: "Last scan",
      value: summary.last_scan_time
        ? formatter.format(new Date(summary.last_scan_time))
        : "Never",
      icon: Clock,
    },
  ];

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-8">
      {cards.map((card) => {
        const Icon = card.icon ?? Activity;
        return (
          <section
            key={card.label}
            className="rounded-md border border-line bg-panel p-4 shadow-surface"
          >
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-medium text-muted">{card.label}</p>
              <Icon className="h-4 w-4 text-brand" aria-hidden="true" />
            </div>
            <p className="mt-3 truncate text-2xl font-semibold text-ink">
              {card.value}
            </p>
          </section>
        );
      })}
    </div>
  );
}
