import type { Exposure, RiskLevel, Severity } from "../types";

type BadgeTone = RiskLevel | Severity | Exposure | "available" | "not_available" | "unknown";

const toneClass: Record<string, string> = {
  critical: "bg-red-100 text-red-800 ring-red-200 dark:bg-red-950/60 dark:text-red-200 dark:ring-red-800",
  high: "bg-orange-100 text-orange-800 ring-orange-200 dark:bg-orange-950/60 dark:text-orange-200 dark:ring-orange-800",
  medium: "bg-amber-100 text-amber-900 ring-amber-200 dark:bg-amber-950/60 dark:text-amber-200 dark:ring-amber-800",
  low: "bg-sky-100 text-sky-800 ring-sky-200 dark:bg-sky-950/60 dark:text-sky-200 dark:ring-sky-800",
  informational: "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:ring-slate-700",
  negligible: "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:ring-slate-700",
  public: "bg-red-50 text-red-700 ring-red-200 dark:bg-red-950/50 dark:text-red-200 dark:ring-red-800",
  internal: "bg-blue-50 text-blue-700 ring-blue-200 dark:bg-blue-950/50 dark:text-blue-200 dark:ring-blue-800",
  localhost: "bg-teal-50 text-teal-700 ring-teal-200 dark:bg-teal-950/50 dark:text-teal-200 dark:ring-teal-800",
  available: "bg-emerald-50 text-emerald-700 ring-emerald-200 dark:bg-emerald-950/50 dark:text-emerald-200 dark:ring-emerald-800",
  not_available: "bg-stone-100 text-stone-700 ring-stone-200 dark:bg-stone-800 dark:text-stone-200 dark:ring-stone-700",
  unknown: "bg-slate-100 text-slate-700 ring-slate-200 dark:bg-slate-800 dark:text-slate-200 dark:ring-slate-700"
};

export function Badge({ value }: { value?: BadgeTone | null }) {
  const normalized = value ?? "unknown";
  const label = normalized
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");

  return (
    <span
      className={`inline-flex min-w-20 items-center justify-center rounded px-2 py-1 text-xs font-semibold ring-1 ${toneClass[normalized]}`}
    >
      {label}
    </span>
  );
}
