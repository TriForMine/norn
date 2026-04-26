import { Ban } from "lucide-react";
import { FormEvent, useState } from "react";
import { api } from "../lib/api";

export function IgnoreRules() {
  const [vulnerabilityId, setVulnerabilityId] = useState("");
  const [service, setService] = useState("");
  const [days, setDays] = useState(30);
  const [status, setStatus] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setStatus("Saving");
    try {
      await api.ignore(vulnerabilityId, service, days);
      setStatus("Saved");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Failed");
    }
  }

  return (
    <form
      onSubmit={submit}
      className="max-w-2xl rounded-md border border-line bg-panel p-5 shadow-surface"
    >
      <div className="grid gap-4 sm:grid-cols-3">
        <label className="block text-sm font-medium text-ink">
          Vulnerability
          <input
            className="focus-ring mt-2 w-full rounded border border-line bg-panel px-3 py-2 text-ink placeholder:text-muted"
            value={vulnerabilityId}
            onChange={(event) => setVulnerabilityId(event.target.value)}
            required
            placeholder="CVE-2026-0001"
          />
        </label>
        <label className="block text-sm font-medium text-ink">
          Service
          <input
            className="focus-ring mt-2 w-full rounded border border-line bg-panel px-3 py-2 text-ink placeholder:text-muted"
            value={service}
            onChange={(event) => setService(event.target.value)}
            placeholder="nginx"
          />
        </label>
        <label className="block text-sm font-medium text-ink">
          Days
          <input
            className="focus-ring mt-2 w-full rounded border border-line bg-panel px-3 py-2 text-ink placeholder:text-muted"
            min={1}
            type="number"
            value={days}
            onChange={(event) => setDays(Number(event.target.value))}
          />
        </label>
      </div>
      <button
        className="focus-ring mt-4 inline-flex items-center gap-2 rounded bg-ink px-3 py-2 text-sm font-semibold text-white dark:bg-brand dark:text-slate-950"
        type="submit"
      >
        <Ban className="h-4 w-4" aria-hidden="true" />
        Ignore
      </button>
      {status ? <p className="mt-3 text-sm text-muted">{status}</p> : null}
    </form>
  );
}
