import { Bell } from "lucide-react";
import { FormEvent, useState } from "react";
import { api } from "../lib/api";

export function NotificationSettings() {
  const [webhookUrl, setWebhookUrl] = useState("");
  const [status, setStatus] = useState<string | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setStatus("Sending");
    try {
      await api.testNotification(webhookUrl);
      setStatus("Sent");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : "Failed");
    }
  }

  return (
    <form
      onSubmit={submit}
      className="max-w-2xl rounded-md border border-line bg-panel p-5 shadow-surface"
    >
      <label className="block text-sm font-medium text-ink" htmlFor="discord-webhook">
        Discord webhook URL
      </label>
      <div className="mt-2 flex gap-2">
        <input
          id="discord-webhook"
          className="focus-ring min-w-0 flex-1 rounded border border-line bg-panel px-3 py-2 text-ink placeholder:text-muted"
          value={webhookUrl}
          onChange={(event) => setWebhookUrl(event.target.value)}
          placeholder="https://discord.com/api/webhooks/..."
        />
        <button
          className="focus-ring inline-flex items-center gap-2 rounded bg-brand px-3 py-2 text-sm font-semibold text-white"
          type="submit"
        >
          <Bell className="h-4 w-4" aria-hidden="true" />
          Test
        </button>
      </div>
      {status ? <p className="mt-3 text-sm text-muted">{status}</p> : null}
    </form>
  );
}
