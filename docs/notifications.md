# Notifications

The MVP notifier sends Discord webhook messages.

Notifications are intended for:

- New Critical runtime risks.
- New High runtime risks.
- Vulnerabilities becoming more dangerous after exposure changes.
- Running privileged containers.
- Running containers with Docker socket mounts.

Norn only sends notifications when a notifier is enabled. Disabled notifiers skip notification preparation entirely, so scans do not create noisy "pending" alerts.

## Dedupe

Notifications are deduplicated against previously sent notification events, not merely against risks stored in scan history. This means:

- A risk that was discovered while notifications were disabled can still notify later after Discord is enabled.
- A failed Discord send can be retried by a later scan because it is not recorded as sent.
- Repeated scans do not resend the same service/vulnerability notification once it has been successfully delivered.
- Container hardening alerts, such as privileged containers and Docker socket mounts, are deduplicated the same way.

Within a single scan, vulnerability notifications are also deduplicated by service and vulnerability ID so the same CVE does not produce repeated messages for multiple package matches in the same service.

## Digest Behavior

`risk.max_notifications_per_scan` caps the total number of Discord messages one scan can send.

When new notification candidates exceed the cap, Norn sends the highest-priority individual notifications first and reserves one message for a summary. The summary tells you how many additional candidates were summarized and points you to the dashboard or report for the full details.

Set `risk.max_notifications_per_scan = 0` to suppress scan notifications without disabling the Discord webhook configuration.

## Discord

```toml
[notifications.discord]
enabled = true
webhook_url = "https://discord.com/api/webhooks/..."

[risk]
notify_minimum = "High"
max_notifications_per_scan = 50
```

Test:

```bash
norn notify test --config /etc/norn/config.toml
```

Individual messages include host, service, artifact, vulnerability ID, severity, runtime risk, exposure, reason, and recommended action. Summary messages include the configured cap and the number of additional candidates that were summarized.
