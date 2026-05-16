# Configuration

Norn reads TOML configuration from `/etc/norn/config.toml` by default. Use `--config` or `NORN_CONFIG` to select another file.

```toml
[server]
bind = "0.0.0.0:8787"
static_dir = "/opt/norn/web"

[database]
url = "sqlite:///var/lib/norn/norn.db"
retention_days = 90

[scan]
interval = "6h"
run_on_start = true

[collectors.docker]
enabled = true
socket = "/var/run/docker.sock"

[collectors.systemd]
enabled = true

[collectors.packages]
enabled = true

[collectors.ports]
enabled = true

[scanner]
parallelism = 4
scan_host_filesystem = false

[scanner.grype]
enabled = true
binary = "grype"
timeout_seconds = 300

[notifications.discord]
enabled = false
webhook_url = ""

[risk]
notify_minimum = "High"
max_notifications_per_scan = 50
```

## Scan History Retention

`database.retention_days` controls how many days of completed scan history Norn retains. After each scan, Norn automatically deletes scans whose `started_at` timestamp is older than `retention_days` days. Only scans with a non-`running` status are eligible for deletion, so in-progress scans are never removed.

Set `retention_days = 0` to retain all scan history forever (pruning is disabled).

The default is `90` days. Override with the `NORN_RETENTION_DAYS` environment variable.

## Host Filesystem Scanning

The package collector always records installed packages as inventory, but Norn does not run Grype against the whole host filesystem by default. Full host scans can produce very large result sets on long-lived servers and can overwhelm notifications.

Set `scanner.scan_host_filesystem = true` to add a `dir:/` vulnerability scan target for the host. Override with `NORN_SCANNER_SCAN_HOST_FILESYSTEM=true`.

## Summary Labels

The CLI, TUI, API, and dashboard distinguish between runtime inventory categories:

- `Active services`: active systemd service inventory items.
- `Running containers`: running Docker container inventory items.
- `Listening ports`: listening TCP/UDP socket inventory items from `ss`.
- `Publicly bound`: inventory items bound to public addresses such as `0.0.0.0`, `::`, or `*`. This does not guarantee internet reachability because firewalls, reverse proxies, routing, and cloud security groups can still restrict access.

Risk summaries include Critical, High, Medium, Low, and Informational counts so the displayed totals line up with the number of evaluated runtime risk instances.

## Notifications

`risk.notify_minimum` controls the lowest runtime risk level that can create an individual notification.

`risk.max_notifications_per_scan` caps the total Discord messages sent by one scan. If there are more new notification candidates than the cap allows, Norn sends the highest-priority individual notifications first and reserves one message for a scan summary. Set this to `0` to suppress scan notifications without disabling Discord configuration entirely.

## API Limits

`GET /api/vulnerabilities` accepts an optional `limit` query parameter to cap the number of vulnerability summaries returned. This is useful for dashboards and TUIs on hosts with large scan results.

Example:

`GET /api/vulnerabilities?limit=500`

Without `limit`, the endpoint returns all deduplicated vulnerability summaries for the latest completed scan.

## Fixture Mode

Collectors and the Grype adapter support `fixture_path` fields. This is used by tests and by `examples/config.toml` so contributors can run a full scan without Docker, systemd, or Grype.

## Environment Overrides

- `NORN_SERVER_BIND`
- `NORN_DATABASE_URL`
- `NORN_SCAN_INTERVAL`
- `NORN_SCANNER_PARALLELISM`
- `NORN_SCANNER_SCAN_HOST_FILESYSTEM`
- `NORN_GRYPE_BINARY`
- `NORN_DISCORD_ENABLED`
- `NORN_DISCORD_WEBHOOK_URL`
- `NORN_RISK_NOTIFY_MINIMUM`
- `NORN_RISK_MAX_NOTIFICATIONS_PER_SCAN`
- `NORN_RETENTION_DAYS`
