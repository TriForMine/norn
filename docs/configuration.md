# Configuration

Norn reads TOML configuration from `/etc/norn/config.toml` by default. Use `--config` or `NORN_CONFIG` to select another file.

```toml
[server]
bind = "0.0.0.0:8787"
static_dir = "/opt/norn/web"

[database]
url = "sqlite:///var/lib/norn/norn.db"

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

[scanner.grype]
enabled = true
binary = "grype"
timeout_seconds = 300

[notifications.discord]
enabled = false
webhook_url = ""

[risk]
notify_minimum = "High"
```

## Fixture Mode

Collectors and the Grype adapter support `fixture_path` fields. This is used by tests and by `examples/config.toml` so contributors can run a full scan without Docker, systemd, or Grype.

## Environment Overrides

- `NORN_SERVER_BIND`
- `NORN_DATABASE_URL`
- `NORN_SCAN_INTERVAL`
- `NORN_GRYPE_BINARY`
- `NORN_DISCORD_ENABLED`
- `NORN_DISCORD_WEBHOOK_URL`
- `NORN_RISK_NOTIFY_MINIMUM`
