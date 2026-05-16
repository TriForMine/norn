# Norn

[![CI](https://github.com/TriForMine/norn/actions/workflows/ci.yml/badge.svg)](https://github.com/TriForMine/norn/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v0.1.0-lightgrey.svg)](https://github.com/TriForMine/norn/releases)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](Cargo.toml)

Norn is a modular runtime vulnerability monitor for Linux servers. It scans what is actually running on a machine: Docker containers, active services, listening ports, installed packages, and exposed services. It then correlates runtime inventory with vulnerability scanner output, calculates a practical risk score, stores scan history in SQLite, serves an API and dashboard, and sends Discord notifications for important new risks.

Norn is licensed under Apache-2.0.

## Dashboard Preview

The MVP includes a React dashboard with summary cards, services, vulnerabilities, scan history, notification testing, and ignore controls. Build it with `cd apps/web && bun install && bun run build`, then run `norn serve`.

## Features

- Single-host all-in-one mode: collector, scanner, database, API, dashboard, scheduler, and notifications.
- Modular Rust traits for collectors, vulnerability scanners, notifiers, and scan runners.
- Docker runtime collector with Unix socket and HTTP socket-proxy support.
- Docker image scans use local image IDs when available and deduplicate identical images before invoking Grype.
- Linux host collectors for systemd services, dpkg packages, and listening ports.
- Grype scanner adapter with subprocess execution, timeout handling, missing-binary errors, and fixture parsing.
- Runtime risk engine that considers severity, public exposure, container privilege, Docker socket mounts, and fix availability.
- SQLite scan history with versioned migration SQL.
- Axum REST API and Vite/React dashboard with persisted light/dark theme support.
- Polished terminal output with scan progress, readable tables, and an interactive TUI.
- Discord webhook notifications.
- Fixture-first tests that do not require Docker, systemd, dpkg, `ss`, or Grype.

## Non-Goals

Norn MVP does not implement Kubernetes, Windows, macOS, automatic patching, remote multi-host agents, authentication, RBAC, AI features, or cloud account scanning.

## Quick Start

Run the fixture-backed scan from the repository root:

```bash
cargo run -p norn-cli -- scan --config ./examples/config.toml
```

Example output:

```text
Host: homelab
Running containers: 12
Active services: 48
Listening ports: 81
Publicly bound inventory items: 5
Critical runtime risks: 1
High runtime risks: 3
Medium runtime risks: 11
Low runtime risks: 7
Informational runtime risks: 13
```

Build and test everything:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cd apps/web
bun install
bun run lint
bun run test
bun run build
```

Start the API and dashboard:

```bash
cargo run -p norn-cli -- serve --config ./examples/config.toml
```

Open `http://127.0.0.1:8787`.

## CLI

```bash
norn scan --config /etc/norn/config.toml
norn scan --config /etc/norn/config.toml --jobs 8
norn scan --config /etc/norn/config.toml --no-progress
norn tui --config /etc/norn/config.toml
norn serve --config /etc/norn/config.toml
norn inventory --config /etc/norn/config.toml --output table
norn report --config /etc/norn/config.toml
norn notify test --config /etc/norn/config.toml
norn ignore CVE-2026-0001 --service nginx --days 30 --config /etc/norn/config.toml
```

## API

- `GET /api/health`
- `GET /api/summary`
- `GET /api/inventory`
- `GET /api/services`
- `GET /api/vulnerabilities` accepts optional `?limit=500` style caps for dashboard-sized responses
- `GET /api/scans`
- `GET /api/scans/status` returns `running` plus current scan phase, target counters, and active target
- `POST /api/scans/run`
- `POST /api/ignore`
- `POST /api/notifications/test`

## Configuration

Default path: `/etc/norn/config.toml`. Use `--config` or `NORN_CONFIG` to override it.

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

[scanner]
parallelism = 4
scan_host_filesystem = false

[collectors.docker]
enabled = true
socket = "/var/run/docker.sock"

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

Environment overrides include `NORN_SERVER_BIND`, `NORN_DATABASE_URL`, `NORN_SCAN_INTERVAL`, `NORN_SCANNER_PARALLELISM`, `NORN_SCANNER_SCAN_HOST_FILESYSTEM`, `NORN_GRYPE_BINARY`, `NORN_DISCORD_ENABLED`, `NORN_DISCORD_WEBHOOK_URL`, `NORN_RISK_NOTIFY_MINIMUM`, `NORN_RISK_MAX_NOTIFICATIONS_PER_SCAN`, and `NORN_RETENTION_DAYS`.

## Docker Compose

Direct Docker socket mode:

```bash
docker compose -f docker/docker-compose.yml up --build
```

Socket-proxy mode:

```bash
docker compose -f docker/docker-compose.socket-proxy.yml up --build
```

Mounting `/var/run/docker.sock` is sensitive. Read-only mounts do not make the Docker socket safe: access to the Docker API can still expose host control paths. Prefer the socket-proxy example when possible and grant only the endpoints Norn needs.

## Discord Notification Example

```text
Critical runtime risk: CVE-2026-0001
Host: homelab
Service: norn-nginx
Artifact: nginx:1.25.3
Severity: Critical
Runtime risk: Critical
Exposure: public
Recommended action: Patch or redeploy the affected service as soon as possible.
```

## Example Report

```markdown
# Norn Runtime Security Report

Generated at: 2026-04-25T10:00:00Z
Host: homelab

## Urgent
- **CVE-2026-0001** on `norn-nginx`: Critical risk, public exposure, fix Available

## Important
- **CVE-2026-0002** on `norn-postgres`: High risk, internal exposure, fix NotAvailable

## Low priority
- None
```

## Security Model

Norn observes runtime state and stores local scan history. It does not sandbox workloads, patch systems, enforce network policy, or replace a hardening baseline. Docker access is the most sensitive permission. See [docs/security-model.md](docs/security-model.md).

## Roadmap

- EPSS and CISA KEV enrichment.
- More package managers and service managers.
- Optional authentication for exposed dashboards.
- Remote agent and multi-host aggregation.
- Community collector protocol using JSON stdin/stdout.
- SARIF and CycloneDX export.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues should follow [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
