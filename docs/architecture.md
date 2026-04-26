# Architecture

Norn is split into small Rust crates so runtime discovery, scanning, risk scoring, persistence, API serving, and notifications can evolve independently.

## Crates

- `norn-core`: shared models, configuration, and extension traits.
- `norn-inventory`: collector registry and scan target derivation.
- `norn-collector-*`: Docker, systemd, package, and port collectors.
- `norn-scanner-grype`: Grype subprocess adapter and JSON parser.
- `norn-risk`: runtime risk scoring rules.
- `norn-db`: SQLite schema and query layer.
- `norn-notify`: notification adapters, currently Discord.
- `norn-api`: Axum REST API and dashboard serving.
- `norn-cli`: all-in-one binary and scan orchestration.

## Flow

1. Collectors produce `InventoryItem` values for containers, services, packages, and ports.
2. Inventory items become `ScanTarget` values when a scanner can act on them.
3. Scanner adapters produce `VulnerabilityFinding` values.
4. The risk engine combines findings with runtime context into `RiskEvaluation` values.
5. SQLite stores scans, inventory, findings, risks, ignore rules, and notification events.
6. The API and dashboard read the latest scan plus scan history.
7. Notifiers receive important new runtime risk events.

## Partial Failure

A collector or scanner failure does not abort the whole scan. Norn records structured errors in the scan record and continues with the remaining runtime data.

## Dashboard

The dashboard is a Vite React app served from a static directory by the all-in-one binary. During development, Vite proxies `/api` to the Axum server.
