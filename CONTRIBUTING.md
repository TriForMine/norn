# Contributing

Thanks for improving Norn.

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cd apps/web
npm install
npm run lint
npm test
npm run build
```

Use fixture-based tests for collectors and scanners unless a test explicitly requires a real host integration.

## Pull Requests

- Keep changes focused.
- Add or update tests for behavior changes.
- Document new collectors, scanners, risk rules, and configuration options.
- Avoid panics on normal runtime paths.
- Surface partial failures as structured scan errors.

## Collector Guidelines

Collectors should return strong typed `InventoryItem` values and preserve enough raw context to explain exposure and runtime status. Do not require privileged access unless the collector clearly documents why.
