# Collectors

Collectors discover runtime inventory by implementing:

```rust
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    async fn collect(&self) -> anyhow::Result<Vec<InventoryItem>>;
}
```

## MVP Collectors

- Docker: running containers, image references, labels, published ports, privileged mode, and Docker socket mounts.
- systemd: active services from `systemctl list-units`.
- packages: installed dpkg packages.
- ports: listening TCP/UDP sockets from `ss`.

## Adding Collectors

New collectors should:

- Return stable IDs.
- Use typed fields for source, kind, status, exposure, and endpoints.
- Avoid panics and return clear errors.
- Include fixture parsers and tests that do not require the real host dependency.
- Document permissions and security tradeoffs.

## Future Plugin Protocol

A future community plugin protocol can use JSON stdin/stdout:

- Norn sends collector configuration and host metadata on stdin.
- The plugin writes an array of `InventoryItem` objects on stdout.
- Errors are returned as structured JSON with a collector name and message.

This keeps untrusted or experimental collectors outside the main binary while preserving typed data at the boundary.
