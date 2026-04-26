# Scanner Adapters

Scanner adapters transform runtime scan targets into vulnerability findings.

```rust
#[async_trait]
pub trait VulnerabilityScanner: Send + Sync {
    fn name(&self) -> &'static str;
    async fn scan(&self, target: ScanTarget) -> anyhow::Result<Vec<VulnerabilityFinding>>;
}
```

## Grype Adapter

The MVP adapter runs Grype as a subprocess:

```bash
grype -o json docker:nginx:1.25.3
```

It supports:

- Configurable binary path.
- Configurable timeout.
- JSON fixture parsing for tests.
- Clear missing-binary errors.
- Partial scan success when one target fails.

## Future Adapters

Adapters can be added for scanners such as Trivy, OSV-Scanner, vendor feeds, or package-manager native advisory sources. They should map scanner-specific output into `VulnerabilityFinding` without leaking scanner-specific strings into risk logic.
