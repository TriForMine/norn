# Notifications

The MVP notifier sends Discord webhook messages.

Notifications are intended for:

- New Critical runtime risks.
- New High runtime risks.
- Vulnerabilities becoming more dangerous after exposure changes.
- Running privileged containers.
- Running containers with Docker socket mounts.

The current implementation sends new High/Critical risk events based on stored risk history and emits container hardening events during scans.

## Discord

```toml
[notifications.discord]
enabled = true
webhook_url = "https://discord.com/api/webhooks/..."
```

Test:

```bash
norn notify test --config /etc/norn/config.toml
```

Messages include host, service, artifact, vulnerability ID, severity, runtime risk, exposure, reason, and recommended action.
