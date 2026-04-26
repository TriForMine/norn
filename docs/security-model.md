# Security Model

Norn observes runtime state and stores local scan results. It does not enforce isolation, patch systems, block network traffic, or replace endpoint security controls.

## Permissions

Collectors may need access to:

- Docker API socket or socket proxy.
- `systemctl` output.
- Package database commands such as `dpkg-query`.
- Listening socket information from `ss`.

Run Norn with the least permissions that still allow the collectors you enable.

## Docker Socket Risk

Mounting `/var/run/docker.sock` gives access to the Docker API. Read-only bind mounts do not make this safe. A client that can talk to the Docker API may be able to create containers, mount host paths, inspect secrets in metadata, or otherwise reach host-control operations depending on API exposure and daemon policy.

Prefer a Docker socket proxy that only exposes the endpoints Norn needs. The example in `docker/docker-compose.socket-proxy.yml` is safer than direct socket mounting, but it still depends on proxy configuration and Docker daemon trust.

## Host Filesystem

Future host filesystem scanning may require read-only host mounts. Read-only helps reduce accidental writes but still exposes sensitive file contents. Mount only paths required for the enabled scanner.

## Threat Model

Norn helps operators prioritize vulnerable running assets. It assumes:

- The host running Norn is trusted enough to collect inventory.
- The SQLite database is protected as local security data.
- Webhook URLs are secrets.
- The dashboard is not exposed to untrusted networks in the MVP because authentication is not implemented.

## What Norn Does Not Protect Against

- Compromise of the Docker daemon or socket.
- Malicious scanner binaries.
- Vulnerabilities with no scanner coverage.
- Network exposure not visible from local runtime data.
- Dashboard access by unauthorized users if exposed publicly.
