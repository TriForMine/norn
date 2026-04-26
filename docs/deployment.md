# Deployment

## Binary

Build the dashboard and binary:

```bash
cd apps/web
bun install
bun run build
cd ../..
cargo build --release -p norn-cli
```

Install the binary and create configuration:

```bash
sudo install -m 0755 target/release/norn /usr/local/bin/norn
sudo mkdir -p /etc/norn /var/lib/norn
sudo cp docker/config.toml /etc/norn/config.toml
sudo norn serve --config /etc/norn/config.toml
```

## Docker Compose

Direct socket:

```bash
docker compose -f docker/docker-compose.yml up --build
```

Socket proxy:

```bash
docker compose -f docker/docker-compose.socket-proxy.yml up --build
```

The dashboard is exposed on port `8787`.

## Grype

The Docker image installs Grype. Binary deployments should install Grype separately and set `scanner.grype.binary` if it is not on `PATH`.

## Persistence

SQLite data should live on persistent storage. The Docker Compose files mount `../data` to `/data`.
