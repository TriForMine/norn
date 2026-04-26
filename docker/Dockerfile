FROM oven/bun:1.2.20-debian AS web
WORKDIR /src/apps/web
COPY apps/web/package.json apps/web/bun.lock ./
RUN bun install --frozen-lockfile
COPY apps/web ./
RUN bun run build

FROM rust:1.86-bookworm AS builder
WORKDIR /src
RUN apt-get update \
  && apt-get install -y --no-install-recommends pkg-config ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p norn-cli

FROM debian:bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl dpkg iproute2 \
  && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin \
  && useradd --system --create-home --home-dir /var/lib/norn norn \
  && mkdir -p /data /etc/norn /opt/norn/web \
  && chown -R norn:norn /data /var/lib/norn \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/norn /usr/local/bin/norn
COPY --from=web /src/apps/web/dist /opt/norn/web
COPY docker/config.toml /etc/norn/config.toml
EXPOSE 8787
VOLUME ["/data"]
CMD ["norn", "serve", "--config", "/etc/norn/config.toml"]
