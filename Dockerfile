# syntax=docker/dockerfile:1
# Copyright 2026 Ronny Trommer <ronny@no42.org>
# SPDX-License-Identifier: MIT

# ---- Build stage -------------------------------------------------------------
# The full `rust` image ships a C toolchain, which rusqlite's bundled SQLite
# needs to compile. migrations/ and the UI are embedded into the binary at build
# time (include_str!), so the runtime image needs only the binary.
FROM rust:1-bookworm AS builder

WORKDIR /src
COPY Cargo.toml ./
COPY migrations ./migrations
COPY assets ./assets
COPY src ./src

# BuildKit cache mounts keep the registry and target dir warm across rebuilds.
# The binary is copied out of the cached target before the mount is released.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release && \
    cp target/release/amiga-game-vault /amiga-game-vault && \
    strip /amiga-game-vault

# ---- Runtime stage -----------------------------------------------------------
FROM debian:bookworm-slim AS runtime

# xdms enables .dms (DiskMasher) ingestion; curl is used by the healthcheck.
# (xdftool/amitools for filesystem walks is optional and not installed here.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends xdms ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

# Run as a non-root system user that owns the data volume.
RUN useradd --system --uid 10001 --create-home --home-dir /data vault

COPY --from=builder /amiga-game-vault /usr/local/bin/amiga-game-vault

ENV VAULT_DATA=/data \
    VAULT_ADDR=0.0.0.0:4500

VOLUME ["/data"]
EXPOSE 4500
USER vault

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:4500/ >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/amiga-game-vault"]
