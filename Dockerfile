FROM docker.io/library/rust:1-trixie AS builder

# Built from crates.io at a pinned version against its own lockfile, rather than
# piping an unverified "latest" release binary into the image.
ARG CARGO_LEPTOS_VERSION=0.3.11
RUN cargo install cargo-leptos --version "${CARGO_LEPTOS_VERSION}" --locked \
  && rustup target add wasm32-unknown-unknown

WORKDIR /app
COPY . .

# Build the app
RUN cargo leptos build --release

FROM docker.io/library/debian:trixie-slim AS runtime

# Unprivileged 10001:10001 account that owns the data volume. The group is
# created explicitly so its GID does not rely on useradd's defaults.
# SQLite is compiled into the binary and the server makes no outbound TLS
# connections, so no extra runtime packages are needed.
RUN groupadd --gid 10001 carbon \
  && useradd --uid 10001 --gid 10001 --no-create-home \
  --home-dir /app --shell /usr/sbin/nologin carbon \
  && mkdir -p /data \
  && chown carbon:carbon /data

WORKDIR /app

# Copy the server binary to the /app directory
COPY --from=builder /app/target/release/carbon-white /app/

# /target/site contains our JS/WASM/CSS, etc.
COPY --from=builder /app/target/site /app/site

ENV RUST_LOG="info" \
  LEPTOS_SITE_ADDR="0.0.0.0:8080" \
  LEPTOS_SITE_ROOT="site" \
  CARBON_DATA_DIR="/data"

VOLUME ["/data"]
USER carbon
EXPOSE 8080

CMD ["/app/carbon-white"]
