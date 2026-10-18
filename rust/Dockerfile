FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/ninerouter /usr/local/bin/ninerouter
ENV HOST=0.0.0.0 PORT=20127 DATA_DIR=/data RUST_LOG=info
EXPOSE 20127
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/ninerouter"]
