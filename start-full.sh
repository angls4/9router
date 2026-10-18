#!/usr/bin/env sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
rust_port=${RUST_PORT:-20128}
app_port=${PORT:-20127}
export NINEROUTER_RUST_URL=${NINEROUTER_RUST_URL:-http://127.0.0.1:$rust_port}

cd "$repo_dir"
cargo build --release --manifest-path rust/Cargo.toml
HOST=127.0.0.1 PORT="$rust_port" ./rust/target/release/ninerouter &
rust_pid=$!
node custom-server.js --port "$app_port" &
node_pid=$!
stop_all() {
  kill "$node_pid" "$rust_pid" 2>/dev/null || true
  wait "$node_pid" "$rust_pid" 2>/dev/null || true
}
trap stop_all EXIT INT TERM
wait "$node_pid"
