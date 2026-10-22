#!/usr/bin/env sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -z "${NINEROUTER_STATIC_DIR:-}" ] && [ -d "$repo_dir/out" ]; then
  export NINEROUTER_STATIC_DIR="$repo_dir/out"
fi
exec cargo run --release --manifest-path "$repo_dir/rust/Cargo.toml" -- "$@"
