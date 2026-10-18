#!/usr/bin/env sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec cargo run --release --manifest-path "$repo_dir/rust/Cargo.toml" -- "$@"
