#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo fmt --all --check
cargo clippy --workspace --all-targets -q -- -D warnings
cargo test --workspace -q
cargo +1.85 check --workspace -q
cargo check -p overhear-decode -p overhear --target x86_64-pc-windows-msvc -q
cargo audit
podchecker doc/overhear.pod
[ "${SKIP_ARM:-0}" = 1 ] || scripts/arm64-test.sh
echo "all checks passed"
