#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
IMG=overhear-bookworm
BIN=target/bookworm/aarch64-unknown-linux-gnu/debug/overhear
docker image inspect "$IMG" >/dev/null 2>&1 \
  || docker build -t "$IMG" -f packaging/Dockerfile.bookworm packaging
run_in() {
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/work -w /work \
    -e CARGO_HOME=/work/.cache/cargo-bookworm -e CARGO_TARGET_DIR=/work/target/bookworm \
    -e LIBPCAP_LIBDIR=/usr/lib/aarch64-linux-gnu -e LIBPCAP_VER=1.10.3 \
    "$IMG" "$@"
}
run_in cargo test --workspace -q --target aarch64-unknown-linux-gnu
# cargo test does not link the final bin; build it for the glibc check
run_in cargo build -q -p overhear --target aarch64-unknown-linux-gnu
max=$(run_in aarch64-linux-gnu-objdump -T "$BIN" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)
top=$(printf '%s\n%s\n' "$max" GLIBC_2.36 | sort -V | tail -1)
if [ "$top" != GLIBC_2.36 ]; then
  echo "glibc too new: $max (limit GLIBC_2.36)" >&2
  exit 1
fi
echo "arm64 tests passed (max $max)"
