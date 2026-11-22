#!/usr/bin/env bash
# Builds the release: the manual page, and the amd64 and arm64 .deb packages in the
# Debian 12 image, plus a testgen for the Raspberry Pi. Needs Docker. Output is in dist/.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=0.1.0
IMG=overhear-bookworm
X86=x86_64-unknown-linux-gnu
ARM=aarch64-unknown-linux-gnu
TARGET=target/bookworm
LIMIT=GLIBC_2.36

mkdir -p dist/man
# Nothing left over from an earlier build may pass for this one.
rm -f dist/*.deb dist/testgen-arm64
pod2man --section 1 --center overhear --release "overhear $VERSION" doc/overhear.pod \
  | gzip -9n > dist/man/overhear.1.gz

# Always build: cached layers make it quick, and it picks up Dockerfile changes.
docker build -q -t "$IMG" -f packaging/Dockerfile.bookworm packaging >/dev/null
run_in() {
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/work -w /work \
    -e CARGO_HOME=/work/.cache/cargo-bookworm -e CARGO_TARGET_DIR=/work/$TARGET \
    -e LIBPCAP_LIBDIR=/usr/lib/aarch64-linux-gnu -e LIBPCAP_VER=1.10.3 \
    "$IMG" "$@"
}

# The x86-64 build does not use the cross-build settings above: libpcap is found
# through pkg-config there.
run_x86() {
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/work -w /work \
    -e CARGO_HOME=/work/.cache/cargo-bookworm -e CARGO_TARGET_DIR=/work/$TARGET \
    "$IMG" "$@"
}

run_x86 cargo deb -p overhear --target "$X86" --output dist/
run_in cargo deb -p overhear --target "$ARM" --output dist/
run_in cargo build --release -p overhear-testgen --target "$ARM"
cp "$TARGET/$ARM/release/testgen" dist/testgen-arm64

scripts/arm64-test.sh

# No release binary may need a newer glibc than Debian 12 has.
glibc_check() { # label, objdump command, binary
  local max top
  max=$(run_in "$2" -T "$3" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)
  top=$(printf '%s\n%s\n' "$max" "$LIMIT" | sort -V | tail -1)
  if [ "$top" != "$LIMIT" ]; then
    echo "$1: glibc too new: $max (limit $LIMIT)" >&2
    exit 1
  fi
  echo "$1: glibc ok (max $max)"
}
glibc_check amd64 objdump "$TARGET/$X86/release/overhear"
glibc_check arm64 aarch64-linux-gnu-objdump "$TARGET/$ARM/release/overhear"

# Each package must hold the program and the manual page.
for arch in amd64 arm64; do
  deb=dist/overhear_${VERSION}-1_$arch.deb
  list=$(dpkg-deb -c "$deb")
  for f in ./usr/bin/overhear ./usr/share/man/man1/overhear.1.gz; do
    if ! grep -q " $f\$" <<<"$list"; then
      echo "$deb: missing $f" >&2
      exit 1
    fi
  done
  echo "$deb: contents ok"
done

ls -l dist
