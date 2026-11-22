#!/usr/bin/env bash
# Regenerates crates/overhear/src/vendor/table.rs from the IEEE MA-L, MA-M and MA-S registries.
# If IEEE refuses the download this stops; do not substitute another source (licensing).
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
ua="Mozilla/5.0 (compatible; oui-updater)"
fetch() {
    curl --fail --silent --show-error --location --user-agent "$ua" --output "$tmp/$2" "$1" || {
        echo "update-oui: IEEE refused or failed the download of $1" >&2
        exit 1
    }
}
fetch https://standards-oui.ieee.org/oui/oui.csv oui.csv
fetch https://standards-oui.ieee.org/oui28/mam.csv mam.csv
fetch https://standards-oui.ieee.org/oui36/oui36.csv oui36.csv
OUI_DATE=$(date -u +%F) cargo run -q -p overhear-testgen --bin testgen -- gen-oui \
    "$tmp/oui.csv" "$tmp/mam.csv" "$tmp/oui36.csv" crates/overhear/src/vendor/table.rs
echo "wrote crates/overhear/src/vendor/table.rs"
