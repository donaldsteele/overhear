#!/usr/bin/env bash
# Replays a million frames from distinct MACs and checks the peak resident set
# stays near the --max-memory budget (budget plus 48 MiB of fixed overhead).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x /usr/bin/time ]; then
    echo "flood-test: /usr/bin/time is missing; installing the 'time' package" >&2
    sudo apt-get install -y time
fi

TESTGEN=target/release/testgen
OVERHEAR=target/release/overhear
FRAMES=${FLOOD_FRAMES:-1000000}
fail=0

run() { # label, limit-KB, extra args...
    local label=$1 limit=$2
    shift 2
    local rss
    rss=$("$TESTGEN" flood "$FRAMES" | /usr/bin/time -f %M "$OVERHEAR" -r - -j "$@" 2>&1 >/dev/null | tail -n 1)
    if [ "$rss" -le "$limit" ]; then
        echo "PASS  $label: max RSS $rss KB (limit $limit KB)"
    else
        echo "FAIL  $label: max RSS $rss KB (limit $limit KB)"
        fail=1
    fi
}

run "default 64M" 114688
run "--max-memory 16M" 65536 --max-memory 16M

if [ "$fail" = 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
