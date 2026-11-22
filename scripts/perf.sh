#!/usr/bin/env bash
# Usage: scripts/perf.sh RATE SECONDS
# Offers RATE frames/s for SECONDS to overhear on a veth pair, in line mode and in JSON
# mode, and checks overhear reports no drops. Also prints the rate the injector really
# achieved, since a PASS only means overhear kept up with what was offered.
set -uo pipefail
cd "$(dirname "$0")/.."
. scripts/lib-netns.sh
RATE=${1:?usage: perf.sh RATE SECONDS}
SECS=${2:?usage: perf.sh RATE SECONDS}
enter_netns "$PWD/scripts/perf.sh" "$RATE" "$SECS"

TESTGEN=$PWD/target/release/testgen
OVERHEAR=$PWD/target/release/overhear
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0

setup_veth
"$TESTGEN" perfgen "$work/perf.pcap" 200000

run() { # label, then overhear args; output handling by mode
    local label=$1 mode=$2
    if [ "$mode" = line ]; then
        "$OVERHEAR" -i veth1 > /dev/null 2> "$work/err" &
    else
        "$OVERHEAR" -i veth1 -j 2> "$work/err" | tail -n1 > "$work/final" &
    fi
    local job=$!
    sleep 1
    "$TESTGEN" inject veth0 "$work/perf.pcap" --rate "$RATE" --seconds "$SECS" > "$work/sent" 2> "$work/inj.err"
    sleep 1
    pkill -INT -x overhear
    wait "$job"
    local sent
    sent=$(sed 's/^sent //' "$work/sent")
    echo "$label: injector $(sed "s/^testgen: //" "$work/inj.err" | tr "\n" ";")"
    if [ "$mode" = line ]; then
        echo "$label: $(tail -n1 "$work/err")"
        if grep -q '0 dropped by the kernel, 0 dropped by overhear' "$work/err"; then
            echo "PASS: $label at $RATE pps (offered $sent frames)"
        else
            echo "FAIL: $label at $RATE pps"; fails=1
        fi
    else
        echo "$label: $(cat "$work/final")"
        if grep -q '"kernel_drops":0,"channel_drops":0' "$work/final"; then
            echo "PASS: $label at $RATE pps (offered $sent frames)"
        else
            echo "FAIL: $label at $RATE pps"; fails=1
        fi
    fi
}

run "line mode" line
run "json mode" json

if [ "$fails" = 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
