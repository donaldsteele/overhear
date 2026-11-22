#!/usr/bin/env bash
# Usage: scripts/perf.sh RATE SECONDS
# Offers RATE frames/s for SECONDS to overhear on a veth pair, in line mode and in JSON
# mode. A mode passes when overhear exits normally, reports no drops, and the injector
# really achieved at least 98% of RATE (a PASS must not mean that less was offered).
# A setup step that fails ends the run with FAIL at once.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
. scripts/lib-netns.sh
RATE=${1:?usage: perf.sh RATE SECONDS}
SECS=${2:?usage: perf.sh RATE SECONDS}
enter_netns "$PWD/scripts/perf.sh" "$RATE" "$SECS"

TESTGEN=$PWD/target/release/testgen
OVERHEAR=$PWD/target/release/overhear
work=$(mktemp -d) || die "mktemp"
trap 'stop_jobs; rm -rf "$work"' EXIT
fails=0

setup_veth || die "could not set up the veth pair"
"$TESTGEN" perfgen "$work/perf.pcap" 200000 || die "perfgen"

run() { # label, mode (line or json)
    local label=$1 mode=$2 pid tailer="" status ok=1
    # Only the overhear started here is signalled, never another one.
    if [ "$mode" = line ]; then
        "$OVERHEAR" -i veth1 > /dev/null 2> "$work/err" &
        pid=$!
    else
        # Keep only the last JSON line; the FIFO gives overhear's own pid.
        rm -f "$work/json"
        mkfifo "$work/json" || die "mkfifo"
        tail -n1 < "$work/json" > "$work/final" &
        tailer=$!
        "$OVERHEAR" -i veth1 -j > "$work/json" 2> "$work/err" &
        pid=$!
    fi
    sleep 1
    kill -0 "$pid" 2>/dev/null || die "$label: overhear is not running: $(cat "$work/err")"
    "$TESTGEN" inject veth0 "$work/perf.pcap" --rate "$RATE" --seconds "$SECS" \
        > "$work/sent" 2> "$work/inj.err"
    local inj=$?
    sleep 1
    kill -INT "$pid"
    wait "$pid"
    status=$?
    [ -z "$tailer" ] || wait "$tailer"

    local sent achieved
    sent=$(sed 's/^sent //' "$work/sent")
    achieved=$(sed -n 's/^testgen: sent [0-9]* in [0-9.]*s (\([0-9]*\) frames\/s)$/\1/p' "$work/inj.err")
    echo "$label: injector $(sed "s/^testgen: //" "$work/inj.err" | tr "\n" ";")"
    if [ "$inj" -ne 0 ] || [ -z "$achieved" ]; then
        echo "$label: the injector failed (exit status $inj)"; ok=0
    elif ! awk -v a="$achieved" -v r="$RATE" 'BEGIN { exit !(a >= 0.98 * r) }'; then
        echo "$label: the injector achieved $achieved frames/s, below 98% of $RATE"; ok=0
    fi
    if [ "$status" -ne 0 ]; then
        echo "$label: overhear exit status $status"; ok=0
    fi
    if [ "$mode" = line ]; then
        echo "$label: $(tail -n1 "$work/err")"
        grep -q '0 dropped by the kernel, 0 dropped by overhear' "$work/err" || ok=0
    else
        echo "$label: $(cat "$work/final")"
        grep -q '"kernel_drops":0,"channel_drops":0' "$work/final" || ok=0
    fi
    if [ "$ok" = 1 ]; then
        echo "PASS: $label at $RATE pps (offered $sent frames, achieved $achieved frames/s)"
    else
        echo "FAIL: $label at $RATE pps"; fails=1
    fi
}

run "line mode" line
run "json mode" json

if [ "$fails" = 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
