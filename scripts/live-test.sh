#!/usr/bin/env bash
# Runs the real binary on a veth pair in a private namespace: injects every scenario
# capture, checks the output, and checks overhear transmits nothing.
set -uo pipefail
cd "$(dirname "$0")/.."
. scripts/lib-netns.sh
enter_netns "$PWD/scripts/live-test.sh" "$@"

TESTGEN=$PWD/target/release/testgen
OVERHEAR=$PWD/target/release/overhear
DATA=$PWD/crates/overhear/tests/data
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
check() { # name, status (0 = pass)
    if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1"; fails=1; fi
}

setup_veth

# Expected packet count: the offline run over the same captures.
expected=0
for f in "$DATA"/*.pcap; do
    n=$("$OVERHEAR" -r "$f" -j | grep -c '"type":"packet"')
    expected=$((expected + n))
done

"$TESTGEN" count-inbound veth0 20 > "$work/inbound" 2>"$work/inbound.err" &
counter=$!
"$OVERHEAR" -i veth1 -j > "$work/out.jsonl" 2> "$work/err" &
pid=$!

# Privileges are dropped once the capture is open; wait for that.
cap=""
for _ in $(seq 1 50); do
    cap=$(sed -n 's/^CapEff:[[:space:]]*//p' "/proc/$pid/status" 2>/dev/null)
    [ "$cap" = 0000000000000000 ] && break
    sleep 0.1
done
sleep 0.5
cap=$(sed -n 's/^CapEff:[[:space:]]*//p' "/proc/$pid/status" 2>/dev/null)

"$TESTGEN" inject veth0 "$DATA"/*.pcap --rate 500 2> "$work/inject.err"
# The injector skips frames too short for the kernel to send; overhear cannot see them.
skipped=$(sed -n "s/^testgen: skipped \([0-9]*\) frames.*/\1/p" "$work/inject.err")
expected=$((expected - ${skipped:-0}))
sleep 2
kill -INT "$pid"
wait "$pid"
status=$?
wait "$counter"
inbound=$(cat "$work/inbound")

final=$(tail -n1 "$work/out.jsonl")
got=$(grep -c '"type":"packet"' "$work/out.jsonl")

check "exit status 0 (got $status)" "$status"
check "kernel_drops 0" "$(echo "$final" | grep -q '"final":true.*"kernel_drops":0,'; echo $?)"
check "channel_drops 0" "$(echo "$final" | grep -q '"channel_drops":0,'; echo $?)"
check "packet lines $got equal offline count minus unsendable runts ($expected)" "$([ "$got" -eq "$expected" ]; echo $?)"
check "second-dhcp-server warning present" "$(grep -q '"rule":"second-dhcp-server"' "$work/out.jsonl"; echo $?)"
check "CapEff zero while running (got '$cap')" "$([ "$cap" = 0000000000000000 ]; echo $?)"
check "overhear sent 0 frames (count-inbound printed '$inbound')" "$([ "$inbound" = 0 ]; echo $?)"

# Control: the counter does see inbound frames (sent from the other end).
"$TESTGEN" count-inbound veth0 3 > "$work/control" &
counter=$!
sleep 1
"$TESTGEN" inject veth1 "$DATA/arp.pcap" --rate 500 > /dev/null 2>&1
wait "$counter"
check "control: count-inbound sees frames sent from veth1 ($(cat "$work/control"))" "$([ "$(cat "$work/control")" -gt 0 ]; echo $?)"

if [ "$fails" = 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
