#!/usr/bin/env bash
# Runs the real binary on a veth pair in a private namespace: injects every scenario
# capture, checks the output, and checks overhear transmits nothing. A setup step
# that fails ends the run with FAIL at once.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
. scripts/lib-netns.sh
enter_netns "$PWD/scripts/live-test.sh" "$@"

TESTGEN=$PWD/target/release/testgen
OVERHEAR=$PWD/target/release/overhear
DATA=$PWD/crates/overhear/tests/data
work=$(mktemp -d) || die "mktemp"
trap 'stop_jobs; rm -rf "$work"' EXIT
fails=0
check() { # name, status (0 = pass)
    if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1"; fails=1; fi
}

setup_veth || die "could not set up the veth pair"

# Expected packet count: the offline run over the same captures.
expected=0
for f in "$DATA"/*.pcap; do
    n=$("$OVERHEAR" -r "$f" -j | grep -c '"type":"packet"') || die "offline run over $f"
    expected=$((expected + n))
done

# Count what arrives on veth0, which is what veth1 sends, from before overhear
# starts until after it has exited; the counter is then stopped and prints its count.
"$TESTGEN" count-inbound veth0 600 > "$work/inbound" 2> "$work/inbound.err" &
counter=$!
wait_for "count-inbound to start" grep -q '^testgen: counting' "$work/inbound.err"

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
kill -0 "$pid" 2>/dev/null || die "overhear is not running: $(cat "$work/err")"
cap=$(sed -n 's/^CapEff:[[:space:]]*//p' "/proc/$pid/status" 2>/dev/null)

"$TESTGEN" inject veth0 "$DATA"/*.pcap --rate 500 2> "$work/inject.err" \
    || die "inject: $(cat "$work/inject.err")"
# The injector skips frames too short for the kernel to send; overhear cannot see them.
skipped=$(sed -n "s/^testgen: skipped \([0-9]*\) frames.*/\1/p" "$work/inject.err")
expected=$((expected - ${skipped:-0}))
sleep 2
kill -INT "$pid"
wait "$pid"
status=$?

# The counter must still be running: its window then covered overhear's whole life.
kill -0 "$counter" 2>/dev/null
window=$?
kill -INT "$counter" 2>/dev/null
wait "$counter"
counter_status=$?
inbound=$(cat "$work/inbound")

final=$(tail -n1 "$work/out.jsonl")
got=$(grep -c '"type":"packet"' "$work/out.jsonl")

check "exit status 0 (got $status)" "$status"
check "kernel_drops 0" "$(echo "$final" | grep -q '"final":true.*"kernel_drops":0,'; echo $?)"
check "channel_drops 0" "$(echo "$final" | grep -q '"channel_drops":0,'; echo $?)"
check "packet lines $got equal offline count minus unsendable runts ($expected)" "$([ "$got" -eq "$expected" ]; echo $?)"
check "second-dhcp-server warning present" "$(grep -q '"rule":"second-dhcp-server"' "$work/out.jsonl"; echo $?)"
check "CapEff zero while running (got '$cap')" "$([ "$cap" = 0000000000000000 ]; echo $?)"
check "count-inbound ran from before overhear started until after it exited" "$window"
check "count-inbound exit status 0 (got $counter_status)" "$counter_status"
check "overhear sent 0 frames (count-inbound printed '$inbound')" "$([ "$inbound" = 0 ]; echo $?)"

# Control: the counter does see inbound frames (sent from the other end).
"$TESTGEN" count-inbound veth0 600 > "$work/control" 2> "$work/control.err" &
counter=$!
wait_for "the control count-inbound to start" grep -q '^testgen: counting' "$work/control.err"
"$TESTGEN" inject veth1 "$DATA/arp.pcap" --rate 500 > /dev/null 2> "$work/inject.err" \
    || die "control inject: $(cat "$work/inject.err")"
sleep 0.5
kill -INT "$counter" 2>/dev/null
wait "$counter" || die "control count-inbound: $(cat "$work/control.err")"
check "control: count-inbound sees frames sent from veth1 ($(cat "$work/control"))" "$([ "$(cat "$work/control")" -gt 0 ]; echo $?)"

if [ "$fails" = 0 ]; then echo "PASS"; else echo "FAIL"; exit 1; fi
