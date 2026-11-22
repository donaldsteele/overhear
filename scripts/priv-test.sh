#!/usr/bin/env bash
# Checks the privilege drop on a real capture of `lo`. Needs passwordless sudo.
set -uo pipefail
cd "$(dirname "$0")/.."
cargo build --release -q || exit 1
BIN=$PWD/target/release/overhear

fails=0
work=$(mktemp -d)
d=""
cleanup() {
    [ -n "$d" ] && rm -rf "$d"
    rm -rf "$work"
}
trap cleanup EXIT

check() { # name, condition result (0 = pass)
    if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1"; fails=1; fi
}
field() { # pid, field name -> value of /proc/PID/status line
    sed -n "s/^$2:[[:space:]]*//p" "/proc/$1/status"
}
same() { [ "$(field "$1" "$2")" = "$3" ]; }

# 1. Started as root: switch to nobody.
pidfile=$work/root.pid
sudo sh -c 'echo $$ > "$1"; shift; exec "$@"' sh "$pidfile" "$BIN" -i lo -Z nobody -j >/dev/null 2>"$work/root.err" &
sleep 1
pid=$(cat "$pidfile")
check "root: Uid all 65534" "$(same "$pid" Uid $'65534\t65534\t65534\t65534'; echo $?)"
check "root: Gid all 65534" "$(same "$pid" Gid $'65534\t65534\t65534\t65534'; echo $?)"
check "root: CapEff zero" "$(same "$pid" CapEff 0000000000000000; echo $?)"
check "root: CapPrm zero" "$(same "$pid" CapPrm 0000000000000000; echo $?)"
check "root: NoNewPrivs 1" "$(same "$pid" NoNewPrivs 1; echo $?)"
sudo kill -INT "$pid"
wait $!
check "root: SIGINT exits 0" "$([ $? -eq 0 ]; echo $?)"

# 2. Unknown user.
sudo "$BIN" -i lo -Z nosuchuser >/dev/null 2>"$work/unk.err"
rc=$?
check "unknown user: exit 1" "$([ $rc -eq 1 ]; echo $?)"
check "unknown user: message" "$(grep -q 'unknown user nosuchuser' "$work/unk.err"; echo $?)"

# 3. File capabilities, run as the normal user. /tmp is nosuid, so use $HOME.
d=$(mktemp -d -p "$HOME")
cp "$BIN" "$d/overhear"
sudo setcap cap_net_raw,cap_net_admin=eip "$d/overhear"
"$d/overhear" -i lo -j >/dev/null 2>"$work/cap.err" &
pid=$!
sleep 1
check "setcap: still running" "$(kill -0 "$pid" 2>/dev/null; echo $?)"
for f in CapEff CapPrm CapInh CapAmb; do
    check "setcap: $f zero" "$(same "$pid" $f 0000000000000000; echo $?)"
done
check "setcap: NoNewPrivs 1" "$(same "$pid" NoNewPrivs 1; echo $?)"
kill "$pid" 2>/dev/null
wait "$pid" 2>/dev/null
rm -rf "$d"
d=""

exit $fails
