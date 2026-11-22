# shellcheck shell=bash
# Shared by live-test.sh and perf.sh: re-runs the calling script inside a private
# user+network namespace (as the current user, with ambient capabilities) and
# creates a veth pair with no addresses, so the kernel sends nothing on its own.

enter_netns() { # script, args...
    if [ -z "${OVERHEAR_NETNS:-}" ]; then
        export OVERHEAR_NETNS=1
        exec unshare --user --map-current-user --keep-caps --net bash "$@"
    fi
}

# Ends the script at once, failed: a step the checks depend on did not work.
die() {
    echo "FAIL: $*"
    echo "FAIL"
    exit 1
}

# Kills the background jobs still running; for the scripts' EXIT traps, so that
# nothing started here outlives the script.
stop_jobs() {
    local j
    for j in $(jobs -p); do
        kill "$j" 2>/dev/null
    done
}

# wait_for WHAT COMMAND...: retries COMMAND for up to 5 s; dies if it never succeeds.
wait_for() {
    local what=$1 _
    shift
    for _ in $(seq 1 50); do
        "$@" 2>/dev/null && return 0
        sleep 0.1
    done
    die "timed out waiting for $what"
}

# Returns non-zero as soon as a step fails.
setup_veth() {
    local f
    # sysctl(8) may be missing; /proc/sys is the same thing.
    for f in default all; do
        echo 1 > "/proc/sys/net/ipv6/conf/$f/disable_ipv6" || return 1
    done
    ip link add veth0 type veth peer name veth1 || return 1
    ip link set veth0 up || return 1
    ip link set veth1 up || return 1
    # Wait for the link to settle (carrier up) without sending anything.
    sleep 1
}
