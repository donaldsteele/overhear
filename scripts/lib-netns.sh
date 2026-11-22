# Shared by live-test.sh and perf.sh: re-runs the calling script inside a private
# user+network namespace (as the current user, with ambient capabilities) and
# creates a veth pair with no addresses, so the kernel sends nothing on its own.

enter_netns() { # script, args...
    if [ -z "${OVERHEAR_NETNS:-}" ]; then
        export OVERHEAR_NETNS=1
        exec unshare --user --map-current-user --keep-caps --net bash "$@"
    fi
}

setup_veth() {
    local f
    # sysctl(8) may be missing; /proc/sys is the same thing.
    for f in default all; do
        echo 1 > "/proc/sys/net/ipv6/conf/$f/disable_ipv6"
    done
    ip link add veth0 type veth peer name veth1
    ip link set veth0 up
    ip link set veth1 up
    # Wait for the link to settle (carrier up) without sending anything.
    sleep 1
}
