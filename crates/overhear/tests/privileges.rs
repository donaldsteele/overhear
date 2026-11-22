// This file reads capabilities and /proc directly. That is an allowed
// exception to the rule that only `platform` touches the OS: the test checks
// the process state that `drop_privileges` is supposed to leave behind.
#![cfg(target_os = "linux")]

use overhear::platform::{PrivOpts, PrivReport, drop_privileges};

#[test]
fn plain_user_drop() {
    if nix::unistd::geteuid().is_root() {
        println!("skipped: running as root (priv-test.sh covers the root path)");
        return;
    }
    let report = drop_privileges(&PrivOpts { user: None }).expect("drop_privileges");
    assert_eq!(report, PrivReport::CapabilitiesCleared);
    let eff = caps::read(None, caps::CapSet::Effective).expect("read effective set");
    assert!(eff.is_empty(), "effective set not empty: {eff:?}");
    // no_new_privs and capabilities are per thread, and the test harness runs
    // this on its own thread, so read this thread's status, not the leader's.
    let status = std::fs::read_to_string("/proc/thread-self/status").expect("status");
    assert!(
        status.contains("NoNewPrivs:\t1"),
        "NoNewPrivs not set:\n{status}"
    );
}
