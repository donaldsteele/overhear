use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;

use super::{Interface, PlatformError, PrivOpts, PrivReport};
use caps::CapSet;
use nix::sys::prctl;
use nix::sys::signal::{SigHandler, Signal, raise, signal};
use nix::unistd::{Uid, User, geteuid, setgid, setgroups, setuid};

pub fn list_interfaces() -> Result<Vec<Interface>, PlatformError> {
    match pcap::Device::list() {
        Ok(devices) => Ok(devices
            .into_iter()
            .map(|d| Interface {
                friendly: d.name.clone(),
                addrs: d.addresses.iter().map(|a| a.addr).collect(),
                name: d.name,
            })
            .collect()),
        // libpcap gives up on the whole list when one interface cannot be
        // probed (seen under emulation); the kernel's own list still works,
        // just without addresses.
        Err(e) => sys_class_net().ok_or_else(|| PlatformError(e.to_string())),
    }
}

fn sys_class_net() -> Option<Vec<Interface>> {
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .ok()?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    names.sort();
    Some(
        names
            .into_iter()
            .map(|n| Interface {
                friendly: n.clone(),
                name: n,
                addrs: Vec::new(),
            })
            .collect(),
    )
}

pub fn resolve_interface(name: &str) -> Result<String, PlatformError> {
    Ok(name.to_string())
}

pub fn stdout_is_file() -> bool {
    io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .and_then(|fd| File::from(fd).metadata())
        .map(|m| m.is_file())
        .unwrap_or(false)
}

fn err(what: &str, e: impl std::fmt::Display) -> PlatformError {
    PlatformError(format!("{what}: {e}"))
}

pub fn drop_privileges(opts: &PrivOpts) -> Result<PrivReport, PlatformError> {
    if geteuid().is_root() {
        drop_root(opts)
    } else {
        if opts.user.is_some() {
            // The caller may have no stderr left; nothing more to do then.
            let _ = writeln!(io::stderr(), "overhear: -Z ignored: not running as root");
        }
        clear_capabilities()?;
        no_new_privs()?;
        Ok(PrivReport::CapabilitiesCleared)
    }
}

fn drop_root(opts: &PrivOpts) -> Result<PrivReport, PlatformError> {
    let name = opts.user.as_deref().unwrap_or("nobody");
    let user = User::from_name(name)
        .map_err(|e| err(&format!("cannot look up user {name}"), e))?
        .ok_or_else(|| PlatformError(format!("unknown user {name}")))?;
    setgroups(&[user.gid]).map_err(|e| err("setgroups", e))?;
    setgid(user.gid).map_err(|e| err("setgid", e))?;
    setuid(user.uid).map_err(|e| err("setuid", e))?;
    if setuid(Uid::from_raw(0)).is_ok() {
        return Err(PlatformError("could not drop root".into()));
    }
    clear_capabilities()?;
    no_new_privs()?;
    Ok(PrivReport::SwitchedUser {
        user: user.name,
        uid: user.uid.as_raw(),
        gid: user.gid.as_raw(),
    })
}

/// Empties every capability set, then checks the effective one.
fn clear_capabilities() -> Result<(), PlatformError> {
    // Ambient first: it is bounded by the other two. A kernel without
    // ambient capabilities has nothing to clear.
    if let Err(e) = caps::clear(None, CapSet::Ambient) {
        if caps::runtime::ambient_set_supported().is_ok() {
            return Err(err("cannot clear ambient capabilities", e));
        }
    }
    for set in [CapSet::Inheritable, CapSet::Effective, CapSet::Permitted] {
        caps::clear(None, set)
            .map_err(|e| err(&format!("cannot clear {set:?} capabilities"), e))?;
    }
    let eff = caps::read(None, CapSet::Effective)
        .map_err(|e| err("cannot read effective capabilities", e))?;
    if !eff.is_empty() {
        return Err(PlatformError("could not clear capabilities".into()));
    }
    Ok(())
}

fn no_new_privs() -> Result<(), PlatformError> {
    prctl::set_no_new_privs().map_err(|e| err("cannot set no_new_privs", e))
}

pub fn force_exit_on_signal() {
    // SAFETY: SigDfl installs no Rust handler, so nothing runs in signal
    // context.
    unsafe {
        let _ = signal(Signal::SIGTERM, SigHandler::SigDfl);
        let _ = signal(Signal::SIGINT, SigHandler::SigDfl);
    }
    let _ = raise(Signal::SIGINT);
    // Only reached if the signal was somehow not fatal.
    std::process::exit(130)
}
