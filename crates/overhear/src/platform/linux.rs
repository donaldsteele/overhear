use std::fs::File;
use std::io;
use std::os::fd::AsFd;

use super::{Interface, PlatformError};

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
