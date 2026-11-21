use super::{Interface, PlatformError};

const UNSUPPORTED: &str = "not supported on this platform yet";

pub fn list_interfaces() -> Result<Vec<Interface>, PlatformError> {
    Err(PlatformError(UNSUPPORTED.into()))
}

pub fn resolve_interface(_name: &str) -> Result<String, PlatformError> {
    Err(PlatformError(UNSUPPORTED.into()))
}

pub fn stdout_is_file() -> bool {
    false
}
