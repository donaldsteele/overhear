//! Command line.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;

use crate::observe::Segment;
use crate::warn::{Pins, RouterId, parse_dhcp_pin, parse_router_pin};

#[derive(Parser, Debug)]
#[command(
    name = "overhear",
    version,
    about = "Passively listens to a LAN and reports who is there",
    trailing_var_arg = true
)]
pub struct Args {
    /// Capture from this interface
    #[arg(short = 'i', conflicts_with = "read")]
    pub iface: Option<String>,
    /// Read packets from a capture file ("-" for standard input)
    #[arg(short = 'r')]
    pub read: Option<PathBuf>,
    /// One JSON object per line
    #[arg(short = 'j')]
    pub json: bool,
    /// Full-screen view
    #[arg(short = 't')]
    pub tui: bool,
    /// Multi-line detail for every packet
    #[arg(short = 'v')]
    pub verbose: bool,
    /// Add a hex dump of each packet
    #[arg(short = 'H')]
    pub hex: bool,
    /// Do not put the interface in promiscuous mode
    #[arg(short = 'p')]
    pub no_promisc: bool,
    /// Drop privileges to this user after opening the capture
    #[arg(short = 'Z')]
    pub user: Option<String>,
    /// A DHCP server you expect, optionally on one VLAN only (repeatable)
    #[arg(long = "dhcp-server", value_name = "IP[@VLAN]", value_parser = parse_dhcp_pin)]
    pub dhcp_server: Vec<(Ipv4Addr, Option<Segment>)>,
    /// An IPv6 router you expect, by MAC or link-local address, optionally on
    /// one VLAN only (repeatable)
    #[arg(long = "router", value_name = "MAC|IPV6[@VLAN]", value_parser = parse_router_pin)]
    pub router: Vec<(RouterId, Option<Segment>)>,
    /// Memory budget for tracked state (K, M or G)
    #[arg(long = "max-memory", default_value = "64M", value_parser = parse_size)]
    pub max_memory: usize,
    /// List capture interfaces and exit
    #[arg(short = 'D')]
    pub list: bool,
    /// Extra capture filter words, ANDed with the built-in filter
    #[arg(allow_hyphen_values = true)]
    pub filter: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Line,
    Verbose,
    Json,
    Tui,
}

impl Args {
    /// The expected servers given with `--dhcp-server` and `--router`.
    pub fn pins(&self) -> Pins {
        Pins {
            dhcp: self.dhcp_server.clone(),
            routers: self.router.clone(),
        }
    }

    pub fn mode(&self) -> Mode {
        if self.json {
            Mode::Json
        } else if self.tui {
            Mode::Tui
        } else if self.verbose {
            Mode::Verbose
        } else {
            Mode::Line
        }
    }
}

/// A decimal number with an optional K, M or G suffix (powers of 1024, any
/// case), at least 4 MiB.
pub fn parse_size(s: &str) -> Result<usize, String> {
    let t = s.trim();
    let (digits, mult): (&str, usize) = match t.char_indices().last() {
        Some((i, c)) if c.eq_ignore_ascii_case(&'k') => (&t[..i], 1 << 10),
        Some((i, c)) if c.eq_ignore_ascii_case(&'m') => (&t[..i], 1 << 20),
        Some((i, c)) if c.eq_ignore_ascii_case(&'g') => (&t[..i], 1 << 30),
        _ => (t, 1),
    };
    let n: usize = digits
        .parse()
        .map_err(|_| format!("'{s}' is not a size (try 64M)"))?;
    let bytes = n
        .checked_mul(mult)
        .ok_or_else(|| format!("'{s}' is too large"))?;
    if bytes < 4 << 20 {
        return Err("must be at least 4M".into());
    }
    Ok(bytes)
}

fn conflict(a: &str, b: &str) -> ExitCode {
    eprintln!("overhear: {a} and {b} can not be combined");
    ExitCode::from(1)
}

/// Parses the command line. `Err` carries the exit code to leave with now:
/// 0 for `--help` and `--version`, 1 for mistakes.
pub fn parse_args() -> Result<Args, ExitCode> {
    let args = match Args::try_parse() {
        Ok(a) => a,
        Err(e) => {
            let _ = e.print();
            return Err(match e.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => ExitCode::SUCCESS,
                _ => ExitCode::from(1),
            });
        }
    };
    if args.json && args.tui {
        return Err(conflict("-j", "-t"));
    }
    if args.verbose && args.json {
        return Err(conflict("-v", "-j"));
    }
    if args.verbose && args.tui {
        return Err(conflict("-v", "-t"));
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("64M"), Ok(64 << 20));
        assert_eq!(parse_size("1g"), Ok(1 << 30));
        assert_eq!(parse_size("4096k"), Ok(4 << 20));
        assert_eq!(parse_size("4M"), Ok(4 << 20));
        assert_eq!(parse_size("3M"), Err("must be at least 4M".into()));
        assert_eq!(parse_size("1M"), Err("must be at least 4M".into()));
        assert_eq!(parse_size("10K"), Err("must be at least 4M".into()));
        assert!(parse_size("abc").is_err());
        assert!(parse_size("").is_err());
    }
}
