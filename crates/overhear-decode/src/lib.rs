#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unreachable,
    clippy::todo,
    clippy::arithmetic_side_effects
)]

//! Pure, never-panic packet decoders.

mod arp;
mod cursor;
mod dhcp;
pub mod dhcp_opts;
mod ether;
mod ip;
mod mac;
mod packet;
mod problem;

pub use arp::{Arp, ArpKind, parse as parse_arp};
pub use cursor::Cursor;
pub use dhcp::{Dhcp, DhcpOption, OptSource, parse as parse_dhcp};
pub use ether::{EthHeader, EthKind, Vlan, Vlans, ethernet};
pub use ip::{Frag, IpHeader, Ipv4Header, Ipv6Header};
pub use mac::Mac;
pub use packet::{Decoded, L4, Packet, Proto, UdpHeader, decode};
pub use problem::{Layer, Problem};
