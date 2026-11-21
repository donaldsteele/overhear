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

mod cursor;
mod ether;
mod mac;
mod problem;

pub use cursor::Cursor;
pub use ether::{EthHeader, EthKind, Vlan, Vlans, ethernet};
pub use mac::Mac;
pub use problem::{Layer, Problem};
