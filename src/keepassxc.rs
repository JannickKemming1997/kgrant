//! Client for KeePassXC's browser-integration protocol.
//!
//! Talks to a running, unlocked KeePassXC over its native-messaging socket,
//! the same channel browser extensions use. See `docs/design.md`.

mod client;
mod error;
#[cfg(test)]
pub(crate) mod fake;
mod login;
mod socket;
mod wire;

pub use client::{Association, Client};
pub use error::Error;
pub use login::{FIELD_PREFIX, Login};
pub use socket::default_socket_path;
