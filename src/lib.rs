//! `kgrant`: read secrets from a running KeePassXC, with the approval of the
//! user in KeePassXC.
//!
//! The binary (`main.rs`) is only the composition root: it picks the real
//! source of secrets ([`KeePassXc`]) and calls [`run`]. Everything else lives
//! here, so that tests can call [`run`] with a [`StaticSecrets`]. Code that
//! needs secrets takes a [`Secrets`] and does not know where they come from.

#![deny(missing_docs)]

mod cli;
mod keepassxc;
mod secret;
mod secrets;
mod store;

pub use cli::run;
pub use secret::{Secret, SecretError, entry_slug};
pub use secrets::{KeePassXc, Secrets, StaticSecrets};

/// `Box<dyn Error>` can hold any error type. A `String` or `&str` converts
/// into one with `.into()`, and `?` converts any real error automatically.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
