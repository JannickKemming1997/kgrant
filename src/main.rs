//! The composition root of `kgrant`: the only place that chooses the real
//! source of secrets. See `lib.rs`.

use std::process::ExitCode;

use kgrant::KeePassXc;

fn main() -> ExitCode {
    kgrant::run(std::env::args_os(), &KeePassXc)
}
