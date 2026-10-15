//! Shell completion, through the real binary: answering `COMPLETE=<shell>`
//! exits the process, so it cannot be called in the test process.

use std::process::Command;

/// Runs `kgrant` with `COMPLETE=fish` and these arguments, and returns what it
/// prints to stdout.
fn complete(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_kgrant"))
        .env("COMPLETE", "fish")
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn the_script_registers_completion_for_kgrant() {
    let script = complete(&[]);
    assert!(script.starts_with("complete "), "{script}");
    assert!(script.contains("--command kgrant"), "{script}");
}

#[test]
fn subcommands_are_completed() {
    let candidates = complete(&["--", "kgrant", ""]);
    assert!(candidates.contains("get\t"), "{candidates}");
    assert!(candidates.contains("pair\t"), "{candidates}");
}

#[test]
fn options_of_a_subcommand_are_completed() {
    let candidates = complete(&["--", "kgrant", "get", "--"]);
    assert!(candidates.contains("--json"), "{candidates}");
}
