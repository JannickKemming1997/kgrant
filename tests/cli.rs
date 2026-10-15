//! Whole commands, run through [`kgrant::run`] with fixed secrets.

use std::process::ExitCode;

use kgrant::StaticSecrets;

fn run(args: &[&str], secrets: &StaticSecrets) -> ExitCode {
    kgrant::run(
        std::iter::once("kgrant").chain(args.iter().copied()),
        secrets,
    )
}

#[test]
fn help_and_version_succeed() {
    let secrets = StaticSecrets::default();
    assert_eq!(run(&["--help"], &secrets), ExitCode::SUCCESS);
    assert_eq!(run(&["--version"], &secrets), ExitCode::SUCCESS);
    assert_eq!(run(&["get", "--help"], &secrets), ExitCode::SUCCESS);
}

#[test]
fn get_reads_through_the_secrets_it_is_given() {
    let secrets = StaticSecrets::new([
        ("multi-field", "token", "value"),
        ("multi-field", "user", "u"),
    ]);
    assert_eq!(
        run(&["get", "Multi-Field", "token"], &secrets),
        ExitCode::SUCCESS
    );
    assert_eq!(
        run(&["get", "Multi Field", "token", "user", "--json"], &secrets),
        ExitCode::SUCCESS
    );
    // Several fields need --json, an unknown field or entry fails.
    for args in [
        &["get", "Multi-Field", "token", "user"][..],
        &["get", "Multi-Field", "unknown"],
        &["get", "Unknown", "token"],
    ] {
        assert_eq!(run(args, &secrets), ExitCode::FAILURE, "{args:?}");
    }
    // An entry and a field are both needed.
    assert_eq!(run(&["get", "Multi-Field"], &secrets), ExitCode::from(2));
}
