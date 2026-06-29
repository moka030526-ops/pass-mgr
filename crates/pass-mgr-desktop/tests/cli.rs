//! CLI surface regression tests.
//!
//! The arg-parser helpers are unit-tested, but nothing runs the real binary for
//! `--help` or a malformed invocation, so `main()`'s dispatch glue (mapping a
//! command + arity to a usage error) and the `ExitCode::FAILURE` path are never
//! exercised. These spawn the actual `pass-mgr` binary and pin the help output,
//! the usage strings, and the exit codes — a cheap guard against a UX/exit-code
//! regression. They need no display (every case returns before launching the UI).

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pass-mgr")
}

#[test]
fn help_lists_every_subcommand_and_exits_zero() {
    let out = Command::new(bin()).arg("--help").output().expect("run --help");
    assert!(out.status.success(), "--help must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("USAGE:"), "help has a USAGE section");
    for sub in [
        "decrypt",
        "manifest",
        "extract",
        "backup",
        "export-tree",
        "import-tree",
        "update-from",
        "compact",
        "migrate-doc-paths",
        "--write",
        "--tui",
    ] {
        assert!(stdout.contains(sub), "help should mention `{sub}`");
    }
}

#[test]
fn too_many_positionals_is_a_usage_error_with_nonzero_exit() {
    let out = Command::new(bin()).args(["decrypt", "A", "B", "C"]).output().expect("run decrypt");
    assert!(!out.status.success(), "a malformed invocation exits non-zero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage: pass-mgr decrypt [DIR]"), "got stderr: {stderr}");
}

#[test]
fn missing_required_output_dir_is_a_usage_error() {
    // `extract` requires an OUTPUT_DIR; with only the subcommand the arity is wrong.
    let out = Command::new(bin()).arg("extract").output().expect("run extract");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("usage: pass-mgr extract [DIR] <OUTPUT_DIR>"),
        "got stderr: {stderr}"
    );
}

#[test]
fn part_flag_on_a_command_that_rejects_it_errors() {
    let out = Command::new(bin()).args(["--part", "2", "decrypt"]).output().expect("run");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--part only applies to 'manifest' and 'extract'"),
        "got stderr: {stderr}"
    );
}
