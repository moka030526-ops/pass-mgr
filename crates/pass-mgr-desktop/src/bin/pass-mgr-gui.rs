//! Windowed launcher for the graphical UI.
//!
//! This is the same as `pass-mgr [DIR] [--write]`, but built as a Windows
//! **GUI-subsystem** executable. A normal Rust binary uses the *console* subsystem,
//! so when Windows launches it from Explorer or a shortcut it first allocates a
//! command window and *then* the GUI opens on top — the "two windows" you'd
//! otherwise see. Marking this binary `windows_subsystem = "windows"` tells the
//! linker it is a GUI app, so no console window is ever created.
//!
//! The console `pass-mgr` binary is unchanged and remains the home for the CLI
//! subcommands and the `--tui` terminal UI — those genuinely need a console, which
//! is exactly what a GUI-subsystem app does not have. (Mirrors the classic
//! `python.exe` vs `pythonw.exe` split.) The attribute is inert on non-Windows
//! targets, so this binary is just "the GUI" everywhere else.

#![cfg_attr(windows, windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    // Everything after the program name. The windowed launcher only understands an
    // interactive launch (optional vault DIR + `--write`); CLI subcommands belong to
    // the console binary, which can actually show their output.
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Reject a malformed command line (e.g. more than one vault DIR) before opening a window.
    let (path, writable) = match pass_mgr::launch::resolve_interactive(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("pass-mgr error: {e}");
            return ExitCode::FAILURE;
        }
    };

    match pass_mgr::gui::run(path, writable) {
        Ok(()) => ExitCode::SUCCESS,
        // No console is attached under the Windows GUI subsystem, so this `eprintln`
        // is a no-op there; it still surfaces a fatal launch error on other
        // platforms (and the GUI handles ordinary errors — bad password, locked
        // vault — inside its own window, not via this path).
        Err(e) => {
            eprintln!("pass-mgr error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
