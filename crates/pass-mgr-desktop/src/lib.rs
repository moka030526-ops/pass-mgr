//! pass-mgr (desktop) — the command-line, terminal (ratatui) and graphical
//! (egui) front-ends for the offline, two-password encrypted **estate vault**.
//!
//! All of the vault logic — data model, file format, crypto, and the
//! [`vault::OpenVault`] API — lives in the headless [`pass_mgr_core`] crate.
//! This crate is the desktop *shell* on top of it: the two binaries
//! (`pass-mgr`, the console build, and `pass-mgr-gui`, the Windows
//! GUI-subsystem build) plus the interchangeable [`gui`] and [`ui`] front-ends.
//!
//! The core modules are re-exported here so the binaries' `pass_mgr::<mod>`
//! import paths and the front-ends' in-crate `crate::<mod>` paths keep
//! resolving unchanged after the workspace split.
//!
//! (`//!` is an inner doc comment for the whole crate; `///` documents the item
//! that follows; `//` is an ordinary comment.)
#![forbid(unsafe_code)]

// Re-export the headless core so existing `pass_mgr::crypto`, `pass_mgr::vault`,
// `crate::records`, … paths in the binaries and front-ends resolve unchanged.
pub use pass_mgr_core::{crypto, fault, password, records, storage, types, vault};

pub mod gui; // graphical front-end (drives the same vault API as `ui`)
pub mod launch; // vault-path/flag resolution shared by the console + windowed binaries
pub mod single_instance; // GUI single-instance guard (coalesces repeated launches)
pub mod ui; // text/terminal front-end (interchangeable with `gui`)

/// Copy a SECRET (a password) into the OS clipboard, flagging it so clipboard
/// managers don't retain it. On Linux, arboard's `exclude_from_history` sets the
/// `x-kde-passwordManagerHint` (honoured over X11 — including XWayland — by
/// klipper/GPaste/clipman), so the password isn't logged into a manager's
/// persistent history; the GUI/TUI 15 s + on-exit clears only overwrite the live
/// selection, not such a log. On other platforms this is a plain set. Shared by the
/// GUI and TUI so both copy paths get the hint. (A clipboard manager that ignores
/// the hint, or a native-Wayland-only setup, may still retain history.)
pub(crate) fn copy_secret_to_clipboard(text: &str) -> Result<(), arboard::Error> {
    let mut cb = arboard::Clipboard::new()?;
    #[cfg(target_os = "linux")]
    {
        use arboard::SetExtLinux;
        cb.set().exclude_from_history().text(text.to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        cb.set_text(text.to_owned())
    }
}
