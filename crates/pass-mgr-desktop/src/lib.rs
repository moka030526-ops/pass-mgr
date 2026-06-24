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
pub use pass_mgr_core::{crypto, fault, merge, password, records, storage, types, vault};

#[cfg(feature = "gui")]
pub mod gui; // graphical front-end (drives the same vault API as `ui`); behind `gui`
pub mod launch; // vault-path/flag resolution shared by the console + windowed binaries
#[cfg(feature = "gui")]
pub mod single_instance; // GUI single-instance guard (raises the egui window); behind `gui`
pub mod ui; // text/terminal front-end (interchangeable with `gui`)

/// Copy a SECRET (a password) into the OS clipboard, flagging it so clipboard
/// managers don't retain it. On Linux, arboard's `exclude_from_history` sets the
/// `x-kde-passwordManagerHint` (honoured over X11 — including XWayland — by
/// klipper/GPaste/clipman), so the password isn't logged into a manager's
/// persistent history; the GUI/TUI 15 s + on-exit clears only overwrite the live
/// selection, not such a log. On other platforms this is a plain set. Shared by the
/// GUI and TUI so both copy paths get the hint. (A clipboard manager that ignores
/// the hint, or a native-Wayland-only setup, may still retain history.)
///
/// Behind the `clipboard` feature: on Linux arboard dynamically loads X11/Wayland, so a
/// fully-static (musl) terminal build omits it (the TUI's copy then becomes a no-op).
#[cfg(feature = "clipboard")]
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

/// Pure decision for the clipboard auto-clear "tick", shared by the TUI (`ui.rs`) and
/// GUI (`gui.rs`) so both obey the SAME security-relevant contract. Given the pending
/// wipe `deadline` (if any), the current time `now`, and the current `status` line:
///   * `None` — nothing scheduled, or the deadline has not been reached: do nothing.
///   * `Some(None)` — wipe the clipboard now, but LEAVE the status untouched (it shows a
///     message the user may not have seen yet, e.g. `"Save failed: …"`).
///   * `Some(Some(s))` — wipe the clipboard now and set the status to `s`.
///
/// Kept side-effect-free (no clipboard or egui access) so the two rules a password
/// manager must not get wrong — fire only at/after the deadline, and never clobber an
/// unseen status, only a blank or a prior `"Copied …"` notice — are unit-testable.
pub(crate) fn clipboard_tick_decision(
    deadline: Option<std::time::Instant>,
    now: std::time::Instant,
    status: &str,
) -> Option<Option<String>> {
    match deadline {
        Some(t) if now >= t => {
            if status.is_empty() || status.starts_with("Copied") {
                Some(Some("Clipboard cleared.".to_string()))
            } else {
                Some(None) // keep the existing (possibly unseen) status
            }
        }
        _ => None,
    }
}

// --- Local, non-secret preferences (shared by the GUI and TUI) ---------------
//
// A tiny `prefs.json` in the OS config dir holds UI preferences that are NOT vault
// content — the GUI color theme and the document **export directory**. Keeping the
// export directory here (rather than in the encrypted vault) is deliberate: it is a
// local-machine preference, so it can be changed even in a READ-ONLY session, which
// is what lets a read-only user (an heir) set where to extract documents. Both
// front-ends read/write the same file through these helpers, and every write is a
// read-modify-write so the theme and export-dir keys never clobber each other.

use std::path::{Path, PathBuf};

/// Hard cap on the prefs file size. It holds one short JSON object, so a larger file
/// is corrupt or hostile; bounding the read before allocating means a huge or
/// symlinked `prefs.json` can never stall or OOM the UI at startup.
pub(crate) const MAX_PREFS_SIZE: u64 = 64 * 1024;

/// Standard preferences path (`<config dir>/pass-mgr/prefs.json`), or `None` if the
/// platform has no config dir.
pub(crate) fn prefs_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("dev", "passmgr", "pass-mgr").map(|d| d.config_dir().join("prefs.json"))
}

/// Bounded, symlink-safe read of the prefs JSON object (empty map on any failure), so
/// a setter can read-modify-write without clobbering other keys. `symlink_metadata`
/// doesn't follow links — a symlinked prefs file fails `is_file()` — and the size
/// check rejects an oversized file before reading.
pub(crate) fn read_prefs_obj(path: &Path) -> serde_json::Map<String, serde_json::Value> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && m.len() <= MAX_PREFS_SIZE => {}
        _ => return serde_json::Map::new(),
    }
    let Ok(bytes) = std::fs::read(path) else { return serde_json::Map::new() };
    serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&bytes).unwrap_or_default()
}

/// Best-effort write of the prefs object (a write failure is ignored — prefs are
/// non-critical and trivially re-picked).
pub(crate) fn write_prefs_obj(path: &Path, obj: &serde_json::Map<String, serde_json::Value>) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec_pretty(obj) {
        let _ = std::fs::write(path, bytes);
    }
}

/// The saved export-destination directory ("" if unset).
pub(crate) fn load_export_dir() -> String {
    prefs_path().map(|p| load_export_dir_from(&p)).unwrap_or_default()
}
pub(crate) fn load_export_dir_from(path: &Path) -> String {
    read_prefs_obj(path).get("export_dir").and_then(|v| v.as_str()).unwrap_or("").to_string()
}
/// Persist the export-destination directory, preserving any other prefs keys (theme).
pub(crate) fn save_export_dir(dir: &str) {
    if let Some(path) = prefs_path() {
        save_export_dir_to(&path, dir);
    }
}
pub(crate) fn save_export_dir_to(path: &Path, dir: &str) {
    let mut obj = read_prefs_obj(path);
    obj.insert("export_dir".into(), serde_json::Value::String(dir.to_string()));
    write_prefs_obj(path, &obj);
}

/// The saved **vault root** — the folder the start page scans for vaults ("" if unset).
/// Like the export dir, this is a local-machine UI preference (NOT vault content), so it
/// persists across sessions and is settable even in a read-only session.
pub(crate) fn load_vault_root() -> String {
    prefs_path().map(|p| load_vault_root_from(&p)).unwrap_or_default()
}
pub(crate) fn load_vault_root_from(path: &Path) -> String {
    read_prefs_obj(path).get("vault_root").and_then(|v| v.as_str()).unwrap_or("").to_string()
}
/// Persist the vault root, preserving any other prefs keys (theme, export dir).
pub(crate) fn save_vault_root(dir: &str) {
    // This is reached from the unlock/create flow, which the front-end unit tests drive
    // directly; skip the real-prefs write under `cfg(test)` so the suite never clobbers the
    // developer's `~/.config/pass-mgr/prefs.json`. The write logic itself stays covered via
    // the path-parametrized `save_vault_root_to` (see the `vault_root_round_trips` test).
    if cfg!(test) {
        return;
    }
    if let Some(path) = prefs_path() {
        save_vault_root_to(&path, dir);
    }
}
pub(crate) fn save_vault_root_to(path: &Path, dir: &str) {
    let mut obj = read_prefs_obj(path);
    obj.insert("vault_root".into(), serde_json::Value::String(dir.to_string()));
    write_prefs_obj(path, &obj);
}

#[cfg(test)]
mod tests {
    use super::*;

    // Hermetic prefs round-trip via the path-parametrized helpers (never touches the
    // real `~/.config` prefs). Uses a nanosecond-tagged temp dir for isolation.
    fn tmp_prefs_dir() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("pmprefs-export-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn export_dir_round_trips_and_defaults_empty() {
        let dir = tmp_prefs_dir();
        let p = dir.join("prefs.json");
        // Absent file -> empty string (unset).
        assert_eq!(load_export_dir_from(&p), "");
        // Save then load round-trips.
        save_export_dir_to(&p, "/srv/exports");
        assert_eq!(load_export_dir_from(&p), "/srv/exports");
        // Re-saving overwrites the value.
        save_export_dir_to(&p, "/other");
        assert_eq!(load_export_dir_from(&p), "/other");
        // Clearing it (empty string) is preserved as empty.
        save_export_dir_to(&p, "");
        assert_eq!(load_export_dir_from(&p), "");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_dir_save_preserves_other_prefs_keys() {
        // The read-modify-write must not clobber a co-resident key (e.g. the GUI theme).
        let dir = tmp_prefs_dir();
        let p = dir.join("prefs.json");
        std::fs::write(&p, br#"{"theme":"solarized"}"#).unwrap();
        save_export_dir_to(&p, "/exports");
        let obj = read_prefs_obj(&p);
        assert_eq!(obj.get("theme").and_then(|v| v.as_str()), Some("solarized"), "theme key preserved");
        assert_eq!(obj.get("export_dir").and_then(|v| v.as_str()), Some("/exports"), "export_dir written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vault_root_round_trips_and_coexists_with_other_keys() {
        let dir = tmp_prefs_dir();
        let p = dir.join("prefs.json");
        // Absent -> empty (unset), so the front-end falls back to its launch default.
        assert_eq!(load_vault_root_from(&p), "");
        // Round-trips, and the read-modify-write preserves a co-resident export dir.
        save_export_dir_to(&p, "/exports");
        save_vault_root_to(&p, "/vaults");
        assert_eq!(load_vault_root_from(&p), "/vaults");
        assert_eq!(load_export_dir_from(&p), "/exports", "export_dir preserved");
        save_vault_root_to(&p, "/other-vaults");
        assert_eq!(load_vault_root_from(&p), "/other-vaults");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_prefs_obj_is_bounded_and_symlink_safe() {
        let dir = tmp_prefs_dir();
        let p = dir.join("prefs.json");
        // Over-cap file is rejected before the body is parsed (DoS guard) -> empty map.
        std::fs::write(&p, vec![b'{'; (MAX_PREFS_SIZE as usize) + 1]).unwrap();
        assert!(read_prefs_obj(&p).is_empty(), "over-cap prefs rejected");
        // A symlinked prefs file is refused even if its target is valid.
        #[cfg(unix)]
        {
            let real = dir.join("real.json");
            std::fs::write(&real, br#"{"export_dir":"/x"}"#).unwrap();
            let link = dir.join("link.json");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(read_prefs_obj(&link).is_empty(), "symlinked prefs refused");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clipboard_tick_decision_obeys_deadline_and_preserves_unseen_status() {
        use std::time::{Duration, Instant};
        let now = Instant::now();
        let future = now + Duration::from_secs(60);
        // Nothing scheduled, or deadline not reached → no action.
        assert_eq!(clipboard_tick_decision(None, now, ""), None);
        assert_eq!(clipboard_tick_decision(Some(future), now, "anything"), None);
        // Deadline reached + a blank or "Copied …" status → wipe and show the cleared notice.
        assert_eq!(
            clipboard_tick_decision(Some(now), now, ""),
            Some(Some("Clipboard cleared.".to_string()))
        );
        assert_eq!(
            clipboard_tick_decision(Some(now), now, "Copied password to clipboard."),
            Some(Some("Clipboard cleared.".to_string()))
        );
        // Deadline reached but an important status is showing → wipe, but DON'T clobber it
        // (the core rule: a "Save failed: …" the user hasn't seen must survive the auto-clear).
        assert_eq!(clipboard_tick_decision(Some(now), now, "Save failed: disk full"), Some(None));
    }
}
