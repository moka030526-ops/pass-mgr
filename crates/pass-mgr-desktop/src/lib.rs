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

/// Format a Summary-tab amount as a grouped, whole-unit currency string, shared by the GUI
/// and TUI so both render identically: `1_234_567.8 -> "$1,234,568"`, `-2500.0 -> "-$2,500"`,
/// `0.0 -> "$0"`. The summary is an approximation, so cents are rounded away for legibility.
pub(crate) fn fmt_money(v: f64) -> String {
    let neg = v < 0.0;
    let digits = (v.abs().round() as u64).to_string();
    let bytes = digits.as_bytes();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3 + 2);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(*b as char);
    }
    if neg {
        format!("-${grouped}")
    } else {
        format!("${grouped}")
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
//
// Vault-root fallback: when a key is absent from the config-dir file, the loaders fall
// back to a `prefs.json` sitting in the open vault's root folder. This lets a
// self-contained / portable vault (see `docs/SELF_CONTAINED_BACKUP.md`) carry its own UI
// defaults so they travel with the vault to a new machine. The fallback is READ-only:
// the config-dir file always wins when it sets a key, and every `save_*` keeps writing
// to the config dir, so a local choice is never silently overridden by the vault. The
// `vault_root` key itself is the one exception — it bootstraps which vault is open, so it
// is read from the config dir alone (a vault can't tell us where to find itself).

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

/// Path to the vault-local `prefs.json` (`<vault_root>/prefs.json`), or `None` when no
/// vault root is known yet (e.g. on the start page before a root is chosen). This file is
/// a read-only fallback that lets a portable vault carry its own UI defaults.
pub(crate) fn vault_prefs_path(vault_root: &str) -> Option<PathBuf> {
    (!vault_root.trim().is_empty()).then(|| Path::new(vault_root).join("prefs.json"))
}

/// Overlay `config` onto `fallback`: every key present in `config` wins, while keys found
/// only in `fallback` survive. Split out from `effective_prefs_obj` so the precedence rule
/// (config-dir beats vault-root) is unit-tested without touching the real config dir.
pub(crate) fn merge_prefs(
    config: serde_json::Map<String, serde_json::Value>,
    fallback: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut obj = fallback;
    for (k, v) in config {
        obj.insert(k, v);
    }
    obj
}

/// The effective prefs object for the given vault root: the config-dir `prefs.json`
/// overlaid (key-by-key) onto the vault-root `prefs.json` fallback. A missing/corrupt file
/// on either side contributes nothing (see `read_prefs_obj`), so the worst case is an empty
/// map and today's built-in defaults.
pub(crate) fn effective_prefs_obj(vault_root: &str) -> serde_json::Map<String, serde_json::Value> {
    effective_prefs_obj_from(prefs_path().as_deref(), vault_root)
}
/// Path-parametrized core of `effective_prefs_obj` (testable without the real config dir).
pub(crate) fn effective_prefs_obj_from(
    config_path: Option<&Path>,
    vault_root: &str,
) -> serde_json::Map<String, serde_json::Value> {
    let config = config_path.map(read_prefs_obj).unwrap_or_default();
    let fallback = vault_prefs_path(vault_root).map(|p| read_prefs_obj(&p)).unwrap_or_default();
    merge_prefs(config, fallback)
}

/// The saved export-destination directory ("" if unset), with the vault-root fallback.
pub(crate) fn load_export_dir(vault_root: &str) -> String {
    effective_prefs_obj(vault_root).get("export_dir").and_then(|v| v.as_str()).unwrap_or("").to_string()
}
/// Single-path read (no fallback) — retained for the prefs round-trip tests.
#[cfg(test)]
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

// --- View defaults: three local UI preferences (NOT vault content) -----------
//
// Each is a bool persisted in the shared `prefs.json` and read at startup by BOTH
// front-ends to seed per-tab view state (so a freshly opened vault honours the
// user's saved defaults). Like every other UI preference here they are settable
// even in a read-only session and follow the export-dir read-modify-write template
// (`as_bool()` / `Value::Bool`, defaulting to `false` = today's behaviour when
// unset). The public `load_*`/`save_*` wrappers short-circuit under `cfg(test)`:
// the loaders are invoked from `App::new`/`GuiApp::new` (which the unit tests
// construct), so a stable `false` keeps those tests hermetic and independent of the
// developer's real `~/.config/pass-mgr/prefs.json`; the path-parametrized
// `_from`/`_to` helpers stay fully exercised by the round-trip tests.

/// "Reveal all passwords by default" — when set, every tab that has passwords opens
/// with its reveal-all toggle ON instead of masked.
pub(crate) fn load_reveal_all_default(vault_root: &str) -> bool {
    if cfg!(test) {
        return false;
    }
    effective_prefs_obj(vault_root).get("reveal_all_default").and_then(|v| v.as_bool()).unwrap_or(false)
}
#[cfg(test)]
pub(crate) fn load_reveal_all_default_from(path: &Path) -> bool {
    read_prefs_obj(path).get("reveal_all_default").and_then(|v| v.as_bool()).unwrap_or(false)
}
/// Persist the "reveal all by default" flag, preserving any other prefs keys.
pub(crate) fn save_reveal_all_default(on: bool) {
    if cfg!(test) {
        return;
    }
    if let Some(path) = prefs_path() {
        save_reveal_all_default_to(&path, on);
    }
}
pub(crate) fn save_reveal_all_default_to(path: &Path, on: bool) {
    let mut obj = read_prefs_obj(path);
    obj.insert("reveal_all_default".into(), serde_json::Value::Bool(on));
    write_prefs_obj(path, &obj);
}

/// "Group assets by default" — when set, the Assets & Liabilities view opens grouped.
pub(crate) fn load_group_assets_default(vault_root: &str) -> bool {
    if cfg!(test) {
        return false;
    }
    effective_prefs_obj(vault_root).get("group_assets_default").and_then(|v| v.as_bool()).unwrap_or(false)
}
#[cfg(test)]
pub(crate) fn load_group_assets_default_from(path: &Path) -> bool {
    read_prefs_obj(path).get("group_assets_default").and_then(|v| v.as_bool()).unwrap_or(false)
}
/// Persist the "group assets by default" flag, preserving any other prefs keys.
pub(crate) fn save_group_assets_default(on: bool) {
    if cfg!(test) {
        return;
    }
    if let Some(path) = prefs_path() {
        save_group_assets_default_to(&path, on);
    }
}
pub(crate) fn save_group_assets_default_to(path: &Path, on: bool) {
    let mut obj = read_prefs_obj(path);
    obj.insert("group_assets_default".into(), serde_json::Value::Bool(on));
    write_prefs_obj(path, &obj);
}

/// "Group accounts by default" — when set, the Accounts view opens grouped.
pub(crate) fn load_group_accounts_default(vault_root: &str) -> bool {
    if cfg!(test) {
        return false;
    }
    effective_prefs_obj(vault_root).get("group_accounts_default").and_then(|v| v.as_bool()).unwrap_or(false)
}
#[cfg(test)]
pub(crate) fn load_group_accounts_default_from(path: &Path) -> bool {
    read_prefs_obj(path).get("group_accounts_default").and_then(|v| v.as_bool()).unwrap_or(false)
}
/// Persist the "group accounts by default" flag, preserving any other prefs keys.
pub(crate) fn save_group_accounts_default(on: bool) {
    if cfg!(test) {
        return;
    }
    if let Some(path) = prefs_path() {
        save_group_accounts_default_to(&path, on);
    }
}
pub(crate) fn save_group_accounts_default_to(path: &Path, on: bool) {
    let mut obj = read_prefs_obj(path);
    obj.insert("group_accounts_default".into(), serde_json::Value::Bool(on));
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
    fn view_default_bool_prefs_round_trip_and_default_false() {
        let dir = tmp_prefs_dir();
        let p = dir.join("prefs.json");
        // Absent file -> false (today's behaviour) for each flag.
        assert!(!load_reveal_all_default_from(&p));
        assert!(!load_group_assets_default_from(&p));
        assert!(!load_group_accounts_default_from(&p));
        // Save true, then load round-trips for each.
        save_reveal_all_default_to(&p, true);
        save_group_assets_default_to(&p, true);
        save_group_accounts_default_to(&p, true);
        assert!(load_reveal_all_default_from(&p));
        assert!(load_group_assets_default_from(&p));
        assert!(load_group_accounts_default_from(&p));
        // Toggling back to false is preserved as false.
        save_reveal_all_default_to(&p, false);
        save_group_assets_default_to(&p, false);
        save_group_accounts_default_to(&p, false);
        assert!(!load_reveal_all_default_from(&p));
        assert!(!load_group_assets_default_from(&p));
        assert!(!load_group_accounts_default_from(&p));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn view_default_bool_prefs_coexist_with_other_keys() {
        // Each flag's read-modify-write must not clobber co-resident keys (theme,
        // export dir, vault root, or the sibling bool flags).
        let dir = tmp_prefs_dir();
        let p = dir.join("prefs.json");
        std::fs::write(&p, br#"{"theme":"solarized"}"#).unwrap();
        save_export_dir_to(&p, "/exports");
        save_vault_root_to(&p, "/vaults");
        save_reveal_all_default_to(&p, true);
        save_group_assets_default_to(&p, true);
        save_group_accounts_default_to(&p, true);
        let obj = read_prefs_obj(&p);
        assert_eq!(obj.get("theme").and_then(|v| v.as_str()), Some("solarized"), "theme preserved");
        assert_eq!(obj.get("export_dir").and_then(|v| v.as_str()), Some("/exports"), "export_dir preserved");
        assert_eq!(obj.get("vault_root").and_then(|v| v.as_str()), Some("/vaults"), "vault_root preserved");
        assert_eq!(obj.get("reveal_all_default").and_then(|v| v.as_bool()), Some(true), "reveal_all_default written");
        assert_eq!(obj.get("group_assets_default").and_then(|v| v.as_bool()), Some(true), "group_assets_default written");
        assert_eq!(obj.get("group_accounts_default").and_then(|v| v.as_bool()), Some(true), "group_accounts_default written");
        // A non-bool value for a flag key falls back to false rather than panicking.
        std::fs::write(&p, br#"{"reveal_all_default":"yes"}"#).unwrap();
        assert!(!load_reveal_all_default_from(&p), "non-bool value falls back to false");
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
    fn merge_prefs_config_wins_key_by_key() {
        // Config-dir keys override the vault-root fallback; fallback-only keys survive.
        let mut config = serde_json::Map::new();
        config.insert("export_dir".into(), serde_json::Value::String("/config".into()));
        let mut fallback = serde_json::Map::new();
        fallback.insert("export_dir".into(), serde_json::Value::String("/vault".into()));
        fallback.insert("reveal_all_default".into(), serde_json::Value::Bool(true));
        let merged = merge_prefs(config, fallback);
        assert_eq!(merged.get("export_dir").and_then(|v| v.as_str()), Some("/config"), "config wins on shared key");
        assert_eq!(merged.get("reveal_all_default").and_then(|v| v.as_bool()), Some(true), "fallback-only key survives");
    }

    #[test]
    fn vault_root_prefs_json_is_a_read_fallback() {
        // A `prefs.json` in the vault root seeds keys the config-dir file leaves unset, but
        // never overrides a key the config-dir file does set.
        let dir = tmp_prefs_dir();
        let config = dir.join("config-prefs.json");
        let vault_root = dir.join("vault");
        std::fs::create_dir_all(&vault_root).unwrap();
        let vault_prefs = vault_root.join("prefs.json");
        let vroot = vault_root.to_str().unwrap();

        // Vault carries its own defaults; config dir is absent entirely.
        std::fs::write(&vault_prefs, br#"{"export_dir":"/from/vault","reveal_all_default":true}"#).unwrap();
        let eff = effective_prefs_obj_from(Some(&config), vroot);
        assert_eq!(eff.get("export_dir").and_then(|v| v.as_str()), Some("/from/vault"), "vault seeds export_dir");
        assert_eq!(eff.get("reveal_all_default").and_then(|v| v.as_bool()), Some(true), "vault seeds a bool flag");

        // Now the config dir sets export_dir: it wins; the vault still seeds the unset bool.
        std::fs::write(&config, br#"{"export_dir":"/from/config"}"#).unwrap();
        let eff = effective_prefs_obj_from(Some(&config), vroot);
        assert_eq!(eff.get("export_dir").and_then(|v| v.as_str()), Some("/from/config"), "config-dir export_dir wins");
        assert_eq!(eff.get("reveal_all_default").and_then(|v| v.as_bool()), Some(true), "vault flag still seeds when config unset");

        // An empty vault root disables the fallback (start page, before a root is chosen).
        assert!(vault_prefs_path("").is_none(), "no vault-root path without a root");
        assert!(vault_prefs_path("   ").is_none(), "whitespace-only root is treated as unset");
        let eff = effective_prefs_obj_from(Some(&config), "");
        assert_eq!(eff.get("reveal_all_default"), None, "no fallback contribution without a vault root");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fmt_money_groups_thousands_and_signs() {
        assert_eq!(fmt_money(0.0), "$0");
        assert_eq!(fmt_money(1500.0), "$1,500");
        assert_eq!(fmt_money(1_234_567.8), "$1,234,568"); // rounds, groups
        assert_eq!(fmt_money(-2500.0), "-$2,500");
        assert_eq!(fmt_money(999.0), "$999");
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
