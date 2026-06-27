//! Launch helpers shared by the two binaries.
//!
//! The project ships two executables that resolve the vault location identically:
//! the console `pass-mgr` (CLI subcommands + the `--tui` terminal UI) and the
//! windowed `pass-mgr-gui` (the graphical UI built as a Windows **GUI-subsystem**
//! app, so it opens *without* a command window). Keeping the path/flag logic here —
//! instead of duplicated in each binary — guarantees `pass-mgr DIR` and
//! `pass-mgr-gui DIR` open the same vault.

use std::path::{Path, PathBuf};

use directories::ProjectDirs;

/// Default vault location: the per-user data directory for this app
/// (`~/.local/share/pass-mgr/` on Linux, `%APPDATA%\pass-mgr\` on Windows).
pub fn default_vault_path() -> PathBuf {
    match ProjectDirs::from("dev", "passmgr", "pass-mgr") {
        Some(dirs) => dirs.data_dir().join("vault.pmv"),
        None => PathBuf::from("vault.pmv"),
    }
}

/// The name of the encrypted vault file inside a vault directory. A directory is
/// treated as a vault iff it directly contains a file with this name.
const VAULT_FILE: &str = "vault.pmv";

/// The vault file inside a user-supplied vault directory.
pub fn vault_file(dir: &str) -> PathBuf {
    PathBuf::from(dir).join(VAULT_FILE)
}

/// The outcome of scanning a root directory for vaults: the discovered vault names
/// plus an optional human-readable `warning` to surface in the UI. The warning is
/// `Some` when the root itself can't be read (the list is then empty) or when some
/// entries beneath it had to be skipped because they were inaccessible.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct VaultScan {
    pub vaults: Vec<String>,
    pub warning: Option<String>,
}

/// The vault directory for a `root` plus a selected/typed leaf `name`. An empty name
/// resolves to the root itself (so a vault sitting directly at the root still opens);
/// otherwise it is `<root>/<name>`. Both sides are trimmed. This is the collapsed start
/// page's single source of truth: the open target is always `root` + `name`.
pub fn join_root_name(root: &str, name: &str) -> String {
    let root = root.trim();
    // Trim only to DECIDE empty-vs-present; when present, join the name VERBATIM so this is
    // the exact inverse of `discover_vaults`, which returns raw directory names. Trimming the
    // joined name would make a vault folder whose name has leading/trailing whitespace
    // un-openable from the dropdown — the derived path wouldn't match the real folder, so the
    // start page would silently flip to "Create" instead of opening the selected vault.
    if name.trim().is_empty() {
        root.to_string()
    } else {
        Path::new(root).join(name).display().to_string()
    }
}

/// Compute the start page's initial `(root, vault_name)` for a launched vault `path`,
/// given the persisted root preference `saved_root` and last-opened vault `saved_vault`
/// ("" if unset).
///
/// An **explicitly launched** vault (a `path` differing from the per-user default) always
/// wins: its parent becomes the root and its folder the selected name, so `pass-mgr DIR`
/// opens exactly `DIR` — the saved last vault is ignored, since the user named a specific
/// target. For a **default** launch, the saved root preference (if any) seeds the root —
/// that is what makes "remember my root across startups" work — and the name is the
/// remembered `saved_vault` (so the last opened vault is pre-selected), falling back to the
/// default vault's folder only when it lives directly under that root, else empty (the user
/// picks from the dropdown). A `saved_vault` that no longer exists under the root simply
/// resolves to "Create" via the caller's `path.exists()` check — harmless, not an error.
pub fn initial_root_and_name(path: &Path, saved_root: &str, saved_vault: &str) -> (String, String) {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir_parent = dir.and_then(|d| d.parent()).filter(|p| !p.as_os_str().is_empty());
    let parent_str = dir_parent.map(|p| p.display().to_string());
    let leaf = dir.and_then(|d| d.file_name()).and_then(|n| n.to_str()).map(str::to_owned);

    let launched_default = path == default_vault_path();
    let saved = saved_root.trim();
    if !launched_default || saved.is_empty() {
        // Honor the launched vault: root = its parent, name = its folder.
        (parent_str.unwrap_or_else(|| ".".into()), leaf.unwrap_or_default())
    } else {
        // Default launch + a saved root: browse that root. Prefer the remembered last vault;
        // otherwise pre-select the default vault's folder when it lives directly under the
        // root. The name is used VERBATIM (matching `discover_vaults`/`join_root_name`), so
        // only the emptiness decision trims.
        let name = if !saved_vault.trim().is_empty() {
            saved_vault.to_string()
        } else {
            match (&parent_str, &leaf) {
                (Some(p), Some(l)) if p == saved => l.clone(),
                _ => String::new(),
            }
        };
        (saved.to_string(), name)
    }
}

/// Discover the vaults directly beneath `root`: every IMMEDIATE subdirectory that
/// contains a `vault.pmv`. Returns the subdirectory NAMES (not full paths), sorted
/// case-insensitively. The scan is one level deep only (never recursive) and never
/// includes `root` itself. This powers the start-page vault dropdown in both front-ends.
///
/// Errors are reported, not hidden. An unreadable root (missing, not a directory, or
/// permission-denied) yields an empty list with an explanatory `warning`. Individual
/// entries that can't be inspected — an unreadable directory entry, a subdirectory
/// whose metadata or vault-marker can't be read — are skipped and tallied into a
/// "N skipped (inaccessible)" warning rather than aborting the whole scan.
pub fn discover_vaults(root: &str) -> VaultScan {
    let root = std::path::Path::new(root.trim());
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) => {
            return VaultScan {
                vaults: Vec::new(),
                warning: Some(format!("Cannot read vault root '{}': {e}", root.display())),
            };
        }
    };
    let mut vaults: Vec<String> = Vec::new();
    let mut skipped: usize = 0;
    for entry in entries {
        // An entry that errors mid-iteration (e.g. a racing unlink, an unreadable
        // name) is skipped, not fatal.
        let Ok(entry) = entry else {
            skipped += 1;
            continue;
        };
        let path = entry.path();
        // `metadata` follows symlinks, so a subdir symlinked to a vault still counts;
        // a permission error reading the metadata means we can't classify it → skip.
        let is_dir = match std::fs::metadata(&path) {
            Ok(m) => m.is_dir(),
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        if !is_dir {
            continue; // a plain file under the root is simply not a vault.
        }
        // `try_exists` distinguishes "no marker" (Ok(false)) from "couldn't check"
        // (Err, e.g. a permission-denied subtree) — the latter is surfaced as skipped
        // rather than silently treated as "not a vault".
        match path.join(VAULT_FILE).try_exists() {
            Ok(true) => {
                if let Some(name) = entry.file_name().to_str() {
                    vaults.push(name.to_owned());
                } else {
                    skipped += 1; // a non-UTF-8 directory name we can't display/select.
                }
            }
            Ok(false) => {}
            Err(_) => skipped += 1,
        }
    }
    // Case-insensitive so the list reads naturally regardless of the OS's raw
    // directory-entry order.
    vaults.sort_by_key(|s| s.to_lowercase());
    let warning = (skipped > 0)
        .then(|| format!("{skipped} item(s) under the root were skipped (inaccessible)."));
    VaultScan { vaults, warning }
}

/// Resolve an interactive launch from the process arguments (everything *after*
/// the program name): the `(vault path, writable)` pair.
///
/// The first non-flag argument is the vault DIRECTORY (its `vault.pmv` is used);
/// if there is none, the per-user default is used. `--write` enables mutations.
/// This is the windowed launcher's whole command line — it has no console, so it
/// deliberately understands only what an interactive launch needs and leaves the
/// CLI subcommands to the console binary.
pub fn resolve_interactive(args: &[String]) -> (PathBuf, bool) {
    let writable = args.iter().any(|a| a == "--write");
    // Treat ONLY the exact known flags as flags — NOT any '-'-prefixed token. A blanket
    // `starts_with('-')` filter silently ignored a vault directory whose name begins with
    // '-' (falling back to the default vault) while the console binary, which strips only the
    // exact `--write`/`--tui` tokens, treated it as the directory — so `pass-mgr DIR` and
    // `pass-mgr-gui DIR` could open DIFFERENT vaults. Matching the exact set keeps both
    // binaries' resolution identical (the module's stated guarantee).
    let path = args
        .iter()
        .find(|a| !matches!(a.as_str(), "--write" | "--tui"))
        .map(|d| vault_file(d))
        .unwrap_or_else(default_vault_path);
    (path, writable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_vault_path_ends_with_vault_pmv() {
        assert!(default_vault_path().ends_with("vault.pmv"));
    }

    #[test]
    fn vault_file_appends_vault_pmv_to_the_dir() {
        assert_eq!(vault_file("/some/dir"), PathBuf::from("/some/dir/vault.pmv"));
    }

    #[test]
    fn resolve_interactive_reads_dir_and_write_flag() {
        // No args → default path, read-only.
        let (p, w) = resolve_interactive(&[]);
        assert!(p.ends_with("vault.pmv"));
        assert!(!w);

        // A positional dir is used; flag order doesn't matter.
        let (p, w) = resolve_interactive(&["--write".into(), "/v".into()]);
        assert_eq!(p, PathBuf::from("/v/vault.pmv"));
        assert!(w);

        // The first NON-flag argument is the directory.
        let (p, w) = resolve_interactive(&["/v".into(), "--write".into()]);
        assert_eq!(p, PathBuf::from("/v/vault.pmv"));
        assert!(w);

        // A directory whose NAME begins with '-' is still recognized (only the exact known
        // flags are treated as flags), so this binary opens the same vault the console
        // binary would — not the silent default.
        let (p, w) = resolve_interactive(&["-weird-dir".into()]);
        assert_eq!(p, PathBuf::from("-weird-dir/vault.pmv"));
        assert!(!w);
    }

    #[test]
    fn join_root_name_combines_or_falls_back_to_root() {
        assert_eq!(join_root_name("/a/b", "vault1"), PathBuf::from("/a/b/vault1").display().to_string());
        // The ROOT is trimmed, but the NAME is joined VERBATIM, so a folder name round-trips
        // through discovery → join (trimming it would make a whitespace-named folder unopenable).
        assert_eq!(join_root_name("  /a/b ", "vault1"), PathBuf::from("/a/b/vault1").display().to_string());
        assert_eq!(join_root_name("/a/b", " vault1 "), PathBuf::from("/a/b/ vault1 ").display().to_string());
        // Empty / all-whitespace name → the root itself (a vault sitting directly at the root).
        assert_eq!(join_root_name("/a/b", ""), "/a/b");
        assert_eq!(join_root_name("/a/b", "   "), "/a/b");
    }

    #[test]
    fn discovered_whitespace_named_vault_round_trips_through_join() {
        // Regression: a vault folder whose name has surrounding whitespace must be OPENABLE
        // from the dropdown — discover_vaults returns the raw name, and join_root_name must
        // produce the path that actually holds its vault.pmv (not a trimmed, non-existent path,
        // which would silently flip the start page to "Create").
        let root = std::env::temp_dir().join(format!("pmv-ws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let weird = " spaced "; // leading + trailing space in the folder name
        std::fs::create_dir_all(root.join(weird)).unwrap();
        std::fs::write(root.join(weird).join(VAULT_FILE), b"x").unwrap();

        let scan = discover_vaults(root.to_str().unwrap());
        assert!(scan.vaults.contains(&weird.to_string()), "whitespace-named vault is discovered: {:?}", scan.vaults);
        let joined = join_root_name(root.to_str().unwrap(), weird);
        assert!(vault_file(&joined).exists(), "join must resolve to the discovered vault's vault.pmv: {joined}");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn initial_root_and_name_honors_explicit_launch_and_saved_root() {
        // An explicit launch (path != default) always wins: parent is the root, folder the name.
        let p = PathBuf::from("/vaults/work/vault.pmv");
        assert_eq!(initial_root_and_name(&p, "", ""), ("/vaults".to_string(), "work".to_string()));
        // ...even when a (different) saved root exists — the explicit arg is not overridden.
        assert_eq!(initial_root_and_name(&p, "/elsewhere", ""), ("/vaults".to_string(), "work".to_string()));
        // ...and even when a saved last-vault exists: an explicit launch ignores it.
        assert_eq!(initial_root_and_name(&p, "/elsewhere", "personal"), ("/vaults".to_string(), "work".to_string()));

        // A DEFAULT launch with a saved root browses that root; the name is empty unless the
        // default vault lives directly under it (and no last-vault is remembered).
        let def = default_vault_path();
        let (root, name) = initial_root_and_name(&def, "/my/vaults", "");
        assert_eq!(root, "/my/vaults");
        assert!(name.is_empty(), "default vault isn't under the saved root → no pre-selection");

        // A default launch with NO saved root falls back to the default's own parent/leaf.
        let (root2, name2) = initial_root_and_name(&def, "", "");
        let def_parent = def.parent().unwrap().parent().unwrap().display().to_string();
        let def_leaf = def.parent().unwrap().file_name().unwrap().to_str().unwrap().to_string();
        assert_eq!(root2, def_parent);
        assert_eq!(name2, def_leaf);
    }

    #[test]
    fn initial_root_and_name_prefers_saved_last_vault_on_default_launch() {
        // A default launch with a saved root AND a remembered last vault pre-selects that
        // vault, so the start page reopens where the user left off.
        let def = default_vault_path();
        let (root, name) = initial_root_and_name(&def, "/my/vaults", "personal");
        assert_eq!(root, "/my/vaults");
        assert_eq!(name, "personal", "remembered last vault is pre-selected");

        // The remembered name is used VERBATIM (it round-trips with `discover_vaults`, which
        // returns raw folder names) — only the emptiness decision trims.
        let (_, spaced) = initial_root_and_name(&def, "/my/vaults", " my vault ");
        assert_eq!(spaced, " my vault ", "name kept verbatim, not trimmed");

        // A whitespace-only last vault counts as unset → no pre-selection.
        let (_, blank) = initial_root_and_name(&def, "/my/vaults", "   ");
        assert!(blank.is_empty(), "whitespace-only last vault → no pre-selection");
    }

    #[test]
    fn discover_vaults_unreadable_root_is_empty_with_warning() {
        // A root that does not exist can't be read → empty list, explanatory warning.
        let scan = discover_vaults("/nonexistent-pass-mgr-root-zzz-9173");
        assert!(scan.vaults.is_empty());
        assert!(scan.warning.is_some(), "missing root should warn");
    }

    #[test]
    fn discover_vaults_finds_only_subdirs_with_a_vault_file() {
        // Build a throwaway root: two vault subdirs, one empty subdir, one loose file.
        let root = std::env::temp_dir().join(format!("pmv-scan-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("Bravo")).unwrap();
        std::fs::create_dir_all(root.join("alpha")).unwrap();
        std::fs::create_dir_all(root.join("not-a-vault")).unwrap();
        std::fs::write(root.join("Bravo").join(VAULT_FILE), b"x").unwrap();
        std::fs::write(root.join("alpha").join(VAULT_FILE), b"x").unwrap();
        std::fs::write(root.join("loose.txt"), b"x").unwrap();

        let scan = discover_vaults(root.to_str().unwrap());
        // Only the two dirs holding a vault.pmv, sorted case-insensitively.
        assert_eq!(scan.vaults, vec!["alpha".to_string(), "Bravo".to_string()]);
        assert!(scan.warning.is_none(), "no inaccessible entries expected: {:?}", scan.warning);

        let _ = std::fs::remove_dir_all(&root);
    }
}
