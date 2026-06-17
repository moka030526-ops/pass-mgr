//! Launch helpers shared by the two binaries.
//!
//! The project ships two executables that resolve the vault location identically:
//! the console `pass-mgr` (CLI subcommands + the `--tui` terminal UI) and the
//! windowed `pass-mgr-gui` (the graphical UI built as a Windows **GUI-subsystem**
//! app, so it opens *without* a command window). Keeping the path/flag logic here —
//! instead of duplicated in each binary — guarantees `pass-mgr DIR` and
//! `pass-mgr-gui DIR` open the same vault.

use std::path::PathBuf;

use directories::ProjectDirs;

/// Default vault location: the per-user data directory for this app
/// (`~/.local/share/pass-mgr/` on Linux, `%APPDATA%\pass-mgr\` on Windows).
pub fn default_vault_path() -> PathBuf {
    match ProjectDirs::from("dev", "passmgr", "pass-mgr") {
        Some(dirs) => dirs.data_dir().join("vault.pmv"),
        None => PathBuf::from("vault.pmv"),
    }
}

/// The vault file inside a user-supplied vault directory.
pub fn vault_file(dir: &str) -> PathBuf {
    PathBuf::from(dir).join("vault.pmv")
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
    let path = args
        .iter()
        .find(|a| !a.starts_with('-'))
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
    }
}
