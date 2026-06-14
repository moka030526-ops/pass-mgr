//! pass-mgr — a standalone, offline, two-password encrypted password manager.
//!
//! `main` handles command-line dispatch, chooses the vault file path, and sets
//! up / tears down the terminal. All UI logic lives in [`ui`]; all crypto in
//! [`crypto`]; the data model and file format in [`vault`]; password generation
//! in [`password`].
//!
//! Usage:
//! ```text
//!   pass-mgr [VAULT]              launch the graphical UI (default vault if omitted)
//!   pass-mgr --tui [VAULT]        launch the terminal UI instead
//!   pass-mgr decrypt [VAULT]      decrypt the vault and print its JSON to stdout
//!   pass-mgr extract [VAULT] DIR  decrypt all documents into DIR
//!   pass-mgr --help               show this help
//! ```

mod crypto;
mod gui;
mod password;
mod records;
mod types;
mod ui;
mod vault;

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use directories::ProjectDirs;
use zeroize::{Zeroize, Zeroizing};

use crate::vault::OpenVault;

/// Default vault location: the per-user data directory for this app
/// (`~/.local/share/pass-mgr/` on Linux, `%APPDATA%\pass-mgr\` on Windows).
fn default_vault_path() -> PathBuf {
    match ProjectDirs::from("dev", "passmgr", "pass-mgr") {
        Some(dirs) => dirs.data_dir().join("vault.pmv"),
        None => PathBuf::from("vault.pmv"),
    }
}

const HELP: &str = "\
pass-mgr — standalone, offline, two-password encrypted password manager

USAGE:
    pass-mgr [VAULT]              Launch the graphical UI (default vault if omitted)
    pass-mgr --tui [VAULT]        Launch the terminal UI instead
    pass-mgr decrypt [VAULT]      Decrypt the vault and print its JSON to stdout
    pass-mgr extract [VAULT] DIR  Decrypt all stored documents into DIR
    pass-mgr --help               Show this help

The vault is protected by two passwords entered in sequence.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let result = match args.first().map(String::as_str) {
        Some("--help" | "-h") => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Some("decrypt" | "export") => {
            let path = args.get(1).map(PathBuf::from).unwrap_or_else(default_vault_path);
            cli_decrypt(path)
        }
        // `extract [VAULT] DIR` — the output directory is always the LAST argument.
        Some("extract") => match args.len() {
            2 => cli_extract(default_vault_path(), PathBuf::from(&args[1])),
            3 => cli_extract(PathBuf::from(&args[1]), PathBuf::from(&args[2])),
            _ => Err(anyhow::anyhow!("usage: pass-mgr extract [VAULT] <OUTPUT_DIR>")),
        },
        Some("--tui") => {
            let path = args.get(1).map(PathBuf::from).unwrap_or_else(default_vault_path);
            run_ui(path, types::TypeLists::load())
        }
        // Otherwise the (optional) first argument is the vault path for the GUI.
        _ => {
            let path = args.first().map(PathBuf::from).unwrap_or_else(default_vault_path);
            gui::run(path, types::TypeLists::load())
        }
    };

    if let Err(e) = result {
        eprintln!("pass-mgr error: {e:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run_ui(path: PathBuf, types: types::TypeLists) -> anyhow::Result<()> {
    // `ratatui::init` enters the alternate screen + raw mode and installs a
    // panic hook that restores the terminal before printing the panic, so a
    // crash never leaves the user's terminal in a broken state.
    let mut terminal = ratatui::init();
    let result = ui::run(&mut terminal, path, types);
    ratatui::restore();
    result
}

/// Decrypt the vault and print its full JSON (including all passwords) to
/// stdout. Prompts for both passwords on stderr. WARNING: this writes every
/// stored secret to your terminal in plaintext — see `docs/DESIGN.md` §9.10.
fn cli_decrypt(path: PathBuf) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("no vault found at {}", path.display());
    }
    eprintln!("Decrypting {} — this prints all secrets in plaintext.", path.display());
    let pw1 = read_password("Password 1: ")?;
    let pw2 = read_password("Password 2: ")?;

    let vault = OpenVault::export(&path, pw1.as_bytes(), pw2.as_bytes())?;
    // Zeroizing so the (secret-bearing) serialized JSON is wiped after printing.
    let json = Zeroizing::new(serde_json::to_string_pretty(&vault)?);
    println!("{}", json.as_str());
    Ok(())
}

/// Decrypt the whole document archive and write every stored document into
/// `out_dir`, reconstructing the virtual directory tree. Prompts for both
/// passwords. WARNING: this writes unencrypted copies of all documents to disk.
fn cli_extract(path: PathBuf, out_dir: PathBuf) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("no vault found at {}", path.display());
    }
    eprintln!(
        "Extracting documents from {} into {} — these are UNENCRYPTED copies.",
        path.display(),
        out_dir.display()
    );
    let pw1 = read_password("Password 1: ")?;
    let pw2 = read_password("Password 2: ")?;

    let docs = OpenVault::export_documents(&path, pw1.as_bytes(), pw2.as_bytes())?;
    if docs.is_empty() {
        eprintln!("No documents stored in this vault.");
        return Ok(());
    }

    std::fs::create_dir_all(&out_dir)?;
    let mut written = 0usize;
    for (meta, bytes) in &docs {
        // Build a SAFE relative path from the (decrypted) location/filename so a
        // crafted manifest can never escape out_dir (no `..`, no absolute paths).
        let rel = safe_relative_path(&meta.location, &meta.filename, &meta.id);
        let dest = unique_path(out_dir.join(rel));
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, bytes)?;
        harden_path(&dest); // owner-only on unix (no-op elsewhere)
        eprintln!("  {}", dest.display());
        written += 1;
    }
    eprintln!("Extracted {written} document(s) to {}", out_dir.display());
    Ok(())
}

/// Build a safe RELATIVE path under the output directory from an attacker-
/// influenced virtual `location` + `filename`. Splits on both `/` and `\`, drops
/// empty / `.` / `..` / drive-letter components, so the result can never escape
/// the output directory. Falls back to the document id if no usable name remains.
fn safe_relative_path(location: &str, filename: &str, id: &str) -> PathBuf {
    fn clean(part: &str) -> Option<String> {
        let p = part.trim();
        if p.is_empty() || p == "." || p == ".." {
            return None;
        }
        // Reject anything that still looks like a separator, drive, or NUL.
        if p.contains(['/', '\\', ':', '\0']) {
            return None;
        }
        Some(p.to_string())
    }
    let mut path = PathBuf::new();
    for part in location.split(['/', '\\']) {
        if let Some(c) = clean(part) {
            path.push(c);
        }
    }
    match filename.split(['/', '\\']).filter_map(clean).next_back() {
        Some(name) => path.push(name),
        None => path.push(format!("{id}.bin")),
    }
    path
}

/// Return `p` if it does not exist, otherwise a sibling with a `_N` suffix so an
/// extraction never silently overwrites a just-written file.
fn unique_path(p: PathBuf) -> PathBuf {
    if !p.exists() {
        return p;
    }
    let parent = p.parent().map(PathBuf::from).unwrap_or_default();
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file").to_string();
    let ext = p.extension().and_then(|s| s.to_str()).map(|e| format!(".{e}")).unwrap_or_default();
    for n in 1..10_000 {
        let candidate = parent.join(format!("{stem}_{n}{ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    p
}

/// Tighten an extracted file to owner-only (0600) on Unix; no-op elsewhere.
#[cfg(unix)]
fn harden_path(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(p) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(p, perms);
    }
}

#[cfg(not(unix))]
fn harden_path(_p: &Path) {}

#[cfg(test)]
mod tests {
    use super::safe_relative_path;
    use std::path::{Component, PathBuf};

    /// A path is "contained" if it is relative and has no `..`, root, or drive
    /// component — i.e. it can never escape the directory it is joined to.
    fn contained(p: &PathBuf) -> bool {
        !p.is_absolute()
            && p.components()
                .all(|c| !matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
    }

    #[test]
    fn safe_path_normal_tree() {
        let p = safe_relative_path("/statements/2026", "q1.pdf", "id");
        assert_eq!(p, PathBuf::from("statements/2026/q1.pdf"));
        assert!(contained(&p));
    }

    #[test]
    fn safe_path_rejects_all_traversal() {
        let cases = [
            ("../../etc", "passwd"),
            ("..\\..\\windows", "system32"),
            ("a/../../b", "f"),
            ("/abs/path", "/etc/shadow"),
            ("C:\\Windows", "x.dll"),
            ("....//....//", ".."),
        ];
        for (loc, name) in cases {
            let p = safe_relative_path(loc, name, "fallbackid");
            assert!(contained(&p), "must stay contained: {loc:?} {name:?} -> {p:?}");
        }
    }

    #[test]
    fn safe_path_empty_filename_uses_id() {
        assert_eq!(safe_relative_path("/d", "", "abc123"), PathBuf::from("d/abc123.bin"));
        assert_eq!(safe_relative_path("", "..", "abc123"), PathBuf::from("abc123.bin"));
    }

    #[test]
    fn safe_path_drive_letter_dropped() {
        let p = safe_relative_path("C:", "x.txt", "id");
        assert!(contained(&p));
        assert_eq!(p, PathBuf::from("x.txt"));
    }
}

/// Prompt (on stderr) and read one password into a self-zeroizing buffer. When
/// stdin is an interactive terminal the input is read without echo; when piped,
/// a line is read from stdin (so `printf 'pw1\npw2\n' | pass-mgr decrypt` works).
fn read_password(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();

    if std::io::stdin().is_terminal() {
        read_line_no_echo()
    } else {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        let pw = Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string());
        line.zeroize();
        Ok(pw)
    }
}

/// Read a line from the terminal without echoing it, using crossterm raw mode.
fn read_line_no_echo() -> anyhow::Result<Zeroizing<String>> {
    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
    use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    enable_raw_mode()?;
    let mut input = Zeroizing::new(String::new());
    let outcome = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Char(c) => input.push(c),
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Esc => {
                    input.clear();
                    break Ok(());
                }
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };
    disable_raw_mode()?;
    eprintln!();
    outcome?;
    Ok(input)
}
