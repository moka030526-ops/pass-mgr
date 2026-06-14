//! pass-mgr — a standalone, offline, two-password encrypted password manager.
//!
//! `main` handles command-line dispatch, chooses the vault file path, and sets
//! up / tears down the terminal. All UI logic lives in [`ui`]; all crypto in
//! [`crypto`]; the data model and file format in [`vault`]; password generation
//! in [`password`].
//!
//! Usage:
//! ```text
//!   pass-mgr [VAULT]            launch the graphical UI (default vault if omitted)
//!   pass-mgr --tui [VAULT]      launch the terminal UI instead
//!   pass-mgr decrypt [VAULT]    decrypt the vault and print its JSON to stdout
//!   pass-mgr --help             show this help
//! ```

mod crypto;
mod gui;
mod password;
mod records;
mod types;
mod ui;
mod vault;

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
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
    pass-mgr [VAULT]            Launch the graphical UI (default vault if omitted)
    pass-mgr --tui [VAULT]      Launch the terminal UI instead
    pass-mgr decrypt [VAULT]    Decrypt the vault and print its JSON to stdout
    pass-mgr --help             Show this help

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
