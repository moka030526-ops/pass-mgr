//! pass-mgr — command-line entry point for the standalone, offline,
//! two-password encrypted **estate vault**.
//!
//! `main` handles command-line dispatch, chooses the vault file path, and sets
//! up / tears down the terminal. The whole implementation (data model, file
//! format, crypto, the two UIs, and the category lists) lives in the `pass_mgr`
//! library crate (`src/lib.rs`); this binary is a thin wrapper over it.
//!
//! Notes for readers new to Rust (this `//!` block is a *module doc comment*;
//! `///` documents the item that follows, `//` is an ordinary line comment):
//! - Functions here return `anyhow::Result<T>` or `Result<(), E>`. A `Result`
//!   is either `Ok(value)` or `Err(error)` — Rust has no exceptions, so errors
//!   are values you return. The `?` operator after an expression means "if this
//!   is an `Err`, stop and return that error from the current function; if it is
//!   `Ok`, unwrap the inner value and continue." It is the idiomatic early-return.
//! - `Option<T>` is `Some(value)` or `None` (a present-or-absent value, like a
//!   nullable type but checked by the compiler).
//! - `&T` is a *shared/read-only borrow* of a value owned elsewhere; `&mut T` is
//!   an *exclusive/writable borrow*. Passing `&x` lets a function read `x`
//!   without taking ownership (so the caller keeps using it afterwards).
//! - Secrets are wrapped in `Zeroizing<...>`, which overwrites the memory with
//!   zeros when the value goes out of scope, so passwords don't linger in RAM.
//!
//! Usage:
//! ```text
//!   pass-mgr [DIR]                    launch the graphical UI (default vault if omitted)
//!   pass-mgr --tui [DIR]             launch the terminal UI instead
//!   pass-mgr decrypt [DIR]           decrypt the vault and print its JSON to stdout
//!   pass-mgr manifest [DIR] [--part N]  print the document manifest (one partition or all)
//!   pass-mgr extract [DIR] OUT [--part N]  decrypt documents into OUT (one volume or all)
//!   pass-mgr backup [DIR] DEST       copy the encrypted vault tree into DEST
//!   pass-mgr --help                  show this help
//! ```
// Crate-wide attribute: refuse to even compile any `unsafe` block in this crate.
// `unsafe` is Rust's escape hatch for memory operations the compiler can't verify;
// forbidding it is a hard guarantee that this security tool stays memory-safe.
#![forbid(unsafe_code)]

// `use` brings names into scope (like `import`). `{A, B}` imports several at once.
// `BufRead`/`IsTerminal`/`Write` are *traits* (interfaces): importing a trait makes
// its methods (e.g. `.read_line()`, `.flush()`, `.is_terminal()`) callable here.
use std::io::{BufRead, IsTerminal, Write};
// `PathBuf` is an owned, growable filesystem path (the owned counterpart of the
// borrowed `&Path`, much like `String` is the owned form of the borrowed `&str`).
use std::path::PathBuf;
// `ExitCode` is the process exit status this `main` returns to the OS.
use std::process::ExitCode;

use directories::ProjectDirs;
// `Zeroize` (trait providing `.zeroize()`) and `Zeroizing` (a wrapper that wipes
// its contents on drop) — used to scrub passwords/plaintext from memory.
use zeroize::{Zeroize, Zeroizing};

use pass_mgr::vault::OpenVault;
use pass_mgr::{gui, ui, vault};

/// Default vault location: the per-user data directory for this app
/// (`~/.local/share/pass-mgr/` on Linux, `%APPDATA%\pass-mgr\` on Windows).
fn default_vault_path() -> PathBuf {
    // `match` is like a `switch` that must cover every case. `ProjectDirs::from`
    // returns an `Option`: `Some(dirs)` if a platform data dir was found, else
    // `None`. Each arm binds the inner value and produces the resulting path.
    match ProjectDirs::from("dev", "passmgr", "pass-mgr") {
        Some(dirs) => dirs.data_dir().join("vault.pmv"),
        None => PathBuf::from("vault.pmv"),
    }
}

// `const` is a compile-time constant. `&str` is a borrowed string slice (a view
// into text); this one points at a string literal baked into the binary. The
// leading `\` on the first line is a line-continuation that swallows the newline.
const HELP: &str = "\
pass-mgr — standalone, offline, two-password encrypted estate vault

DIR is the vault DIRECTORY (it holds vault.pmv, manifest/, and volume/).
If omitted, the per-user default directory is used.

USAGE:
    pass-mgr [DIR]                  Launch the graphical UI (read-only by default)
    pass-mgr --write [DIR]          Launch writable (allow creating/editing/deleting)
    pass-mgr --tui [DIR]            Launch the terminal UI instead (add --write to edit)
    pass-mgr decrypt [DIR]          Decrypt the vault and print its JSON to stdout
    pass-mgr manifest [DIR] [--part N]
                                    Decrypt the document manifest (index): one
                                    partition N, or ALL partitions (default)
    pass-mgr extract [DIR] OUT [--part N]
                                    Decrypt documents into OUT: one volume/partition
                                    N, or ALL volumes (default)
    pass-mgr backup [DIR] DEST      Copy the whole encrypted vault tree into DEST (timestamped)
    pass-mgr --help                 Show this help

The vault is protected by two passwords entered in sequence. The interactive UI
opens READ-ONLY unless --write is given (a writable session takes a single-writer
lock, so a second --write instance fails fast). The category dropdown lists are
stored inside the encrypted vault — there are no external configuration files.";

/// The vault file inside a user-supplied vault directory.
// Takes `dir` by shared borrow (`&str`): it only reads the text, so the caller
// keeps ownership of the original string.
fn vault_file(dir: &str) -> PathBuf {
    PathBuf::from(dir).join("vault.pmv")
}

/// Pull an optional `--part N` / `--part=N` flag out of the argument list,
/// returning the parsed partition index plus the remaining arguments. Errors if
/// the flag is present but its value is missing or not a non-negative integer.
// `Vec<String>` is a growable array of owned strings; `args` is taken by value
// (moved in), so this function consumes the original list. It returns a tuple:
// the optional parsed partition index and the leftover arguments.
fn extract_part_flag(args: Vec<String>) -> anyhow::Result<(Option<u32>, Vec<String>)> {
    // A *closure* (anonymous function). `|v: &str| { ... }` captures nothing and
    // turns a string into a `u32`. `parse::<u32>()` itself returns a `Result`;
    // `map_err` rewrites the failure case into our anyhow error message.
    // `{v:?}` is debug formatting (shows the quoted/escaped string).
    let parse = |v: &str| {
        v.parse::<u32>()
            .map_err(|_| anyhow::anyhow!("--part value must be a non-negative integer, got {v:?}"))
    };
    // `mut` marks a binding as reassignable/mutable. `None` is the empty `Option`.
    let mut part = None;
    let mut rest = Vec::with_capacity(args.len());
    // Turn the vector into an iterator we can advance manually with `.next()`.
    let mut it = args.into_iter();
    // `while let Some(a) = it.next()` loops as long as the iterator yields a value,
    // binding each one to `a` and stopping when `.next()` returns `None`.
    while let Some(a) = it.next() {
        if a == "--part" {
            // `--part` expects the next argument to be its value. `.next()` gives an
            // `Option`; `.ok_or_else(...)` converts a missing `None` into an error,
            // and the trailing `?` returns that error early if so.
            let v = it.next().ok_or_else(|| anyhow::anyhow!("--part requires a partition number"))?;
            part = Some(parse(&v)?);
        // `if let Some(v) = ...` runs this branch only when `strip_prefix` matched
        // (i.e. the arg started with `--part=`), binding the suffix to `v`.
        } else if let Some(v) = a.strip_prefix("--part=") {
            part = Some(parse(v)?);
        } else {
            rest.push(a);
        }
    }
    // Wrap the successful result in `Ok`; the caller unwraps it with `?` or `match`.
    Ok((part, rest))
}

fn main() -> ExitCode {
    // Collect the process arguments, skipping arg 0 (the program name), into a
    // `Vec<String>`. `.skip(1)` drops the first item; `.collect()` materializes
    // the iterator into the annotated collection type.
    let args: Vec<String> = std::env::args().skip(1).collect();

    // `.iter()` borrows each element; `.any(|a| ...)` returns true if the closure
    // is true for at least one of them. `|a|` is the closure's parameter (here a
    // `&String`). `{HELP}` interpolates the constant into the formatted output.
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }

    // Flags may appear anywhere. `--part N` (or `--part=N`) selects one
    // partition for `manifest`/`extract`; extract it (and its value) first.
    // The `match` both destructures the returned tuple into `(part, args)` and
    // handles the error case. Note `args` is *shadowed*: a new binding reuses the
    // same name, deliberately replacing the old `args` from here on. `{e:#}` is
    // alternate debug formatting (anyhow uses it to print the full error chain).
    let (part, args) = match extract_part_flag(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("pass-mgr error: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    // The interactive UI is read-only unless --write is given; --tui selects the
    // terminal UI over the graphical one.
    let writable = args.iter().any(|a| a == "--write");
    let tui = args.iter().any(|a| a == "--tui");
    // Keep only the *positional* args by filtering out the recognized flags.
    // `matches!(value, pattern)` is true if `value` fits the pattern; here the
    // `|` lists alternatives. `.collect()` rebuilds them into a new `Vec<String>`.
    let pos: Vec<String> =
        args.into_iter().filter(|a| !matches!(a.as_str(), "--write" | "--tui")).collect();

    // The (optional) positional vault DIRECTORY → its vault.pmv file. This is a
    // closure capturing `pos`: `.get(i)` returns `Option<&String>` (the i-th arg
    // if present); `.map(...)` transforms it to a path; `.unwrap_or_else(f)` falls
    // back to calling `f` (here `default_vault_path`) when the arg was absent.
    let vault_dir_arg = |i: usize| pos.get(i).map(|d| vault_file(d)).unwrap_or_else(default_vault_path);

    // `--part` only makes sense for the two partition-aware read commands.
    // `.first()` borrows the first element (an `Option<&String>`), then `.map`
    // turns it into an `Option<&str>` for matching below.
    let cmd = pos.first().map(String::as_str);
    if part.is_some() && !matches!(cmd, Some("manifest") | Some("extract")) {
        eprintln!("pass-mgr error: --part only applies to 'manifest' and 'extract'");
        return ExitCode::FAILURE;
    }

    // Hidden test affordance: a scripted vault operation that honors the
    // PMVAULT_CRASH_AT fault points, so the crash-recovery integration tests can
    // run a REAL operation in this binary and abort it at a chosen commit step.
    // Compiled ONLY with `--features fault-injection`; absent from release builds.
    #[cfg(feature = "fault-injection")]
    if cmd == Some("__crashop") {
        return match crashop(&pos) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("crashop error: {e:#}");
                ExitCode::FAILURE
            }
        };
    }

    // Dispatch on the subcommand. Matching on `Option<&str>` lets each arm test a
    // specific command name (with `|` allowing aliases like decrypt/export). The
    // chosen arm calls the matching handler, and the resulting `Result` is stored.
    let result = match cmd {
        Some("decrypt" | "export") => cli_decrypt(vault_dir_arg(1)),
        Some("manifest") => cli_manifest(vault_dir_arg(1), part),
        // `extract [DIR] OUT` — the output directory is always the LAST argument.
        Some("extract") => match pos.len() {
            2 => cli_extract(default_vault_path(), PathBuf::from(&pos[1]), part),
            3 => cli_extract(vault_file(&pos[1]), PathBuf::from(&pos[2]), part),
            _ => Err(anyhow::anyhow!("usage: pass-mgr extract [DIR] <OUTPUT_DIR> [--part N]")),
        },
        // `backup [DIR] DEST` — copies the encrypted tree; no passwords needed.
        Some("backup") => match pos.len() {
            2 => cli_backup(default_vault_path(), PathBuf::from(&pos[1])),
            3 => cli_backup(vault_file(&pos[1]), PathBuf::from(&pos[2])),
            _ => Err(anyhow::anyhow!("usage: pass-mgr backup [DIR] <DEST_DIR>")),
        },
        // Otherwise the (optional) positional argument is the vault directory for
        // the interactive UI (graphical by default, terminal with --tui).
        _ => {
            let path = vault_dir_arg(0);
            if tui {
                run_ui(path, writable)
            } else {
                gui::run(path, writable)
            }
        }
    };

    // `if let Err(e) = result` runs the block only when the command failed,
    // binding the error to `e`; otherwise we fall through to the success exit.
    if let Err(e) = result {
        eprintln!("pass-mgr error: {e:#}");
        return ExitCode::FAILURE;
    }
    // No trailing semicolon: this expression is the function's return value.
    ExitCode::SUCCESS
}

fn run_ui(path: PathBuf, writable: bool) -> anyhow::Result<()> {
    // `ratatui::init` enters the alternate screen + raw mode and installs a
    // panic hook that restores the terminal before printing the panic, so a
    // crash never leaves the user's terminal in a broken state.
    let mut terminal = ratatui::init();
    // `&mut terminal` passes an *exclusive borrow* so `ui::run` can draw to and
    // mutate the terminal while `run_ui` retains ownership and restores it after.
    let result = ui::run(&mut terminal, path, writable);
    ratatui::restore();
    // Return the UI's `Result` unchanged (last expression, no semicolon).
    result
}

/// Decrypt the vault and print its full JSON (including all passwords) to
/// stdout. Prompts for both passwords on stderr. WARNING: this writes every
/// stored secret to your terminal in plaintext — see `docs/DESIGN.md` §9.10.
// Returns `anyhow::Result<()>`: `()` is the empty/"unit" type, so on success there
// is no meaningful value — the function is run for its effects (printing).
fn cli_decrypt(path: PathBuf) -> anyhow::Result<()> {
    if !path.exists() {
        // `bail!` constructs an error and returns it immediately (early exit).
        anyhow::bail!("no vault found at {}", path.display());
    }
    eprintln!("Decrypting {} — this prints all secrets in plaintext.", path.display());
    // Each `?` returns early if reading the password failed. `pw1`/`pw2` are
    // `Zeroizing<String>` buffers that wipe themselves when this function ends.
    let pw1 = read_password("Password 1: ")?;
    let pw2 = read_password("Password 2: ")?;

    // Pass the path by shared borrow and the passwords as byte slices (`&[u8]`).
    // `.as_bytes()` borrows the string's underlying bytes without copying them.
    let vault = OpenVault::export(&path, pw1.as_bytes(), pw2.as_bytes())?;
    // Zeroizing so the (secret-bearing) serialized JSON is wiped after printing.
    // `&vault` lets serde read the value to serialize it without taking ownership.
    let json = Zeroizing::new(serde_json::to_string_pretty(&vault)?);
    println!("{}", json.as_str());
    Ok(())
}

/// Decrypt and print the document manifest (the index of stored documents) as
/// JSON. With `part = Some(n)` only partition `n`'s manifest is decrypted; with
/// `None`, all of them. Prompts for both passwords; does not modify the vault.
// `part: Option<u32>` — `Some(n)` for one partition, `None` for all of them.
fn cli_manifest(path: PathBuf, part: Option<u32>) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("no vault found at {}", path.display());
    }
    let pw1 = read_password("Password 1: ")?;
    let pw2 = read_password("Password 2: ")?;
    // `part` is forwarded unchanged; the library decides one-vs-all from it.
    let entries = OpenVault::export_manifests(&path, pw1.as_bytes(), pw2.as_bytes(), part)?;
    println!("{}", serde_json::to_string_pretty(&entries)?);
    Ok(())
}

/// Copy the whole encrypted vault tree into `dest_dir` as a timestamped,
/// self-consistent set. No passwords needed (nothing is decrypted).
fn cli_backup(path: PathBuf, dest_dir: PathBuf) -> anyhow::Result<()> {
    // Both paths passed by shared borrow; the library copies files and returns the
    // path it created (or an error, which `?` would propagate).
    let backup = vault::backup(&path, &dest_dir)?;
    eprintln!("Backed up to {}", backup.display());
    Ok(())
}

/// Decrypt stored documents and write them into `out_dir`, reconstructing the
/// virtual directory tree. With `part = Some(n)` only partition `n`'s volume is
/// decrypted; with `None`, every partition. Prompts for both passwords.
/// WARNING: this writes unencrypted copies of the documents to disk.
fn cli_extract(path: PathBuf, out_dir: PathBuf, part: Option<u32>) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("no vault found at {}", path.display());
    }
    // Build a human-readable scope string depending on whether one partition or
    // all were requested. `format!` returns an owned `String`; `{n}` interpolates.
    let scope = match part {
        Some(n) => format!("partition {n} of {}", path.display()),
        None => path.display().to_string(),
    };
    eprintln!("Extracting documents from {scope} into {} — these are UNENCRYPTED copies.", out_dir.display());
    let pw1 = read_password("Password 1: ")?;
    let pw2 = read_password("Password 2: ")?;

    let docs = OpenVault::export_documents(&path, pw1.as_bytes(), pw2.as_bytes(), part)?;
    if docs.is_empty() {
        eprintln!("No documents stored in this vault.");
        // Early success return: nothing to write.
        return Ok(());
    }

    std::fs::create_dir_all(&out_dir)?;
    vault::harden_dir(&out_dir); // 0700 on unix (filenames/paths are sensitive)
    // `0usize` is a zero literal typed as `usize` (the pointer-sized unsigned int
    // used for counts/indices). `mut` because we increment it in the loop.
    let mut written = 0usize;
    // Iterate over `&docs` (borrowing, so `docs` stays usable afterwards). Each
    // item is a `(meta, bytes)` tuple that this pattern destructures in place.
    for (meta, bytes) in &docs {
        // The manifest stores one combined virtual path ("/loc/file"); split it
        // back into directory + filename for the sanitizer. Build a SAFE relative
        // path so a crafted manifest can never escape out_dir (no `..`/absolute).
        // `rsplit_once('/')` returns `Option<(&str, &str)>` — the parts before and
        // after the last `/`. `.unwrap_or(default)` substitutes the default tuple
        // when there is no `/` (the whole path is then treated as the filename).
        let (location, filename) = meta.path.rsplit_once('/').unwrap_or(("", meta.path.as_str()));
        let rel = safe_relative_path(location, filename, &meta.id);
        let dest = unique_path(out_dir.join(rel));
        // `.parent()` is the containing directory, if any. `if let Some(parent)`
        // runs only when there is one, binding it for use inside the block.
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
            vault::harden_dir(parent);
        }
        // Reuse the vault's hardened writer: create_new (O_EXCL, no symlink
        // follow) + 0600, removing any partial fragment on a write error.
        vault::write_new_bytes(&dest, bytes)?;
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
// All three inputs are shared borrows (`&str`): read-only views into strings the
// caller owns. Returns an owned `PathBuf` built fresh inside.
fn safe_relative_path(location: &str, filename: &str, id: &str) -> PathBuf {
    // A nested helper function. Returns `Option<String>`: `Some(name)` for a safe
    // component, or `None` to signal "drop this component entirely".
    fn clean(part: &str) -> Option<String> {
        let p = part.trim();
        if p.is_empty() || p == "." || p == ".." {
            return None;
        }
        // Reject anything that still looks like a separator, drive, or NUL.
        if p.contains(['/', '\\', ':', '\0']) {
            return None;
        }
        // Windows: strip trailing dots/spaces (they're silently dropped by the OS,
        // which can alias names) and refuse reserved DOS device names (CON, PRN,
        // AUX, NUL, COM1-9, LPT1-9), with or without an extension.
        let trimmed = p.trim_end_matches(['.', ' ']);
        if trimmed.is_empty() {
            return None;
        }
        // Take the part before the first `.` as the name "stem". `.next()` on the
        // split iterator yields the first piece; `.unwrap_or(trimmed)` is a safe
        // fallback (it never actually triggers here, since split yields >=1 item).
        let stem = trimmed.split('.').next().unwrap_or(trimmed);
        // `[&str; 4]` is a fixed-size array of 4 string slices, known at compile time.
        const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
        let upper = stem.to_ascii_uppercase();
        // A boolean built from chained `&&` conditions (all must hold). `b'0'` is a
        // byte literal; `as_bytes()[3]` indexes the 4th raw byte of the name.
        let is_com_lpt = (upper.starts_with("COM") || upper.starts_with("LPT"))
            && upper.len() == 4
            && upper.as_bytes()[3].is_ascii_digit()
            && upper.as_bytes()[3] != b'0';
        if RESERVED.contains(&upper.as_str()) || is_com_lpt {
            return None;
        }
        // `.to_string()` makes an owned `String` copy to hand back to the caller.
        Some(trimmed.to_string())
    }
    let mut path = PathBuf::new();
    // Split the directory portion on either separator and append each safe piece.
    // `if let Some(c)` skips components that `clean` rejected (returned `None`).
    for part in location.split(['/', '\\']) {
        if let Some(c) = clean(part) {
            path.push(c);
        }
    }
    // For the filename: split it, run every piece through `clean` keeping only the
    // `Some` results (`filter_map`), and take the LAST surviving one (`next_back`).
    // `match` then either appends that name or, if none survived, falls back to an
    // id-derived name so we always produce a file.
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
    // `.parent()` → `Option<&Path>`; `.map(PathBuf::from)` converts the borrow to
    // an owned path; `.unwrap_or_default()` yields an empty path if there was none.
    let parent = p.parent().map(PathBuf::from).unwrap_or_default();
    // `.and_then(|s| s.to_str())` chains a step that may also fail (OS strings are
    // not guaranteed valid UTF-8); together these get the filename-without-extension
    // as a `&str`, defaulting to "file", then copy it into an owned `String`.
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("file").to_string();
    let ext = p.extension().and_then(|s| s.to_str()).map(|e| format!(".{e}")).unwrap_or_default();
    // `1..10_000` is a half-open range (1 up to, but not including, 10000). Try
    // `stem_1`, `stem_2`, ... until one does not yet exist on disk.
    for n in 1..10_000 {
        let candidate = parent.join(format!("{stem}_{n}{ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    p
}

/// Prompt (on stderr) and read one password into a self-zeroizing buffer. When
/// stdin is an interactive terminal the input is read without echo; when piped,
/// a line is read from stdin (so `printf 'pw1\npw2\n' | pass-mgr decrypt` works).
// Returns the password inside a `Zeroizing<String>` so it is wiped on drop.
fn read_password(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    eprint!("{prompt}");
    // `.flush()` forces the prompt out before we block on input; `.ok()` discards
    // its `Result` (a failed flush here is not worth aborting over).
    std::io::stderr().flush().ok();

    // `is_terminal()` (from the `IsTerminal` trait) distinguishes an interactive
    // TTY from a pipe. The two branches are the function's return value (no
    // semicolons), so whichever runs supplies the `Result`.
    if std::io::stdin().is_terminal() {
        read_line_no_echo()
    } else {
        let mut line = String::new();
        // `&mut line` lends the buffer exclusively so `read_line` can append into it.
        std::io::stdin().lock().read_line(&mut line)?;
        // Strip the trailing newline(s) and copy into a self-wiping buffer...
        let pw = Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string());
        // ...then explicitly scrub the original `line`, which still holds the secret.
        line.zeroize();
        Ok(pw)
    }
}

/// Read a line from the terminal without echoing it, using crossterm raw mode.
fn read_line_no_echo() -> anyhow::Result<Zeroizing<String>> {
    // Function-local `use`: these imports are only in scope inside this function.
    // `self` in `{self, Event, ...}` imports the `event` module itself too.
    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
    use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    enable_raw_mode()?;
    let mut input = Zeroizing::new(String::new());
    // `loop {}` runs forever until a `break` exits it; `break value` makes the loop
    // *evaluate to* that value, which is assigned to `outcome` here.
    let outcome = loop {
        match event::read() {
            // Match an `Ok(Event::Key(k))` only when the extra `if` guard holds
            // (a key *press*, not a release/repeat). The inner `match` then
            // dispatches on which key it was.
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break Ok(()),
                // `KeyCode::Char(c)` binds the typed character to `c`.
                KeyCode::Char(c) => input.push(c),
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Esc => {
                    input.clear();
                    break Ok(());
                }
                // `_` is the wildcard arm: ignore every other key.
                _ => {}
            },
            // Non-key events are ignored; a read error breaks out carrying the error.
            Ok(_) => {}
            Err(e) => break Err(e),
        }
    };
    disable_raw_mode()?;
    eprintln!();
    // Propagate a read error now (after raw mode is restored), then hand back input.
    outcome?;
    Ok(input)
}

/// Test-only scripted vault operation behind the `__crashop` subcommand (compiled
/// only with `--features fault-injection`). It runs a real vault operation in this
/// binary so the crash-recovery integration tests can abort it at a chosen commit
/// step via `PMVAULT_CRASH_AT` (handled by the fault points in storage/vault).
/// `pos` is `["__crashop", <scenario>, <DIR>]`.
#[cfg(feature = "fault-injection")]
fn crashop(pos: &[String]) -> anyhow::Result<()> {
    use pass_mgr::records;
    let scenario = pos.get(1).map(String::as_str).unwrap_or("");
    let dir = pos.get(2).cloned().ok_or_else(|| anyhow::anyhow!("crashop: missing DIR"))?;
    let path = vault_file(&dir);
    let src = PathBuf::from(&dir).join("__crashop_src.bin");
    match scenario {
        // Create a vault (fast KDF) with one committed, record-referenced document.
        "setup" => {
            let params = pass_mgr::crypto::KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 };
            let mut v = OpenVault::create(path, b"a", b"b", params)?;
            std::fs::write(&src, b"doc-one")?;
            let id = v.add_document("/w", "d1.txt", &src)?;
            let mut tw = records::TrustWill::new()?;
            tw.file = Some(id);
            records::upsert(&mut v.vault.trust_wills, tw);
            v.save()?;
        }
        // Add a second document + link it + save. Crash points put.*/vault.* fire.
        "adddoc" => {
            let mut v = OpenVault::open(path, b"a", b"b")?;
            std::fs::write(&src, b"doc-two")?;
            let id = v.add_document("/w", "d2.txt", &src)?;
            let mut tw = records::TrustWill::new()?;
            tw.file = Some(id);
            records::upsert(&mut v.vault.trust_wills, tw);
            v.save()?;
        }
        // Rotate the passwords (a -> c). Crash points rekey.* fire mid roll-forward.
        "rekey" => {
            let mut v = OpenVault::open(path, b"a", b"b")?;
            v.change_password(b"c", b"d")?;
        }
        other => anyhow::bail!("crashop: unknown scenario {other:?}"),
    }
    Ok(())
}

// `#[cfg(test)]` is *conditional compilation*: this whole module is compiled only
// when running `cargo test`, and is absent from the shipped binary. `mod tests` is
// an inline submodule grouping the unit tests.
#[cfg(test)]
mod tests {
    // `super::` refers to the parent module (this file), pulling in the private
    // function under test.
    use super::safe_relative_path;
    use std::path::{Component, Path, PathBuf};

    /// A path is "contained" if it is relative and has no `..`, root, or drive
    /// component — i.e. it can never escape the directory it is joined to.
    // `p: &Path` is a borrowed (read-only) path. `.components()` yields each path
    // segment; `.all(|c| ...)` is true only if the closure holds for every one.
    fn contained(p: &Path) -> bool {
        !p.is_absolute()
            && p.components()
                .all(|c| !matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
    }

    // `#[test]` marks a function as a test case the test runner will execute.
    // `assert_eq!`/`assert!` fail (and thus fail the test) if their condition is not met.
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

    #[test]
    fn safe_path_rejects_windows_reserved_and_trailing() {
        // Reserved DOS device names are dropped (filename falls back to the id).
        assert_eq!(safe_relative_path("", "CON", "id1"), PathBuf::from("id1.bin"));
        assert_eq!(safe_relative_path("", "nul.txt", "id2"), PathBuf::from("id2.bin"));
        assert_eq!(safe_relative_path("", "COM1", "id3"), PathBuf::from("id3.bin"));
        assert_eq!(safe_relative_path("", "LPT9", "id4"), PathBuf::from("id4.bin"));
        // A reserved *directory* component is dropped, not used as a folder.
        assert_eq!(safe_relative_path("CON/sub", "f.txt", "id5"), PathBuf::from("sub/f.txt"));
        // Trailing dots/spaces are stripped (Windows aliases them away).
        assert_eq!(safe_relative_path("", "report.pdf. .", "id6"), PathBuf::from("report.pdf"));
        // COM0/LPT0 are NOT reserved.
        assert_eq!(safe_relative_path("", "LPT0.log", "id7"), PathBuf::from("LPT0.log"));
    }

    #[test]
    fn unique_path_avoids_existing() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("passmgr-uniq-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("doc.txt");
        // Non-existing path is returned as-is.
        assert_eq!(super::unique_path(p.clone()), p);
        std::fs::write(&p, b"x").unwrap();
        // Existing path gets a `_N` suffix that doesn't yet exist.
        let u = super::unique_path(p.clone());
        assert_ne!(u, p);
        assert!(!u.exists());
        assert_eq!(u.file_name().unwrap().to_str().unwrap(), "doc_1.txt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cli_backup_copies_file() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // backup() copies the whole vault tree as-is; a dummy file suffices here.
        let vdir = std::env::temp_dir().join(format!("passmgr-clibk-{nanos}"));
        std::fs::create_dir_all(&vdir).unwrap();
        let vault = vdir.join("vault.pmv");
        std::fs::write(&vault, b"PMVAULT\0 fake").unwrap();
        let dest = std::env::temp_dir().join(format!("passmgr-clibk-dest-{nanos}"));
        super::cli_backup(vault.clone(), dest.clone()).unwrap();
        let n = std::fs::read_dir(&dest).unwrap().count();
        assert_eq!(n, 1, "one timestamped backup directory created");
        let _ = std::fs::remove_dir_all(&vdir);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn default_vault_path_ends_with_vault_pmv() {
        assert!(super::default_vault_path().ends_with("vault.pmv"));
    }

    #[test]
    fn part_flag_is_parsed_and_stripped() {
        let s = |v: &str| v.to_string();
        // `--part N` form: value consumed, rest preserved in order.
        let (p, rest) = super::extract_part_flag(vec![s("manifest"), s("--part"), s("2"), s("dir")]).unwrap();
        assert_eq!(p, Some(2));
        assert_eq!(rest, vec![s("manifest"), s("dir")]);
        // `--part=N` form.
        let (p, rest) = super::extract_part_flag(vec![s("--part=5"), s("x")]).unwrap();
        assert_eq!(p, Some(5));
        assert_eq!(rest, vec![s("x")]);
        // Absent → None, args untouched.
        let (p, rest) = super::extract_part_flag(vec![s("extract")]).unwrap();
        assert_eq!(p, None);
        assert_eq!(rest, vec![s("extract")]);
        // Missing or non-numeric values are errors.
        assert!(super::extract_part_flag(vec![s("--part")]).is_err());
        assert!(super::extract_part_flag(vec![s("--part"), s("abc")]).is_err());
        assert!(super::extract_part_flag(vec![s("--part=-1")]).is_err());
    }
}
