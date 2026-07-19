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
//!   pass-mgr export-tree [DIR] OUT   decrypt the whole vault into OUT (plaintext mirror)
//!   pass-mgr import-tree SRC [DIR]   build a new encrypted vault from a plaintext mirror
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
use std::path::{Path, PathBuf};
// `ExitCode` is the process exit status this `main` returns to the OS.
use std::process::ExitCode;

// `Zeroize` (trait providing `.zeroize()`) and `Zeroizing` (a wrapper that wipes
// its contents on drop) — used to scrub passwords/plaintext from memory.
use zeroize::{Zeroize, Zeroizing};

// The vault-path helpers live in the library so the windowed `pass-mgr-gui`
// binary resolves the vault identically; importing them keeps every call site
// below unqualified.
use pass_mgr::launch::{default_vault_path, vault_file};
use pass_mgr::vault::OpenVault;
use pass_mgr::{ui, vault};
// The GUI is behind the `gui` feature; a `--no-default-features` build is terminal-only.
#[cfg(feature = "gui")]
use pass_mgr::gui;

// THROWAWAY: the one-shot `migrate-doc-paths` subcommand. Delete this line, its dispatch
// arm, and `src/migrate_cli.rs` to remove the feature.
mod migrate_cli;

// `const` is a compile-time constant. `&str` is a borrowed string slice (a view
// into text); this one points at a string literal baked into the binary. The
// leading `\` on the first line is a line-continuation that swallows the newline.
const HELP: &str = "\
pass-mgr — standalone, offline, two-password encrypted estate vault

DIR is the vault DIRECTORY (it holds vault.pmv, manifest/, and volume/).
If omitted, the per-user default directory is used.

This is the console build. The graphical app is a separate binary, `pass-mgr-gui`
(`pass-mgr-gui[.exe]`), which is identical to `pass-mgr [DIR]` but opens with no
console window on Windows. Use `pass-mgr-gui` for the GUI; use this binary for the
commands below and the terminal UI.

USAGE:
    pass-mgr [DIR]                  Launch the graphical UI (read-only by default)
                                    (prefer `pass-mgr-gui` — no console window)
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
    pass-mgr export-tree [DIR] OUT  Decrypt the WHOLE vault into OUT as a plaintext mirror
                                    (vault.json + manifest/ + volume/); round-trips with import-tree
    pass-mgr import-tree SRC [DIR]  Build a NEW encrypted vault (new passwords) from a
                                    plaintext mirror SRC produced by export-tree
    pass-mgr update-from OTHER [DIR]
                                    Update DIR's vault from ANOTHER vault (OTHER): pull
                                    records that are newer (or new) in OTHER, plus the
                                    documents they reference. One-way and ADDITIVE — it
                                    never deletes anything from DIR. Prompts FOUR passwords
                                    in order: DIR's two, then OTHER's two. Add --dry-run to
                                    preview the patch without changing anything (recommended
                                    first). Tip: back up DIR first (`pass-mgr backup`).
    pass-mgr compact [DIR] <what>   Reclaim space (writable; backs up first by default).
                                    Crash-safe: a power loss leaves the old OR the
                                    compacted vault, never a mix. <what> is one or both:
                                      --volume   re-pack the document store, dropping the
                                                 dead blocks left by edits/deletes
                                      --json     trim each record's edit-history log; pick
                                                 --history-before YYYY-MM-DD (UTC; keeps
                                                 entries on/after that date) OR --history-all
                                    Options: --dry-run (report only, no changes),
                                      --backup DEST (where to back up; must be outside DIR),
                                      --no-backup (skip the pre-compaction backup).
                                    The vault-level audit log is always preserved.
    pass-mgr migrate-doc-paths [DIR]
                                    One-shot migration of stored document paths to the
                                    owner-first layout (/<owner-initials>/<type>/…) with the
                                    timestamp folded into the filename (<ts>_<file>). Also
                                    DELETES all history and compacts the volume to shrink the
                                    vault. Writable; backs up first by default. Options:
                                      --dry-run (preview old->new paths, no changes),
                                      --no-backup (skip the pre-migration backup).
    pass-mgr --help                 Show this help

The vault is protected by two passwords entered in sequence. The interactive UI
opens READ-ONLY unless --write is given (a writable session takes a single-writer
lock, so a second --write instance fails fast). The category dropdown lists are
stored inside the encrypted vault — there are no external configuration files.";

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

/// Flags for the `compact` command, pulled out of the argument list the same way
/// `--part` is (so they may appear in any position). `--volume`/`--json` choose
/// what to reclaim; `--history-before DATE`/`--history-all` set the JSON history
/// retention; `--no-backup`/`--backup DEST` control the pre-compaction backup;
/// `--dry-run` reports without writing.
// `#[derive(Default)]` gives an all-false/None starting value via `::default()`.
#[derive(Default)]
struct CompactFlags {
    volume: bool,
    json: bool,
    history_before: Option<String>,
    history_all: bool,
    no_backup: bool,
    backup_dest: Option<String>,
    dry_run: bool,
}

impl CompactFlags {
    /// Whether any compact-only flag was supplied (used to reject them on other
    /// commands, mirroring the `--part` guard).
    fn any(&self) -> bool {
        self.volume
            || self.json
            || self.history_before.is_some()
            || self.history_all
            || self.no_backup
            || self.backup_dest.is_some()
            || self.dry_run
    }

    /// True when `--dry-run` is the ONLY compact-set flag present. `update-from` reuses
    /// `--dry-run` for its preview, so the cross-command guard in `main` allows exactly
    /// this combination (and nothing else from the compact set) for that command.
    fn is_only_dry_run(&self) -> bool {
        self.dry_run
            && !self.volume
            && !self.json
            && self.history_before.is_none()
            && !self.history_all
            && !self.no_backup
            && self.backup_dest.is_none()
    }

    /// True when only `--dry-run` and/or `--no-backup` are present (the compact-set subset the
    /// THROWAWAY `migrate-doc-paths` command accepts). Delete with that command.
    fn is_only_dry_run_or_no_backup(&self) -> bool {
        !self.volume && !self.json && self.history_before.is_none() && !self.history_all && self.backup_dest.is_none()
    }
}

/// Pull the `compact` flags out of `args`, returning them plus the leftover
/// (positional + other) arguments. Errors if a value-taking flag is missing its
/// value. Both `--flag value` and `--flag=value` spellings are accepted for the
/// two value flags. Recognized flags are stripped for every command; a guard in
/// `main` rejects their use outside `compact`.
fn extract_compact_flags(args: Vec<String>) -> anyhow::Result<(CompactFlags, Vec<String>)> {
    let mut f = CompactFlags::default();
    let mut rest = Vec::with_capacity(args.len());
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--volume" {
            f.volume = true;
        } else if a == "--json" {
            f.json = true;
        } else if a == "--history-all" {
            f.history_all = true;
        } else if a == "--no-backup" {
            f.no_backup = true;
        } else if a == "--dry-run" {
            f.dry_run = true;
        } else if a == "--history-before" {
            // The value is the NEXT argument; a missing one is an error.
            let v = it.next().ok_or_else(|| anyhow::anyhow!("--history-before requires a YYYY-MM-DD date"))?;
            f.history_before = Some(v);
        } else if let Some(v) = a.strip_prefix("--history-before=") {
            f.history_before = Some(v.to_string());
        } else if a == "--backup" {
            let v = it.next().ok_or_else(|| anyhow::anyhow!("--backup requires a destination directory"))?;
            f.backup_dest = Some(v);
        } else if let Some(v) = a.strip_prefix("--backup=") {
            f.backup_dest = Some(v.to_string());
        } else {
            rest.push(a); // not a compact flag — keep it
        }
    }
    Ok((f, rest))
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
    // Pull the `compact` flags out next (same shadowing of `args`), so the
    // positional/`--write` logic below never sees them.
    let (cflags, args) = match extract_compact_flags(args) {
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
    if cflags.any() && cmd != Some("compact") {
        // `update-from` reuses --dry-run for its preview; allow exactly that (and nothing
        // else from the compact set) for that command, but reject every other combination.
        let update_from_dry_run = cmd == Some("update-from") && cflags.is_only_dry_run();
        // THROWAWAY: migrate-doc-paths accepts --dry-run and/or --no-backup (delete with it).
        let migrate_ok = cmd == Some("migrate-doc-paths") && cflags.is_only_dry_run_or_no_backup();
        if !(update_from_dry_run || migrate_ok) {
            eprintln!(
                "pass-mgr error: --volume/--json/--history-before/--history-all/--backup/--no-backup only apply to 'compact'; --dry-run also applies to 'update-from'"
            );
            return ExitCode::FAILURE;
        }
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

    // Hidden test affordance: open the vault read-WRITE (taking the single-writer lock)
    // and hold it until stdin closes, so the cross-process lock test can hold the lock
    // from a REAL second process. Compiled ONLY with `--features fault-injection`.
    #[cfg(feature = "fault-injection")]
    if cmd == Some("__holdlock") {
        return match holdlock(&pos) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("holdlock error: {e:#}");
                ExitCode::FAILURE
            }
        };
    }

    // Dispatch on the subcommand. Matching on `Option<&str>` lets each arm test a
    // specific command name (with `|` allowing aliases like decrypt/export). The
    // chosen arm calls the matching handler, and the resulting `Result` is stored.
    let result = match cmd {
        // `decrypt [DIR]` / `manifest [DIR]` — like the sibling commands, reject extra
        // positionals instead of silently ignoring them (an index-based `.get(1)` dropped
        // a mistyped/extra arg, masking a mistake about which vault was acted on).
        Some("decrypt" | "export") => match pos.len() {
            1 => cli_decrypt(default_vault_path()),
            2 => cli_decrypt(vault_file(&pos[1])),
            _ => Err(anyhow::anyhow!("usage: pass-mgr decrypt [DIR]")),
        },
        Some("manifest") => match pos.len() {
            1 => cli_manifest(default_vault_path(), part),
            2 => cli_manifest(vault_file(&pos[1]), part),
            _ => Err(anyhow::anyhow!("usage: pass-mgr manifest [DIR] [--part N]")),
        },
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
        // `export-tree [DIR] OUTDIR` — full decrypted mirror (OUTDIR is last).
        Some("export-tree") => match pos.len() {
            2 => cli_export_tree(default_vault_path(), PathBuf::from(&pos[1])),
            3 => cli_export_tree(vault_file(&pos[1]), PathBuf::from(&pos[2])),
            _ => Err(anyhow::anyhow!("usage: pass-mgr export-tree [DIR] <OUTPUT_DIR>")),
        },
        // `import-tree SRCDIR [DIR]` — build a new encrypted vault from a mirror.
        Some("import-tree") => match pos.len() {
            2 => cli_import_tree(PathBuf::from(&pos[1]), default_vault_path()),
            3 => cli_import_tree(PathBuf::from(&pos[1]), vault_file(&pos[2])),
            _ => Err(anyhow::anyhow!("usage: pass-mgr import-tree <SOURCE_DIR> [DIR]")),
        },
        // `update-from OTHER [DIR]` — pull newer/new records (+ their docs) from OTHER.
        Some("update-from") => match pos.len() {
            2 => cli_update_from(PathBuf::from(&pos[1]), default_vault_path(), cflags.dry_run),
            3 => cli_update_from(PathBuf::from(&pos[1]), vault_file(&pos[2]), cflags.dry_run),
            _ => Err(anyhow::anyhow!("usage: pass-mgr update-from <OTHER_DIR> [DIR] [--dry-run]")),
        },
        // `compact [DIR] <flags>` — reclaim dead volume bytes and/or trim history.
        Some("compact") => cli_compact(&pos, &cflags),
        // THROWAWAY: `migrate-doc-paths [DIR]` — owner-first path migration + history drop + compact.
        Some("migrate-doc-paths") => migrate_cli::run(&pos, &cflags),
        // Otherwise the (optional) positional argument is the vault directory for
        // the interactive UI (graphical by default, terminal with --tui). In a build
        // without the `gui` feature there is no graphical UI, so always run the TUI.
        _ => {
            // Interactive launch: `pass-mgr [DIR] [--write] [--tui]` — at most ONE positional
            // (the optional vault DIR; there is no subcommand here). Reject a 2nd+ positional
            // (a stray token, or a mistyped subcommand like `extarct OUT`) instead of silently
            // ignoring it and opening pos[0] — matching the explicit arity checks on every
            // subcommand above.
            if pos.len() > 1 {
                Err(anyhow::anyhow!(
                    "unrecognized extra arguments: {:?}\nUsage: pass-mgr [DIR] [--write] [--tui], or a subcommand (run `pass-mgr --help`).",
                    &pos[1..]
                ))
            } else {
                let path = vault_dir_arg(0);
                #[cfg(feature = "gui")]
                {
                    if tui {
                        run_ui(path, writable)
                    } else {
                        gui::run(path, writable)
                    }
                }
                #[cfg(not(feature = "gui"))]
                {
                    let _ = tui; // the flag is accepted but the TUI is the only UI here
                    run_ui(path, writable)
                }
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
    // Serialize the (secret-bearing) JSON into a single exactly-sized Zeroizing buffer so no
    // mid-write reallocation strands cleartext in freed heap (see vault::serialize_secret_json),
    // then write the bytes straight to stdout — converting to a String first would allocate
    // and then free another full plaintext copy unwiped.
    let json = vault::serialize_secret_json(&vault, true)?;
    use std::io::Write as _;
    let mut out = std::io::stdout().lock();
    out.write_all(&json)?;
    out.write_all(b"\n")?;
    out.flush()?;
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

/// Reclaim space: rewrite the document volume to drop dead frames (`--volume`)
/// and/or trim per-record history (`--json` with `--history-before`/`--history-all`).
/// Crash-safe: the volume rewrite stages a fresh tree and swaps it in atomically,
/// so a power loss leaves either the old or the compacted vault, never a mix. By
/// default the encrypted tree is backed up first (`--no-backup` opts out); the
/// trimmed history and reclaimed bytes are otherwise gone permanently. `--dry-run`
/// reports what would be reclaimed without writing. Prompts for both passwords.
/// Resolve the vault target for `compact`, rejecting the silently-wrong default.
/// `pos[0]` is "compact"; an optional `pos[1]` is the vault DIR.
fn compact_target(pos: &[String], f: &CompactFlags) -> anyhow::Result<PathBuf> {
    // A value-taking flag (`--backup DEST` / `--history-before DATE`) greedily
    // consumes the NEXT token as its value, so `compact --backup DIR` leaves
    // pos=["compact"] — which would otherwise fall back to the DEFAULT vault and
    // run a destructive compaction on the WRONG one. If no DIR was given AND such a
    // flag is present, refuse rather than guess: demand the DIR explicitly.
    if pos.len() == 1 && (f.backup_dest.is_some() || f.history_before.is_some()) {
        anyhow::bail!(
            "compact: no vault DIR given, but a value-taking flag (--backup/--history-before) is \
             present and may have consumed the directory you meant. Pass the vault DIR explicitly, \
             e.g. `pass-mgr compact DIR --backup DEST`."
        );
    }
    match pos.len() {
        1 => Ok(default_vault_path()),
        2 => Ok(vault_file(&pos[1])),
        _ => anyhow::bail!(
            "usage: pass-mgr compact [DIR] [--volume] [--json (--history-before YYYY-MM-DD | --history-all)] [--dry-run] [--no-backup] [--backup DEST]"
        ),
    }
}

fn cli_compact(pos: &[String], f: &CompactFlags) -> anyhow::Result<()> {
    let path = compact_target(pos, f)?;
    // Make the target unambiguous before any password prompt or destructive work, so
    // a swallowed-positional mistake is visible instead of silently hitting a vault.
    eprintln!("pass-mgr: compact target vault → {}", path.display());
    if !path.exists() {
        anyhow::bail!("no vault found at {}", path.display());
    }

    // Validate the flag combination BEFORE prompting for passwords.
    if !f.volume && !f.json {
        anyhow::bail!("compact: specify --volume and/or --json (nothing to do otherwise)");
    }
    if f.json {
        match (f.history_before.is_some(), f.history_all) {
            (true, true) => anyhow::bail!("compact --json: give either --history-before or --history-all, not both"),
            (false, false) => {
                anyhow::bail!("compact --json: choose --history-before YYYY-MM-DD or --history-all")
            }
            _ => {}
        }
    } else if f.history_before.is_some() || f.history_all {
        anyhow::bail!("compact: --history-before/--history-all only apply together with --json");
    }

    // Parse the cutoff (UTC midnight); `--history-all` removes every entry instead.
    let history_cutoff = match &f.history_before {
        Some(s) => Some(
            pass_mgr::records::parse_ymd_utc(s)
                .ok_or_else(|| anyhow::anyhow!("invalid --history-before date {s:?}; expected YYYY-MM-DD (UTC)"))?,
        ),
        None => None,
    };
    let opts = vault::CompactOptions {
        volume: f.volume,
        json: f.json,
        history_cutoff,
        drop_all_history: f.history_all,
    };

    // The vault DIRECTORY (parent of vault.pmv) — used for the default backup
    // location and the inside-the-vault guard. A bare relative vault path (e.g.
    // `vault.pmv`) has an EMPTY parent; map that to "." and canonicalize to an
    // absolute path so `default_backup_dir` sees real path components (otherwise the
    // default sibling backup gets wrongly flagged as inside the vault dir).
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);

    // Validate an explicit backup destination up front (a pure arg check, before
    // prompting or opening): a backup placed inside the vault dir would be copied
    // into the very tree being rewritten.
    if let Some(d) = &f.backup_dest
        && dest_inside(&dir, &PathBuf::from(d))
    {
        anyhow::bail!("--backup destination must be OUTSIDE the vault directory");
    }

    // --- Dry run: open READ-ONLY (no lock contention), report, write nothing. ---
    if f.dry_run {
        let pw1 = read_password("Password 1: ")?;
        let pw2 = read_password("Password 2: ")?;
        let v = OpenVault::open_read_only(path.clone(), pw1.as_bytes(), pw2.as_bytes())?;
        let report = v.compact_dry_run(&opts);
        print_compact_report(&report, &opts, true, None);
        return Ok(());
    }

    // --- Real run: writable open (takes the single-writer lock + rolls forward any
    // pending rekey), optional backup, then the compaction itself. ---
    let pw1 = read_password("Password 1: ")?;
    let pw2 = read_password("Password 2: ")?;
    let mut v = OpenVault::open(path.clone(), pw1.as_bytes(), pw2.as_bytes())?;

    // Skip the backup + rewrite entirely when there is genuinely nothing to do.
    let pre = v.compact_dry_run(&opts);
    if pre.bytes_reclaimed == 0 && pre.history_removed == 0 {
        eprintln!("Nothing to reclaim (no dead volume bytes, no history to trim).");
        return Ok(());
    }

    // Auto-backup the encrypted tree first (unless opted out). This MUST happen
    // before the staged rewrite creates `.rekey` — `vault::backup` refuses while a
    // rekey is staged. Default destination: a sibling `<name>-backups/` dir.
    let mut backup_path = None;
    if !f.no_backup {
        // Resolve the destination (explicit, or the default sibling) and validate it
        // is OUTSIDE the vault dir for BOTH sources, right before the write. The
        // earlier check only covered an explicit --backup; the DEFAULT must be gated
        // too (it could resolve inside via a crafted/symlinked layout), and checking
        // adjacent to the call shrinks the validate-vs-write window.
        let dest = f.backup_dest.as_ref().map(PathBuf::from).unwrap_or_else(|| default_backup_dir(&dir));
        if dest_inside(&dir, &dest) {
            anyhow::bail!("backup destination must be OUTSIDE the vault directory");
        }
        // `v.backup(...)`, NOT the free `vault::backup(...)`: this session already holds
        // the single-writer lock, and the free function re-acquires it. flock binds to the
        // open file description, so a second in-process acquire returns WouldBlock →
        // `Locked`, reported as "another writable session already has this vault open" —
        // naming a session that does not exist. That made the DEFAULT path of this
        // destructive command fail outright and funnelled users to `--no-backup`, i.e. an
        // irreversible volume re-pack / history trim with no backup at all. The GUI and TUI
        // were fixed for exactly this (audit R-9); this call site was missed.
        let bp = v.backup(&dest)?;
        eprintln!("Backed up to {} before compacting.", bp.display());
        backup_path = Some(bp);
    }

    let report = v.compact(&opts)?;
    print_compact_report(&report, &opts, false, backup_path.as_deref());
    Ok(())
}

/// Print a compaction report. `dry` switches the verbs between "would" and the
/// past tense; the partition transition is shown only for a real volume run.
fn print_compact_report(r: &vault::CompactReport, opts: &vault::CompactOptions, dry: bool, backup: Option<&Path>) {
    if opts.volume {
        if dry {
            eprintln!("Would reclaim {} bytes of dead volume data.", r.bytes_reclaimed);
        } else {
            eprintln!(
                "Reclaimed {} bytes of dead volume data ({} -> {} partitions).",
                r.bytes_reclaimed, r.partitions_before, r.partitions_after
            );
        }
    }
    if opts.json {
        let verb = if dry { "Would remove" } else { "Removed" };
        eprintln!("{verb} {} history entries.", r.history_removed);
    }
    if let Some(b) = backup {
        eprintln!("Backup written to {}", b.display());
    }
}

/// Default backup destination for `compact`: a sibling `<name>-backups/` directory
/// next to the vault directory, so it is never inside the tree being rewritten.
fn default_backup_dir(vault_dir: &Path) -> PathBuf {
    let name = vault_dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "vault".to_string());
    match vault_dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(format!("{name}-backups")),
        _ => PathBuf::from(format!("{name}-backups")),
    }
}

/// Whether `dest` is the vault directory itself or a path inside it (a backup
/// there would be copied into the very tree being rewritten). Best-effort: uses
/// canonical paths when both exist, else a lexical prefix check.
fn dest_inside(vault_dir: &Path, dest: &Path) -> bool {
    // Both sides are resolved AS FAR AS THE FILESYSTEM ALLOWS (see `resolve_existing`),
    // never by text alone.
    //
    // This used to canonicalize both and fall back to a purely LEXICAL comparison when
    // either failed. A destination almost never exists yet — it is a fresh export or
    // backup directory — so the lexical path was the normal one, and it folds `..` and
    // absolutizes without ever touching the filesystem. A destination reached through a
    // SYMLINKED PARENT therefore compared as "outside" while physically resolving inside
    // the vault directory, and `extract`/`export-tree` would write a full cleartext
    // mirror (vault.json holds every password) right next to vault.pmv — exactly what
    // this guard exists to prevent, since the user's next backup of the vault folder
    // sweeps the plaintext up with it.
    let v = resolve_existing(vault_dir);
    let d = resolve_existing(dest);
    d == v || d.starts_with(&v)
}

/// Resolve `path` as far as it exists: canonicalize the deepest ancestor that is really
/// there (following symlinks, folding `..` truthfully) and re-append the components below
/// it, folding any `.`/`..` left in that non-existent tail lexically.
///
/// Canonicalizing the whole path is not an option — the interesting paths here are ones
/// that have not been created yet — and comparing them purely as text is what let a
/// symlinked parent slip past. This gives the filesystem the final say over every
/// component that exists, which is every component that can carry a symlink.
fn resolve_existing(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(path)
    };
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = abs.clone();
    loop {
        if let Ok(real) = std::fs::canonicalize(&cur) {
            let mut out = real;
            // `suffix` was collected from the leaf upward, so replay it in reverse.
            for part in suffix.iter().rev() {
                out.push(part);
            }
            return lexical_normalize(&out);
        }
        // Not there (yet): peel one component and try the parent.
        match cur.file_name() {
            Some(name) => suffix.push(name.to_os_string()),
            // No file name (root, or a trailing `..`): nothing left to peel.
            None => return lexical_normalize(&abs),
        }
        if !cur.pop() {
            return lexical_normalize(&abs);
        }
    }
}

/// Absolutize `path` against the current directory and fold away `.` and `..`
/// components purely lexically (no filesystem access, so it works for paths that do
/// not exist yet). Used by [`dest_inside`] when the destination cannot be canonicalized.
fn lexical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };
    for comp in path.components() {
        match comp {
            Component::CurDir => {}                       // drop "."
            Component::ParentDir => { out.pop(); }        // resolve ".." lexically
            Component::RootDir | Component::Prefix(_) => out.push(comp.as_os_str()),
            Component::Normal(c) => out.push(c),
        }
    }
    out
}

/// Decrypt stored documents and write them into `out_dir`, reconstructing the
/// virtual directory tree. With `part = Some(n)` only partition `n`'s volume is
/// decrypted; with `None`, every partition. Prompts for both passwords.
/// WARNING: this writes unencrypted copies of the documents to disk.
fn cli_extract(path: PathBuf, out_dir: PathBuf, part: Option<u32>) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("no vault found at {}", path.display());
    }
    // Refuse a symlinked OUT root (audit R4-1: a pre-planted symlink would redirect the
    // decrypted documents outside the chosen dir) and refuse extracting INTO the live vault
    // directory (audit R4-4: plaintext next to vault.pmv gets swept into the next backup).
    vault::reject_symlink_dir(&out_dir)?;
    if let Some(vault_dir) = path.parent()
        && dest_inside(vault_dir, &out_dir)
    {
        anyhow::bail!("extract destination must be OUTSIDE the vault directory");
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

    // Snapshot the directory BEFORE writing so a failure warning names only what this run
    // created, not the user's pre-existing files (audit F1).
    let before = dir_entry_names(&out_dir);
    std::fs::create_dir_all(&out_dir)?;
    vault::harden_dir(&out_dir); // 0700 on unix (filenames/paths are sensitive)
    // The write loop is not transactional: a mid-loop failure leaves already-extracted
    // documents on disk in the clear. Run it in a closure so an error can trigger the
    // same partial-cleartext warning as export-tree (audit L1) before propagating.
    let write_docs = || -> anyhow::Result<usize> {
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
            let dest = unique_path(out_dir.join(rel), Some(&meta.id));
            // `.parent()` is the containing directory, if any. `if let Some(parent)`
            // runs only when there is one, binding it for use inside the block.
            if let Some(parent) = dest.parent() {
                // Reject a symlinked intermediate dir before create_dir_all, so a symlink
                // seeded in a shared OUT dir can't redirect decrypted plaintext outside it.
                vault::reject_symlinked_descendants(&out_dir, parent)?;
                std::fs::create_dir_all(parent)?;
                vault::harden_dir(parent);
            }
            // Reuse the vault's hardened writer: create_new (O_EXCL, no symlink
            // follow) + 0600, removing any partial fragment on a write error.
            vault::write_new_bytes(&dest, bytes)?;
            eprintln!("  {}", dest.display());
            written += 1;
        }
        Ok(written)
    };
    match write_docs() {
        Ok(written) => {
            eprintln!("Extracted {written} document(s) to {}", out_dir.display());
            Ok(())
        }
        Err(e) => {
            warn_partial_plaintext(&out_dir, &before);
            Err(e)
        }
    }
}

/// Decrypt the WHOLE vault into a plaintext mirror at `out_dir` that mirrors the
/// encrypted layout: `vault.json` + `manifest/manifest.<N>.json` +
/// `volume/vol.<N>/<id>`. Round-trips with `import-tree`. Prompts for both
/// passwords. WARNING: writes everything UNENCRYPTED (see DESIGN.md §9.17).
fn cli_export_tree(path: PathBuf, out_dir: PathBuf) -> anyhow::Result<()> {
    if !path.exists() {
        anyhow::bail!("no vault found at {}", path.display());
    }
    // Refuse exporting the whole-vault cleartext mirror INTO the live encrypted vault directory:
    // it would strand vault.json (every password) + the per-tab CSVs next to vault.pmv, where the
    // user's next backup/sync of that directory sweeps the plaintext up — and then abort on the
    // volume/ name collision anyway (audit R4-4). Mirror cmd_compact's backup-destination guard.
    // (export_tree itself rejects a symlinked OUT root — audit R4-1.)
    if let Some(vault_dir) = path.parent()
        && dest_inside(vault_dir, &out_dir)
    {
        anyhow::bail!("export-tree destination must be OUTSIDE the vault directory");
    }
    eprintln!(
        "Decrypting the ENTIRE vault into {} — vault.json + manifests + volume blobs + a documents/ \
         folder tree + per-tab CSVs, all UNENCRYPTED.",
        out_dir.display()
    );
    let pw1 = read_password("Password 1: ")?;
    let pw2 = read_password("Password 2: ")?;
    // Snapshot the directory BEFORE writing so a failure warning names only what this run
    // created, not the user's pre-existing files (audit F1).
    let before = dir_entry_names(&out_dir);
    // export_tree writes plaintext incrementally and is NOT transactional: a mid-walk
    // failure (ENOSPC, a bit-rotted frame failing AEAD, a symlinked dir, …) can leave
    // PARTIAL unencrypted files already on disk. If anything landed, warn loudly so the
    // user securely deletes it rather than assuming "error ⇒ nothing was written" (audit L1).
    if let Err(e) = vault::OpenVault::export_tree(&path, pw1.as_bytes(), pw2.as_bytes(), &out_dir) {
        warn_partial_plaintext(&out_dir, &before);
        return Err(e.into());
    }
    eprintln!("Wrote a decrypted mirror to {} (re-encrypt it with `import-tree`).", out_dir.display());
    Ok(())
}

/// Snapshot the names of the top-level entries currently in `dir` (an empty set if `dir`
/// does not exist). Captured BEFORE a plaintext export so [`warn_partial_plaintext`] can
/// attribute exactly which entries *this run* created — never the user's own pre-existing,
/// unrelated files (audit F1).
fn dir_entry_names(dir: &std::path::Path) -> std::collections::HashSet<std::ffi::OsString> {
    std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.file_name()).collect()
}

/// After a failed plaintext export, warn about the cleartext entries THIS run wrote — the
/// top-level entries that appeared since the `before` snapshot. Stays silent when nothing
/// new landed (a clean first-write failure, or a pre-existing dir we never added to), and
/// names only the new entries so the user is never told to delete their own pre-existing
/// files. Audit L1 (warn at all) + F1 (attribute precisely). All `export_tree`/extract
/// writes create new top-level entries (`vault.json`, `manifest/`, `volume/`, `documents/`,
/// `csv/`, or the per-document subtree), so a top-level diff captures every addition.
fn new_entries_since(out_dir: &std::path::Path, before: &std::collections::HashSet<std::ffi::OsString>) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(out_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name())
        .filter(|name| !before.contains(name))
        .map(|name| out_dir.join(name))
        .collect()
}

fn warn_partial_plaintext(out_dir: &std::path::Path, before: &std::collections::HashSet<std::ffi::OsString>) {
    let new_entries = new_entries_since(out_dir, before);
    // A top-level-name diff only catches entries this run CREATED. If OUT already held an
    // entry of the same top-level name (e.g. a `documents/`/`csv/` dir from a prior export),
    // `export_tree` writes fresh cleartext INTO that pre-existing subtree and the diff misses
    // it entirely — so a non-empty pre-existing OUT means cleartext may have landed where we
    // cannot attribute it precisely. Warn conservatively in that case, even when no NEW
    // top-level entry appeared (audit 2026-07-03 A-9; extends L1/F1).
    let preexisting_may_hold_cleartext = !before.is_empty();
    if new_entries.is_empty() && !preexisting_may_hold_cleartext {
        return; // truly nothing of ours could have landed
    }
    eprintln!("WARNING: the export failed after possibly writing PARTIAL UNENCRYPTED files to {}:", out_dir.display());
    for p in &new_entries {
        eprintln!("    {}  (created by this run)", p.display());
    }
    if preexisting_may_hold_cleartext {
        eprintln!(
            "    NOTE: {} already contained entries before this run. The export may have \
             written cleartext INTO those pre-existing directories too, which cannot be \
             listed separately — treat the ENTIRE directory as potentially holding \
             decrypted secrets.",
            out_dir.display()
        );
    }
    eprintln!(
        "Securely delete the cleartext (e.g. `shred -u` each file, `srm -r` the directories) \
         before discarding."
    );
}

/// Build a NEW encrypted vault (at `dest`'s directory) from a plaintext mirror at
/// `src_dir` (as produced by `export-tree`), under two NEW passwords. Refuses to
/// overwrite an existing vault.
fn cli_import_tree(src_dir: PathBuf, dest: PathBuf) -> anyhow::Result<()> {
    if !src_dir.join("vault.json").exists() {
        anyhow::bail!("no vault.json in {} (expected an `export-tree` mirror)", src_dir.display());
    }
    if dest.exists() {
        anyhow::bail!("a vault already exists at {}", dest.display());
    }
    eprintln!("Creating a new encrypted vault at {} from {}.", dest.display(), src_dir.display());
    eprintln!("Choose TWO NEW passwords for the new vault (entered in sequence).");
    let pw1 = read_password("New password 1: ")?;
    let pw2 = read_password("New password 2: ")?;
    let params = pass_mgr::crypto::KdfParams::default();
    vault::OpenVault::import_tree(&src_dir, &dest, pw1.as_bytes(), pw2.as_bytes(), params)?;
    eprintln!("Imported. The new vault directory is {}.", dest.parent().unwrap_or(&dest).display());
    Ok(())
}

/// `update-from OTHER [DIR]` — update DIR's vault from ANOTHER vault: pull records that are
/// newer (or new) in OTHER, plus the documents they reference. One-way and ADDITIVE (never
/// deletes from DIR). With `dry_run`, opens BOTH read-only and only prints the patch.
///
/// Prompts FOUR passwords in a fixed, documented order so it is scriptable: DIR's two
/// (the destination), then OTHER's two (the source). The destination is opened writable
/// (single-writer lock); the source is always opened read-only.
fn cli_update_from(other_dir: PathBuf, current_path: PathBuf, dry_run: bool) -> anyhow::Result<()> {
    let other_path = vault_file(&other_dir.to_string_lossy());
    // Make BOTH targets unambiguous before any password prompt or write.
    eprintln!("pass-mgr: update target vault   → {}", current_path.display());
    eprintln!("pass-mgr: read updates FROM     → {}", other_path.display());
    if !current_path.exists() {
        anyhow::bail!("no vault to update at {}", current_path.display());
    }
    if !other_path.exists() {
        anyhow::bail!("no source vault at {}", other_path.display());
    }
    // Refuse to merge a vault into itself (a no-op that almost certainly signals a
    // mistaken DIR). Compare canonicalized paths when possible, else the raw paths.
    let same = match (std::fs::canonicalize(&current_path), std::fs::canonicalize(&other_path)) {
        (Ok(a), Ok(b)) => a == b,
        _ => current_path == other_path,
    };
    if same {
        anyhow::bail!("the source and target are the same vault — nothing to update");
    }

    // Four prompts, fixed order (target first, then source) — load-bearing for piped use:
    //   printf 'dpw1\ndpw2\nopw1\nopw2\n' | pass-mgr update-from OTHER DIR
    let dpw1 = read_password("Target (this vault) password 1: ")?;
    let dpw2 = read_password("Target (this vault) password 2: ")?;
    let opw1 = read_password("Other (source) password 1: ")?;
    let opw2 = read_password("Other (source) password 2: ")?;

    // The source is ALWAYS read-only (a different fd/path — no lock contention with the
    // target). For a dry run the target is read-only too (no lock, no writes).
    let source = OpenVault::open_read_only(other_path.clone(), opw1.as_bytes(), opw2.as_bytes())?;

    if dry_run {
        let current = OpenVault::open_read_only(current_path.clone(), dpw1.as_bytes(), dpw2.as_bytes())?;
        let plan = current.plan_merge_from(&source)?;
        print_merge_plan(&plan, true);
        return Ok(());
    }

    // Real run: open the target WRITABLE (single-writer lock + rolls forward any pending
    // rekey), show the patch, then apply + save atomically.
    let mut current = OpenVault::open(current_path.clone(), dpw1.as_bytes(), dpw2.as_bytes())?;
    let plan = current.plan_merge_from(&source)?;
    print_merge_plan(&plan, false);
    if plan.is_empty() {
        return Ok(()); // nothing to apply (skipped-only plans print their reasons above)
    }
    let report = current.apply_merge_from(&source)?;
    eprintln!(
        "Applied: {} new, {} updated record(s); {} document(s) copied ({} bytes); {} type(s) added.{}",
        report.records_added,
        report.records_updated,
        report.blobs_copied,
        report.bytes_copied,
        report.categories_added,
        if report.records_skipped > 0 { format!(" {} record(s) skipped.", report.records_skipped) } else { String::new() },
    );
    Ok(())
}

/// Print a merge [`MergePlan`](pass_mgr::merge::MergePlan) for the `update-from` preview /
/// pre-apply summary. `dry` switches the verbs between "would" and the imperative. Shows
/// the records to change (label + recency), the documents to copy, and any skipped records
/// with their reason. Record labels never include secret field values.
fn print_merge_plan(plan: &pass_mgr::merge::MergePlan, dry: bool) {
    let verb = if dry { "would change" } else { "will change" };
    if plan.is_empty() && plan.skipped.is_empty() {
        eprintln!("Already up to date — no records in the source are newer or new.");
        return;
    }
    let short = plan.source_vault_id.get(..8).unwrap_or(plan.source_vault_id.as_str());
    eprintln!(
        "Update from vault {short}: {verb} {} record(s) ({} new, {} updated) and copy {} document(s) ({} bytes).",
        plan.records.len(),
        plan.new_count(),
        plan.updated_count(),
        plan.blobs_to_copy(),
        plan.bytes_to_copy(),
    );
    for r in &plan.records {
        // `current_updated_at` is None for a brand-new record.
        let recency = match r.current_updated_at {
            Some(cur) => format!("{} → {}", fmt_unix(cur), fmt_unix(r.source_updated_at)),
            None => format!("new @ {}", fmt_unix(r.source_updated_at)),
        };
        eprintln!("  [{}] {} — {} ({recency})", r.change.as_str(), r.kind.as_str(), r.label);
    }
    if !plan.blobs.is_empty() {
        eprintln!("  documents:");
        for b in &plan.blobs {
            let state = if b.already_present { "present" } else { "copy" };
            eprintln!("    [{state}] {} ({} bytes)  {}", b.id, b.size, b.path);
        }
    }
    if !plan.new_categories.is_empty() {
        eprintln!("  category types to add (so the merged records' types show in Config):");
        for c in &plan.new_categories {
            eprintln!("    + {c}");
        }
    }
    if !plan.skipped.is_empty() {
        eprintln!("  skipped (not applied):");
        for s in &plan.skipped {
            eprintln!("    {} — {} — {}", s.kind.as_str(), s.label, s.reason);
        }
    }
}

/// Format a unix-seconds timestamp as a compact UTC date-time (`YYYYMMDD-HHMMSS`) for CLI
/// output — the same human-readable UTC stamp the document paths use.
fn fmt_unix(at: i64) -> String {
    pass_mgr::records::compact_utc(at)
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
        // Neutralize control + bidi/zero-width spoof chars (e.g. U+202E RLO) in the final
        // name, matching `export_document_into`: a crafted manifest path must not write a
        // SPOOFED on-disk filename (report<RLO>txt.exe) or inject terminal escapes into the
        // extract list this CLI prints. The checks above already rejected empty/separator/
        // reserved on the un-mapped form, and `display_safe` only turns control/spoof chars
        // into '_', so it cannot reintroduce any of those.
        Some(pass_mgr::records::display_safe(trimmed))
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
/// extraction never silently overwrites a just-written file. `fallback_token` (a
/// document id) disambiguates when the `_1.._9999` range is exhausted, so >10000
/// documents sharing one virtual path can't EEXIST-abort the whole extract and strand
/// cleartext (audit R5-2 — the desktop twin of the core `unique_export_path` F2 fix).
fn unique_path(p: PathBuf, fallback_token: Option<&str>) -> PathBuf {
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
    // Range exhausted (>10000 files share this name). Disambiguate with the unique doc
    // id if the caller supplied one, so the O_EXCL write can't EEXIST-abort; otherwise
    // fall back to the colliding path (the prior behavior).
    match fallback_token {
        Some(t) => {
            let candidate = parent.join(format!("{stem}_{t}{ext}"));
            if candidate.exists() { p } else { candidate }
        }
        None => p,
    }
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
        let n = std::io::stdin().lock().read_line(&mut line)?;
        // EOF with no bytes (piped fewer lines than prompts) would otherwise yield a SILENT
        // empty password and a confusing downstream AEAD failure — fail loudly instead.
        if n == 0 {
            anyhow::bail!("unexpected end of input while reading {prompt}");
        }
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
    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    // RAII guard: restore cooked/echo mode on EVERY exit path — including a panic unwinding
    // out of event::read()/crossterm. Without it a panic between enable_raw_mode and the
    // explicit restore would leave the user's shell in raw, no-echo mode (they'd have to
    // blindly run `reset`/`stty sane`), and a password typed into a following command could
    // be mishandled. Mirrors the panic-safe terminal restore ratatui::init() gives the TUI.
    struct RawModeGuard;
    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            let _ = disable_raw_mode(); // idempotent: harmless if already restored below
        }
    }

    enable_raw_mode()?;
    let _guard = RawModeGuard;
    // Pre-reserve so per-keystroke `push` never grows the buffer: a reallocation frees the
    // old backing store (holding the password prefix) WITHOUT zeroizing it, and `Zeroizing`
    // only wipes the final allocation on drop. 256 covers any realistic passphrase (mirrors
    // the GUI's `reserve` mitigation on its secret fields).
    let mut input = Zeroizing::new(String::with_capacity(256));
    // `loop {}` runs forever until a `break` exits it; `break value` makes the loop
    // *evaluate to* that value, which is assigned to `outcome` here.
    let outcome: anyhow::Result<()> = loop {
        match event::read() {
            // Match an `Ok(Event::Key(k))` only when the extra `if` guard holds
            // (a key *press*, not a release/repeat). The inner `match` then
            // dispatches on which key it was.
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break Ok(()),
                // Ctrl+C / Ctrl+D cancel the prompt. In raw mode ISIG is off, so the kernel
                // does NOT turn Ctrl+C into SIGINT — it arrives as Char('c')+CONTROL. Without
                // this arm it would push a literal 'c'/'d' into the invisible password buffer,
                // silently corrupting an otherwise-correct passphrase. Treat like Esc.
                KeyCode::Char('c' | 'd') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    input.clear();
                    break Err(anyhow::anyhow!("input cancelled"));
                }
                // Ignore any other control-modified key (Ctrl+U/Ctrl+W/…) instead of inserting a
                // literal char; only real text reaches the buffer.
                KeyCode::Char(_) if k.modifiers.contains(KeyModifiers::CONTROL) => {}
                // `KeyCode::Char(c)` binds the typed character to `c`.
                KeyCode::Char(c) => input.push(c),
                KeyCode::Backspace => {
                    input.pop();
                }
                // Esc ABORTS the prompt (distinct from Enter-on-empty): return a
                // cancellation error so the caller stops cleanly rather than proceeding
                // with an empty password toward, e.g., a destructive `compact` run.
                KeyCode::Esc => {
                    input.clear();
                    break Err(anyhow::anyhow!("input cancelled"));
                }
                // `_` is the wildcard arm: ignore every other key.
                _ => {}
            },
            // Non-key events are ignored; a read error breaks out carrying the error.
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
    };
    // Restore cooked mode before the trailing newline so it prints normally (the guard is a
    // panic-path backstop; this explicit call keeps the newline ordering and is idempotent).
    disable_raw_mode()?;
    eprintln!();
    // Propagate a cancellation / read error now (after raw mode is restored), then hand back.
    outcome?;
    Ok(input)
}

/// Test-only affordance behind the `__holdlock` subcommand (compiled only with
/// `--features fault-injection`). Opens `DIR`'s vault read-WRITE — acquiring the OS
/// advisory single-writer lock for this process's lifetime — prints `LOCKED`, then
/// blocks until stdin reaches EOF before dropping the handle (releasing the lock). Lets
/// `tests/lock_cross_process.rs` hold the lock from a genuine second OS process. `pos`
/// is `["__holdlock", <DIR>]`; the test's fixed `a`/`b` passwords are used.
#[cfg(feature = "fault-injection")]
fn holdlock(pos: &[String]) -> anyhow::Result<()> {
    use std::io::{BufRead, Write};
    let dir = pos.get(1).cloned().ok_or_else(|| anyhow::anyhow!("holdlock: missing DIR"))?;
    // Open writable: this acquires the single-writer lock and holds it via `_held`.
    let _held = OpenVault::open(vault_file(&dir), b"a", b"b")?;
    let mut out = std::io::stdout();
    writeln!(out, "LOCKED")?;
    out.flush()?;
    // Block until the parent closes our stdin (EOF); then `_held` drops and unlocks.
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
    Ok(())
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
    // ~40 KB doc bodies + the 64 KiB volume floor (the smallest cap set_volume_max_size
    // allows — sub-floor values clamp up to it) so two documents can't share one partition:
    // each lands in a SEPARATE partition and the crash tests exercise new-volume creation,
    // not just appends to an existing volume. Distinct first bytes identify each doc.
    let body = |marker: u8| vec![marker; 40_000];
    match scenario {
        // Create a vault (fast KDF), shrink the volume cap, and add one committed,
        // record-referenced document (doc-one == 0xA1 x40_000) in partition 0.
        "setup" => {
            let params = pass_mgr::crypto::KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 };
            let mut v = OpenVault::create(path, b"a", b"b", params)?;
            v.set_volume_max_size(64 * 1024)?;
            std::fs::write(&src, body(0xA1))?;
            let id = v.add_document("/w", "d1.txt", &src)?;
            let mut tw = records::TrustWill::new()?;
            tw.file = Some(id);
            records::upsert(&mut v.vault.trust_wills, tw);
            v.save()?;
        }
        // Add a second document (0xB2 x40_000) — rolls into a NEW partition (vol.1)
        // given the 64 KiB floor — link it + save. Crash points put.*/vault.* fire.
        "adddoc" => {
            let mut v = OpenVault::open(path, b"a", b"b")?;
            std::fs::write(&src, body(0xB2))?;
            let id = v.add_document("/w", "d2.txt", &src)?;
            let mut tw = records::TrustWill::new()?;
            tw.file = Some(id);
            records::upsert(&mut v.vault.trust_wills, tw);
            v.save()?;
        }
        // Like `setup`, but with in-place redundancy enabled (depth 2) so the §12.8
        // mirror + generation-ring writes run. One committed, record-referenced doc.
        "setup_redundant" => {
            let params = pass_mgr::crypto::KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 };
            let mut v = OpenVault::create(path, b"a", b"b", params)?;
            v.set_volume_max_size(64 * 1024)?;
            v.set_redundancy(2)?;
            std::fs::write(&src, body(0xA1))?;
            let id = v.add_document("/w", "d1.txt", &src)?;
            let mut tw = records::TrustWill::new()?;
            tw.file = Some(id);
            records::upsert(&mut v.vault.trust_wills, tw);
            v.save()?;
        }
        // A redundancy-enabled save that adds a 2nd doc. The redundancy.* crash points
        // (rotate/bak/mirror) fire AFTER the authoritative primary commit, so an abort
        // there must still leave an openable vault with both committed docs intact.
        "redundant_save" => {
            let mut v = OpenVault::open(path, b"a", b"b")?;
            std::fs::write(&src, body(0xB2))?;
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
        // Compact (volume re-pack + drop all history). Like rekey it stages a full
        // rewrite and swaps it in, so the SAME rekey.* crash points fire mid-commit;
        // recovery must roll forward to the compacted tree with both docs intact.
        "compact" => {
            let mut v = OpenVault::open(path, b"a", b"b")?;
            let opts = vault::CompactOptions { volume: true, json: true, history_cutoff: None, drop_all_history: true };
            v.compact(&opts)?;
        }
        // Just open under the NEW passwords — triggers recover_pending_rekey, so a
        // crash point can abort recovery itself (testing idempotent re-recovery).
        "open" => {
            let _ = OpenVault::open(path, b"c", b"d")?;
        }
        // Recovery check (used by the dm-flakey power-loss harness): the vault must
        // open and the committed, record-referenced document (doc-one) must be intact.
        // A crashed password change may have rolled FORWARD (a/b -> c/d) or been
        // DISCARDED (still a/b), and either outcome is a valid recovery — so accept
        // whichever password pair opens it. A wrong pair fails the AEAD (it cannot
        // open an a/b vault with c/d), so there is no false acceptance. Exits non-zero
        // if NEITHER pair opens (real corruption) or the document is lost/mismatched.
        "verify" => {
            let v = OpenVault::open(path.clone(), b"a", b"b")
                .or_else(|_| OpenVault::open(path, b"c", b"d"))
                .map_err(|e| anyhow::anyhow!("verify: vault did not open under a/b or c/d: {e}"))?;
            let tw = v
                .vault
                .trust_wills
                .iter()
                .find(|t| t.file.is_some())
                .ok_or_else(|| anyhow::anyhow!("verify: no record-referenced document found"))?;
            let id = tw.file.clone().expect("file present");
            let got = v.read_document(&id)?;
            if got[..] != body(0xA1)[..] {
                anyhow::bail!("verify: recovered document does not match the committed doc-one");
            }
            eprintln!("verify: OK — vault opened and the committed document is intact");
        }
        // --- Cross-vault merge crash-safety ---------------------------------
        // Build a CURRENT vault (a/b) holding an OLDER record "shared" referencing
        // doc-one (0xA1), and a SOURCE vault (s/t) under <DIR>/__merge_src holding a
        // NEWER "shared" (same id) referencing a fresh doc-two (0xB2). A merge then
        // pulls the newer record + copies doc-two. The 64 KiB volume floor forces the
        // copied blob into its own partition (exercises new-volume creation on copy).
        "setup_merge" => {
            let params = pass_mgr::crypto::KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 };
            // CURRENT: older shared record, references doc-one.
            let mut v = OpenVault::create(path.clone(), b"a", b"b", params)?;
            v.set_volume_max_size(64 * 1024)?;
            std::fs::write(&src, body(0xA1))?;
            let id1 = v.add_document("/w", "d1.txt", &src)?;
            let mut tw = records::TrustWill::new()?;
            tw.id = "shared".into();
            tw.updated_at = 1000; // OLDER — pushed directly so upsert can't restamp it to now
            tw.file = Some(id1);
            v.vault.trust_wills.push(tw);
            v.save()?;
            // SOURCE: newer shared record (same id), references doc-two.
            let src_dir = PathBuf::from(&dir).join("__merge_src");
            std::fs::create_dir_all(&src_dir)?;
            let mut s = OpenVault::create(src_dir.join("vault.pmv"), b"s", b"t", params)?;
            s.set_volume_max_size(64 * 1024)?;
            std::fs::write(&src, body(0xB2))?;
            let id2 = s.add_document("/w", "d2.txt", &src)?;
            let mut tw2 = records::TrustWill::new()?;
            tw2.id = "shared".into();
            tw2.updated_at = 2000; // NEWER
            tw2.file = Some(id2);
            s.vault.trust_wills.push(tw2);
            s.save()?;
        }
        // Like `setup_merge`, but the CURRENT vault has in-place redundancy (depth 2), so the
        // merge's final save runs the §12.8 mirror + generation-ring writes — exercising the
        // redundancy.* crash points (which fire AFTER the authoritative primary commit).
        "setup_merge_redundant" => {
            let params = pass_mgr::crypto::KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 };
            let mut v = OpenVault::create(path.clone(), b"a", b"b", params)?;
            v.set_volume_max_size(64 * 1024)?;
            v.set_redundancy(2)?;
            std::fs::write(&src, body(0xA1))?;
            let id1 = v.add_document("/w", "d1.txt", &src)?;
            let mut tw = records::TrustWill::new()?;
            tw.id = "shared".into();
            tw.updated_at = 1000;
            tw.file = Some(id1);
            v.vault.trust_wills.push(tw);
            v.save()?;
            let src_dir = PathBuf::from(&dir).join("__merge_src");
            std::fs::create_dir_all(&src_dir)?;
            let mut s = OpenVault::create(src_dir.join("vault.pmv"), b"s", b"t", params)?;
            s.set_volume_max_size(64 * 1024)?;
            std::fs::write(&src, body(0xB2))?;
            let id2 = s.add_document("/w", "d2.txt", &src)?;
            let mut tw2 = records::TrustWill::new()?;
            tw2.id = "shared".into();
            tw2.updated_at = 2000;
            tw2.file = Some(id2);
            s.vault.trust_wills.push(tw2);
            s.save()?;
        }
        // Open CURRENT writable + SOURCE read-only and apply the merge. The blob-copy
        // (put.*) and final save (vault.*/redundancy.*) crash points fire mid-apply.
        "merge" => {
            let src_dir = PathBuf::from(&dir).join("__merge_src");
            let mut v = OpenVault::open(path, b"a", b"b")?;
            let source = OpenVault::open_read_only(src_dir.join("vault.pmv"), b"s", b"t")?;
            v.apply_merge_from(&source)?;
        }
        // Recovery check for the merge: CURRENT must open under a/b, and the "shared"
        // record's referenced document must be CONSISTENT with the record — either the
        // merge fully took (updated_at 2000 ⇒ doc-two) or it did not (updated_at 1000 ⇒
        // doc-one), never a half state. OpenVault::open already enforces referenced⊆stored.
        "verify_merge" => {
            let v = OpenVault::open(path, b"a", b"b")
                .map_err(|e| anyhow::anyhow!("verify_merge: current vault did not open: {e}"))?;
            let tw = v
                .vault
                .trust_wills
                .iter()
                .find(|t| t.id == "shared")
                .ok_or_else(|| anyhow::anyhow!("verify_merge: 'shared' record missing"))?;
            let id = tw.file.clone().ok_or_else(|| anyhow::anyhow!("verify_merge: 'shared' has no doc"))?;
            let got = v.read_document(&id)?;
            let merged = tw.updated_at == 2000;
            let expect = if merged { body(0xB2) } else { body(0xA1) };
            if got[..] != expect[..] {
                anyhow::bail!("verify_merge: doc mismatch for the recovered state (merged={merged})");
            }
            eprintln!("verify_merge: OK — consistent (merged={merged})");
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
    fn compact_target_rejects_implicit_default_when_value_flag_present() {
        use super::{CompactFlags, compact_target, default_vault_path, vault_file};
        let s = |v: &str| v.to_string();

        // No DIR + a value-taking flag that may have eaten it → refuse (the footgun).
        let f = CompactFlags { backup_dest: Some(s("/some/dir")), ..Default::default() };
        assert!(compact_target(&[s("compact")], &f).is_err(), "swallowed-DIR case must be rejected");
        let f2 = CompactFlags { history_before: Some(s("2026-01-01")), ..Default::default() };
        assert!(compact_target(&[s("compact")], &f2).is_err());

        // Explicit DIR alongside the value-flag → unambiguous, accepted.
        let f = CompactFlags { backup_dest: Some(s("/dest")), ..Default::default() };
        assert_eq!(
            compact_target(&[s("compact"), s("/my/vault")], &f).unwrap(),
            vault_file("/my/vault")
        );

        // Implicit default with NO value-flag → still allowed (the common case).
        let none = CompactFlags::default();
        assert_eq!(compact_target(&[s("compact")], &none).unwrap(), default_vault_path());
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
    fn safe_path_strips_bidi_and_control_chars() {
        // A crafted manifest path must not write a SPOOFED on-disk filename or inject escapes
        // into the printed extract list: U+202E (RLO) and control chars become '_', matching
        // export_document_into.
        let p = safe_relative_path("docs", "invoice\u{202e}fdp.exe", "id");
        let s = p.to_string_lossy();
        assert!(!s.contains('\u{202e}'), "bidi override stripped from extract filename: {s}");
        assert!(s.contains('_'), "spoof char replaced with '_': {s}");
        assert!(contained(&p));
        // ...also in a location (directory) component.
        let p2 = safe_relative_path("a\u{202e}b", "f.txt", "id");
        assert!(!p2.to_string_lossy().contains('\u{202e}'));
        assert!(contained(&p2));
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
        assert_eq!(super::unique_path(p.clone(), None), p);
        std::fs::write(&p, b"x").unwrap();
        // Existing path gets a `_N` suffix that doesn't yet exist.
        let u = super::unique_path(p.clone(), None);
        assert_ne!(u, p);
        assert!(!u.exists());
        assert_eq!(u.file_name().unwrap().to_str().unwrap(), "doc_1.txt");
        // With a fallback token, an existing path falls back to the id-disambiguated name
        // (the _1..9999 range still wins first; this just verifies the token is wired).
        let u2 = super::unique_path(p.clone(), Some("abc123"));
        assert_ne!(u2, p);
        assert!(!u2.exists());
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

    // (path-helper tests moved to `pass_mgr::launch`, which now owns them.)

    // ---- compact CLI flag parsing & guards ---------------------------------

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn extract_compact_flags_parses_every_flag_form() {
        let (f, rest) = super::extract_compact_flags(argv(&[
            "compact", "DIR", "--volume", "--json", "--history-before", "2025-01-01", "--no-backup", "--dry-run",
            "--backup", "/tmp/x", "extra",
        ]))
        .unwrap();
        assert!(f.volume && f.json && f.no_backup && f.dry_run && f.any());
        assert_eq!(f.history_before.as_deref(), Some("2025-01-01"));
        assert_eq!(f.backup_dest.as_deref(), Some("/tmp/x"));
        // Non-flag args are preserved in order for positional/dispatch handling.
        assert_eq!(rest, argv(&["compact", "DIR", "extra"]));
    }

    #[test]
    fn extract_compact_flags_accepts_equals_forms_and_history_all() {
        let (f, _) = super::extract_compact_flags(argv(&["--history-before=2024-12-31", "--backup=/d"])).unwrap();
        assert_eq!(f.history_before.as_deref(), Some("2024-12-31"));
        assert_eq!(f.backup_dest.as_deref(), Some("/d"));
        let (g, _) = super::extract_compact_flags(argv(&["--history-all"])).unwrap();
        assert!(g.history_all && g.any());
    }

    #[test]
    fn extract_compact_flags_errors_on_missing_values() {
        assert!(super::extract_compact_flags(argv(&["--history-before"])).is_err());
        assert!(super::extract_compact_flags(argv(&["--backup"])).is_err());
    }

    #[test]
    fn extract_compact_flags_absent_means_none_and_passthrough() {
        let (f, rest) = super::extract_compact_flags(argv(&["decrypt", "DIR"])).unwrap();
        assert!(!f.any());
        assert_eq!(rest, argv(&["decrypt", "DIR"]));
    }

    #[test]
    fn default_backup_dir_is_a_sibling_outside_the_vault() {
        let vault_dir = Path::new("/home/u/myvault");
        let d = super::default_backup_dir(vault_dir);
        assert_eq!(d, PathBuf::from("/home/u/myvault-backups"));
        assert!(!d.starts_with(vault_dir), "default backup dir must be outside the vault dir");
    }

    #[test]
    fn dest_inside_flags_self_and_children_allows_siblings() {
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let vault_dir = std::env::temp_dir().join(format!("pmdi-{nanos}"));
        std::fs::create_dir_all(&vault_dir).unwrap();
        // The vault dir itself, and an existing child, are "inside".
        assert!(super::dest_inside(&vault_dir, &vault_dir));
        let child = vault_dir.join("volume");
        std::fs::create_dir_all(&child).unwrap();
        assert!(super::dest_inside(&vault_dir, &child));
        // A not-yet-existing absolute child is still caught (lexical fallback).
        assert!(super::dest_inside(&vault_dir, &vault_dir.join("backups")));
        // A sibling directory outside the vault is allowed.
        let sibling = vault_dir.parent().unwrap().join(format!("pmdi-out-{nanos}"));
        assert!(!super::dest_inside(&vault_dir, &sibling));
        let _ = std::fs::remove_dir_all(&vault_dir);
    }

    #[test]
    fn dest_inside_catches_dot_slash_relative_child() {
        // Regression: the lexical fallback used a raw component-wise starts_with that
        // missed a leading "./", wrongly allowing a backup INSIDE the vault tree.
        // These names don't exist, so canonicalize() fails and the lexical path runs.
        let vault = Path::new("pmrel-vault-zzz");
        assert!(super::dest_inside(vault, Path::new("./pmrel-vault-zzz/inside")));
        assert!(super::dest_inside(vault, Path::new("pmrel-vault-zzz/inside")));
        // A genuinely separate relative dir is still allowed.
        assert!(!super::dest_inside(vault, Path::new("pmrel-other-zzz")));
    }

    #[test]
    fn compact_flags_any_detects_each_flag() {
        use super::CompactFlags;
        assert!(!CompactFlags::default().any(), "no flags set -> any() is false");
        // Each flag ALONE makes any() true. (Kills the `||`->`&&` mutants: with `&&`,
        // a single set flag would yield false.)
        assert!(CompactFlags { volume: true, ..Default::default() }.any());
        assert!(CompactFlags { json: true, ..Default::default() }.any());
        assert!(CompactFlags { history_before: Some("2025-01-01".into()), ..Default::default() }.any());
        assert!(CompactFlags { history_all: true, ..Default::default() }.any());
        assert!(CompactFlags { no_backup: true, ..Default::default() }.any());
        assert!(CompactFlags { backup_dest: Some("/tmp/x".into()), ..Default::default() }.any());
        assert!(CompactFlags { dry_run: true, ..Default::default() }.any());
    }

    #[test]
    fn safe_path_drops_dot_and_dotdot_components() {
        // A location or filename component that is exactly "." or ".." must be dropped,
        // never kept as a path component (kills the `||`->`&&` mutant in clean's
        // empty/"."/".." guard, which would otherwise admit traversal).
        let traversal = |p: &Path| {
            p.is_absolute()
                || p.components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir | Component::RootDir | Component::Prefix(_)))
        };
        for (loc, name) in [("..", "f.txt"), (".", "f.txt"), ("ok", ".."), ("ok", "."), ("..", "..")] {
            let p = safe_relative_path(loc, name, "fallbackid");
            assert!(!traversal(&p), "({loc:?},{name:?}) produced a traversal component: {p:?}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn dest_inside_resolves_a_symlinked_dest_via_canonical() {
        // A dest that is a SYMLINK pointing into the vault dir must be detected as
        // inside — the canonical-both arm resolves it; a purely lexical check would
        // miss it. (Kills the deletion of the `(Some(v), Some(d))` arm in dest_inside.)
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let vault = std::env::temp_dir().join(format!("pmdi-sym-{nanos}"));
        std::fs::create_dir_all(vault.join("sub")).unwrap();
        let link = std::env::temp_dir().join(format!("pmdi-symlink-{nanos}"));
        std::os::unix::fs::symlink(vault.join("sub"), &link).unwrap();
        assert!(super::dest_inside(&vault, &link), "a symlink into the vault resolves to inside");
        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&vault);
    }

    #[test]
    #[cfg(unix)]
    fn dest_inside_sees_through_a_symlinked_parent_of_a_dest_that_does_not_exist_yet() {
        // The realistic shape, and the one that used to slip through: the destination
        // has NOT been created yet (it is a fresh export/backup dir), and it is named
        // through a symlink that points into the vault directory.
        //
        // With no destination to canonicalize, the old code fell back to comparing the
        // paths as TEXT, which cannot see a symlink — so it answered "outside" and
        // `extract`/`export-tree` wrote a full cleartext mirror inside the live vault
        // directory, next to vault.pmv.
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let vault = std::env::temp_dir().join(format!("pmdi-symparent-{nanos}"));
        std::fs::create_dir_all(&vault).unwrap();

        // `link` -> the vault dir itself. `link/plaintext` does not exist.
        let link = std::env::temp_dir().join(format!("pmdi-symparentlink-{nanos}"));
        std::os::unix::fs::symlink(&vault, &link).unwrap();
        let dest = link.join("plaintext");
        assert!(!dest.exists(), "the destination must NOT exist — that is the whole case");

        assert!(
            super::dest_inside(&vault, &dest),
            "a not-yet-created destination reached through a symlinked parent resolves \
             INSIDE the vault and must be refused"
        );

        // Control: the same shape pointing somewhere else must still be allowed, so the
        // guard is not simply rejecting everything.
        let outside = std::env::temp_dir().join(format!("pmdi-symparent-out-{nanos}"));
        std::fs::create_dir_all(&outside).unwrap();
        let outlink = std::env::temp_dir().join(format!("pmdi-symparent-outlink-{nanos}"));
        std::os::unix::fs::symlink(&outside, &outlink).unwrap();
        assert!(
            !super::dest_inside(&vault, &outlink.join("plaintext")),
            "control: a symlinked parent pointing OUTSIDE the vault stays allowed"
        );

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&outlink);
        let _ = std::fs::remove_dir_all(&vault);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn cli_compact_rejects_missing_vault_then_bad_flag_combos() {
        use super::CompactFlags;
        // Missing vault: bails before any prompt/validation.
        let f = CompactFlags { volume: true, ..Default::default() };
        assert!(super::cli_compact(&argv(&["compact", "/no/such/pmvault/dir"]), &f).is_err());

        // A dummy (non-empty) vault dir so path.exists() passes; the flag-combination
        // validation below all bails BEFORE opening the vault or prompting.
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("pmclic-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vault.pmv"), b"PMVAULT\0 dummy").unwrap();
        let d = dir.to_str().unwrap();
        let bad: &[CompactFlags] = &[
            // no mode flag
            CompactFlags::default(),
            // --json without a retention choice
            CompactFlags { json: true, ..Default::default() },
            // retention flag without --json
            CompactFlags { volume: true, history_all: true, ..Default::default() },
            // both retention choices at once
            CompactFlags { json: true, history_before: Some("2025-01-01".into()), history_all: true, ..Default::default() },
            // unparseable cutoff date
            CompactFlags { json: true, history_before: Some("not-a-date".into()), ..Default::default() },
        ];
        for f in bad {
            assert!(super::cli_compact(&argv(&["compact", d]), f).is_err(), "expected validation error");
        }
        let _ = std::fs::remove_dir_all(&dir);
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

    #[test]
    fn partial_plaintext_warning_attributes_only_new_entries() {
        // Audit F1: after a failed plaintext export, only the entries THIS run created are
        // flagged — never the user's pre-existing files (so the shred advice can never
        // target their unrelated data).
        let nanos =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("passmgr-f1-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        // Pre-existing, unrelated user files in the chosen output directory.
        std::fs::write(dir.join("notes.txt"), b"mine").unwrap();
        std::fs::write(dir.join("photo.jpg"), b"mine").unwrap();
        let before = super::dir_entry_names(&dir);
        // Before any of our writes, nothing is attributed to this run.
        assert!(super::new_entries_since(&dir, &before).is_empty(), "pre-existing files are never attributed");
        // Simulate this run writing a partial mirror (a file and a subdir).
        std::fs::write(dir.join("vault.json"), b"secret").unwrap();
        std::fs::create_dir_all(dir.join("volume")).unwrap();
        let new: std::collections::HashSet<std::ffi::OsString> = super::new_entries_since(&dir, &before)
            .into_iter()
            .map(|p| p.file_name().unwrap().to_owned())
            .collect();
        assert!(new.contains(std::ffi::OsStr::new("vault.json")), "newly-written file is flagged");
        assert!(new.contains(std::ffi::OsStr::new("volume")), "newly-written dir is flagged");
        assert!(!new.contains(std::ffi::OsStr::new("notes.txt")), "pre-existing file NOT flagged");
        assert!(!new.contains(std::ffi::OsStr::new("photo.jpg")), "pre-existing file NOT flagged");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
