//! Single-instance guard for the graphical app.
//!
//! The GUI opens its window *immediately* (before the vault is even unlocked),
//! and nothing in the binary used to detect an already-running instance — so
//! launching pass-mgr repeatedly (a double-clicked launcher, a dock icon, a
//! script) stacked a separate window per launch, which the user then had to close
//! one by one. This module coalesces launches for the **same vault** into a single
//! window:
//!
//! - The first launch for a vault becomes the **primary**: it takes an OS
//!   advisory lock on a per-vault lock file (kernel-released on exit/crash, so it
//!   never goes stale — the same mechanism the vault's single-writer lock uses)
//!   and, on Unix, binds a tiny local socket.
//! - A later launch for the same vault finds the lock held → it is a
//!   **secondary**: on Unix it pings the primary's socket to raise its window,
//!   then exits without opening a second window. On other platforms it simply
//!   exits (still no pile-up, just no raise-to-front).
//!
//! Keyed on the *canonical vault path*, so two different vaults still get two
//! windows. The lock/socket live in the per-user runtime (or cache) directory and
//! carry **no vault data** — the socket only ever transports a "raise your window"
//! nudge (the connection itself is the signal; no bytes are trusted).
//!
//! The guard must never stop the app from running: any I/O problem setting it up
//! degrades to "run as an unguarded primary" (see [`acquire`]). Power users who
//! deliberately want several windows for one vault can set
//! `PMVAULT_ALLOW_MULTIPLE=1` to bypass the guard entirely.
//!
//! (Rust note: `#[cfg(unix)]` compiles an item only on Unix-like targets; the
//! `#[cfg(not(unix))]` twin provides a no-op fallback so the crate still builds
//! everywhere. A field/binding named with a leading `_` is intentionally unused —
//! here `InstanceGuard._lock` exists only so its `Drop` releases the lock.)

use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use eframe::egui;

/// The outcome of [`acquire`]: either we own this vault's window, or someone else
/// already does.
pub enum Instance {
    /// We are the sole instance for this vault. Keep `guard` alive for the whole
    /// GUI session (dropping it releases the lock), and call [`FocusServer::serve`]
    /// on `focus` once the egui context exists so later launches can raise us.
    Primary { guard: InstanceGuard, focus: FocusServer },
    /// Another instance is already running for this vault (and, on Unix, has been
    /// asked to come to the front). The caller should exit without opening a window.
    AlreadyRunning,
}

/// Holds the OS advisory lock for as long as it lives. Drop it (on normal exit)
/// to release the lock; the kernel also releases it automatically on crash.
pub struct InstanceGuard {
    // Never read — present only for its `Drop`, which closes the file handle and
    // thereby releases the advisory lock (mirrors `vault::WriteLock`).
    _lock: Option<fs::File>,
}

impl InstanceGuard {
    /// A guard that locks nothing (used when the guard can't be set up but the
    /// app should still run).
    fn unguarded() -> Self {
        InstanceGuard { _lock: None }
    }
}

/// Serves "raise the window" requests from later launches. Created by [`acquire`]
/// for the primary; moved into the eframe creation closure so it can be started
/// once the live egui [`egui::Context`] exists.
pub struct FocusServer {
    // Only Unix has the local socket; on other targets this struct is empty and
    // `serve` is a no-op.
    #[cfg(unix)]
    listener: Option<std::os::unix::net::UnixListener>,
}

impl FocusServer {
    /// A server bound to nothing (non-Unix, or when binding failed).
    fn none() -> Self {
        FocusServer {
            #[cfg(unix)]
            listener: None,
        }
    }

    /// Start serving raise-to-front requests, given the live egui context. Call
    /// once, from the eframe creation closure. No-op without a bound socket.
    pub fn serve(self, ctx: egui::Context) {
        #[cfg(unix)]
        {
            if let Some(listener) = self.listener {
                // A detached background thread: it blocks on `accept` and is torn
                // down when the process exits. Each connection is a secondary
                // asking us to come to the front — we don't read/trust any bytes.
                std::thread::spawn(move || {
                    for stream in listener.incoming() {
                        match stream {
                            Ok(_) => {
                                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                                ctx.request_repaint();
                            }
                            // A persistent accept error would otherwise spin this
                            // loop; stop serving focus rather than burn a core (the
                            // lock still prevents new windows — only the
                            // raise-to-front nicety stops).
                            Err(_) => break,
                        }
                    }
                });
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctx; // nothing to serve without a socket
        }
    }
}

/// Try to become the single instance for `vault_path`. Never fails for the
/// caller: any I/O problem (or the `PMVAULT_ALLOW_MULTIPLE` escape hatch) yields an
/// *unguarded* [`Instance::Primary`] so the app still runs.
pub fn acquire(vault_path: &Path) -> Instance {
    if env_flag("PMVAULT_ALLOW_MULTIPLE") {
        return Instance::Primary { guard: InstanceGuard::unguarded(), focus: FocusServer::none() };
    }
    match base_dir().and_then(|dir| acquire_in(&dir, vault_path)) {
        Ok(inst) => inst,
        Err(e) => {
            eprintln!("pass-mgr: single-instance guard unavailable ({e}); continuing without it.");
            Instance::Primary { guard: InstanceGuard::unguarded(), focus: FocusServer::none() }
        }
    }
}

/// The lock/socket logic, split from [`acquire`] so tests can point it at a
/// throwaway directory instead of the real per-user runtime dir.
fn acquire_in(dir: &Path, vault_path: &Path) -> io::Result<Instance> {
    let key = instance_key(vault_path);
    let lock_path = dir.join(format!("instance-{key}.lock"));

    // Same rationale as the vault's write-lock: never truncate (would race a
    // concurrent holder's handle); just ensure the file exists and is lockable.
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&lock_path)?;

    match file.try_lock() {
        Ok(()) => {
            // We're the sole instance for this vault. Best-effort: bind the focus
            // socket so future launches can raise our window.
            let focus = serve_socket(dir, &key);
            Ok(Instance::Primary { guard: InstanceGuard { _lock: Some(file) }, focus })
        }
        // Someone else holds it: ask them to come to the front, then report back so
        // the caller exits without opening a second window.
        Err(fs::TryLockError::WouldBlock) => {
            request_focus(dir, &key);
            Ok(Instance::AlreadyRunning)
        }
        Err(fs::TryLockError::Error(e)) => Err(e),
    }
}

/// The directory holding the lock/socket: prefer the volatile per-user runtime dir
/// (cleared on logout), then the cache dir, then the system temp dir. Made 0700.
fn base_dir() -> io::Result<PathBuf> {
    let dir = match ProjectDirs::from("dev", "passmgr", "pass-mgr") {
        Some(pd) => pd
            .runtime_dir()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| pd.cache_dir().to_path_buf()),
        None => std::env::temp_dir(),
    };
    fs::create_dir_all(&dir)?;
    crate::vault::harden_dir(&dir); // 0700 on Unix; no-op elsewhere
    Ok(dir)
}

/// A short, stable, filesystem-safe token identifying a vault. We hash the
/// canonical path (best-effort): two launches naming the same vault — even via
/// different relative paths or symlinks — must produce the same token so they
/// rendezvous on the same lock. The hash is for *naming*, not security, so the
/// fixed-seed std hasher is fine (and must be identical across processes).
fn instance_key(vault_path: &Path) -> String {
    let canonical = canonical_best_effort(vault_path);
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    canonical.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn canonical_best_effort(path: &Path) -> PathBuf {
    if let Ok(c) = fs::canonicalize(path) {
        return c;
    }
    // The vault may not exist yet (first run / create). Anchor on the canonical
    // parent + the final component so the token is still stable and absolute.
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name())
        && let Ok(cp) = fs::canonicalize(parent)
    {
        return cp.join(name);
    }
    // Last resort: make it absolute against the cwd (lexically), else use as-is.
    std::env::current_dir().map(|d| d.join(path)).unwrap_or_else(|_| path.to_path_buf())
}

fn env_flag(name: &str) -> bool {
    match std::env::var_os(name) {
        Some(v) => {
            let s = v.to_string_lossy();
            !s.is_empty() && s != "0"
        }
        None => false,
    }
}

// --- Unix focus socket -------------------------------------------------------

#[cfg(unix)]
fn socket_path(dir: &Path, key: &str) -> PathBuf {
    dir.join(format!("instance-{key}.sock"))
}

#[cfg(unix)]
fn serve_socket(dir: &Path, key: &str) -> FocusServer {
    use std::os::unix::net::UnixListener;
    let path = socket_path(dir, key);
    // We hold the lock, so any socket file here is stale (a previous primary that
    // exited). Remove it before binding; ignore "not found".
    let _ = fs::remove_file(&path);
    match UnixListener::bind(&path) {
        Ok(listener) => {
            harden_socket(&path);
            FocusServer { listener: Some(listener) }
        }
        // Binding is a nicety; if it fails we still hold the lock (no pile-up) —
        // we just can't raise the window from a later launch.
        Err(_) => FocusServer::none(),
    }
}

#[cfg(not(unix))]
fn serve_socket(_dir: &Path, _key: &str) -> FocusServer {
    FocusServer::none()
}

#[cfg(unix)]
fn harden_socket(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600); // owner-only; the runtime dir is already 0700
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(unix)]
fn request_focus(dir: &Path, key: &str) {
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    let path = socket_path(dir, key);
    // The primary may hold the lock but not yet have bound its socket (it starts a
    // hair later). Retry briefly so the raise-to-front lands; give up quietly
    // otherwise (the lock already told us another instance exists).
    for _ in 0..10 {
        match UnixStream::connect(&path) {
            Ok(mut stream) => {
                let _ = stream.write_all(b"focus");
                return;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
        }
    }
}

#[cfg(not(unix))]
fn request_focus(_dir: &Path, _key: &str) {}

// --- Tests -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A unique throwaway directory for the lock/socket files.
    fn tmp() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("pmsi-{nanos}-{n}"));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn first_launch_is_primary_second_is_secondary_then_primary_again() {
        let dir = tmp();
        let vault = dir.join("vault.pmv");

        let first = acquire_in(&dir, &vault).unwrap();
        assert!(matches!(first, Instance::Primary { .. }), "first launch should own the instance");

        // While the first guard is alive, a second acquire for the SAME vault must
        // detect it and refuse to become primary.
        let second = acquire_in(&dir, &vault).unwrap();
        assert!(matches!(second, Instance::AlreadyRunning), "second launch should see the first");

        // Releasing the primary frees the lock for a fresh launch.
        drop(first);
        let third = acquire_in(&dir, &vault).unwrap();
        assert!(matches!(third, Instance::Primary { .. }), "after release, a new launch is primary");
    }

    #[test]
    fn different_vaults_get_separate_instances() {
        let dir = tmp();
        let a = acquire_in(&dir, &dir.join("a.pmv")).unwrap();
        let b = acquire_in(&dir, &dir.join("b.pmv")).unwrap();
        assert!(matches!(a, Instance::Primary { .. }));
        assert!(matches!(b, Instance::Primary { .. }), "a different vault is independently primary");
    }

    #[test]
    fn instance_key_is_stable_and_path_specific() {
        let a1 = instance_key(Path::new("/tmp/some/where/vault.pmv"));
        let a2 = instance_key(Path::new("/tmp/some/where/vault.pmv"));
        let b = instance_key(Path::new("/tmp/some/other/vault.pmv"));
        assert_eq!(a1, a2, "same path must hash to the same token across calls");
        assert_ne!(a1, b, "different paths must not collide");
    }

    #[test]
    fn env_flag_reads_truthy_values() {
        assert!(!env_flag("PMVAULT_DEFINITELY_UNSET_VAR_XYZ"));
    }
}
