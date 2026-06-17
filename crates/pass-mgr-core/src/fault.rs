//! Fault injection for crash-safety / corruption tests.
//!
//! This module exposes a single hook, [`point`], that the storage and vault
//! commit paths call at each on-disk mutation step. With the `fault-injection`
//! cargo feature **disabled** (the default, and every release build) `point` is a
//! `#[inline(always)]` no-op that returns `Ok(())` — zero cost, compiled away.
//!
//! With the feature **enabled** (tests only, `cargo test --features
//! fault-injection`) `point(label)` can do one of two things, to model the two
//! failure classes the vault must survive:
//!
//! - **Full disk (`ENOSPC`)** — if a test has armed a matching `label` via
//!   [`fail_at`], `point` returns an I/O error, exactly as a real write to a full
//!   disk would. The operation must then fail cleanly, leaving the prior on-disk
//!   state intact and recoverable. Tested **in-process**.
//! - **Force-kill / power loss** — if the environment variable `PMVAULT_CRASH_AT`
//!   equals `label`, `point` calls [`std::process::abort`]: an instant termination
//!   with no unwinding, no `Drop`, and no buffered flush — the closest in-process
//!   model of a `SIGKILL` / abrupt shutdown. Used only by **subprocess**
//!   crash-recovery tests (the parent spawns the binary with the env var set,
//!   expects it to die at the chosen commit step, then reopens and asserts the
//!   vault recovered).

#[cfg(feature = "fault-injection")]
mod imp {
    use std::cell::Cell;
    use std::io;

    thread_local! {
        // (label, remaining hits): while remaining > 0, a matching `point(label)`
        // returns ENOSPC and decrements. One-shot by default (count == 1).
        static FAIL: Cell<Option<(&'static str, u32)>> = const { Cell::new(None) };
    }

    /// Arm an in-process I/O failure: the next `count` calls to `point(label)`
    /// return an `ENOSPC`-style error. Use `clear()` to disarm.
    pub fn fail_at(label: &'static str, count: u32) {
        FAIL.with(|f| f.set(Some((label, count))));
    }

    /// Disarm any pending injected failure on this thread.
    pub fn clear() {
        FAIL.with(|f| f.set(None));
    }

    /// A fault point named `label`. See the module docs for the two behaviours.
    pub fn point(label: &str) -> io::Result<()> {
        // Force-kill / power-loss model (subprocess tests): abort immediately.
        if std::env::var("PMVAULT_CRASH_AT").ok().as_deref() == Some(label) {
            std::process::abort();
        }
        // Full-disk model (in-process tests): return ENOSPC if armed for `label`.
        if let Some((l, n)) = FAIL.with(|f| f.get())
            && l == label
            && n > 0
        {
            FAIL.with(|f| f.set((n - 1 > 0).then_some((l, n - 1))));
            return Err(io::Error::other(format!("injected disk-full (ENOSPC) at {label}")));
        }
        Ok(())
    }
}

#[cfg(not(feature = "fault-injection"))]
mod imp {
    use std::io;

    /// No-op in normal/release builds: every fault point is a free pass-through.
    #[inline(always)]
    pub fn point(_label: &str) -> io::Result<()> {
        Ok(())
    }
}

pub use imp::*;
