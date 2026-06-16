#!/usr/bin/env bash
#
# dm-flakey power-loss crash test for pass-mgr.
# =============================================
#
# WHY THIS EXISTS
# ---------------
# The in-tree crash tests (`tests/crash_recovery.rs`) abort the process with
# `std::process::abort()` (SIGKILL-class). That models the PROCESS dying, but the OS
# still flushes its page cache afterward — so a *missing or wrong `fsync`* is invisible
# to those tests (and to mutation testing: an `fsync` removed by a mutant changes no
# in-process behaviour). The ONLY way to verify the fsync/ordering is genuinely correct
# is to simulate a real power loss where **un-fsync'd writes never reach the platter**.
#
# This harness does exactly that, using Linux device-mapper `dm-flakey`:
#   1. pass-mgr's vault lives on an ext4 fs on a dm-flakey device.
#   2. A workload runs with the device in normal pass-through mode (its `fsync`s reach
#      the backing store; un-fsync'd writes sit in the page cache).
#   3. "Power loss": the device is reloaded with the `drop_writes` feature and the fs is
#      unmounted — the unmount flushes the page cache, but the device DISCARDS those
#      writes. Result: the on-disk state contains only what pass-mgr actually fsync'd.
#   4. The device is restored to normal, the fs remounted, and the vault is reopened.
#      It MUST still open and the committed document MUST still be intact. If pass-mgr
#      were missing an fsync, that data would be gone here and `verify` would fail.
#
# It also crashes mid-operation at each named commit point (`PMVAULT_CRASH_AT`, the
# same labels the in-tree tests use) so the power loss lands at a precise commit step.
#
# REQUIREMENTS
# ------------
#   * Linux, run as ROOT (it uses losetup / dmsetup / mount / mkfs.ext4).
#   * A nightly-or-stable cargo toolchain (only to build the test binary).
#   * Tools: dmsetup, losetup, mkfs.ext4, mount, umount, blockdev.
#
# USAGE
# -----
#   sudo tests/dmflakey_powerloss.sh
#
# Optional env vars:
#   PASSMGR_BIN=/path/to/pass-mgr   use a prebuilt binary (must be built with
#                                   `--features fault-injection`; default: build it)
#   BACKING_DIR=/var/tmp            where the backing image lives (real storage is best;
#                                   it is the simulated "disk")
#   KEEP=1                          don't tear down the dm/loop devices on exit (debug)
#
# SAFETY: everything is created under unique names and removed by the EXIT trap; it
# never touches your real vault or any existing block device.

set -euo pipefail

# ---- config -----------------------------------------------------------------
NAME="pmflakey$$"                       # unique dm + mount name for this run
BACKING_DIR="${BACKING_DIR:-/var/tmp}"
BACKING="$BACKING_DIR/$NAME.img"
MNT="$BACKING_DIR/$NAME.mnt"
DM="$NAME"
DEV="/dev/mapper/$DM"
SIZE_MB=128
SECTORS=$(( SIZE_MB * 1024 * 1024 / 512 ))
TABLE_NORMAL="0 $SECTORS flakey @LOOP@ 0 1 0"                 # always up, pass-through
TABLE_DROP="0 $SECTORS flakey @LOOP@ 0 1 0 1 drop_writes"     # always up, silently drop writes
LOOP=""
PASS=0
FAIL=0

log()  { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }

# ---- prerequisites ----------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: must run as root (uses losetup/dmsetup/mount). Try: sudo $0" >&2
  exit 2
fi
for t in dmsetup losetup mkfs.ext4 mount umount blockdev; do
  command -v "$t" >/dev/null || { echo "ERROR: missing required tool: $t" >&2; exit 2; }
done

# Build (or locate) the test binary. It needs the fault-injection feature for __crashop.
BIN="${PASSMGR_BIN:-}"
if [[ -z "$BIN" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  log "Building pass-mgr (--release --features fault-injection)"
  ( cd "$SCRIPT_DIR" && cargo build --release --features fault-injection >&2 )
  BIN="$SCRIPT_DIR/target/release/pass-mgr"
fi
[[ -x "$BIN" ]] || { echo "ERROR: binary not found/executable: $BIN" >&2; exit 2; }
echo "Using binary: $BIN"

# ---- teardown ---------------------------------------------------------------
cleanup() {
  set +e
  mountpoint -q "$MNT" && umount "$MNT" 2>/dev/null
  [[ -e "$DEV" ]] && dmsetup remove "$DM" 2>/dev/null
  [[ -n "$LOOP" ]] && losetup -d "$LOOP" 2>/dev/null
  if [[ "${KEEP:-0}" != "1" ]]; then
    rm -f "$BACKING"; rmdir "$MNT" 2>/dev/null
  else
    echo "KEEP=1: left $BACKING / $MNT / loop $LOOP in place"
  fi
}
trap cleanup EXIT

# ---- bring up the flakey device ---------------------------------------------
log "Setting up loop + dm-flakey device ($SIZE_MB MiB ext4)"
mkdir -p "$MNT"
truncate -s "${SIZE_MB}M" "$BACKING"
LOOP="$(losetup --find --show "$BACKING")"
TABLE_NORMAL="${TABLE_NORMAL/@LOOP@/$LOOP}"
TABLE_DROP="${TABLE_DROP/@LOOP@/$LOOP}"
dmsetup create "$DM" --table "$TABLE_NORMAL"
mkfs.ext4 -q -F "$DEV"
# commit=999 delays the ext4 journal/writeback so un-fsync'd data lingers in cache
# until our explicit "power loss", widening the window the test depends on.
mount -o commit=999 "$DEV" "$MNT"
echo "Mounted $DEV at $MNT (loop $LOOP)"

# ---- the power-loss primitive ----------------------------------------------
# Reload the device to drop_writes, unmount (page cache flushed -> discarded by the
# device), then restore pass-through and remount the surviving on-disk state.
power_loss_remount() {
  dmsetup suspend "$DM"
  dmsetup load "$DM" --table "$TABLE_DROP" >/dev/null
  dmsetup resume "$DM"
  umount "$MNT"                       # dirty (un-fsync'd) pages flushed -> dropped
  dmsetup suspend "$DM"
  dmsetup load "$DM" --table "$TABLE_NORMAL" >/dev/null
  dmsetup resume "$DM"
  mount -o commit=999 "$DEV" "$MNT"
}

# ---- one test case ----------------------------------------------------------
# args: <description> <setup-scenario> <op-scenario> <crash-label-or-empty>
run_case() {
  local desc="$1" setup="$2" op="$3" label="$4"
  local vault="$MNT/vault-$RANDOM"
  rm -rf "$vault"; mkdir -p "$vault"

  # 1) Baseline: create the vault + one committed, fsync'd document. Force it durable.
  "$BIN" __crashop "$setup" "$vault" >/dev/null 2>&1
  sync; sync

  # 2) Run the operation; abort it mid-commit at `label` (or run it fully if empty).
  #    Its fsync'd writes reach the device; un-fsync'd writes stay in the page cache.
  if [[ -n "$label" ]]; then
    PMVAULT_CRASH_AT="$label" "$BIN" __crashop "$op" "$vault" >/dev/null 2>&1 || true
  else
    "$BIN" __crashop "$op" "$vault" >/dev/null 2>&1 || true
  fi

  # 3) Power loss: drop everything that was not fsync'd.
  power_loss_remount

  # 4) Recovery must succeed and the committed document must be intact.
  if "$BIN" __crashop verify "$vault" >/dev/null 2>&1; then
    ok "$desc"
  else
    bad "$desc  (vault did not recover cleanly — possible missing fsync / ordering bug)"
  fi
  rm -rf "$vault"
}

# ---- the matrix -------------------------------------------------------------
log "Power-loss recovery matrix"
# Plain vault: the storage commit + vault save fsync surface.
run_case "adddoc, clean op then power loss"        setup           adddoc vault.rename
run_case "adddoc crash @ put.after_append"         setup           adddoc put.after_append
run_case "adddoc crash @ put.after_commit"         setup           adddoc put.after_commit
run_case "adddoc crash @ vault.write"              setup           adddoc vault.write
run_case "adddoc crash @ vault.rename"             setup           adddoc vault.rename
run_case "adddoc, full op (no crash) + power loss" setup           adddoc ""
# Rekey / compaction roll-forward fsync surface (passwords may roll a->c; this case
# only asserts the baseline doc-one survives, which holds in both old and rolled trees).
run_case "rekey crash @ rekey.after_volume"        setup           rekey  rekey.after_volume
run_case "compact crash @ rekey.after_manifest"    setup           compact rekey.after_manifest
# In-place redundancy write surface.
run_case "redundant save crash @ redundancy.rotate"  setup_redundant redundant_save redundancy.rotate
run_case "redundant save crash @ redundancy.bak"     setup_redundant redundant_save redundancy.bak
run_case "redundant save crash @ redundancy.mirror"  setup_redundant redundant_save redundancy.mirror
run_case "redundant save, full op + power loss"      setup_redundant redundant_save ""

# ---- summary ----------------------------------------------------------------
log "Summary"
echo "  passed: $PASS    failed: $FAIL"
if [[ "$FAIL" -ne 0 ]]; then
  echo "  -> a FAIL means the vault did not recover from a simulated power loss:" >&2
  echo "     committed data was lost or the vault would not open, which points to a" >&2
  echo "     missing/incorrect fsync or a commit-ordering bug. Investigate before shipping." >&2
  exit 1
fi
echo "  All power-loss scenarios recovered cleanly."
