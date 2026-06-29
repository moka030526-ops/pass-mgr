# Deep Audit (Round 4) — 2026-06-29

The deepest pass: **12 fresh lenses** on the least-examined subsystems (CLI dispatch,
cross-process locking/TOCTOU, TUI & GUI rendering robustness, `csv.rs`/`merge.rs`/`records.rs`
in depth, time/number edge cases, fault-injection release-gating, DoS/resource exhaustion,
`migrate`, and the FFI mobile boundary) plus **4 cross-cutting invariant verifiers** that
trace a single global property through *all* code. Every candidate was independently
verified by 3 skeptical agents (2-of-3 to survive). Run after rounds 1–3 had converged.

**Result.** The 12 fresh lenses found **nothing** — the encryption, AEAD/AAD domain
separation, rollback/truncation detection, untrusted-mirror parsing, locking, delete
rollback, and the four invariants (plaintext-confinement, zeroization, atomic-save,
tombstone-never-surfaces) all held. **All 4 surviving findings cluster on one newer
feature** — the whole-vault plaintext mirror (`export_tree`/`import_tree`, commit
`2ae73ab`), which post-dates the converged rounds and reintroduced the round-1 **M1**
symlink-on-write-path class. **2 Medium, 2 Low — all fixed in this commit** with regression
tests.

---

## Methodology

**Empirical pass.**

| Tool | Scope | Result |
|------|-------|--------|
| `cargo fuzz` | `parse_manifest`, `parse_frame`, `scan_volume` (extended) | **0 crashes** — 3.5M / 5.06M / 3.42M executions |
| `cargo mutants` | **crypto.rs + storage.rs** (the security core, full) | **41 caught + 3 timeout-caught, 3 unviable, 1 missed** — the 1 miss is `Key::drop`'s zeroization, correct-by-construction but not unit-observable (freed memory). Near-complete mutation coverage of the crypto + parser core |
| `cargo test --workspace` | every crate | **all green** (incl. the new R4 regression tests) |

**Static / invariant pass.** A multi-agent workflow ran 12 lenses + 4 invariant verifiers
(34 agents), each candidate 3-skeptic verified. The lenses returned clean; the only
confirmed findings came from the plaintext-confinement invariant verifier and the
completeness critic's follow-up hunts — all on `export_tree`/`import_tree`.

---

## Findings (all fixed)

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| R4-1 | Medium | `export_tree` followed a symlinked OUT **root** → whole-vault cleartext escaped + target chmod'd 0700 | **Fixed** |
| R4-2 | Medium | `export_tree`'s authoritative `manifest/`,`volume/`,`csv/` subdirs followed a pre-planted symlinked component | **Fixed** |
| R4-3 | Low | `import_tree` silently dropped orphan docs from a **tail-truncated** mirror (contiguity guard only caught a *middle* gap) | **Fixed** |
| R4-4 | Low | `export-tree`/`extract` into the **live vault dir** stranded cleartext next to `vault.pmv` | **Fixed** |

### R4-1 (Medium) — symlinked export root

`export_tree` did `create_dir_all(out)` → `harden_dir(out)` → write cleartext with no
symlink check on `out` itself (`create_dir_all`/`harden_dir` follow symlinks; `O_EXCL`
guards only the final filename). A local process winning a symlink pre-plant on a
predictable/reused export path caused the next `export-tree` to write the **entire** vault
(every password/record/blob/CSV) into the attacker's directory and chmod it 0700 —
whole-vault confidentiality breach (source read-only, no data loss). `backup()` already
guards its root; `export_tree` did not.

**Fix.** `reject_symlink_dir(out)` before `create_dir_all`, exactly as `backup()` does. The
same root guard was added to the sibling write paths the finding flagged: `cli_extract` and
`write_export_bytes` (the CSV exporter). Test: `export_tree_refuses_a_symlinked_out_root`.

### R4-2 (Medium) — symlinked authoritative subdirs

`export_tree` created `manifest/`, `volume/vol.N/`, and `csv/` with bare `create_dir_all`
and no symlink guard — even though the *cosmetic* `documents/` copy was guarded. A
pre-planted `out/volume` (or `out/manifest`, `out/csv`) symlink redirected the decrypted
blobs / manifest / password-bearing CSVs outside the export root. (Commit `2ae73ab` intended
this guard but it reached only the cosmetic copy.)

**Fix.** `reject_symlinked_descendants(out, …)` before each subdir `create_dir_all`, matching
`export_document_into` / `cli_extract` / `write_human_tree_copy`. Test:
`export_tree_refuses_a_symlinked_subdir`.

### R4-3 (Low) — tail-truncated mirror silently dropped orphan documents

`import_tree` walked partitions `0..p` stopping at the first absent manifest, then rejected
non-contiguity *only* by detecting a surviving **higher** manifest (a missing *middle*
partition). A mirror missing only its **tail** partitions is a clean contiguous prefix the
guard cannot catch — import reported success while omitting every unreferenced (orphan)
document in the dropped tail. The only producer is a *failed* `export_tree` (which already
warns to shred the partial mirror), so the trigger is narrow — but import should fail closed.

**Fix.** `export_tree` now records the authoritative partition count in a
`manifest/partitions` sidecar **before** writing any partition; `import_tree` requires the
number of partitions read to equal it (a mirror lacking the count — legacy/hand-built —
keeps the middle-gap-only guard, so no false rejections). A partial export thus leaves the
full count but fewer partitions → import rejects. Test:
`import_tree_rejects_a_tail_truncated_mirror`.

### R4-4 (Low) — export/extract into the live vault directory

`cli_export_tree` / `cli_extract` lacked the `dest_inside` guard that `cmd_compact`'s backup
path uses. `export-tree vault.pmv <vault-dir>` wrote cleartext `vault.json` (every password)
next to `vault.pmv`, then aborted on the `volume/` name collision — leaving plaintext inside
the live tree where the user's next backup/sync sweeps it up (no data loss; `create_new`
never clobbers the encrypted files, and the partial-cleartext warning already fires).

**Fix.** Both CLI commands now `bail` when the destination resolves inside the vault
directory (canonical + lexical, via the existing `dest_inside`), mirroring `cmd_compact`.

---

## Examined and found clean (this round)

CLI subcommand dispatch & path resolution; cross-process lock / single-instance TOCTOU;
TUI and GUI rendering robustness (terminal geometry, unicode width, index/scroll math, NaN
in Summary); `csv.rs` anti-formula + quoting; `merge.rs` one-way-additive data-loss
invariants; `records.rs`/`types.rs` serialization & the additive category sync; time/date/
number extremes; `fault.rs` release-gating (no production-reachable fault point); DoS/
resource amplification (the round-1 O(N²) fixes verified intact); `migrate-doc-paths`; the
FFI panic/secret/threading boundary; and the four cross-cutting invariants. No issue
survived verification in any of these. The codebase has converged.
