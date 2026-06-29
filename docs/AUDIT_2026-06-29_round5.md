# Deep Audit (Round 5) — 2026-06-29

The deepest pass yet: an **adversarial self-review of the round-4 fixes** plus **byte-exact
lenses** over the surfaces the prior rounds touched least — crypto AAD/domain-separation
injectivity, storage frame/offset arithmetic, the compaction path, information disclosure,
panic-safety / lock-poisoning, and the crafted-`vault.json` serde surface. Verifiers were
empowered to write and run repro code. Run after rounds 1–4 had converged.

**Result.** The R4 fixes verified **sound (0 regressions)**, and every deep lens came back
**clean** — no AAD collision, no storage-arithmetic overflow, no compaction data-loss, no
secret/path leak in errors/Debug/panics, no panic-corruption or lock-poison hang. Only **2
Low, pre-existing** findings survived (both surfaced by the completeness critic), plus **1
test-robustness issue** found empirically by the amplified property run. **All three are
fixed in this commit** with regression tests.

---

## Methodology

**Empirical pass.**

| Tool | Scope | Result |
|------|-------|--------|
| `cargo mutants` | **records.rs** (the serialization/validation core, not previously mutated) | **36 tested, all caught** before the 40-min cap (clean subset) |
| amplified `cargo test` | every `prop_*` property at **20000–50000 cases** + the metamorphic suite | metamorphic 8/8; properties all hold — but exposed a **test-harness** bug (below) |

The amplified property run **found a real issue in the test harness** (not the product):
`prop_generate_length_and_charset` used `prop_assume!(≥1 class)` to discard the all-classes-
off combo (1/16 of cases); past proptest's default 1024 global-reject limit the test **aborts
("Too many global rejects")**, so the password generator was silently **un-stress-testable**
above ~the default 256 cases. The generator itself is correct (16k+ cases passed before the
abort). Fixed by deriving the four class flags from a non-zero 4-bit mask — zero rejects, so
the generator is now verifiable at any case count.

**Static / self-review pass.** A multi-agent workflow ran 4 adversarial self-reviews of the
R4 fixes + 9 byte-exact/deep lenses (24 agents), each candidate 3-skeptic verified with repro
code. Self-review and all 9 lenses returned clean; the only findings came from the critic.

---

## Findings (all fixed)

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| R5-1 | Low | `import_tree`/open had no manifest **entry-count** cap → a crafted mirror of millions of tiny docs drives O(M²) → CPU DoS (round-1 L3, never fixed) | **Fixed** |
| R5-2 | Low | desktop `extract`'s `unique_path` never got the L2/F2 **id-token fallback** → >10000 docs sharing a virtual path abort extract and strand cleartext | **Fixed** |
| (test) | — | `prop_generate_length_and_charset` aborted above ~1024 cases (proptest reject limit) | **Fixed** |

### R5-1 (Low) — missing manifest entry-count cap (round-1 L3)

The manifest is bounded only by the 256 MiB **byte** cap, which still admits millions of
minimal (~70-byte) entries. The per-document `put`/import loop re-serializes + re-encrypts
the whole partition manifest each time (O(M) per entry, **O(M²)** overall), and a crafted
mirror can pack every doc into one partition by adopting a huge `volume_max_size`. A
deliberately-imported untrusted mirror of a few million entries could therefore hang
import/open/merge/compact for hours — availability-only (killable, no data loss, vault never
corrupted), which is why round 1 filed it Low and "planned".

**Fix.** Added `MAX_MANIFEST_ENTRIES = 100_000` (per partition — orders of magnitude above
any real vault) and enforce it **on deserialize**, failing closed with `TooLarge` before the
quadratic loop: in `storage::load_manifest` (covers open/compact/rekey/merge-source) and in
`import_tree`'s untrusted-mirror manifest parse. Test:
`import_tree_rejects_a_manifest_with_too_many_entries`.

### R5-2 (Low) — extract collision aborts and strands cleartext

`cli_extract` writes each document via `unique_path`, which disambiguates collisions with a
`_1.._9999` suffix and, on exhaustion, returned the **colliding** path → the O_EXCL write
fails `EEXIST` and aborts the whole extract mid-loop, leaving ~10000 cleartext files on disk
and skipping the rest. The core `export_tree` path got an id-token fallback in round-3 (F2),
but the desktop `unique_path` twin never did. Loud (the partial-cleartext warning lists every
stranded file), no vault data loss; bounded to a pathological >10000-identical-path vault.

**Fix.** Gave `unique_path` the same `fallback_token: Option<&str>` as `unique_export_path`
(append `_<id>` on range exhaustion) and pass the document id at the `cli_extract` call site,
so the authoritative extract can never `EEXIST`-abort on a collision.

---

## Examined and found clean (this round)

The R4 symlink guards, partition-count, and `dest_inside` (no TOCTOU beyond the accepted
posture, no missed path, the count file robust against crafted content); crypto AAD/domain-
separation injectivity and `Header` byte-layout; storage frame/offset/size arithmetic;
compaction (no live-doc loss, tombstones purged, crash-safe); information disclosure (no
secret/key/path in errors, Debug, panics, or status lines — `OpenVault` deliberately has no
`Debug`); panic-safety & lock behaviour (atomic temp+rename holds across a panic; the
single-writer lock is RAII-released; no poisoning hang); the crafted-`vault.json` serde
surface (size-capped before parse, sanitization holds); the GUI/TUI crafted-content paths;
and the FFI mobile lifecycle. After five adversarial rounds the codebase has converged —
the surviving items are Low availability/robustness polish, not confidentiality, integrity,
or the owner's non-destructive guarantee.
