# Fuzzing pass-mgr's untrusted-input parsers

Every byte the vault reads from disk is attacker-influenceable, so the four
hand-written parsers are fuzzed. The invariant is strict: **arbitrary bytes must
only ever produce `Ok`/`Err` — never a panic, hang, or unbounded allocation.**

## Targets (`fuzz/fuzz_targets/`)

| Target | Wraps | Surface |
|---|---|---|
| `parse_header` | `vault::fuzz::header` → `Header::parse` | the 61-byte vault header (magic, version, KDF-param bounds) |
| `parse_frame` | `storage::fuzz::frame` → `parse_plaintext` | the length-prefixed decrypted volume frame `[id_len][id][path_len][path][bytes]` (highest OOB/over-alloc risk) |
| `parse_manifest` | `storage::fuzz::manifest` → `serde_json::from_slice::<Manifest>` | the decrypted manifest JSON |
| `scan_volume` | `storage::fuzz::scan_volume` → `scan_volume` | the volume rebuild path (frame length prefix + bounds + seek/advance) over arbitrary bytes |
| `doc_paths` | `records::{doc_slug,doc_filename,doc_upload_dir}` | virtual-path sanitization invariants over arbitrary subfolder/filename strings |
| `merge_from` | `OpenVault::plan_merge_from` + `apply_merge_from` | the cross-vault merge over an attacker-shaped SOURCE vault (arbitrary record ids / `updated_at` / duplicates + a document). Invariant: the destination always reopens (never corrupted) and nothing panics |

> **Note on `merge_from`:** unlike the pure-parser targets (millions of execs/min), this one
> builds two real encrypted vaults and runs a full merge per iteration, so it does real crypto
> + disk I/O and runs at roughly **1–10 exec/s**. Budget more wall-clock (or fewer execs)
> accordingly; it complements — does not replace — the `parse_*` parser coverage.

## Run

Requires nightly + `cargo install cargo-fuzz`.

```bash
# Build all targets
cargo +nightly fuzz build

# Fuzz one target for a fixed CI budget, seeded from the committed corpus:
cargo +nightly fuzz run parse_frame fuzz/seeds/parse_frame -- -max_total_time=60 -max_len=4096

# Just replay the seeds (no fuzzing) to confirm none crash:
cargo +nightly fuzz run parse_frame fuzz/seeds/parse_frame -- -runs=0
```

A 60 s × 4-target campaign has been run clean (~62M executions, zero crashes).
Suggested CI budget: 60–300 s per target on each run, seeded from `fuzz/seeds/`.

## Corpus / seeds

- `fuzz/seeds/<target>/` — a small, **committed** seed corpus (valid + edge-case
  inputs) so a fuzz run starts from good coverage. Hand-crafted; safe to extend.
- `fuzz/corpus/` and `fuzz/artifacts/` — the libFuzzer-generated working corpus
  and any crash reproducers; **git-ignored** (regenerable). If a run finds a
  crash, copy the artifact into `fuzz/seeds/<target>/` as a permanent regression
  seed and fix the parser.
