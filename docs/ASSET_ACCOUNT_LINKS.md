# Asset ↔ Account Links — Design

_Status: implemented. Added 2026-07-03. Schema stays at format version 4._

## 1. Problem

Assets and liabilities usually have online accounts behind them — the brokerage
login for an investment, the bank login for the checking account that funds a
mortgage payment. Until now the vault had **no way to connect them**: the
`AssetLiability` and `Account` records lived side by side, and the only prior
art was Real Estate's `income_account` / `financing_account` / `payment_account`
fields — plain **free-text strings** that name an account but are never
validated against the Accounts tab and can silently drift when the account is
renamed.

This feature adds a first-class, navigable link: an asset/liability can be
linked to any number of accounts, both front-ends (GUI and TUI) can jump from
the asset to a linked account and back, and the export/merge/history machinery
treats the link as real data.

## 2. Chosen design

`AssetLiability` gains one field:

```rust
/// Ids of the Account records this entry is linked to.
#[serde(default)]
pub linked_accounts: Vec<String>,
```

This is the vault's **first record→record reference** (every earlier reference
is record→document-blob: `statement`, `file`, `documents`). It works because
record ids are load-bearing identity in this codebase:

- ids are 128-bit CSPRNG hex (`records::random_id`), stamped once at creation
  and **never regenerated** — `upsert` replaces slots by id, nothing renumbers;
- the cross-vault merge copies records **verbatim, id included** ("a shared id
  reliably denotes the same logical record", `merge.rs`), so a link made in one
  copy of a vault still resolves after merging into another copy.

Links are stored **on the asset side only** and edited there. The account side
shows a computed, read-only reverse view ("Linked from") produced by scanning
`vault.assets` on demand — the same no-stored-back-pointers approach as the
category-usage counts (`asset_type_usage` etc.), so there is no second copy of
the relationship to drift out of sync.

Two shared helpers in `records.rs` keep the display convention in one place:

- `account_label(accounts, id) -> Option<String>` — id → "Title - Type -
  Username" (the account's `Record::label()`); `None` for a dangling id.
- `assets_linking_account(assets, account_id) -> Vec<(id, label)>` — the
  reverse lookup feeding the "Linked from" views and the delete-time warning.

## 3. Alternatives considered (and why not)

| Alternative | Why rejected |
|---|---|
| Single `account_id: Option<String>` (1:1) | An asset plausibly relates to several accounts (login + funding account). The `Vec` costs nothing extra in any layer. |
| Match on `institution`/title heuristics (no schema change) | Guess-work; repeats the Real-Estate free-text anti-pattern this feature exists to improve on. |
| Generic top-level `links: Vec<{from, to, kind}>` collection | Most general (could later cover Real Estate → accounts too) but a whole new record kind touching merge/FFI/every tab — overkill for one relationship. Revisit if a second link kind ever appears. |

## 4. Semantics

### 4.1 Deletion — warn and tolerate, never cascade

Deleting an account that assets still link to is **allowed but surfaced**.
Neither front-end had any delete confirmation before this feature (Delete was
immediate everywhere), so each surfaces the warning in its own idiom:

- **GUI**: deleting a *linked* account arms a red warning ("linked from N
  asset/liability record(s) … will show as unresolved ids") with **Delete
  anyway** / **Cancel**; unlinked accounts (and every other tab) still delete
  immediately, exactly as before.
- **TUI**: `d` stays immediate (its file-wide convention — no modal exists);
  the linked-from count is captured before the remove and reported with the
  outcome in the status line ("Deleted. Linked from N … now show as
  unresolved"). Promoting this to a pre-delete confirm would mean introducing
  the TUI's first modal flow — noted as possible future work.

The links themselves are **not** touched — no cascade,
no auto-unlink — for two reasons:

1. the user's standing data-integrity policy (additive, no silent loss,
   flag-don't-delete);
2. delete/rollback safety: the existing account-delete flow re-inserts the
   removed record verbatim if the persist fails. Because we mutate nothing
   besides the account itself, that rollback stays trivially correct.

A link whose account no longer resolves is rendered as the **raw id** — visible
but obviously stale — mirroring the tolerant `doc_path(id).unwrap_or(id)`
fallback the doc lists already use. It can be unlinked manually at any time.

### 4.2 Merge (`update-from`) — verbatim, tolerant, last-writer-wins

The merge is record-granular: an applied record replaces the destination slot
verbatim, so `linked_accounts` travels with its record — no union, no per-field
reconciliation. Consequences, accepted deliberately:

- **Shared-lineage ids resolve.** If vault B's asset links account X and A
  lacks X, the merge brings X in with its id intact (accounts and assets are
  applied in the same pass), so the link resolves in A.
- **Independently-created twins don't.** Two vaults that each created "the
  same" account by hand have different ids; after a merge the link points at
  the imported record, not the local twin.
- **Dangling links can arrive.** The merge planner validates only document ids
  (`docs_of`/`resolve` skip-machinery); there is no record→record validation
  arm. A merged asset may carry a link to an account absent from the
  destination — it renders as a raw id, exactly like a post-delete dangling
  link. (Blocking the record, as the doc machinery does, would contradict the
  additive policy; a warn-only planner arm is possible future work.)
- **Whole-record last-writer-wins.** If A edited an asset's fields and B edited
  only its links, whichever copy has the greater `updated_at` wins entirely.
  Field-level merging does not exist anywhere in the vault; links are not
  special.

### 4.3 History, trim, and audit hygiene

- A link change is logged in the record history as a **content-free** line —
  `"linked accounts changed"` — following the `statement`-document precedent
  (raw ids are meaningless in a history line and would only add noise).
- `trim_fields` leaves `linked_accounts` untouched (link ids are bookkeeping,
  not free text; a "trimmed" id would dangle). Covered by a regression test.
- `referenced_doc_ids` (compaction + the open-time `referenced ⊆ stored`
  fail-closed check) must **never** include link ids — they are record ids, not
  volume blobs; misclassifying them would brick every vault with links. The
  coverage proptest now sets `linked_accounts` on its generated assets and
  asserts the exact doc-id count, guarding this permanently.

### 4.4 Export

- **CSV** (`assets_csv`): a new `linked_accounts` column (after `statement`,
  matching struct order) holds the accounts' **display labels** joined with
  `"; "`. A dangling id is exported as the **raw id** — visible, not dropped
  (deliberately different from doc columns, whose unresolved ids are
  meaningless outside the volume and export as empty).
- **JSON** (`decrypt`/`export-tree`/`import-tree`): serde-driven, automatic.
  One asymmetry to know about: a tree exported by **this** build and imported
  by an **older** build silently drops the field (old serde ignores unknown
  keys). Same-or-newer builds round-trip it.

### 4.5 Backward compatibility

`#[serde(default)]` keeps every pre-feature vault loadable (missing field →
empty vec); the on-disk schema stays **format version 4**, per the project's
established recipe for additive fields (`title`, `url`, `beneficiary`,
`review`). `format_compat.rs` now includes an old-style asset without the field.

## 5. Front-end design

### 5.1 GUI (egui)

- **Asset editor**: a "Linked accounts" section next to the document block —
  one row per link showing the account label with **Open** (always) and
  **Unlink** (writable only) buttons, plus an add-link ComboBox listing
  not-yet-linked accounts by label. All mutations and jumps go through a
  deferred request enum handled after rendering (the `DocSectionReq` idiom), and
  links live in the `edit_asset` buffer until Save like every other field.
- **Open (jump)**: sets the Accounts tab + loads the record into the editor.
  Two verified pitfalls are handled: active Accounts filters are retargeted so
  the record is visible in the left list (`sync_account_filters_to` pattern),
  and the reveal/doc-input resets that the top bar performs on a *user* tab
  switch are re-applied manually (a programmatic tab change bypasses its
  `prev_tab` comparison).
- **Account editor**: a read-only **"Linked from"** block (only when non-empty)
  listing the assets that link this account, each with an Open button jumping
  back to the asset.
- **Delete**: the account-delete confirmation appends "linked from N
  asset/liability record(s); those links will show as unresolved ids".

### 5.2 TUI (ratatui)

- **Edit/view screen (Assets)**: a numbered cyan "Linked accounts (N)" sub-list
  between the attached-document line and the History block (same rendering as
  the Taxes/Real-Estate doc lists), each id resolved to the account label with
  raw-id fallback.
- **Editing**: an "Add link" Choice field (←/→ cycles candidate accounts; a
  parallel id list keeps label collisions unambiguous) and a "Link #" selector
  field, appended so that **every existing positional field index is
  preserved** (the Assets form is index-coupled in commit/validation/doc-path
  code). Keys, following the edit screen's Ctrl-combo convention:
  - **Ctrl+L** — link the selected account (writable-gated),
  - **Ctrl+O** — open link `#N` (allowed read-only; leaves the editor with the
    same discard semantics Esc already has),
  - **Ctrl+X** — unlink `#N` (writable-gated).
- **Jump**: switches to the Accounts tab, relaxes any filters hiding the target
  (the same filter-relaxing logic `save_edit` already uses), and selects its
  row. A dangling link shows a status-line message and stays put.
- **Account view**: read-only "Linked from (N)" sub-list (display-only — no
  jump-back key, unlike the GUI's Open buttons); delete reporting per §4.1.
  Read-only quirk: typing is inert in read-only mode, so read-only Ctrl+O can
  only follow link **#1** (the blank-`Link #` default) — same limitation the
  Doc# field already has for read-only exports.

### 5.3 Mobile / FFI — deferred deliberately

The UniFFI layer mirrors records into separate DTOs (`map_asset`), so the core
field lands with **zero FFI changes** — the mobile surface simply doesn't carry
it yet. Exposing it later is a self-contained change (DTO field + `map_asset` +
the compile-time surface-lock literal + one Compose `Field(...)` line) and was
deferred because the read-only mobile app would need id→label resolution
plumbing to display anything more useful than hex. The v1 FFI surface lock
stays intact.

## 6. Test coverage added

- `records.rs`: diff logs the generic line and never leaks ids; helper
  forward/reverse lookup incl. dangling; trim leaves link ids untouched.
- `csv.rs`: header pin updated; label + raw-id-fallback cells; `build_tab_csv`
  resolves from the vault's own accounts.
- `vault.rs` proptest: link ids never surface in `referenced_doc_ids`.
- `metamorphic.rs`: `rand_asset` now generates (possibly dangling) links; the
  save/reopen round-trip key and merge properties cover the field.
- `format_compat.rs`: old-style asset JSON (no `linked_accounts`) still loads.
- `gui.rs` / `ui.rs`: link add/remove, jump behavior (incl. dangling), delete
  warning, raw-id rendering — in each front-end's existing test harness.

## 7. Future work

- **Real Estate account fields**: `income_account`/`financing_account`/
  `payment_account` could migrate to the same id-linked mechanism (with the
  free text kept as a fallback label) — they are the anti-pattern this feature
  replaces.
- **Merge planner arm**: an advisory `MergePlan` note listing incoming assets
  whose links won't resolve in the destination (warn-only; never skip).
- **FFI/mobile exposure**: per §5.3.
- **TUI pre-delete confirm** and a **TUI jump-back** from the "Linked from"
  list (both per §4.1/§5.2).
