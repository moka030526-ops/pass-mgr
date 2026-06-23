//! Ratatui terminal interface: a tabbed estate vault (the keyboard-driven,
//! SSH-friendly counterpart to [`crate::gui`]).
//!
//! Screens: Auth (unlock/create/change-password), Browse (a tab bar + the
//! current tab's record list), and Edit (a field form for one record). Both
//! front-ends share the same [`crate::records`] model and [`OpenVault`] API.
//!
//! Edit forms are built as a flat list of [`Field`]s from the typed record, then
//! written back on save — so the per-type knowledge lives in two small places
//! (`start_edit` and `save_edit`) instead of throughout the key handler.

// `use` brings names into scope (like `import` in other languages). The `{a, b}`
// braces import several items from one module at once.
//
// `Path` is a borrowed filesystem path (a view, like `&str`); `PathBuf` is an
// owned, growable path (like `String`). You hand out `&Path` to read, keep a
// `PathBuf` to own.
use std::path::{Path, PathBuf};
// `Duration` = a length of time; `Instant` = a specific moment on the monotonic
// clock (used for "do X after N seconds").
use std::time::{Duration, Instant};

use ratatui::DefaultTerminal;
use ratatui::Frame;
// `self` in a `{...}` import also brings in the module itself, so we can write
// both `event::poll(...)` (via `event`) and the individual `Event`, `KeyCode`… types.
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap};
// Secret-wiping helpers. `Zeroize` = a trait (interface) providing `.zeroize()`
// to overwrite memory with zeros; `ZeroizeOnDrop` makes a type wipe itself
// automatically when it goes out of scope; `Zeroizing<T>` wraps a value so it is
// zeroed on drop. These keep passwords from lingering in RAM.
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::KdfParams;
use crate::password::{self, GenOptions};
use crate::records::{
    self, Account, AssetLiability, Change, GeneralDocument, Instruction, RealEstate, Record, TaxFiling, TrustWill,
};
use crate::vault::{CategoryRemoval, OpenVault, VaultError};

/// Run the UI event loop until the user quits. `writable` enables mutations;
/// when false the vault is opened read-only and write keys are inert.
///
/// `&mut DefaultTerminal` is an *exclusive borrow*: this function may mutate the
/// terminal but does not own it (the caller keeps it). `path` and `writable` are
/// passed by value (moved/copied in). The return type `anyhow::Result<()>` is
/// either `Ok(())` (success, no useful value) or `Err(e)` (some error);
/// `anyhow::Result` is a convenience alias whose error type can hold any error.
pub fn run(terminal: &mut DefaultTerminal, path: PathBuf, writable: bool) -> anyhow::Result<()> {
    // `let mut` = a mutable variable (without `mut`, bindings are read-only).
    let mut app = App::new(path, writable);
    loop {
        // `|frame| app.draw(frame)` is a closure (an inline anonymous function);
        // `terminal.draw` calls it back with a drawing surface.
        // The trailing `?` means "if this returns an error, stop and return it
        // from `run`"; on success it unwraps the `Ok` value and continues.
        terminal.draw(|frame| app.draw(frame))?;
        // Poll rather than block so the clipboard auto-clear deadline fires even
        // when the user isn't pressing keys.
        //
        // This is a *let-chain*: a sequence of `&&`-joined conditions where some
        // bind with `let`. It only enters the `if` body when ALL hold, evaluated
        // left to right (short-circuiting). Read it as:
        //   - a key event arrived within the poll interval, AND
        //   - `event::read()` produced an `Event::Key` (the `let Event::Key(key)`
        //     pattern matched and bound `key`), AND
        //   - it was a key *press* (not release/repeat), AND
        //   - `app.handle_key(key)` returned true (meaning "quit").
        if event::poll(CLIPBOARD_POLL_INTERVAL)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && app.handle_key(key)
        {
            break;
        }
        app.tick_clipboard();
    }
    Ok(())
}

// `enum` defines a type with a fixed set of named variants (like a tagged union
// / a closed set of states). `#[derive(...)]` auto-generates trait impls so we
// don't write them by hand: `PartialEq`/`Eq` enable `==`, `Debug` enables
// `{:?}` formatting for logging/tests.
#[derive(PartialEq, Eq, Debug)]
enum Screen {
    Auth,
    Browse,
    Edit,
    Config,
}

// `Clone` allows explicit `.clone()` copies; `Copy` makes the type copy
// implicitly on assignment (cheap value types like this small enum). With `Copy`,
// passing a `Tab` around does not "move" (consume) it.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Tab {
    Instructions,
    TrustWill,
    Assets,
    Accounts,
    RealEstate,
    Taxes,
    GeneralDocuments,
}

// `impl Tab { ... }` attaches methods/constants to the `Tab` type.
impl Tab {
    // `[Tab; 6]` is a fixed-size array of 6 `Tab` values. `const` = a
    // compile-time constant.
    const ALL: [Tab; 7] = [
        Tab::Instructions,
        Tab::TrustWill,
        Tab::Assets,
        Tab::Accounts,
        Tab::RealEstate,
        Tab::Taxes,
        Tab::GeneralDocuments,
    ];

    // Methods take `self`; because `Tab` is `Copy`, taking `self` by value here is
    // cheap and does not consume the caller's copy. The return type
    // `&'static str` is a borrowed string slice that lives for the whole program
    // (`'static` is the lifetime of program-long data, e.g. string literals).
    fn title(self) -> &'static str {
        match self {
            Tab::Instructions => "Instructions",
            Tab::TrustWill => "Trust and Will",
            Tab::Assets => "Assets & Liabilities",
            Tab::Accounts => "Accounts",
            Tab::RealEstate => "Real Estate",
            Tab::Taxes => "Taxes",
            Tab::GeneralDocuments => "General Documents",
        }
    }

    fn index(self) -> usize {
        // `.iter()` walks the array by reference; `.position(closure)` returns the
        // index of the first element where the closure is true, as `Option<usize>`
        // (`Some(i)` or `None`). `|t| *t == self` is a closure taking each item as
        // `t: &Tab`; `*t` dereferences the borrow to compare by value.
        // `.unwrap_or(0)` yields the inner index, or `0` if `None`.
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    fn shifted(self, delta: isize) -> Tab {
        // `as` is a primitive numeric cast. `rem_euclid` is a modulo that always
        // returns a non-negative result, so stepping left past 0 wraps to the end.
        let n = Tab::ALL.len() as isize;
        let i = (self.index() as isize + delta).rem_euclid(n) as usize;
        Tab::ALL[i]
    }
}

// --- Auth state --------------------------------------------------------------

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum AuthMode {
    Create,
    Unlock,
    ChangePassword,
}

// A `struct` groups named fields (like a record/object). Deriving `Zeroize` and
// `ZeroizeOnDrop` here means: when an `AuthField` is dropped, its memory is wiped.
// `#[zeroize(skip)]` excludes a field — `label` is a non-secret static string, so
// it is skipped; `value` (a typed password) is wiped. `String` is an owned,
// growable, heap-allocated UTF-8 string (vs `&str`, a borrowed view).
#[derive(Zeroize, ZeroizeOnDrop)]
struct AuthField {
    #[zeroize(skip)]
    label: &'static str,
    value: String,
}

struct AuthState {
    mode: AuthMode,
    // `Vec<T>` is a growable array (heap-allocated list) of `T`.
    fields: Vec<AuthField>,
    focus: usize,
    // `Option<T>` is either `Some(value)` or `None` — Rust's null-free "maybe".
    error: Option<String>,
}

impl AuthState {
    // `Self` is shorthand for the enclosing type (`AuthState`).
    fn new(mode: AuthMode) -> Self {
        // `&[&'static str]` is a slice (borrowed view) of static string slices.
        // `if` is an expression here: the chosen `&[...]` array literal is bound
        // to `labels`.
        let labels: &[&'static str] = if mode == AuthMode::Unlock {
            &["Password 1", "Password 2"]
        } else {
            &["Password 1", "Confirm password 1", "Password 2", "Confirm password 2"]
        };
        AuthState {
            mode,
            // Iterator pipeline: `.iter()` borrows each label, `.map(closure)`
            // transforms each into an `AuthField`, `.collect()` gathers the
            // results into the `Vec<AuthField>` the field's type demands.
            // `with_capacity(256)` pre-sizes the buffer so typing a master password
            // never grows (and so reallocates) it — a realloc frees the old buffer
            // WITHOUT zeroizing, stranding plaintext password fragments in freed
            // heap. Same mitigation as the GUI's pw fields (gui.rs).
            fields: labels.iter().map(|l| AuthField { label: l, value: String::with_capacity(256) }).collect(),
            focus: 0,
            error: None,
        }
    }
}

// --- Edit form ---------------------------------------------------------------

// An enum variant can carry data: `Choice(Vec<String>)` holds the list of
// selectable options; the others are data-less markers.
#[derive(Clone)]
enum FieldKind {
    Text,
    Multiline,
    Password,
    Choice(Vec<String>),
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Field {
    #[zeroize(skip)]
    label: String,
    value: String,
    #[zeroize(skip)]
    kind: FieldKind,
}

// FieldKind holds no secrets; skip-zeroize is fine. Implement Zeroize for it as
// a no-op so the derive on Field is satisfied without wiping option lists.
//
// (To satisfy `#[derive(Zeroize)]` on `Field`, every field's type must itself be
// `Zeroize`; this manual `impl` makes `FieldKind` count, doing nothing. `&mut
// self` is an exclusive borrow of the value being zeroized.)
impl Zeroize for FieldKind {
    fn zeroize(&mut self) {}
}

impl Field {
    // These are "constructor" helper functions (no `self`, called as
    // `Field::text(...)`). `label: &str` is a borrowed string view; `.into()`
    // converts it into the owned `String` the field needs. `value` uses field
    // init shorthand (the variable name matches the field name).
    fn text(label: &str, value: String) -> Field {
        Field { label: label.into(), value, kind: FieldKind::Text }
    }
    fn multiline(label: &str, value: String) -> Field {
        Field { label: label.into(), value, kind: FieldKind::Multiline }
    }
    fn password(label: &str, mut value: String) -> Field {
        // Pre-size the buffer so per-keystroke typing never reallocates (which would
        // strand un-zeroized fragments of the secret in freed heap). Copy into the
        // pre-sized buffer, then wipe the transient incoming `String`.
        let mut buf = String::with_capacity(value.len() + 128);
        buf.push_str(&value);
        value.zeroize();
        Field { label: label.into(), value: buf, kind: FieldKind::Password }
    }
    fn choice(label: &str, value: String, options: Vec<String>) -> Field {
        Field { label: label.into(), value, kind: FieldKind::Choice(options) }
    }

    /// Cycle a Choice field's value by `delta` (no-op for other kinds).
    fn cycle(&mut self, delta: isize) {
        // `if let PATTERN = EXPR` runs the body only when the pattern matches.
        // Here it both checks that `self.kind` is the `Choice` variant AND binds
        // its inner list to `opts` (as a borrow, via `&self.kind`). Combined with
        // `&& !opts.is_empty()` it is a let-chain: enter only when both hold.
        if let FieldKind::Choice(opts) = &self.kind
            && !opts.is_empty()
        {
            // Find the current option's index (defaulting to 0 if not found),
            // step by `delta` with wrap-around, then store an owned copy of the
            // new option. `&self.value` borrows the value to compare without
            // moving it; `.clone()` is needed because we can't move out of the
            // borrowed `opts` slice.
            let cur = opts.iter().position(|o| o == &self.value).unwrap_or(0);
            let i = (cur as isize + delta).rem_euclid(opts.len() as isize) as usize;
            self.value = opts[i].clone();
        }
    }
}

/// A record being edited. `fields[0..record_fields]` are the record's own
/// fields; any remaining fields are document-upload inputs (location / filename
/// / upload-from / export-to) for the doc-bearing tabs.
struct EditState {
    tab: Tab,
    // `Option<String>`: `Some(id)` for an existing record, `None` for a brand-new
    // one whose id has not been generated yet.
    id: Option<String>,
    created_at: i64,
    fields: Vec<Field>,
    record_fields: usize,
    focus: usize,
    attached_file_id: Option<String>,
    /// Document file ids for the Taxes tab, which manages several documents per
    /// filing year. Empty/unused for the single-document tabs (TrustWill, Assets),
    /// which carry their one document in `attached_file_id`.
    tax_docs: Vec<String>,
    /// Document file ids for the Real Estate tab, which manages several documents
    /// per property. Empty for the single-document tabs.
    re_docs: Vec<String>,
    history: Vec<Change>,
}

/// One visible row of the grouped Accounts tree: a collapsible group (type/subtype/
/// owner) or a leaf (one account, shown by title). Rebuilt each render from the tree
/// + the expand set; `App::selected` indexes the row list when grouped.
struct AcctRow {
    depth: u16,
    label: String,
    kind: AcctRowKind,
}

enum AcctRowKind {
    /// A type/subtype/owner header; `path` (the stack of ancestor labels) keys its
    /// expand state, `expanded` is its current state (drives the ▸/▾ marker). A Vec —
    /// not a separator-joined string — so two distinct group paths can never collide
    /// (e.g. owner "a\x1fb" vs owner "a" + type "b").
    Group { path: Vec<String>, expanded: bool },
    /// An account leaf carrying its record id (what selecting it edits).
    Leaf { id: String },
}

impl AcctRow {
    fn group(depth: u16, label: &str, expanded: bool, path: Vec<String>) -> Self {
        AcctRow { depth, label: label.to_string(), kind: AcctRowKind::Group { path, expanded } }
    }
    fn leaf(depth: u16, label: &str, id: String) -> Self {
        AcctRow { depth, label: label.to_string(), kind: AcctRowKind::Leaf { id } }
    }
}

/// Flatten one grouped-tree node into visible rows: each child group becomes a
/// header row (recursed into when expanded), then this node's leaf accounts follow
/// (at the same depth, so they sit *inside* their parent group). `parent_path` is the
/// stack of ancestor labels keying each group's expand state in `expanded`. Mirrors
/// the GUI's children-then-leaves order so the two front-ends present the same tree.
fn flatten_acct_node(
    node: &records::AcctNode,
    depth: u16,
    parent_path: &[String],
    expanded: &std::collections::HashSet<Vec<String>>,
    rows: &mut Vec<AcctRow>,
) {
    for child in &node.children {
        let mut path = parent_path.to_vec();
        path.push(child.label.clone());
        let exp = expanded.contains(&path);
        rows.push(AcctRow::group(depth, &child.label, exp, path.clone()));
        if exp {
            flatten_acct_node(child, depth + 1, &path, expanded, rows);
        }
    }
    for leaf in &node.leaves {
        let title = if leaf.title.is_empty() { "(no title)".to_string() } else { leaf.title.clone() };
        rows.push(AcctRow::leaf(depth, &title, leaf.id.clone()));
    }
}

/// The tabs whose records can carry an attached document (single source of truth).
fn tab_has_docs(tab: Tab) -> bool {
    // `matches!(value, PATTERN)` is a one-shot boolean: true if `value` fits the
    // pattern. The `|` means "or". These are the SINGLE-document tabs (one file via
    // `attached_file_id`); Taxes/Real Estate manage multi-doc folders separately.
    matches!(tab, Tab::TrustWill | Tab::Assets | Tab::GeneralDocuments)
}

impl EditState {
    fn has_docs(&self) -> bool {
        tab_has_docs(self.tab)
    }
}

// The whole application state lives in one struct, passed around as `&self`
// (read) or `&mut self` (mutate).
struct App {
    path: PathBuf,
    /// When false the vault is opened read-only and mutating keys are inert.
    writable: bool,
    screen: Screen,
    auth: AuthState,
    /// The directory whose `vault.pmv` we open/create. On the collapsed start page this is
    /// DERIVED as `<auth_root>/<auth_name>` (see `recompute_auth_path`), kept in sync with
    /// `path`; it is never an editable field of its own.
    auth_dir: String,
    /// Editable ROOT directory scanned (one level deep) for vaults — focus 0 on the start
    /// page. Seeded from the saved `vault_root` preference (else the launch dir's parent);
    /// editing it re-scans `auth_vaults` and is persisted back to prefs.
    auth_root: String,
    /// The selected/typed vault folder NAME (leaf under `auth_root`) — the editable "Vault"
    /// row at focus 1. Typing edits it (a new name arms Create); ←/→ cycle the discovered
    /// vaults into it. Empty = the root itself. With `auth_root` it derives `auth_dir`/`path`.
    auth_name: String,
    /// Names of the subdirectories of `auth_root` that hold a `vault.pmv` — the choices the
    /// focus-1 Vault row cycles through with ←/→. Empty when none are found.
    auth_vaults: Vec<String>,
    /// Index of the highlighted entry in `auth_vaults` (meaningful only when non-empty).
    auth_vault_sel: usize,
    /// A warning from the most recent scan (root unreadable, or entries skipped), shown
    /// under the Vault row. `None` when the scan was clean.
    auth_scan_warning: Option<String>,
    // The unlocked vault, present only after a successful unlock/create
    // (`None` while on the Auth screen).
    vault: Option<OpenVault>,
    tab: Tab,
    selected: usize,
    edit: Option<EditState>,
    // Accounts-tab display filters (None = no filter).
    acct_filter_type: Option<String>,
    acct_filter_subtype: Option<String>,
    acct_filter_owner: Option<String>,
    acct_filter_title: Option<String>,
    acct_filter_review: bool,
    // Accounts-tab username search: `acct_search` is the active (case-insensitive
    // substring) query; `search_active` is true while typing it (entered with '/').
    acct_search: String,
    search_active: bool,
    // The ONLY reveal control for the Accounts tab: a single global toggle (browse `r`
    // or edit Ctrl+R) that unmasks every account password. No per-record reveal.
    reveal_all: bool,
    // The same for the Real Estate tab's four portal passwords (toggled with `r` on
    // the RE tab). Scoped per-tab so revealing one screen never reveals the other.
    re_reveal_all: bool,
    // Accounts view: false = flat filtered list, true = grouped tree
    // (type → subtype → owner → title), toggled with `g`.
    acct_grouped: bool,
    // Paths (ancestor-label stacks) of the EXPANDED tree nodes (collapsed by default).
    acct_expanded: std::collections::HashSet<Vec<String>>,
    // Assets-tab "review only" filter.
    asset_filter_review: bool,
    // Config screen inputs.
    cfg_focus: usize,
    cfg_asset_type: String,
    cfg_account_type: String,
    cfg_subtype_type: String,
    cfg_subtype_name: String,
    cfg_volume_size: String,
    cfg_backup_dest: String,
    cfg_redundancy: String,
    // Prefs-backed export destination directory (shared with the GUI via prefs.json).
    // Document Export writes here, recreating the in-vault folder structure; settable
    // in read-only mode since it is a local preference, not vault content.
    cfg_export_dir: String,
    status: String,
    clipboard_dirty: bool,
    // When set, the clipboard should be wiped at/after this instant (auto-clear
    // a copied password so it doesn't linger for the whole session).
    clipboard_clear_at: Option<Instant>,
}

/// How long a copied password stays on the clipboard before it is auto-cleared.
/// (Only used when the `clipboard` feature is on — the minimal build does no copying.)
#[cfg(feature = "clipboard")]
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(15);
/// How often the event loop wakes (when idle) to check the auto-clear deadline.
const CLIPBOARD_POLL_INTERVAL: Duration = Duration::from_millis(500);

// `Drop` is the destructor trait: `drop()` runs automatically when an `App` goes
// out of scope (including on quit or panic). This is a security cleanup hook —
// if a password was copied to the OS clipboard this session, wipe it on exit so
// it does not outlive the program.
impl Drop for App {
    fn drop(&mut self) {
        if self.clipboard_dirty {
            clear_clipboard();
        }
    }
}

impl App {
    fn new(path: PathBuf, writable: bool) -> Self {
        // Collapsed start page: the open target is `<root>/<name>`. Seed the root from the
        // saved preference (so startups share a default root), pre-selecting the launched
        // vault's folder when appropriate; then derive the directory/path from root+name.
        let saved_root = crate::load_vault_root();
        let (auth_root, auth_name) = crate::launch::initial_root_and_name(&path, &saved_root);
        // Default the backup destination to the root (see the `cfg_backup_dest` field).
        let cfg_backup_dest = auth_root.clone();
        let auth_dir = crate::launch::join_root_name(&auth_root, &auth_name);
        let path = crate::launch::vault_file(&auth_dir);
        let mode = if path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        let scan = crate::launch::discover_vaults(&auth_root);
        // Highlight the selected vault in the picker if it was discovered under the root.
        let auth_vault_sel = scan.vaults.iter().position(|v| *v == auth_name).unwrap_or(0);
        App {
            path,
            writable,
            screen: Screen::Auth,
            auth: AuthState::new(mode),
            auth_dir,
            auth_root,
            auth_name,
            auth_vaults: scan.vaults,
            auth_vault_sel,
            auth_scan_warning: scan.warning,
            vault: None,
            tab: Tab::Instructions,
            selected: 0,
            edit: None,
            acct_filter_type: None,
            acct_filter_subtype: None,
            acct_filter_owner: None,
            acct_filter_title: None,
            acct_filter_review: false,
            acct_search: String::new(),
            search_active: false,
            reveal_all: false,
            re_reveal_all: false,
            acct_grouped: false,
            acct_expanded: std::collections::HashSet::new(),
            asset_filter_review: false,
            cfg_focus: 0,
            cfg_asset_type: String::new(),
            cfg_account_type: String::new(),
            cfg_subtype_type: String::new(),
            cfg_subtype_name: String::new(),
            cfg_volume_size: String::new(),
            // Default the backup destination to the vault ROOT (editable in Config). It
            // tracks the root while on the start page; once unlocked it's the user's.
            cfg_backup_dest,
            cfg_redundancy: String::new(),
            cfg_export_dir: crate::load_export_dir(),
            status: String::new(),
            clipboard_dirty: false,
            clipboard_clear_at: None,
        }
    }

    /// Wipe the clipboard once the auto-clear deadline has passed. Called from the
    /// event loop, so a copied password is cleared even with no further input.
    fn tick_clipboard(&mut self) {
        // Let-chain: only act when a deadline is set (`Some(deadline)`) AND the
        // current time has reached it.
        if let Some(deadline) = self.clipboard_clear_at
            && Instant::now() >= deadline
        {
            clear_clipboard();
            self.clipboard_dirty = false;
            self.clipboard_clear_at = None;
            // Don't clobber a meaningful status (e.g. "Save failed: …") the user may not
            // have seen yet; only replace a blank or the prior "Copied …" notice.
            if self.status.is_empty() || self.status.starts_with("Copied") {
                self.status = "Clipboard cleared.".into();
            }
        }
    }

    // Returns a shared (read-only) borrow of the open vault.
    // `self.vault` is an `Option`; `.as_ref()` turns `&Option<T>` into
    // `Option<&T>` (borrow the inner value without moving it). `.expect(msg)`
    // unwraps the `Some`, or panics with `msg` if it is `None`. Safe here because
    // the Browse/Edit/Config screens are only reachable once the vault is open.
    fn vault_ref(&self) -> &OpenVault {
        self.vault.as_ref().expect("vault open on browse/edit")
    }

    /// `(id, label)` pairs for the current tab's records. The Accounts tab is
    /// additionally filtered by the active type/subtype/owner/review filters, and
    /// the Assets tab by the review filter.
    // Returns `(id, label)` pairs; `(String, String)` is a tuple (two values in
    // one). `match self.tab { ... }` branches on which tab is active — `match`
    // must cover every variant.
    fn current_labels(&self) -> Vec<(String, String)> {
        let v = &self.vault_ref().vault;
        match self.tab {
            Tab::Instructions => label_list(&v.instructions),
            Tab::TrustWill => label_list(&v.trust_wills),
            // Iterator pipeline: borrow each asset (`.iter()`), keep only those
            // passing the closure in `.filter(...)`, transform survivors into
            // `(id, label)` tuples with `.map(...)`, then `.collect()` into a Vec.
            // `.clone()`/`a.label()` build owned `String`s because the records are
            // only borrowed here. The filter keeps an asset when the review filter
            // is off (`!self.asset_filter_review`) OR the asset is flagged.
            Tab::Assets => v
                .assets
                .iter()
                .filter(|a| !self.asset_filter_review || a.review)
                .map(|a| (a.id.clone(), a.label()))
                .collect(),
            // Same shape, but four chained filters (each must pass).
            // `Option::as_deref()` turns `&Option<String>` into `Option<&str>`;
            // `.is_none_or(closure)` is true when the filter is unset (`None`) OR
            // the closure holds — i.e. "no filter, or it matches".
            Tab::Accounts => v
                .accounts
                .iter()
                .filter(|a| self.acct_filter_type.as_deref().is_none_or(|t| a.account_type == t))
                .filter(|a| self.acct_filter_subtype.as_deref().is_none_or(|s| a.account_subtype == s))
                .filter(|a| self.acct_filter_owner.as_deref().is_none_or(|o| a.owner == o))
                .filter(|a| self.acct_filter_title.as_deref().is_none_or(|t| a.title == t))
                .filter(|a| !self.acct_filter_review || a.review)
                // Free-text search: case-insensitive substring over username OR title
                // (empty = no filter).
                .filter(|a| {
                    records::matches_search(&a.username, &self.acct_search)
                        || records::matches_search(&a.title, &self.acct_search)
                })
                .map(|a| (a.id.clone(), a.label()))
                .collect(),
            Tab::RealEstate => label_list(&v.real_estate),
            Tab::Taxes => label_list(&v.tax_filings),
            Tab::GeneralDocuments => label_list(&v.general_documents),
        }
    }

    /// Whether an account passes the current Accounts filters (mirrors the Accounts
    /// arm of [`current_labels`]); shared by the flat list and the grouped tree.
    fn acct_passes_filters(&self, a: &Account) -> bool {
        self.acct_filter_type.as_deref().is_none_or(|t| a.account_type == t)
            && self.acct_filter_subtype.as_deref().is_none_or(|s| a.account_subtype == s)
            && self.acct_filter_owner.as_deref().is_none_or(|o| a.owner == o)
            && self.acct_filter_title.as_deref().is_none_or(|t| a.title == t)
            && (!self.acct_filter_review || a.review)
            && (records::matches_search(&a.username, &self.acct_search)
                || records::matches_search(&a.title, &self.acct_search))
    }

    /// The currently VISIBLE rows of the grouped Accounts tree (collapsed nodes hide
    /// their children). Built from the filtered accounts so the tree honours filters.
    /// `self.selected` indexes this list when grouped.
    fn account_rows(&self) -> Vec<AcctRow> {
        let v = &self.vault_ref().vault;
        let tree = records::account_tree(v.accounts.iter().filter(|a| self.acct_passes_filters(a)));
        let mut rows = Vec::new();
        flatten_acct_node(&tree, 0, &[], &self.acct_expanded, &mut rows);
        rows
    }

    /// True when the Accounts tab is showing the grouped tree.
    fn acct_tree_mode(&self) -> bool {
        self.tab == Tab::Accounts && self.acct_grouped
    }

    /// Number of selectable rows in the current browse view (tree rows when grouped,
    /// else the flat label list).
    fn current_row_count(&self) -> usize {
        if self.acct_tree_mode() { self.account_rows().len() } else { self.current_labels().len() }
    }

    /// Cross-filtered (faceted) Accounts filter options for the current selections:
    /// each field's distinct values among accounts matching all the OTHER filters.
    fn account_facets(&self) -> records::AccountFacets {
        records::account_facets(
            &self.vault_ref().vault.accounts,
            self.acct_filter_type.as_deref().unwrap_or(""),
            self.acct_filter_subtype.as_deref().unwrap_or(""),
            self.acct_filter_owner.as_deref().unwrap_or(""),
            self.acct_filter_title.as_deref().unwrap_or(""),
            &self.acct_search,
            self.acct_filter_review,
        )
    }

    /// Drop any Accounts filter selection that is no longer one of its cross-filtered
    /// options (to a fixpoint — clearing one filter can free up another). Keeps the
    /// list from going silently empty after a filter/search change.
    fn narrow_account_filters(&mut self) {
        loop {
            let f = self.account_facets();
            let mut changed = false;
            if let Some(v) = self.acct_filter_type.clone()
                && !f.types.contains(&v)
            {
                self.acct_filter_type = None;
                changed = true;
            }
            if let Some(v) = self.acct_filter_subtype.clone()
                && !f.subtypes.contains(&v)
            {
                self.acct_filter_subtype = None;
                changed = true;
            }
            if let Some(v) = self.acct_filter_owner.clone()
                && !f.owners.contains(&v)
            {
                self.acct_filter_owner = None;
                changed = true;
            }
            if let Some(v) = self.acct_filter_title.clone()
                && !f.titles.contains(&v)
            {
                self.acct_filter_title = None;
                changed = true;
            }
            if !changed {
                break;
            }
        }
    }

    fn clamp_selection(&mut self) {
        let n = self.current_row_count();
        if n == 0 {
            self.selected = 0;
        } else if self.selected >= n {
            self.selected = n - 1;
        }
    }

    /// Save the open vault. Returns `true` only if it was actually written. A
    /// caller that reclaims a document blob AFTER persisting MUST gate the reclaim
    /// on this return: a failed save (e.g. full disk) leaves `vault.pmv` still
    /// referencing the doc, so dropping its blob would create a dangling reference
    /// (`ArchiveMismatch` — an unopenable vault) on the next open.
    fn persist(&mut self) -> bool {
        match self.vault.as_mut() {
            Some(ov) => match ov.save() {
                Ok(()) => true,
                Err(e) => {
                    self.status = format!("Save failed: {e}");
                    false
                }
            },
            None => false,
        }
    }

    /// One-off maintenance: left/right-trim every field on every record across ALL
    /// tabs, persist, and report how many changed. Each change is recorded in that
    /// record's history.
    fn trim_all_records(&mut self) {
        let n = match self.vault.as_mut() {
            Some(ov) => records::trim_all_records(&mut ov.vault),
            None => return,
        };
        if n == 0 {
            self.status = "Nothing to trim — every field is already clean.".into();
        } else if self.persist() {
            self.status = format!("Trimmed {n} record(s).");
        }
    }

    /// Switch to tab `t`, reset the selection, and clear the "reveal all" toggles.
    /// Reveal is a momentary, in-context action (and the ONLY reveal control — there is
    /// no per-record reveal), so a stale `reveal_all`/`re_reveal_all` must not silently
    /// persist into a later visit and expose every password.
    fn switch_tab(&mut self, t: Tab) {
        self.tab = t;
        self.selected = 0;
        self.reveal_all = false;
        self.re_reveal_all = false;
    }

    /// Gate a mutating action: returns true if writable, else sets a status hint.
    // `&mut self` because it may set `self.status`. An early `return true` exits
    // immediately; otherwise the function falls through to the final `false`.
    fn require_writable(&mut self) -> bool {
        if self.writable {
            return true;
        }
        self.status = "Read-only — relaunch with --write to make changes.".into();
        false
    }

    // --- Key handling: returns true to quit ---------------------------------

    // Dispatch a key press to the active screen's handler. The bool result
    // (returned by each handler) bubbles up to the event loop: true = quit.
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.screen {
            Screen::Auth => self.handle_auth_key(key),
            Screen::Browse => self.handle_browse_key(key),
            Screen::Edit => self.handle_edit_key(key),
            Screen::Config => self.handle_config_key(key),
        }
    }

    fn handle_auth_key(&mut self, key: KeyEvent) -> bool {
        // `match` on the key code. Arms can have guards (`if ...`) and patterns
        // that bind data (e.g. `Char(c)`); the wildcard `_` matches anything else.
        match key.code {
            KeyCode::Esc => {
                if self.auth.mode == AuthMode::ChangePassword {
                    self.screen = Screen::Browse;
                    return false;
                }
                return true;
            }
            // Guarded arm: a typed character that is NOT a Ctrl-combo. `Char(c)`
            // binds the typed char to `c`; append it to the focused field. Focus 0 is the
            // editable vault-directory field (on the start page); focuses 1.. are the
            // password fields, so subtract the dir slot to index `auth.fields`.
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                if self.on_auth_root_field() {
                    self.auth_root.push(c);
                    self.auth_root_edited();
                } else if self.on_auth_vault_field() {
                    // Type a vault name: pick an existing one or name a new one (→ Create).
                    self.auth_name.push(c);
                    self.recompute_auth_path();
                } else {
                    let idx = self.auth_field_index();
                    self.auth.fields[idx].value.push(c);
                }
            }
            KeyCode::Backspace => {
                // `.pop()` removes the last char (returns an `Option`, ignored here).
                if self.on_auth_root_field() {
                    self.auth_root.pop();
                    self.auth_root_edited();
                } else if self.on_auth_vault_field() {
                    self.auth_name.pop();
                    self.recompute_auth_path();
                } else {
                    let idx = self.auth_field_index();
                    self.auth.fields[idx].value.pop();
                }
            }
            // ←/→ on the Vault row (focus 1) cycle the discovered vaults into the name,
            // adopting each as the open target. Inert elsewhere on the auth screen.
            KeyCode::Left | KeyCode::Right if self.on_auth_vault_field() && !self.auth_vaults.is_empty() => {
                let n = self.auth_vaults.len();
                self.auth_vault_sel = if key.code == KeyCode::Right {
                    (self.auth_vault_sel + 1) % n
                } else {
                    (self.auth_vault_sel + n - 1) % n
                };
                self.apply_auth_vault_selection();
            }
            KeyCode::Tab | KeyCode::Down => {
                let total = self.auth_focus_count();
                self.auth.focus = (self.auth.focus + 1) % total;
            }
            KeyCode::BackTab | KeyCode::Up => {
                let total = self.auth_focus_count();
                self.auth.focus = (self.auth.focus + total - 1) % total;
            }
            KeyCode::Enter => {
                if self.auth.focus + 1 < self.auth_focus_count() {
                    self.auth.focus += 1;
                } else {
                    self.submit_auth();
                }
            }
            _ => {}
        }
        false
    }

    /// True on the start page (Create/Unlock), false in the in-vault Change-password flow.
    /// The start page prepends two non-password rows before the password fields:
    /// focus 0 = Root, focus 1 = the editable "Vault" name (dropdown-filled / ←/→-cycled).
    fn auth_start_page(&self) -> bool {
        self.auth.mode != AuthMode::ChangePassword
    }
    /// Number of leading non-password rows (Root + Vault), or 0 off the start page.
    fn auth_lead_rows(&self) -> usize {
        if self.auth_start_page() {
            2
        } else {
            0
        }
    }
    /// Total focusable rows: the leading non-password rows plus the password fields.
    fn auth_focus_count(&self) -> usize {
        self.auth.fields.len() + self.auth_lead_rows()
    }
    /// True when focus is on the editable ROOT field (focus 0, start page only).
    fn on_auth_root_field(&self) -> bool {
        self.auth_start_page() && self.auth.focus == 0
    }
    /// True when focus is on the editable "Vault" name row (focus 1, start page only).
    fn on_auth_vault_field(&self) -> bool {
        self.auth_start_page() && self.auth.focus == 1
    }
    /// Index into `auth.fields` for the current focus (assumes a password row).
    fn auth_field_index(&self) -> usize {
        self.auth.focus - self.auth_lead_rows()
    }

    /// Re-derive the open target from `<auth_root>/<auth_name>`: rebuild `auth_dir` and the
    /// vault path, then flip the mode — Unlock if a `vault.pmv` already exists there, else
    /// Create. A mode change rebuilds the password fields (Create adds confirm fields),
    /// clearing any half-typed passwords; the current focus row (Root/Vault) is preserved.
    fn recompute_auth_path(&mut self) {
        self.auth_dir = crate::launch::join_root_name(&self.auth_root, &self.auth_name);
        self.path = crate::launch::vault_file(self.auth_dir.trim());
        let new_mode = if self.path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        if new_mode != self.auth.mode {
            let focus = self.auth.focus;
            self.auth = AuthState::new(new_mode);
            // Clamp in case the rebuild has fewer rows (Create→Unlock drops 2 fields); the
            // leading Root/Vault rows always survive, so editing them keeps focus.
            self.auth.focus = focus.min(self.auth_focus_count().saturating_sub(1));
        }
    }

    /// Handle an edit to the Root field: re-scan for vaults, re-derive the open target, and
    /// keep the default backup destination tracking the root until the vault is unlocked (the
    /// Config backup field is freely editable afterwards). The root is persisted to prefs on
    /// a successful open (see `submit_auth`), not on every keystroke.
    fn auth_root_edited(&mut self) {
        self.refresh_auth_vaults();
        self.recompute_auth_path();
        self.cfg_backup_dest = self.auth_root.clone();
    }

    /// Re-scan `auth_root` for vaults (one level deep) and refresh the picker choices and
    /// any access warning. Called when the Root field changes.
    fn refresh_auth_vaults(&mut self) {
        let scan = crate::launch::discover_vaults(&self.auth_root);
        self.auth_vaults = scan.vaults;
        self.auth_scan_warning = scan.warning;
        if self.auth_vault_sel >= self.auth_vaults.len() {
            self.auth_vault_sel = self.auth_vaults.len().saturating_sub(1);
        }
    }

    /// Adopt the currently highlighted picker entry: copy it into the editable `auth_name`
    /// and re-derive the path/mode so the user lands ready to unlock it. No-op if empty.
    fn apply_auth_vault_selection(&mut self) {
        let Some(name) = self.auth_vaults.get(self.auth_vault_sel).cloned() else {
            return;
        };
        self.auth_name = name;
        self.recompute_auth_path();
    }

    // Returns `Result<(Zeroizing<String>, Zeroizing<String>), String>`:
    // on success the two passwords (each wrapped so it self-wipes on drop), or on
    // failure an error message. `&self` (read-only) — it only inspects fields.
    fn confirmed_passwords(&self) -> Result<(Zeroizing<String>, Zeroizing<String>), String> {
        let f = &self.auth.fields;
        // Destructure a tuple of borrows into four named bindings at once.
        let (pw1, c1, pw2, c2) = (&f[0].value, &f[1].value, &f[2].value, &f[3].value);
        if pw1.is_empty() || pw2.is_empty() {
            // `Err(...)` early-returns the failure variant of the Result.
            return Err("Both passwords are required.".into());
        }
        if pw1 != c1 || pw2 != c2 {
            return Err("Password confirmations do not match.".into());
        }
        // `Zeroizing::new(s)` wraps an owned String so its bytes are zeroed when
        // the wrapper drops. We must `.clone()` because the originals are borrowed.
        Ok((Zeroizing::new(pw1.clone()), Zeroizing::new(pw2.clone())))
    }

    /// Wipe entered passwords from the auth fields once we leave the auth screen,
    /// so they don't linger in memory for the rest of the session.
    fn wipe_auth(&mut self) {
        // `for f in &mut self.auth.fields` iterates by exclusive borrow, so each
        // `f` can be mutated. `.zeroize()` overwrites the string's bytes with
        // zeros; `.clear()` then resets its length to 0.
        for f in &mut self.auth.fields {
            f.value.zeroize();
            f.value.clear();
        }
        self.auth.focus = 0;
        self.auth.error = None;
    }

    fn submit_auth(&mut self) {
        match self.auth.mode {
            AuthMode::ChangePassword => {
                // `match` on a `Result` to handle both outcomes: on `Ok(p)` take
                // the passwords; on `Err(m)` record the message and `return` early.
                let (pw1, pw2) = match self.confirmed_passwords() {
                    Ok(p) => p,
                    Err(m) => {
                        self.auth.error = Some(m);
                        return;
                    }
                };
                if let Some(ov) = self.vault.as_mut() {
                    // `.as_bytes()` views a String as a `&[u8]` (raw byte slice) —
                    // the crypto layer works on bytes, not text.
                    match ov.change_password(pw1.as_bytes(), pw2.as_bytes()) {
                        Ok(()) => {
                            self.status = "Master passwords changed.".into();
                            self.wipe_auth();
                            self.screen = Screen::Browse;
                        }
                        Err(e) => {
                            // A failed rekey may have poisoned the handle (read-only)
                            // and left a pending `.rekey` on disk. Drop the handle to
                            // release the single-writer lock and return to the unlock
                            // screen; reopening runs recover_pending_rekey, which
                            // finishes or discards the interrupted rekey idempotently.
                            self.vault = None;
                            self.auth = AuthState::new(AuthMode::Unlock);
                            self.auth.error =
                                Some(format!("Password change interrupted: {e}. Unlock again to recover."));
                            self.screen = Screen::Auth;
                        }
                    }
                }
            }
            AuthMode::Create | AuthMode::Unlock => self.submit_open_or_create(),
        }
    }

    fn submit_open_or_create(&mut self) {
        // `creating` is a bool snapshot of the mode; computed once and reused.
        let creating = self.auth.mode == AuthMode::Create;
        if creating && !self.writable {
            self.auth.error =
                Some("No vault here, and this is read-only. Relaunch with --write to create one.".into());
            return;
        }
        // `result` holds a `Result<OpenVault, VaultError>` from whichever branch
        // ran (both branches must produce the same type). `self.path.clone()` hands
        // an owned copy to the constructor (which takes ownership of the path).
        let result = if creating {
            let (pw1, pw2) = match self.confirmed_passwords() {
                Ok(p) => p,
                Err(m) => {
                    self.auth.error = Some(m);
                    return;
                }
            };
            OpenVault::create(self.path.clone(), pw1.as_bytes(), pw2.as_bytes(), KdfParams::default())
        } else {
            let f = &self.auth.fields;
            let (p1, p2) = (f[0].value.as_bytes(), f[1].value.as_bytes());
            // `!self.writable` becomes the read-only flag.
            OpenVault::open_with(self.path.clone(), p1, p2, !self.writable)
        };
        match result {
            Ok(v) => {
                // Persist the chosen root so the next startup defaults to the same place (a
                // local prefs.json preference — never written into the vault), at the natural
                // point the root is "confirmed" by a successful open/create.
                crate::save_vault_root(self.auth_root.trim());
                // A recovery from an in-place redundant copy (§12.8) takes priority —
                // the user needs to know a roll-forward/rollback happened.
                let recovered = v.recovery_notice().map(|s| s.to_string());
                self.status = if let Some(notice) = recovered {
                    notice
                } else if creating {
                    "New vault created.".into()
                } else if v.previous_access() == 0 {
                    "Vault unlocked.".into()
                } else {
                    format!(
                        "Unlocked. Last opened: {} (generation {})",
                        format_time(v.previous_access()),
                        v.opened_generation()
                    )
                };
                self.vault = Some(v);
                self.wipe_auth();
                self.screen = Screen::Browse;
            }
            // Collapse every CORRECT-password-reachable failure into ONE message so the
            // unlock screen can't be used as a "this password is correct" oracle: wrong
            // password yields `Crypto`, while `ArchiveMismatch`/`Json`/`Storage` are
            // reachable only after a successful decrypt — a distinct message would reveal
            // the password was right (audit O-1; mirrors the FFI collapse). Structural,
            // password-INDEPENDENT errors keep their specific messages in the catch-all.
            Err(VaultError::Crypto(_) | VaultError::ArchiveMismatch | VaultError::Json(_) | VaultError::Storage(_)) => {
                self.auth = AuthState::new(self.auth.mode);
                self.auth.focus = self.auth_lead_rows(); // land on the first password, past the Root/picker/dir rows
                self.auth.error = Some("Wrong password(s) or corrupted/unreadable vault.".into());
            }
            // Catch-all for any other (password-independent) error variant.
            Err(e) => {
                self.auth = AuthState::new(self.auth.mode);
                self.auth.focus = self.auth_lead_rows();
                self.auth.error = Some(format!("{e}"));
            }
        }
    }

    fn handle_browse_key(&mut self, key: KeyEvent) -> bool {
        // Username-search input mode (Accounts tab): capture typed text into
        // `acct_search` until Enter (keep) or Esc (clear). Intercept BEFORE the
        // normal command keys so letters edit the query instead of triggering
        // commands, and so Esc cancels the search rather than quitting the app.
        if self.search_active {
            match key.code {
                KeyCode::Enter => self.search_active = false,
                KeyCode::Esc => {
                    self.acct_search.clear();
                    self.search_active = false;
                    self.selected = 0;
                }
                KeyCode::Backspace => {
                    self.acct_search.pop();
                    self.narrow_account_filters(); // search is a facet too
                    self.selected = 0;
                }
                KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                    self.acct_search.push(c);
                    self.narrow_account_filters(); // narrowing search may invalidate a dropdown pick
                    self.selected = 0;
                }
                _ => {}
            }
            return false;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Right | KeyCode::Tab => self.switch_tab(self.tab.shifted(1)),
            KeyCode::Left | KeyCode::BackTab => self.switch_tab(self.tab.shifted(-1)),
            // `c @ '1'..='9'` is a range pattern that also binds the matched char to
            // `c`: a digit key jumps straight to that tab. `Tab::ALL.get(...)` keys
            // off the actual tab count, so this covers every tab (now 7) and never
            // panics on a digit past the end (it just does nothing).
            KeyCode::Char(c @ '1'..='9') => {
                if let Some(&t) = Tab::ALL.get(c as usize - '1' as usize) {
                    self.switch_tab(t);
                }
            }
            KeyCode::Down => {
                let n = self.current_row_count();
                if n > 0 {
                    // `.min(n - 1)` clamps so we can't move past the last item.
                    self.selected = (self.selected + 1).min(n - 1);
                }
            }
            // `saturating_sub` subtracts but stops at 0 instead of underflowing
            // (unsigned `usize` cannot go negative).
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Enter => {
                if self.acct_tree_mode() {
                    // In the grouped tree, Enter toggles a group's expansion or edits a
                    // leaf account. (←/→ are reserved for switching tabs.)
                    match self.account_rows().get(self.selected).map(|r| &r.kind) {
                        Some(AcctRowKind::Group { path, expanded }) => {
                            let (path, expanded) = (path.clone(), *expanded);
                            if expanded {
                                self.acct_expanded.remove(&path);
                            } else {
                                self.acct_expanded.insert(path);
                            }
                        }
                        Some(AcctRowKind::Leaf { .. }) => self.start_edit(true),
                        None => {}
                    }
                } else if !self.current_labels().is_empty() {
                    self.start_edit(true);
                }
            }
            // Toggle the grouped tree view on the Accounts tab.
            KeyCode::Char('g') if self.tab == Tab::Accounts => {
                self.acct_grouped = !self.acct_grouped;
                self.selected = 0;
            }
            KeyCode::Char('n') => {
                if self.require_writable() {
                    self.start_edit(false);
                }
            }
            KeyCode::Char('d') => {
                if self.require_writable() {
                    self.delete_selected();
                }
            }
            // Accounts-only display filters: cycle by type / subtype / owner.
            // Guarded arms (`if self.tab == Tab::Accounts`): the same key does
            // nothing on other tabs (falls through to the `_ => {}` arm).
            // The four filter cycles all use the CROSS-FILTERED options (values
            // present among accounts matching the OTHER active filters), and then
            // `narrow_account_filters` drops any other selection that is no longer a
            // valid option — full faceted filtering, auto-clearing stale picks.
            KeyCode::Char('t') if self.tab == Tab::Accounts => {
                let opts = self.account_facets().types;
                self.acct_filter_type = cycle_filter(&self.acct_filter_type, &opts);
                self.narrow_account_filters();
                self.selected = 0;
            }
            KeyCode::Char('s') if self.tab == Tab::Accounts => {
                let opts = self.account_facets().subtypes;
                self.acct_filter_subtype = cycle_filter(&self.acct_filter_subtype, &opts);
                self.narrow_account_filters();
                self.selected = 0;
            }
            KeyCode::Char('o') if self.tab == Tab::Accounts => {
                let opts = self.account_facets().owners;
                self.acct_filter_owner = cycle_filter(&self.acct_filter_owner, &opts);
                self.narrow_account_filters();
                self.selected = 0;
            }
            KeyCode::Char('l') if self.tab == Tab::Accounts => {
                let opts = self.account_facets().titles;
                self.acct_filter_title = cycle_filter(&self.acct_filter_title, &opts);
                self.narrow_account_filters();
                self.selected = 0;
            }
            // The single global reveal toggle (Accounts tab) — the only reveal control.
            KeyCode::Char('r') if self.tab == Tab::Accounts => {
                self.reveal_all = !self.reveal_all;
            }
            // Same, for the Real Estate tab's portal passwords.
            KeyCode::Char('r') if self.tab == Tab::RealEstate => {
                self.re_reveal_all = !self.re_reveal_all;
            }
            // One-off maintenance (any tab): left/right-trim every field on every
            // record in the whole vault. Capital T (Shift+t) so it can't be hit by
            // accident.
            KeyCode::Char('T') => {
                if self.require_writable() {
                    self.trim_all_records();
                }
            }
            // Enter username-search input mode (Accounts tab).
            KeyCode::Char('/') if self.tab == Tab::Accounts => {
                self.search_active = true;
            }
            // Review-only filter toggle (Accounts and Assets tabs).
            KeyCode::Char('v') if self.tab == Tab::Accounts => {
                self.acct_filter_review = !self.acct_filter_review;
                self.narrow_account_filters(); // review-only is a facet too
                self.selected = 0;
            }
            KeyCode::Char('v') if self.tab == Tab::Assets => {
                self.asset_filter_review = !self.asset_filter_review;
                self.selected = 0;
            }
            KeyCode::Char('p') => {
                if self.require_writable() {
                    self.auth = AuthState::new(AuthMode::ChangePassword);
                    self.screen = Screen::Auth;
                }
            }
            KeyCode::Char('c') => {
                self.cfg_focus = 0;
                self.screen = Screen::Config;
            }
            _ => {}
        }
        false
    }

    fn handle_config_key(&mut self, key: KeyEvent) -> bool {
        // A local `const` (compile-time constant) for the field count.
        const CFG_FIELDS: usize = 8;
        match key.code {
            KeyCode::Esc => self.screen = Screen::Browse,
            KeyCode::Tab | KeyCode::Down => self.cfg_focus = (self.cfg_focus + 1) % CFG_FIELDS,
            KeyCode::BackTab | KeyCode::Up => self.cfg_focus = (self.cfg_focus + CFG_FIELDS - 1) % CFG_FIELDS,
            // Only allow editing a field whose action is reachable in this mode: in
            // read-only that's just backup-dest (5) and export-dir (7), matching the
            // `submit_config` allow-list. The write-only fields stay inert (the GUI hides
            // them outright), so a read-only user can't type into a control that can never
            // apply. (These buffers are App state, never vault content.)
            KeyCode::Char(c)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && (self.writable || matches!(self.cfg_focus, 5 | 7)) =>
            {
                self.cfg_field_mut().push(c);
            }
            KeyCode::Backspace if self.writable || matches!(self.cfg_focus, 5 | 7) => {
                self.cfg_field_mut().pop();
            }
            KeyCode::Enter => self.submit_config(),
            // Delete the type/subtype named in the focused field (only if unused).
            KeyCode::Delete => self.delete_config(),
            _ => {}
        }
        false
    }

    // Returns `&mut String`: an exclusive borrow of whichever input field is
    // currently focused, so the caller can push/pop characters into it. Each arm
    // hands back a mutable reference to one of the config strings.
    fn cfg_field_mut(&mut self) -> &mut String {
        match self.cfg_focus {
            0 => &mut self.cfg_asset_type,
            1 => &mut self.cfg_account_type,
            2 => &mut self.cfg_subtype_type,
            3 => &mut self.cfg_subtype_name,
            4 => &mut self.cfg_volume_size,
            5 => &mut self.cfg_backup_dest,
            6 => &mut self.cfg_redundancy,
            _ => &mut self.cfg_export_dir,
        }
    }

    /// Perform the focused config action: add a type/subtype, set the volume
    /// size, or run a backup.
    fn submit_config(&mut self) {
        // Backup (focus 5) is a read/copy and the export directory (focus 7) is a
        // local non-vault preference — both are always allowed, even read-only. The
        // type/subtype adds and the volume-size/redundancy changes (focus 0..4, 6)
        // mutate the vault and need --write.
        if self.cfg_focus != 5 && self.cfg_focus != 7 && !self.require_writable() {
            return;
        }
        match self.cfg_focus {
            0 => {
                // `.trim()` strips surrounding whitespace; `.to_string()` makes an
                // owned copy. `.expect(...)` unwraps the open vault (panics with the
                // message if absent — safe, since Config is only reachable unlocked).
                // The result is a `Result<bool, _>`: `Ok(true)` = added, `Ok(false)`
                // = no-op (empty/duplicate), `Err(e)` = save failed.
                let name = self.cfg_asset_type.trim().to_string();
                match self.vault.as_mut().expect("vault open on config").add_asset_type(&name) {
                    Ok(true) => {
                        self.status = format!("Added asset/liability type “{name}”.");
                        self.cfg_asset_type.clear();
                    }
                    Ok(false) => self.status = "Type is empty or already exists.".into(),
                    Err(e) => self.status = format!("Save failed: {e}"),
                }
            }
            1 => {
                let name = self.cfg_account_type.trim().to_string();
                match self.vault.as_mut().expect("vault open on config").add_account_type(&name) {
                    Ok(true) => {
                        self.status = format!("Added account type “{name}”.");
                        self.cfg_account_type.clear();
                    }
                    Ok(false) => self.status = "Type is empty or already exists.".into(),
                    Err(e) => self.status = format!("Save failed: {e}"),
                }
            }
            2 | 3 => {
                let ty = self.cfg_subtype_type.trim().to_string();
                let sub = self.cfg_subtype_name.trim().to_string();
                match self
                    .vault
                    .as_mut()
                    .expect("vault open on config")
                    .add_account_subtype(&ty, &sub)
                {
                    Ok(true) => {
                        self.status = format!("Added subtype “{sub}” under “{ty}”.");
                        self.cfg_subtype_name.clear();
                    }
                    Ok(false) => self.status = "Unknown type, or subtype empty/duplicate.".into(),
                    Err(e) => self.status = format!("Save failed: {e}"),
                }
            }
            // `.parse::<u64>()` attempts to read the text as an unsigned 64-bit
            // integer, returning `Result<u64, _>`. The guarded `Ok(mib) if mib >= 1`
            // arm accepts only a positive number; anything else falls to `_`.
            4 => match self.cfg_volume_size.trim().parse::<u64>() {
                Ok(mib) if mib >= 1 => {
                    // `saturating_mul` clamps to the max instead of overflowing.
                    let bytes = mib.saturating_mul(1024 * 1024);
                    match self.vault.as_mut().expect("vault open on config").set_volume_max_size(bytes) {
                        Ok(()) => {
                            self.status = format!("Volume size set to {mib} MiB (applies to future documents).");
                            self.cfg_volume_size.clear();
                        }
                        Err(e) => self.status = format!("Save failed: {e}"),
                    }
                }
                _ => self.status = "Enter a whole number of MiB (at least 1).".into(),
            },
            5 => {
                let dest = self.cfg_backup_dest.trim().to_string();
                if dest.is_empty() {
                    self.status = "Enter a backup destination directory.".into();
                } else if let Some(ov) = self.vault.as_ref() {
                    // Use the OPEN handle's backup (reuses this session's write lock);
                    // the free `vault::backup` would self-deadlock re-acquiring the lock.
                    match ov.backup(Path::new(&dest)) {
                        Ok(p) => self.status = format!("Backed up to {}", p.display()),
                        Err(e) => self.status = format!("Backup failed: {e}"),
                    }
                }
            }
            // Vault file redundancy depth (0 = off). See `docs/DESIGN.md` §12.8.
            6 => match self.cfg_redundancy.trim().parse::<u32>() {
                Ok(depth) => match self.vault.as_mut().expect("vault open on config").set_redundancy(depth) {
                    Ok(()) => {
                        let applied = self.vault_ref().redundancy();
                        self.status = if applied == 0 {
                            "Vault file redundancy turned off (extra copies removed).".into()
                        } else {
                            format!("Vault file redundancy set to {applied} (mirror + {applied} prior generation(s)).")
                        };
                        self.cfg_redundancy.clear();
                    }
                    Err(e) => self.status = format!("Save failed: {e}"),
                },
                _ => self.status = "Enter a whole number (0 = off).".into(),
            },
            // Document export directory — a local, non-vault preference (prefs.json),
            // so it is settable even read-only. Documents export into this directory,
            // recreating their volume folder structure. An empty value clears it.
            _ => {
                let dir = self.cfg_export_dir.trim().to_string();
                self.cfg_export_dir = dir.clone();
                crate::save_export_dir(&dir);
                self.status = if dir.is_empty() {
                    "Export directory cleared.".into()
                } else {
                    format!("Export directory set to {dir}")
                };
            }
        }
    }

    /// Delete the category named in the focused field (Del key). Asset type (focus 0),
    /// account type (focus 1), or subtype (focus 2/3, using both subtype fields). A
    /// type/subtype is removed only when no LIVE record uses it (history never blocks),
    /// and an account type is refused while it still has subtypes (delete those first).
    fn delete_config(&mut self) {
        if !self.require_writable() {
            return;
        }
        match self.cfg_focus {
            0 => {
                let name = self.cfg_asset_type.trim().to_string();
                if name.is_empty() {
                    self.status = "Type the exact asset/liability type to delete.".into();
                    return;
                }
                self.status = match self.vault.as_mut().expect("vault open on config").remove_asset_type(&name) {
                    Ok(CategoryRemoval::Removed) => {
                        self.cfg_asset_type.clear();
                        format!("Deleted asset/liability type “{name}”.")
                    }
                    Ok(CategoryRemoval::InUse(n)) => format!("Can’t delete “{name}”: still used by {n} record(s)."),
                    Ok(CategoryRemoval::NotFound) => format!("“{name}” was not found."),
                    Ok(CategoryRemoval::HasSubtypes) => unreachable!("asset types have no subtypes"),
                    Err(e) => format!("Delete failed: {e}"),
                };
            }
            1 => {
                let name = self.cfg_account_type.trim().to_string();
                if name.is_empty() {
                    self.status = "Type the exact account type to delete.".into();
                    return;
                }
                self.status = match self.vault.as_mut().expect("vault open on config").remove_account_type(&name) {
                    Ok(CategoryRemoval::Removed) => {
                        self.cfg_account_type.clear();
                        format!("Deleted account type “{name}”.")
                    }
                    Ok(CategoryRemoval::HasSubtypes) => format!("Can’t delete “{name}”: delete its subtypes first."),
                    Ok(CategoryRemoval::InUse(n)) => format!("Can’t delete “{name}”: still used by {n} account(s)."),
                    Ok(CategoryRemoval::NotFound) => format!("“{name}” was not found."),
                    Err(e) => format!("Delete failed: {e}"),
                };
            }
            2 | 3 => {
                let ty = self.cfg_subtype_type.trim().to_string();
                let sub = self.cfg_subtype_name.trim().to_string();
                if ty.is_empty() || sub.is_empty() {
                    self.status = "Fill both subtype fields (type + subtype) to delete.".into();
                    return;
                }
                self.status =
                    match self.vault.as_mut().expect("vault open on config").remove_account_subtype(&ty, &sub) {
                        Ok(CategoryRemoval::Removed) => {
                            self.cfg_subtype_name.clear();
                            format!("Deleted subtype “{sub}” under “{ty}”.")
                        }
                        Ok(CategoryRemoval::InUse(n)) => format!("Can’t delete “{sub}”: still used by {n} account(s)."),
                        Ok(CategoryRemoval::NotFound) => format!("“{sub}” was not found under “{ty}”."),
                        Ok(CategoryRemoval::HasSubtypes) => unreachable!("a subtype has no subtypes"),
                        Err(e) => format!("Delete failed: {e}"),
                    };
            }
            _ => self.status = "Delete (Del) only applies to the type/subtype fields.".into(),
        }
    }

    // --- Editing -------------------------------------------------------------

    /// Build the edit form for the current tab, from the selected record
    /// (`existing = true`) or a fresh one.
    fn start_edit(&mut self, existing: bool) {
        let tab = self.tab;
        // Resolve the selected record by id: the browse list may be filtered
        // (Accounts), so a positional index must not be applied to the unfiltered
        // vector. `sel` finds a record by that id in any record vector.
        // `.get(i)` returns `Option<&T>` (None if out of bounds — no panic).
        // `.map(|(id, _)| id.clone())` transforms the inner `Some` value: it
        // destructures the `(id, label)` tuple, ignores the label (`_`), and clones
        // the id into an owned String. For a new record there is no selection.
        let sel_id: Option<String> = if !existing {
            None
        } else if self.acct_tree_mode() {
            // Grouped Accounts: the selected row's leaf id (a group row has none).
            match self.account_rows().get(self.selected).map(|r| &r.kind) {
                Some(AcctRowKind::Leaf { id }) => Some(id.clone()),
                _ => None,
            }
        } else {
            self.current_labels().get(self.selected).map(|(id, _)| id.clone())
        };
        let v = &self.vault_ref().vault;

        // Destructure the chosen branch's tuple into five named bindings; `mut
        // fields` is mutable because doc inputs may be appended below. The explicit
        // type annotation documents what each arm of the following `match` returns.
        let (id, created_at, mut fields, attached, history): (
            Option<String>,
            i64,
            Vec<Field>,
            Option<String>,
            Vec<Change>,
        ) = match tab {
            Tab::Instructions => {
                // Find the selected record, else build a fresh one:
                //  - `.as_ref()` borrows inside the `Option` so it isn't consumed.
                //  - `.and_then(closure)` runs the closure only if `Some`, and the
                //    closure itself returns an `Option` (flattening the two).
                //  - `.find(|r| &r.id == id)` scans for the matching record and
                //    returns `Option<&Instruction>`; `.cloned()` makes it owned.
                //  - `.unwrap_or_else(|| ...)` supplies a default when `None`; the
                //    inner `unwrap_or_default()` falls back if `Instruction::new()`
                //    (which can fail) returns an error.
                let r = sel_id
                    .as_ref()
                    .and_then(|id| v.instructions.iter().find(|r| &r.id == id).cloned())
                    .unwrap_or_else(|| Instruction::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::text("Title", r.title.clone()),
                        Field::multiline("Description", r.description.clone()),
                    ],
                    None,
                    r.history.clone(),
                )
            }
            Tab::TrustWill => {
                let r = sel_id
                    .as_ref()
                    .and_then(|id| v.trust_wills.iter().find(|r| &r.id == id).cloned())
                    .unwrap_or_else(|| TrustWill::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::text("Document", r.document.clone()),
                        Field::multiline("Usage", r.usage.clone()),
                    ],
                    r.file.clone(),
                    r.history.clone(),
                )
            }
            Tab::Assets => {
                let r = sel_id
                    .as_ref()
                    .and_then(|id| v.assets.iter().find(|r| &r.id == id).cloned())
                    .unwrap_or_else(|| AssetLiability::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::choice("Asset/Liability", r.kind.clone(), vec!["Asset".into(), "Liability".into()]),
                        Field::multiline("Description", r.description.clone()),
                        Field::text("Owner", r.owner.clone()),
                        Field::text("Beneficiary", r.beneficiary.clone()),
                        Field::text("Approx. value", r.approx_value.clone()),
                        Field::text("As-of date", r.as_of_date.clone()),
                        Field::text("Institution", r.institution.clone()),
                        Field::choice(
                            "Type",
                            r.asset_type.clone(),
                            self.vault_ref().categories().asset.clone(),
                        ),
                        Field::text("URL", r.url.clone()),
                        Field::choice("Review", bool_choice(r.review), yes_no()),
                    ],
                    r.statement.clone(),
                    r.history.clone(),
                )
            }
            Tab::Accounts => {
                let mut r = sel_id
                    .as_ref()
                    .and_then(|id| v.accounts.iter().find(|r| &r.id == id).cloned())
                    .unwrap_or_else(|| Account::new().unwrap_or_default());
                // For a NEW account, pre-populate the editable fields from the active
                // Accounts filters / username search, so the entry starts in the
                // bucket the user is viewing. Nothing is saved until they hit save.
                if !existing {
                    if let Some(t) = &self.acct_filter_title {
                        r.title = t.clone();
                    }
                    if let Some(t) = &self.acct_filter_type {
                        r.account_type = t.clone();
                    }
                    if let Some(st) = &self.acct_filter_subtype {
                        r.account_subtype = st.clone();
                    }
                    if let Some(o) = &self.acct_filter_owner {
                        r.owner = o.clone();
                    }
                    let q = self.acct_search.trim();
                    if !q.is_empty() {
                        r.username = q.to_string();
                    }
                }
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::text("Title", r.title.clone()),
                        Field::choice(
                            "Account type",
                            r.account_type.clone(),
                            self.vault_ref().categories().account_type_names(),
                        ),
                        // Subtype is a dependent dropdown of the chosen type's
                        // subtypes; the current value is kept selectable even if
                        // it is not in the configured list (e.g. legacy data).
                        // The third argument is a block expression `{ ... }` that
                        // computes the options list. `.any(|x| x == &...)` returns
                        // true if any option equals the current value; if not, the
                        // current value is prepended so legacy data stays selectable.
                        Field::choice("Subtype", r.account_subtype.clone(), {
                            let mut s = self.vault_ref().categories().subtypes_for(&r.account_type);
                            if !r.account_subtype.is_empty()
                                && !s.iter().any(|x| x == &r.account_subtype)
                            {
                                s.insert(0, r.account_subtype.clone());
                            }
                            s
                        }),
                        Field::text("Owner", r.owner.clone()),
                        Field::text("Username", r.username.clone()),
                        Field::password("Password", r.password.clone()),
                        Field::text("URL", r.url.clone()),
                        Field::text("Closed as of", r.closed_as_of.clone()),
                        Field::multiline("Description", r.description.clone()),
                        Field::choice("Review", bool_choice(r.review), yes_no()),
                    ],
                    None,
                    r.history.clone(),
                )
            }
            Tab::RealEstate => {
                let r = sel_id
                    .as_ref()
                    .and_then(|id| v.real_estate.iter().find(|r| &r.id == id).cloned())
                    .unwrap_or_else(|| RealEstate::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::text("Address", r.address.clone()),
                        Field::text("Ownership", r.ownership.clone()),
                        Field::text("Taxes", r.taxes.clone()),
                        Field::text("HOA dues/info", r.hoa.clone()),
                        Field::text("Income account", r.income_account.clone()),
                        Field::text("Financing account", r.financing_account.clone()),
                        Field::text("Financing balance", r.financing_balance.clone()),
                        Field::text("Payment account", r.payment_account.clone()),
                        Field::text("Property Mgmt URL", r.property_mgmt_url.clone()),
                        Field::text("Property Mgmt username", r.property_mgmt_username.clone()),
                        Field::password("Property Mgmt password", r.property_mgmt_password.clone()),
                        Field::multiline("Property Mgmt comment", r.property_mgmt_comment.clone()),
                        Field::text("Insurance URL", r.insurance_url.clone()),
                        Field::text("Insurance username", r.insurance_username.clone()),
                        Field::password("Insurance password", r.insurance_password.clone()),
                        Field::multiline("Insurance comment", r.insurance_comment.clone()),
                        Field::text("HOA URL", r.hoa_url.clone()),
                        Field::text("HOA username", r.hoa_username.clone()),
                        Field::password("HOA password", r.hoa_password.clone()),
                        Field::multiline("HOA comment", r.hoa_comment.clone()),
                        Field::text("Tax URL", r.tax_portal_url.clone()),
                        Field::text("Tax username", r.tax_portal_username.clone()),
                        Field::password("Tax password", r.tax_portal_password.clone()),
                        Field::multiline("Tax comment", r.tax_portal_comment.clone()),
                        Field::multiline("Comments", r.comments.clone()),
                    ],
                    None,
                    r.history.clone(),
                )
            }
            Tab::Taxes => {
                let r = sel_id
                    .as_ref()
                    .and_then(|id| v.tax_filings.iter().find(|r| &r.id == id).cloned())
                    .unwrap_or_else(|| TaxFiling::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::text("Filing year", r.year.clone()),
                        Field::multiline("Notes", r.notes.clone()),
                    ],
                    None,
                    r.history.clone(),
                )
            }
            Tab::GeneralDocuments => {
                let r = sel_id
                    .as_ref()
                    .and_then(|id| v.general_documents.iter().find(|r| &r.id == id).cloned())
                    .unwrap_or_else(|| GeneralDocument::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::text("Title", r.title.clone()),
                        Field::multiline("Description", r.description.clone()),
                    ],
                    r.file.clone(),
                    r.history.clone(),
                )
            }
        };

        // Remember how many fields belong to the record itself, before appending
        // the extra doc-upload inputs (so the two groups can be told apart later).
        let record_fields = fields.len();
        // Uniform document-upload inputs for every document-bearing tab. The stored
        // location is auto-derived as <root>/<auto-group>/<timestamp>[/<subfolder>];
        // the user controls only the filename and the optional subfolder. There is no
        // per-export path: Ctrl+E exports into the configured export directory (set in
        // Config), recreating the document's folder structure there. The multi-document
        // tabs additionally get a "Doc #" selecting which listed document Ctrl+E / Ctrl+K
        // act on. Field order after `record_fields` (rc):
        //   rc+0 filename · rc+1 upload-from · rc+2 subfolder · rc+3 doc# (multi only).
        let multi = matches!(tab, Tab::Taxes | Tab::RealEstate);
        if tab_has_docs(tab) || multi {
            fields.push(Field::text("Doc filename", String::new()));
            fields.push(Field::text("Upload from", String::new()));
            fields.push(Field::text("Subfolder (optional)", String::new()));
            if multi {
                fields.push(Field::text("Doc # (export/remove)", String::new()));
            }
        }
        // Load the existing document list for the multi-document tabs.
        let tax_docs: Vec<String> = if tab == Tab::Taxes {
            sel_id
                .as_ref()
                .and_then(|id| v.tax_filings.iter().find(|r| &r.id == id).map(|r| r.documents.clone()))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let re_docs: Vec<String> = if tab == Tab::RealEstate {
            sel_id
                .as_ref()
                .and_then(|id| v.real_estate.iter().find(|r| &r.id == id).map(|r| r.documents.clone()))
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        self.edit = Some(EditState {
            tab,
            id,
            created_at,
            fields,
            record_fields,
            focus: 0,
            attached_file_id: attached,
            tax_docs,
            re_docs,
            history,
        });
        self.screen = Screen::Edit;
    }

    fn handle_edit_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        // Captured before borrowing `self.edit` below. In read-only mode the Edit
        // screen is a VIEW: reveal/copy/export still work, but the field-mutating keys
        // (typing, backspace, choice-cycling) are inert — nothing can be edited.
        let writable = self.writable;
        // `let Some(es) = ... else { ... }` is a *let-else*: if the pattern matches,
        // `es` is bound (here an exclusive borrow of the edit buffer) and used
        // after the block; if it does NOT match (no edit in progress), the `else`
        // block runs and MUST diverge (here it `return`s), so `es` is always valid
        // below.
        let Some(es) = self.edit.as_mut() else {
            self.screen = Screen::Browse;
            return false;
        };
        match key.code {
            KeyCode::Esc => {
                self.edit = None;
                self.screen = Screen::Browse;
            }
            // Write actions are gated by --write; reads (reveal/copy/export) are not.
            KeyCode::Char('s') if ctrl => {
                if self.require_writable() {
                    self.save_edit();
                }
            }
            KeyCode::Char('g') if ctrl => {
                // Generate into the FOCUSED password field, not just the first one.
                // The Real Estate tab has four independent portal password fields,
                // so a blind "first password" would always regenerate Property Mgmt
                // (silently overwriting it) and could never reach Insurance/HOA/Tax.
                let pw_idx = target_password_index(&es.fields, es.focus);
                if self.writable
                    && let Some(i) = pw_idx
                {
                    // Wipe the previous value before replacing it: a plain `String`
                    // reassignment frees the old buffer without zeroizing, leaving the
                    // prior password in freed heap.
                    let f = &mut es.fields[i];
                    f.value.zeroize();
                    f.value = password::generate(&GenOptions::default()).unwrap_or_default();
                    // Show the generated value via the single global reveal (the only
                    // reveal control now — there is no per-record reveal).
                    match es.tab {
                        Tab::Accounts => self.reveal_all = true,
                        Tab::RealEstate => self.re_reveal_all = true,
                        _ => {}
                    }
                    self.status = "Generated a random password.".into();
                } else if !self.writable {
                    self.require_writable();
                }
            }
            // Ctrl+R toggles the single GLOBAL reveal for the current tab (the only
            // reveal control; it also governs the browse list, scoped per screen).
            KeyCode::Char('r') if ctrl => match es.tab {
                Tab::Accounts => self.reveal_all = !self.reveal_all,
                Tab::RealEstate => self.re_reveal_all = !self.re_reveal_all,
                _ => {}
            },
            KeyCode::Char('y') if ctrl => {
                // Copy the FOCUSED password field (not just the first), so each Real
                // Estate portal password can be copied independently — otherwise
                // Ctrl+Y on Insurance/HOA would leak the Property Mgmt password.
                if let Some(i) = target_password_index(&es.fields, es.focus) {
                    // Clone into a `Zeroizing<String>` so the temporary copy is
                    // wiped from memory as soon as `pw` drops.
                    let pw = Zeroizing::new(es.fields[i].value.clone());
                    self.copy_to_clipboard(pw);
                }
            }
            KeyCode::Char('u') if ctrl => {
                if self.require_writable() {
                    if self.tab == Tab::Taxes {
                        self.attach_tax_document();
                    } else if self.tab == Tab::RealEstate {
                        self.attach_re_document();
                    } else {
                        self.attach_document();
                    }
                }
            }
            KeyCode::Char('e') if ctrl => {
                if self.tab == Tab::Taxes {
                    self.export_tax_document();
                } else if self.tab == Tab::RealEstate {
                    self.export_re_document();
                } else {
                    self.export_document();
                }
            }
            KeyCode::Char('k') if ctrl => {
                if self.require_writable() {
                    if self.tab == Tab::Taxes {
                        self.remove_tax_document();
                    } else if self.tab == Tab::RealEstate {
                        self.remove_re_document();
                    } else {
                        self.detach_document();
                    }
                }
            }
            KeyCode::Tab | KeyCode::Down => {
                es.focus = (es.focus + 1) % es.fields.len();
            }
            KeyCode::BackTab | KeyCode::Up => {
                let n = es.fields.len();
                es.focus = (es.focus + n - 1) % n;
            }
            // One arm handles both arrow keys (`A | B` = "A or B"); `delta` is -1
            // for Left, +1 for Right, used to step a Choice field's selection.
            // Read-only: cycling a choice would edit the record, so it is inert.
            KeyCode::Left | KeyCode::Right if writable => {
                let delta = if matches!(key.code, KeyCode::Left) { -1 } else { 1 };
                es.fields[es.focus].cycle(delta);
                // On the Accounts tab, cycling the account-type field reconstrains
                // the dependent subtype field: rebuild its options for the new type
                // and drop a value that no longer belongs to it.
                // `.as_str()` borrows the `String` label as a `&str` for comparison.
                if self.tab == Tab::Accounts && es.fields[es.focus].label.as_str() == "Account type" {
                    let new_type = es.fields[es.focus].value.clone();
                    // `.position(...)` finds the subtype field's index, if present.
                    if let Some(si) = es.fields.iter().position(|f| f.label.as_str() == "Subtype") {
                        let opts = self
                            .vault
                            .as_ref()
                            .map(|ov| ov.categories().subtypes_for(&new_type))
                            .unwrap_or_default();
                        let cur = es.fields[si].value.clone();
                        // Keep the current subtype only if it's still a valid option.
                        let value = if opts.iter().any(|o| o == &cur) { cur } else { String::new() };
                        es.fields[si] = Field::choice("Subtype", value, opts);
                    }
                }
            }
            // A typed char (non-Ctrl): append it, but only to free-text fields —
            // `!matches!(f.kind, FieldKind::Choice(_))` skips dropdowns, which are
            // edited with the arrow keys instead. `&mut es.fields[es.focus]` is an
            // exclusive borrow of the focused field.
            // Read-only mode (`writable` false) drops typing/backspace so the fields
            // cannot be edited; reveal/copy/export above remain available for viewing.
            KeyCode::Char(c) if !ctrl && writable => {
                let f = &mut es.fields[es.focus];
                if !matches!(f.kind, FieldKind::Choice(_)) {
                    f.value.push(c);
                }
            }
            KeyCode::Backspace if writable => {
                let f = &mut es.fields[es.focus];
                if !matches!(f.kind, FieldKind::Choice(_)) {
                    f.value.pop();
                }
            }
            _ => {}
        }
        false
    }

    /// Ensure the edit buffer has a stable id (generating one for a new record),
    /// so a brand-new record can't end up with an empty colliding id.
    // No `self` — this is an associated function, called as `Self::ensure_id(...)`.
    // `.map_err(|e| e.to_string())` converts the generator's error into a String,
    // and the `?` then early-returns that `Err` if id generation failed.
    fn ensure_id(es: &mut EditState) -> Result<(), String> {
        if es.id.is_none() {
            es.id = Some(records::random_id().map_err(|e| e.to_string())?);
        }
        Ok(())
    }

    /// Read the doc-input fields, upload the document into the volume, and
    /// immediately persist the record→document link so there is no orphan.
    fn attach_document(&mut self) {
        // `.take()` moves the value out of the `Option`, leaving `None` behind, so
        // we own `es` (mutably) for the duration; the `else { return }` bails if
        // there is no edit in progress. Throughout this function, on any early
        // exit we put `es` back with `self.edit = Some(es)` so the buffer survives.
        let Some(mut es) = self.edit.take() else { return };
        if !es.has_docs() {
            self.edit = Some(es);
            return;
        }
        let rc = es.record_fields;
        let filename = es.fields[rc].value.clone();
        let source = es.fields[rc + 1].value.clone();
        let subfolder = es.fields[rc + 2].value.clone();
        if source.trim().is_empty() {
            self.status = "'Upload from' is required.".into();
            self.edit = Some(es);
            return;
        }
        // If no filename is given, default to the source file's own name.
        let filename = records::effective_doc_filename(&filename, &source);
        if filename.trim().is_empty() {
            self.status = "Doc filename is required (the source path has no file name).".into();
            self.edit = Some(es);
            return;
        }
        // The auto-group level is derived from the record's identifying field; the
        // user controls only the subfolder and filename. Build the uniform
        // <root>/<auto-group>/<timestamp>[/<subfolder>] directory.
        let prefix = match es.tab {
            Tab::TrustWill => records::trust_will_doc_location(&es.fields[0].value),
            Tab::Assets => records::asset_doc_location(&es.fields[1].value),
            Tab::GeneralDocuments => records::general_doc_location(&es.fields[0].value),
            _ => {
                self.edit = Some(es);
                return;
            }
        };
        let fname = records::doc_filename(&filename);
        let location = records::doc_upload_dir(&prefix, &records::compact_utc(records::unix_now()), &subfolder);
        // Reject an over-length virtual path up front (same limit the core
        // enforces) so the upload key gives a clear message, not a generic error.
        let vpath_len = crate::vault::virtual_path(&location, &fname).len();
        if vpath_len > crate::storage::MAX_PATH_LEN {
            self.status =
                format!("Doc path too long: {vpath_len} bytes (max {}). Shorten it.", crate::storage::MAX_PATH_LEN);
            self.edit = Some(es);
            return;
        }
        let id = match self.vault.as_mut() {
            Some(ov) => match ov.add_document(&location, &fname, Path::new(&source)) {
                Ok(id) => id,
                Err(e) => {
                    self.status = format!("Upload failed: {e}");
                    self.edit = Some(es);
                    return;
                }
            },
            None => {
                self.edit = Some(es);
                return;
            }
        };
        // Replacing an existing attachment: reclaim the previous blob so it does
        // not become an orphan in the archive.
        // `.replace(id)` stores the new id and returns the OLD one (as an Option).
        let previous = es.attached_file_id.replace(id);
        // Clear the consumed upload inputs (filename, upload-from, subfolder).
        es.fields[rc].value.clear();
        es.fields[rc + 1].value.clear();
        es.fields[rc + 2].value.clear();
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        // Persist the new link BEFORE reclaiming the replaced blob. Bail on a failed
        // save (full disk, poisoned handle, …): the link never reached vault.pmv, so
        // report the failure rather than a false "uploaded" — and do NOT reclaim
        // `old`, which the on-disk vault still references (dropping it would make the
        // vault unopenable). persist() already set the "Save failed: …" status.
        if !self.persist() {
            self.edit = Some(es);
            return;
        }
        // The new link is durable; reclaim the replaced blob (best-effort).
        if let Some(old) = previous
            && let Some(ov) = self.vault.as_mut()
        {
            let _ = ov.remove_document(&old);
        }
        self.status = "Document uploaded to the encrypted volume.".into();
        self.edit = Some(es);
    }

    /// Detach the current record's document AND reclaim its encrypted blob, then
    /// persist (so a "removed" document does not linger in the archive).
    fn detach_document(&mut self) {
        let Some(mut es) = self.edit.take() else { return };
        // Only the document-bearing tabs have anything to detach; on others this
        // is a no-op (don't commit/persist or show a misleading status).
        if !es.has_docs() {
            self.edit = Some(es);
            return;
        }
        // `.take()` clears the attachment and returns the old id (if any).
        let id = es.attached_file_id.take();
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        // Persist the unlink BEFORE reclaiming the blob, and bail if the save
        // failed: reclaiming after a failed persist would leave vault.pmv pointing
        // at a missing doc (ArchiveMismatch). A dangling reference is fatal on
        // reopen; an orphaned blob is harmless.
        if !self.persist() {
            self.edit = Some(es); // persist() already set the "Save failed" status
            return;
        }
        // Three-condition let-chain: only when there was an id, the vault is open,
        // and the removal failed do we capture the error to report below.
        let mut cleanup_err = None;
        if let Some(id) = id
            && let Some(ov) = self.vault.as_mut()
            && let Err(e) = ov.remove_document(&id)
        {
            cleanup_err = Some(e);
        }
        // Surface a failed blob reclaim instead of silently reporting success.
        self.status = match cleanup_err {
            Some(e) => format!("Unlinked, but blob cleanup failed: {e}"),
            None => "Removed document from the vault.".into(),
        };
        self.edit = Some(es);
    }

    /// Export document `id` into the configured export directory (`cfg_export_dir`),
    /// recreating its volume folder structure under it. There is no per-export path
    /// prompt; the directory is set in Config and is settable even in read-only mode
    /// (it is a local preference), so a read-only user can still extract documents.
    fn export_doc_to_config_dir(&mut self, id: &str) {
        let dir = self.cfg_export_dir.trim().to_string();
        if dir.is_empty() {
            self.status = "Set an export directory in Config first (Config → Export directory).".into();
            return;
        }
        if let Some(ov) = self.vault.as_ref() {
            match ov.export_document_into(id, Path::new(&dir)) {
                Ok(p) => self.status = format!("Exported to {}", p.display()),
                Err(e) => self.status = format!("Export failed: {e}"),
            }
        }
    }

    fn export_document(&mut self) {
        let id = {
            let Some(es) = self.edit.as_ref() else { return };
            if !es.has_docs() {
                return;
            }
            let Some(id) = es.attached_file_id.clone() else {
                self.status = "No document attached to export.".into();
                return;
            };
            id
        };
        self.export_doc_to_config_dir(&id);
    }

    /// Upload a document into the current tax filing's `taxes/<year>/` folder and
    /// append it to the filing's document list. Same persist discipline as
    /// `attach_document` (there is no previous blob to reclaim — this only adds).
    fn attach_tax_document(&mut self) {
        let Some(mut es) = self.edit.take() else { return };
        if es.tab != Tab::Taxes {
            self.edit = Some(es);
            return;
        }
        let rc = es.record_fields;
        let year = es.fields[0].value.clone();
        let filename = es.fields[rc].value.clone();
        let source = es.fields[rc + 1].value.clone();
        let subfolder = es.fields[rc + 2].value.clone();
        if source.trim().is_empty() {
            self.status = "'Upload from' is required.".into();
            self.edit = Some(es);
            return;
        }
        // If no filename is given, default to the source file's own name.
        let filename = records::effective_doc_filename(&filename, &source);
        if filename.trim().is_empty() {
            self.status = "Doc filename is required (the source path has no file name).".into();
            self.edit = Some(es);
            return;
        }
        let prefix = records::tax_doc_location(&year);
        let fname = records::doc_filename(&filename);
        let location = records::doc_upload_dir(&prefix, &records::compact_utc(records::unix_now()), &subfolder);
        let vpath_len = crate::vault::virtual_path(&location, &fname).len();
        if vpath_len > crate::storage::MAX_PATH_LEN {
            self.status =
                format!("Doc path too long: {vpath_len} bytes (max {}). Shorten it.", crate::storage::MAX_PATH_LEN);
            self.edit = Some(es);
            return;
        }
        let id = match self.vault.as_mut() {
            Some(ov) => match ov.add_document(&location, &fname, Path::new(&source)) {
                Ok(id) => id,
                Err(e) => {
                    self.status = format!("Upload failed: {e}");
                    self.edit = Some(es);
                    return;
                }
            },
            None => {
                self.edit = Some(es);
                return;
            }
        };
        es.tax_docs.push(id);
        es.fields[rc].value.clear(); // filename
        es.fields[rc + 1].value.clear(); // upload-from
        es.fields[rc + 2].value.clear(); // subfolder
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        if self.persist() {
            self.status = "Document uploaded to the encrypted volume.".into();
        }
        self.edit = Some(es);
    }

    /// Export the tax document whose 1-based number is in the "Doc #" field, into the
    /// configured export directory (recreating its folder structure there).
    fn export_tax_document(&mut self) {
        let id = {
            let Some(es) = self.edit.as_ref() else { return };
            if es.tab != Tab::Taxes {
                return;
            }
            let rc = es.record_fields;
            let Some(idx) = parse_doc_index(&es.fields[rc + 3].value, es.tax_docs.len()) else {
                self.status = format!("Enter a document # between 1 and {}.", es.tax_docs.len());
                return;
            };
            es.tax_docs[idx].clone()
        };
        self.export_doc_to_config_dir(&id);
    }

    /// Remove (and reclaim) the tax document whose 1-based number is in "Doc #".
    /// Persists the unlink before reclaiming the blob, like `detach_document`.
    fn remove_tax_document(&mut self) {
        let Some(mut es) = self.edit.take() else { return };
        if es.tab != Tab::Taxes {
            self.edit = Some(es);
            return;
        }
        let rc = es.record_fields;
        let Some(idx) = parse_doc_index(&es.fields[rc + 3].value, es.tax_docs.len()) else {
            self.status = format!("Enter a document # between 1 and {} to remove.", es.tax_docs.len());
            self.edit = Some(es);
            return;
        };
        let id = es.tax_docs.remove(idx);
        es.fields[rc + 3].value.clear();
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        if !self.persist() {
            self.edit = Some(es); // persist() already set the "Save failed" status
            return;
        }
        if let Some(ov) = self.vault.as_mut()
            && let Err(e) = ov.remove_document(&id)
        {
            self.status = format!("Unlinked, but blob cleanup failed: {e}");
            self.edit = Some(es);
            return;
        }
        self.status = "Removed document from the vault.".into();
        self.edit = Some(es);
    }

    /// Upload a document into the current property's `real-estate/<address>/`
    /// folder and append it to the property's document list.
    fn attach_re_document(&mut self) {
        let Some(mut es) = self.edit.take() else { return };
        if es.tab != Tab::RealEstate {
            self.edit = Some(es);
            return;
        }
        let rc = es.record_fields;
        let address = es.fields[0].value.clone();
        let filename = es.fields[rc].value.clone();
        let source = es.fields[rc + 1].value.clone();
        let subfolder = es.fields[rc + 2].value.clone();
        if source.trim().is_empty() {
            self.status = "'Upload from' is required.".into();
            self.edit = Some(es);
            return;
        }
        // If no filename is given, default to the source file's own name.
        let filename = records::effective_doc_filename(&filename, &source);
        if filename.trim().is_empty() {
            self.status = "Doc filename is required (the source path has no file name).".into();
            self.edit = Some(es);
            return;
        }
        let prefix = records::real_estate_doc_location(&address);
        let fname = records::doc_filename(&filename);
        let location = records::doc_upload_dir(&prefix, &records::compact_utc(records::unix_now()), &subfolder);
        let vpath_len = crate::vault::virtual_path(&location, &fname).len();
        if vpath_len > crate::storage::MAX_PATH_LEN {
            self.status =
                format!("Doc path too long: {vpath_len} bytes (max {}). Shorten it.", crate::storage::MAX_PATH_LEN);
            self.edit = Some(es);
            return;
        }
        let id = match self.vault.as_mut() {
            Some(ov) => match ov.add_document(&location, &fname, Path::new(&source)) {
                Ok(id) => id,
                Err(e) => {
                    self.status = format!("Upload failed: {e}");
                    self.edit = Some(es);
                    return;
                }
            },
            None => {
                self.edit = Some(es);
                return;
            }
        };
        es.re_docs.push(id);
        es.fields[rc].value.clear(); // filename
        es.fields[rc + 1].value.clear(); // upload-from
        es.fields[rc + 2].value.clear(); // subfolder
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        if self.persist() {
            self.status = "Document uploaded to the encrypted volume.".into();
        }
        self.edit = Some(es);
    }

    /// Export the property document whose 1-based number is in the "Doc #" field, into
    /// the configured export directory (recreating its folder structure there).
    fn export_re_document(&mut self) {
        let id = {
            let Some(es) = self.edit.as_ref() else { return };
            if es.tab != Tab::RealEstate {
                return;
            }
            let rc = es.record_fields;
            let Some(idx) = parse_doc_index(&es.fields[rc + 3].value, es.re_docs.len()) else {
                self.status = format!("Enter a document # between 1 and {}.", es.re_docs.len());
                return;
            };
            es.re_docs[idx].clone()
        };
        self.export_doc_to_config_dir(&id);
    }

    /// Remove (and reclaim) the property document whose 1-based number is in "Doc #".
    fn remove_re_document(&mut self) {
        let Some(mut es) = self.edit.take() else { return };
        if es.tab != Tab::RealEstate {
            self.edit = Some(es);
            return;
        }
        let rc = es.record_fields;
        let Some(idx) = parse_doc_index(&es.fields[rc + 3].value, es.re_docs.len()) else {
            self.status = format!("Enter a document # between 1 and {} to remove.", es.re_docs.len());
            self.edit = Some(es);
            return;
        };
        let id = es.re_docs.remove(idx);
        es.fields[rc + 3].value.clear();
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        if !self.persist() {
            self.edit = Some(es);
            return;
        }
        if let Some(ov) = self.vault.as_mut()
            && let Err(e) = ov.remove_document(&id)
        {
            self.status = format!("Unlinked, but blob cleanup failed: {e}");
            self.edit = Some(es);
            return;
        }
        self.status = "Removed document from the vault.".into();
        self.edit = Some(es);
    }

    /// Rebuild the typed record from the edit fields (using the buffer's stable
    /// id, which must already be set) and upsert it into the vault.
    // `es: &EditState` is a shared borrow — this reads the edit buffer and writes
    // into the vault.
    fn commit_edit_record(&mut self, es: &EditState) {
        // A local closure: `f(i)` returns an owned copy of field `i`'s value,
        // keeping the per-tab record-building below terse (`f(0)`, `f(1)`, …).
        let f = |i: usize| es.fields[i].value.clone();
        // Use the buffer's id, or an empty default if somehow unset.
        let id = es.id.clone().unwrap_or_default();
        let Some(ov) = self.vault.as_mut() else { return };
        // `&mut ov.vault` — exclusive borrow so we can push/replace records.
        let v = &mut ov.vault;
        match es.tab {
            Tab::Instructions => {
                // `Instruction::default()` builds an all-default record, which we
                // then overwrite field by field from the form.
                let mut r = Instruction::default();
                r.id = id;
                r.created_at = es.created_at;
                r.title = f(0);
                r.description = f(1);
                r.trim_fields(); // left/right-trim every field before persisting
                records::upsert(&mut v.instructions, r);
            }
            Tab::TrustWill => {
                let mut r = TrustWill::default();
                r.id = id;
                r.created_at = es.created_at;
                r.document = f(0);
                r.usage = f(1);
                r.file = es.attached_file_id.clone();
                r.trim_fields(); // left/right-trim every field before persisting
                records::upsert(&mut v.trust_wills, r);
            }
            Tab::Assets => {
                let mut r = AssetLiability::default();
                r.id = id;
                r.created_at = es.created_at;
                r.kind = f(0);
                r.description = f(1);
                r.owner = f(2);
                r.beneficiary = f(3);
                r.approx_value = f(4);
                r.as_of_date = f(5);
                r.institution = f(6);
                r.asset_type = f(7);
                r.url = f(8);
                // The "Review" Choice stores "Yes"/"No"; compare to get a bool.
                r.review = f(9) == "Yes";
                r.statement = es.attached_file_id.clone();
                r.trim_fields(); // left/right-trim every field before persisting
                records::upsert(&mut v.assets, r);
            }
            Tab::Accounts => {
                let mut r = Account::default();
                r.id = id;
                r.created_at = es.created_at;
                r.title = f(0);
                r.account_type = f(1);
                r.account_subtype = f(2);
                r.owner = f(3);
                r.username = f(4);
                r.password = f(5);
                r.url = f(6);
                r.closed_as_of = f(7);
                r.description = f(8);
                r.review = f(9) == "Yes";
                r.trim_fields(); // left/right-trim every field before persisting
                records::upsert(&mut v.accounts, r);
            }
            Tab::RealEstate => {
                let mut r = RealEstate::default();
                r.id = id;
                r.created_at = es.created_at;
                r.address = f(0);
                r.ownership = f(1);
                r.taxes = f(2);
                r.hoa = f(3);
                r.income_account = f(4);
                r.financing_account = f(5);
                r.financing_balance = f(6);
                r.payment_account = f(7);
                r.property_mgmt_url = f(8);
                r.property_mgmt_username = f(9);
                r.property_mgmt_password = f(10);
                r.property_mgmt_comment = f(11);
                r.insurance_url = f(12);
                r.insurance_username = f(13);
                r.insurance_password = f(14);
                r.insurance_comment = f(15);
                r.hoa_url = f(16);
                r.hoa_username = f(17);
                r.hoa_password = f(18);
                r.hoa_comment = f(19);
                r.tax_portal_url = f(20);
                r.tax_portal_username = f(21);
                r.tax_portal_password = f(22);
                r.tax_portal_comment = f(23);
                r.comments = f(24);
                r.documents = es.re_docs.clone();
                r.trim_fields(); // left/right-trim every field before persisting
                records::upsert(&mut v.real_estate, r);
            }
            Tab::Taxes => {
                let mut r = TaxFiling::default();
                r.id = id;
                r.created_at = es.created_at;
                r.year = f(0);
                r.notes = f(1);
                r.documents = es.tax_docs.clone();
                r.trim_fields(); // left/right-trim every field before persisting
                records::upsert(&mut v.tax_filings, r);
            }
            Tab::GeneralDocuments => {
                let mut r = GeneralDocument::default();
                r.id = id;
                r.created_at = es.created_at;
                r.title = f(0);
                r.description = f(1);
                r.file = es.attached_file_id.clone();
                r.trim_fields(); // left/right-trim every field before persisting
                records::upsert(&mut v.general_documents, r);
            }
        }
    }

    /// Save the current edit form back into the vault.
    fn save_edit(&mut self) {
        // Take ownership of the buffer; on the id-generation error path we put it
        // back so the user keeps their entered data.
        let Some(mut es) = self.edit.take() else { return };
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = format!("Could not create id: {e}");
            self.edit = Some(es);
            return;
        }
        // Title (field 0) and owner (field 3) are mandatory for accounts: refuse a
        // blank value for either and keep the edit form open so the user can fill it.
        if es.tab == Tab::Accounts && es.fields[0].value.trim().is_empty() {
            self.status = "Title is required — every account must have a title.".into();
            self.edit = Some(es);
            return;
        }
        if es.tab == Tab::Accounts && es.fields[3].value.trim().is_empty() {
            self.status = "Owner is required — every account must have an owner.".into();
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        if self.persist() {
            self.status = "Saved.".into();
            self.screen = Screen::Browse;
            // Keep the just-saved account visible: move any ACTIVE field filter to the
            // saved record's value (Account fields: 0 title, 1 type, 2 subtype, 3 owner)
            // so changing a filtered field follows the entry instead of hiding it.
            if es.tab == Tab::Accounts {
                let sync = |f: &mut Option<String>, v: &str| {
                    if f.is_some() {
                        *f = (!v.is_empty()).then(|| v.to_string());
                    }
                };
                sync(&mut self.acct_filter_title, &es.fields[0].value);
                sync(&mut self.acct_filter_type, &es.fields[1].value);
                sync(&mut self.acct_filter_subtype, &es.fields[2].value);
                sync(&mut self.acct_filter_owner, &es.fields[3].value);
                // Relax the NON-facet constraints too, or the saved record can still
                // vanish: clear review-only if the saved record isn't flagged (field 9),
                // and clear the username search if it no longer matches (field 4).
                if self.acct_filter_review && es.fields[9].value != "Yes" {
                    self.acct_filter_review = false;
                }
                if !self.acct_search.is_empty()
                    && !records::matches_search(&es.fields[4].value, &self.acct_search)
                {
                    self.acct_search.clear();
                }
                self.narrow_account_filters();
            }
            self.clamp_selection();
        } else {
            // persist() already set "Save failed: …". Keep the edit buffer open so the
            // user can retry rather than being told "Saved." while the write failed
            // (full disk, read-only handle, …) and silently losing their data.
            self.edit = Some(es);
        }
    }

    fn delete_selected(&mut self) {
        // Resolve the selected record id. In the grouped Accounts tree the selection
        // may be a GROUP header (nothing to delete) — only a leaf has an id.
        let id = if self.acct_tree_mode() {
            match self.account_rows().get(self.selected).map(|r| &r.kind) {
                Some(AcctRowKind::Leaf { id }) => id.clone(),
                _ => return,
            }
        } else {
            match self.current_labels().get(self.selected).cloned() {
                Some((id, _)) => id,
                None => return,
            }
        };
        // Collect any attached document blob to reclaim after removing the record.
        let mut doc_ids: Vec<String> = Vec::new();
        if let Some(ov) = self.vault.as_mut() {
            let v = &mut ov.vault;
            match self.tab {
                Tab::Instructions => {
                    records::remove(&mut v.instructions, &id, &mut v.audit, "Instruction");
                }
                Tab::TrustWill => {
                    if let Some(r) = v.trust_wills.iter().find(|r| r.id == id)
                        && let Some(f) = &r.file
                    {
                        doc_ids.push(f.clone());
                    }
                    records::remove(&mut v.trust_wills, &id, &mut v.audit, "Trust/Will");
                }
                Tab::Assets => {
                    if let Some(r) = v.assets.iter().find(|r| r.id == id)
                        && let Some(f) = &r.statement
                    {
                        doc_ids.push(f.clone());
                    }
                    records::remove(&mut v.assets, &id, &mut v.audit, "Asset/Liability");
                }
                Tab::Accounts => {
                    records::remove(&mut v.accounts, &id, &mut v.audit, "Account");
                }
                Tab::RealEstate => {
                    // Reclaim every document attached to this property.
                    if let Some(r) = v.real_estate.iter().find(|r| r.id == id) {
                        for f in &r.documents {
                            doc_ids.push(f.clone());
                        }
                    }
                    records::remove(&mut v.real_estate, &id, &mut v.audit, "Real Estate");
                }
                Tab::Taxes => {
                    // Reclaim every document attached to this filing year.
                    if let Some(r) = v.tax_filings.iter().find(|r| r.id == id) {
                        for f in &r.documents {
                            doc_ids.push(f.clone());
                        }
                    }
                    records::remove(&mut v.tax_filings, &id, &mut v.audit, "Tax filing");
                }
                Tab::GeneralDocuments => {
                    // Reclaim the single attached file, if any.
                    if let Some(r) = v.general_documents.iter().find(|r| r.id == id)
                        && let Some(f) = &r.file
                    {
                        doc_ids.push(f.clone());
                    }
                    records::remove(&mut v.general_documents, &id, &mut v.audit, "General document");
                }
            }
        }
        // Persist the record removal before reclaiming blobs, and only reclaim if
        // the save succeeded — otherwise the on-disk vault still references the
        // record and dropping its blobs would make it unopenable (ArchiveMismatch).
        if self.persist() {
            for fid in doc_ids {
                if let Some(ov) = self.vault.as_mut() {
                    let _ = ov.remove_document(&fid);
                }
            }
            self.status = "Deleted.".into();
        }
        // On failure persist() has already set the "Save failed: …" status, and the
        // record is still on disk — so do not claim it was deleted.
        self.clamp_selection();
    }

    // `text: Zeroizing<String>` is taken by value (moved in): this function owns
    // it and it is wiped from memory when it drops at the end of the call.
    fn copy_to_clipboard(&mut self, text: Zeroizing<String>) {
        // `text` wipes on drop; the shared helper copies it into the OS clipboard with
        // the Linux history-exclusion hint so clipboard managers don't retain the
        // password (auto-cleared on the 15s timer and on exit either way).
        #[cfg(feature = "clipboard")]
        match crate::copy_secret_to_clipboard(text.as_str()) {
            Ok(()) => {
                self.clipboard_dirty = true;
                self.clipboard_clear_at = Some(Instant::now() + CLIPBOARD_CLEAR_AFTER);
                self.status = "Copied (clipboard auto-clears in 15s, and on exit).".into();
            }
            Err(e) => self.status = format!("Clipboard unavailable: {e}"),
        }
        // In a minimal build without OS-clipboard support (e.g. the static terminal
        // binary), copy is a no-op — say so instead of silently doing nothing.
        #[cfg(not(feature = "clipboard"))]
        {
            let _ = text;
            self.status = "Clipboard not available in this build.".into();
        }
    }

    // --- Drawing -------------------------------------------------------------

    // Drawing reads state only, hence `&self`; `frame: &mut Frame` is the
    // ratatui canvas we render widgets onto for this tick. Dispatch to the
    // active screen's draw routine.
    fn draw(&self, frame: &mut Frame) {
        match self.screen {
            Screen::Auth => self.draw_auth(frame),
            Screen::Browse => self.draw_browse(frame),
            Screen::Edit => self.draw_edit(frame),
            Screen::Config => self.draw_config(frame),
        }
    }

    fn draw_config(&self, frame: &mut Frame) {
        // Builder pattern: each `.method(...)` returns the (modified) builder, so
        // calls chain. This splits the screen vertically into a flexible main area
        // (`Min(1)`) and a fixed 3-row footer (`Length(3)`); `chunks` is a slice
        // of `Rect`s indexed below.
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(frame.area());

        // An array of `(label, &String)` tuples pairing each input with its value.
        let inputs = [
            ("New asset/liability type", &self.cfg_asset_type),
            ("New account type", &self.cfg_account_type),
            ("Subtype — account type", &self.cfg_subtype_type),
            ("Subtype — name", &self.cfg_subtype_name),
            ("Volume size (MiB)", &self.cfg_volume_size),
            ("Backup destination dir", &self.cfg_backup_dest),
            ("Vault redundancy (0=off)", &self.cfg_redundancy),
            ("Export directory", &self.cfg_export_dir),
        ];
        let cats = self.vault_ref().categories();
        let mut lines = vec![
            // Where this vault lives on disk (the vault.pmv path).
            Line::from(vec![
                Span::styled("Vault location: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(self.path.display().to_string(), Style::default().fg(Color::Gray)),
            ]),
            Line::from(""),
            Line::from(Span::styled("Asset/Liability types:", Style::default().add_modifier(Modifier::BOLD))),
            Line::from(Span::styled(cats.asset.join(" · "), Style::default().fg(Color::Gray))),
            Line::from(""),
            Line::from(Span::styled("Account types (with subtypes):", Style::default().add_modifier(Modifier::BOLD))),
        ];
        for t in &cats.account {
            let subs = if t.subtypes.is_empty() { "—".to_string() } else { t.subtypes.join(", ") };
            lines.push(Line::from(Span::styled(format!("  {}: {subs}", t.name), Style::default().fg(Color::Gray))));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!(
                "Volume size: {} MiB (new documents roll into a fresh volume past this)",
                self.vault_ref().volume_max_size() / (1024 * 1024)
            ),
            Style::default().fg(Color::Gray),
        )));
        lines.push(Line::from(Span::styled(
            match self.vault_ref().redundancy() {
                0 => "Vault redundancy: off (set N>0 to keep a mirror + N prior copies; not a backup)".to_string(),
                n => format!("Vault redundancy: {n} (mirror + {n} prior generation(s); not a backup)"),
            },
            Style::default().fg(Color::Gray),
        )));
        lines.push(Line::from(Span::styled(
            match self.cfg_export_dir.trim() {
                "" => "Export directory: (unset — set one to export documents)".to_string(),
                d => format!("Export directory: {d} (documents export here, recreating their folders)"),
            },
            Style::default().fg(Color::Gray),
        )));
        lines.push(Line::from(""));
        // `.enumerate()` pairs each item with its index; the pattern
        // `(i, (label, value))` destructures index plus the inner tuple in one go.
        for (i, (label, value)) in inputs.iter().enumerate() {
            let focused = i == self.cfg_focus;
            let marker = if focused { "> " } else { "  " };
            let style = if focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{marker}{label:<26}"), style),
                Span::raw((*value).clone()),
            ]));
        }

        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(" Configuration "))
                .wrap(Wrap { trim: true }),
            chunks[0],
        );
        self.draw_footer(
            frame,
            chunks[1],
            "Tab/↑↓ field · type to edit · Enter = add / backup · Del = delete type (if unused) · Esc back",
        );
    }

    fn draw_auth(&self, frame: &mut Frame) {
        let area = frame.area();
        let (title, help) = match self.auth.mode {
            AuthMode::Create => (" Create vault ", "Choose two passwords. Both are required."),
            AuthMode::Unlock => (" Unlock vault ", "Enter both passwords to unlock."),
            AuthMode::ChangePassword => (" Change master passwords ", "Set two new passwords."),
        };
        let mut lines = vec![
            Line::from(Span::styled(format!("Vault: {}", self.path.display()), Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled(help, Style::default().fg(Color::Gray))),
            Line::from(""),
        ];
        // Start-page rows (not shown when changing passwords): an editable Root path
        // (focus 0) and a collapsed "Vault" row (focus 1) — an editable leaf name that the
        // ←/→ picker fills from the vaults scanned under the root, or that you type to name
        // a new vault. Both shown in clear (they are paths, not secrets), highlighted when
        // focused. The resolved open target is shown in the "Vault:" line above.
        let lead_rows = self.auth_lead_rows();
        if lead_rows > 0 {
            // Helper to render a focusable, labelled clear-text row.
            let row = |focus_idx: usize, label: &str, value: String| {
                let focused = self.auth.focus == focus_idx;
                let marker = if focused { "> " } else { "  " };
                let style = if focused {
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Line::from(vec![
                    Span::styled(format!("{marker}{:<22}", label), style),
                    Span::raw(value),
                ])
            };
            lines.push(row(0, "Vault root", self.auth_root.clone()));
            // The Vault row shows the typed/selected name plus a picker hint (count + ←/→).
            let hint = if self.auth_vaults.is_empty() {
                "  (none found — type a name to create)".to_string()
            } else {
                let sel = self.auth_vault_sel.min(self.auth_vaults.len() - 1);
                format!("  (←/→ {}/{})", sel + 1, self.auth_vaults.len())
            };
            let name_shown = if self.auth_name.trim().is_empty() { "—".to_string() } else { self.auth_name.clone() };
            lines.push(row(1, "Vault", format!("{name_shown}{hint}")));
            // Surface a scan problem (root unreadable, or entries skipped) plainly.
            if let Some(warn) = &self.auth_scan_warning {
                lines.push(Line::from(Span::styled(format!("  {warn}"), Style::default().fg(Color::Yellow))));
            }
            // In read-only mode an empty directory can't be created — say so.
            if self.auth.mode == AuthMode::Create && !self.writable {
                lines.push(Line::from(Span::styled(
                    "  (no vault here; read-only — relaunch with --write to create one)",
                    Style::default().fg(Color::Yellow),
                )));
            }
        }
        // Password fields follow; their focus index is offset by the leading rows (if any).
        let offset = lead_rows;
        for (i, field) in self.auth.fields.iter().enumerate() {
            let focused = i + offset == self.auth.focus;
            let marker = if focused { "> " } else { "  " };
            // Never render the actual password: show one `*` per character.
            // `.chars().count()` counts Unicode characters (not raw bytes).
            let masked = "*".repeat(field.value.chars().count());
            let style = if focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{marker}{:<22}", field.label), style),
                Span::raw(masked),
            ]));
        }
        if let Some(err) = &self.auth.error {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(err.clone(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))));
        }
        lines.push(Line::from(""));
        let esc = if self.auth.mode == AuthMode::ChangePassword { "Esc cancel" } else { "Esc quit" };
        let pick = if self.auth_start_page() { "←/→ pick vault · " } else { "" };
        lines.push(Line::from(Span::styled(
            format!("Tab/↑↓ move · {pick}Enter next/submit · {esc}"),
            Style::default().fg(Color::DarkGray),
        )));
        let block = Block::default().borders(Borders::ALL).title(title);
        frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: true }), area);
    }

    fn draw_browse(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(1), Constraint::Length(3)])
            .split(frame.area());

        // `.collect::<Vec<_>>()` is the "turbofish" syntax telling `collect` which
        // collection to build (a `Vec`; `_` lets the compiler infer the element
        // type). Here it gathers every tab's title into a list for the tab bar.
        let tabs = Tabs::new(Tab::ALL.iter().map(|t| t.title()).collect::<Vec<_>>())
            .select(self.tab.index())
            .block(Block::default().borders(Borders::ALL).title(" Tabs (←/→ or 1-7) "))
            .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD));
        frame.render_widget(tabs, chunks[0]);

        let labels = self.current_labels();
        let grouped = self.acct_tree_mode();
        let rows = if grouped { self.account_rows() } else { Vec::new() };
        // Grouped: indent by depth and prefix groups with ▸ (collapsed) / ▾ (expanded);
        // leaves show the title only. Flat: just the record label.
        let items: Vec<ListItem> = if grouped {
            rows.iter()
                .map(|r| {
                    let indent = "  ".repeat(r.depth as usize);
                    let text = match &r.kind {
                        AcctRowKind::Group { expanded, .. } => {
                            format!("{indent}{} {}", if *expanded { "▾" } else { "▸" }, r.label)
                        }
                        AcctRowKind::Leaf { .. } => format!("{indent}  {}", r.label),
                    };
                    ListItem::new(Line::from(text))
                })
                .collect()
        } else {
            labels.iter().map(|(_, l)| ListItem::new(Line::from(l.clone()))).collect()
        };
        let count = items.len();
        // Show any active filters in the title.
        let title = if self.tab == Tab::Accounts
            && (self.acct_filter_type.is_some()
                || self.acct_filter_subtype.is_some()
                || self.acct_filter_owner.is_some()
                || self.acct_filter_title.is_some()
                || self.acct_filter_review
                || !self.acct_search.is_empty()
                || self.search_active
                || self.reveal_all
                || self.acct_grouped)
        {
            let t = self.acct_filter_type.as_deref().unwrap_or("any");
            let s = self.acct_filter_subtype.as_deref().unwrap_or("any");
            let o = self.acct_filter_owner.as_deref().unwrap_or("any");
            let ti = self.acct_filter_title.as_deref().unwrap_or("any");
            let r = if self.acct_filter_review { " · review" } else { "" };
            let rev = if self.reveal_all { " · 🔓reveal-all" } else { "" };
            let grp = if self.acct_grouped { " · grouped" } else { "" };
            // Username search: show the query, with a trailing caret while typing.
            let u = if self.search_active {
                format!(" · find~\"{}_\"", self.acct_search)
            } else if !self.acct_search.is_empty() {
                format!(" · find~\"{}\"", self.acct_search)
            } else {
                String::new()
            };
            format!(" Accounts ({count})  [type={t} · subtype={s} · owner={o} · title={ti}{r}{u}{rev}{grp}] ")
        } else if self.tab == Tab::Assets && self.asset_filter_review {
            format!(" Assets & Liabilities ({count})  [review only] ")
        } else {
            format!(" {} ({count}) ", self.tab.title())
        };
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");
        // A `ListState` tracks which row is highlighted. `render_stateful_widget`
        // takes `&mut state` because it updates scrolling/selection internals as
        // it draws.
        let mut state = ListState::default();
        if count > 0 {
            state.select(Some(self.selected.min(count - 1)));
        }
        frame.render_stateful_widget(list, chunks[1], &mut state);

        let hints = if self.search_active {
            "type to search username/title · Enter keep · Esc clear"
        } else {
            match self.tab {
                Tab::Accounts if self.acct_grouped => {
                    "↑↓ · Enter expand/edit · n new · d del · t/s/o/l filter · r reveal-all · g flat list · / search · ←→ tab · q quit"
                }
                Tab::Accounts => {
                    "↑↓ · Enter edit · n new · d del · t/s/o/l filter · v review · r reveal-all · g grouped · T trim-all · / search · ←→ tab · c config · p pw · q quit"
                }
                Tab::Assets => "↑↓ · Enter edit · n new · d del · v review filter · ←→ tab · c config · p pw · q quit",
                Tab::RealEstate => "↑↓ · Enter edit · n new · d del · r reveal-all (portals) · ←→ tab · c config · p pw · q quit",
                _ => "↑↓ · Enter edit · n new · d del · ←→ tab · c config · p passwords · q quit",
            }
        };
        self.draw_footer(frame, chunks[2], hints);
    }

    fn draw_edit(&self, frame: &mut Frame) {
        let Some(es) = self.edit.as_ref() else { return };
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(frame.area());

        let mut lines: Vec<Line> = Vec::new();
        for (i, field) in es.fields.iter().enumerate() {
            let focused = i == es.focus;
            let marker = if focused { "> " } else { "  " };
            // Decide what to display per field kind: a hidden password shows bullets
            // (unless `reveal` is on); a Choice shows arrows around the value; others
            // show their text verbatim. `&field.kind` matches by borrow.
            // Masked unless the single global "reveal all" for THIS record's tab is on
            // (the only reveal control): the Accounts toggle for account edits, the Real
            // Estate toggle for property edits. Scoping by `es.tab` keeps them independent.
            let reveal_all_here = (self.reveal_all && es.tab == Tab::Accounts)
                || (self.re_reveal_all && es.tab == Tab::RealEstate);
            let shown = match &field.kind {
                FieldKind::Password if !reveal_all_here => "•".repeat(field.value.chars().count()),
                FieldKind::Choice(_) => format!("◄ {} ►", field.value),
                _ => field.value.clone(),
            };
            let style = if focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{marker}{:<16}", field.label), style),
                Span::raw(shown),
            ]));
        }
        if es.has_docs() {
            // Resolve the attached blob id to a human path: borrow the Option
            // (`.as_ref()`), look it up (`.and_then` runs only if `Some` and itself
            // returns an Option), and fall back to "(none)" if there's no doc.
            let attached = es
                .attached_file_id
                .as_ref()
                .and_then(|id| self.vault_ref().doc_path(id))
                .unwrap_or_else(|| "(none)".into());
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("Attached document: {attached}"),
                Style::default().fg(Color::Cyan),
            )));
        }
        if es.tab == Tab::Taxes {
            // List the filing's documents with their 1-based numbers (used by the
            // "Doc #" field for Ctrl+E export / Ctrl+K remove).
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!(
                    "Documents ({}) — under {}/<timestamp>/[subfolder]/",
                    es.tax_docs.len(),
                    records::tax_doc_location(&es.fields[0].value)
                ),
                Style::default().fg(Color::Cyan),
            )));
            for (i, id) in es.tax_docs.iter().enumerate() {
                let label = self.vault_ref().doc_path(id).unwrap_or_else(|| id.clone());
                lines.push(Line::from(Span::styled(
                    format!("  #{}  {label}", i + 1),
                    Style::default().fg(Color::Cyan),
                )));
            }
        }
        if es.tab == Tab::RealEstate {
            // List the property's documents with their 1-based numbers (used by the
            // "Doc #" field for Ctrl+E export / Ctrl+K remove).
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!(
                    "Documents ({}) — under {}/<timestamp>/[subfolder]/",
                    es.re_docs.len(),
                    records::real_estate_doc_location(&es.fields[0].value)
                ),
                Style::default().fg(Color::Cyan),
            )));
            for (i, id) in es.re_docs.iter().enumerate() {
                let label = self.vault_ref().doc_path(id).unwrap_or_else(|| id.clone());
                lines.push(Line::from(Span::styled(
                    format!("  #{}  {label}", i + 1),
                    Style::default().fg(Color::Cyan),
                )));
            }
        }
        if !es.history.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("History:", Style::default().add_modifier(Modifier::BOLD))));
            // `.rev()` walks newest-first, `.take(6)` keeps only the first six —
            // iterators are lazy, so this never materializes the whole history.
            for c in es.history.iter().rev().take(6) {
                // `display_detail` masks password before/after values so the history
                // pane never leaks a cleartext password (the live field's reveal
                // toggle deliberately does not extend here).
                let detail =
                    if c.detail.is_empty() { c.action.clone() } else { records::display_detail(&c.detail) };
                lines.push(Line::from(Span::styled(
                    format!("  {}  {detail}", format_time(c.at)),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        }

        let title = if es.id.is_some() { " Edit " } else { " New " };
        frame.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title)).wrap(Wrap { trim: true }),
            chunks[0],
        );

        let hints = if es.tab == Tab::Taxes {
            "Tab/↑↓ field · Ctrl+S save · Ctrl+U upload · Ctrl+E export(Doc#) · Ctrl+K remove(Doc#) · Esc cancel"
        } else if es.tab == Tab::RealEstate {
            "Tab/↑↓ field · Ctrl+R reveal · Ctrl+Y copy · Ctrl+U upload · Ctrl+E export(Doc#) · Ctrl+K remove(Doc#) · Ctrl+S save · Esc"
        } else if es.has_docs() {
            "Tab/↑↓ field · ←/→ choice · Ctrl+S save · Ctrl+U upload · Ctrl+E export · Ctrl+K detach · Esc cancel"
        } else {
            "Tab/↑↓ field · ←/→ choice · Ctrl+S save · Ctrl+G gen · Ctrl+R reveal · Ctrl+Y copy · Esc cancel"
        };
        self.draw_footer(frame, chunks[1], hints);
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect, hints: &str) {
        let badge = if self.writable { "" } else { "🔒 READ-ONLY · " };
        let text = if self.status.is_empty() {
            format!("{badge}{hints}")
        } else {
            format!("{badge}{}  —  {hints}", self.status)
        };
        let footer = Paragraph::new(text)
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, area);
    }
}

// Generic helper: `<R: Record>` means "for any type `R` that implements the
// `Record` trait" (a trait bound — `R` must provide `.id()` and `.label()`).
// `list: &[R]` is a slice (borrowed view) of any record type, so one function
// serves every tab. Builds `(id, label)` pairs as owned strings.
fn label_list<R: Record>(list: &[R]) -> Vec<(String, String)> {
    list.iter().map(|r| (r.id().to_string(), r.label())).collect()
}

/// Options for a yes/no choice field.
fn yes_no() -> Vec<String> {
    vec!["No".to_string(), "Yes".to_string()]
}

/// The yes/no choice value for a boolean.
fn bool_choice(b: bool) -> String {
    if b { "Yes" } else { "No" }.to_string()
}

/// The password field a copy (Ctrl+Y) or generate (Ctrl+G) action should target:
/// the currently-focused field if it is a password, otherwise the first password
/// field. The focus-first rule matters on the Real Estate tab, which has three
/// independent portal password fields — a blind "first password" would always act
/// on Property Mgmt and so copy/overwrite the wrong secret.
fn target_password_index(fields: &[Field], focus: usize) -> Option<usize> {
    if matches!(fields.get(focus).map(|f| &f.kind), Some(FieldKind::Password)) {
        Some(focus)
    } else {
        fields.iter().position(|f| matches!(f.kind, FieldKind::Password))
    }
}

/// Parse a user-entered 1-based document number into a 0-based index, returning
/// `None` if it is not a number in `1..=len` (so the caller can show a hint).
fn parse_doc_index(s: &str, len: usize) -> Option<usize> {
    let n: usize = s.trim().parse().ok()?;
    if n >= 1 && n <= len { Some(n - 1) } else { None }
}

/// Advance a filter through: None → opts[0] → opts[1] → … → None (wrap to off).
// `current: &Option<String>` borrows the active filter (no ownership taken).
// `match` on it: if currently off (`None`), pick the first option (`.first()` →
// `Option<&String>`, `.cloned()` → owned). If a value is set (`Some(cur)`), find
// its index and — only if there is a next one (guard `i + 1 < len`) — return it;
// otherwise (`_`) wrap back to `None` (filter off).
fn cycle_filter(current: &Option<String>, opts: &[String]) -> Option<String> {
    match current {
        None => opts.first().cloned(),
        Some(cur) => match opts.iter().position(|o| o == cur) {
            Some(i) if i + 1 < opts.len() => Some(opts[i + 1].clone()),
            _ => None,
        },
    }
}

// Best-effort wipe of the OS clipboard (set it to empty). `let _ =` discards the
// `Result`: if the clipboard is unavailable there is nothing useful to do. A no-op in a
// build without the `clipboard` feature (where nothing is ever copied to begin with).
fn clear_clipboard() {
    #[cfg(feature = "clipboard")]
    let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(String::new()));
}

/// Format a unix-seconds timestamp as `YYYY-MM-DD HH:MM:SS UTC` (no date crate).
/// Returns "never" for a zero/negative timestamp. Shared with the GUI; the
/// calendar math lives once in [`crate::records::civil_from_unix`].
// `pub(crate)` = visible to this crate (the whole program) but not external
// users — wider than private, narrower than fully `pub`.
pub(crate) fn format_time(ts: i64) -> String {
    if ts <= 0 {
        return "never".to_string();
    }
    // Destructure the six returned date/time components into named bindings.
    let (year, mo, d, h, m, s) = records::civil_from_unix(ts);
    // `{year:04}` etc. are format specs: zero-pad to the given width (4 or 2).
    format!("{year:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

// `#[cfg(test)]` is conditional compilation: this whole `mod tests` module is
// only built when running `cargo test`, so it adds nothing to the shipped binary.
// `use super::*;` pulls in everything from the parent (this file) so the tests can
// reach private items like `App`, `Tab`, and the helper functions.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fast() -> KdfParams {
        KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
    }

    fn tmp_vault(tag: &str) -> PathBuf {
        // A unique per-test directory; the vault file name is fixed (vault.pmv),
        // matching production where the user controls only the directory.
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("passmgr-ui-{tag}-{nanos}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("vault.pmv")
    }

    /// An `App` with a freshly-created, unlocked vault on the Browse screen — the
    /// state a user reaches after a successful create/unlock, without rendering.
    fn app_unlocked(tag: &str) -> (App, PathBuf) {
        let path = tmp_vault(tag);
        let ov = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut app = App::new(path.clone(), true);
        app.vault = Some(ov);
        app.screen = Screen::Browse;
        (app, path)
    }

    /// A read-only `App` unlocked over an existing vault that already has one
    /// account, on the Browse screen.
    fn app_read_only(tag: &str) -> (App, PathBuf) {
        let path = tmp_vault(tag);
        {
            let mut ov = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            records::upsert(&mut ov.vault.accounts, Account::new().unwrap());
            ov.save().unwrap();
        }
        let ov = OpenVault::open_read_only(path.clone(), b"a", b"b").unwrap();
        let mut app = App::new(path.clone(), false);
        app.vault = Some(ov);
        app.screen = Screen::Browse;
        (app, path)
    }

    fn cleanup(path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    // Tiny constructors for synthetic key events: `key(code)` = a plain key,
    // `ctrl(c)` = Ctrl + a character. Used to drive `handle_key` in tests.
    // (`.unwrap()` is used liberally throughout the tests below: it panics on
    // `Err`/`None`, which is exactly how a test should fail.)
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    #[test]
    fn start_page_vault_dir_field_switches_mode_and_creates() {
        // The collapsed start page exposes a Root field (focus 0) and a "Vault" name row
        // (focus 1); the open target is <root>/<name>. It pre-fills root=parent, name=folder,
        // flips Unlock<->Create as the name changes, and (in --write mode) creates the vault.
        let base = std::env::temp_dir()
            .join(format!("passmgr-ui-startdir-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&base).unwrap();

        let mut app = App::new(base.join("fresh").join("vault.pmv"), true);
        assert_eq!(app.auth.mode, AuthMode::Create, "no vault yet -> Create");
        assert!(app.auth_start_page(), "start page shows the Root + Vault rows");
        assert_eq!(app.auth_dir, base.join("fresh").display().to_string(), "dir = root/name");
        assert_eq!(app.auth_root, base.display().to_string(), "root = parent");
        assert_eq!(app.auth_name, "fresh", "name = launch folder");
        // Focus 0 is the editable Root field; typing there edits the root, not a password.
        assert!(app.on_auth_root_field());
        app.handle_auth_key(key(KeyCode::Char('X')));
        assert!(app.auth_root.ends_with('X'), "typing on focus 0 edits the root");
        app.handle_auth_key(key(KeyCode::Backspace));
        // Focus 1 is the editable Vault name row; typing there edits the name → directory.
        app.auth.focus = 1;
        assert!(app.on_auth_vault_field());
        app.handle_auth_key(key(KeyCode::Char('X')));
        assert!(app.auth_name.ends_with('X'), "typing on the Vault row edits the name");
        assert!(app.auth_dir.ends_with('X'), "...which re-derives the directory");
        app.handle_auth_key(key(KeyCode::Backspace));

        // Type a brand-new vault name and create the vault there.
        let fresh = base.join("brandnew");
        app.auth_name = "brandnew".into();
        app.recompute_auth_path();
        assert_eq!(app.auth_dir, fresh.display().to_string());
        assert_eq!(app.auth.mode, AuthMode::Create);
        // Create has 4 password fields (pw1, confirm1, pw2, confirm2); the lead rows are
        // separate, so fill auth.fields directly.
        app.auth.fields[0].value = "a".into();
        app.auth.fields[1].value = "a".into();
        app.auth.fields[2].value = "b".into();
        app.auth.fields[3].value = "b".into();
        app.submit_auth();
        assert!(app.vault.is_some(), "vault created in the new dir; error: {:?}", app.auth.error);
        assert!(fresh.join("vault.pmv").exists(), "vault.pmv created on disk");

        // A fresh App pointed at that now-existing dir resolves to Unlock.
        let app2 = App::new(fresh.join("vault.pmv"), true);
        assert_eq!(app2.auth.mode, AuthMode::Unlock, "existing vault -> Unlock");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn start_page_vault_picker_scans_root_and_selects() {
        // Two existing vaults plus an empty dir under a common root. The picker should list
        // exactly the two vaults; cycling it with ←/→ adopts a vault and flips to Unlock.
        let root = std::env::temp_dir()
            .join(format!("passmgr-ui-picker-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(root.join("alpha")).unwrap();
        std::fs::create_dir_all(root.join("beta")).unwrap();
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::write(root.join("alpha").join("vault.pmv"), b"x").unwrap();
        std::fs::write(root.join("beta").join("vault.pmv"), b"x").unwrap();

        // Launch pointed at the empty (vault-less) subdir → Create, picker not yet scanned here.
        let mut app = App::new(root.join("empty").join("vault.pmv"), true);
        assert_eq!(app.auth.mode, AuthMode::Create);
        // Point the Root field at the shared root and rescan.
        app.auth_root = root.display().to_string();
        app.refresh_auth_vaults();
        assert_eq!(app.auth_vaults, vec!["alpha".to_string(), "beta".to_string()]);
        assert!(app.auth_scan_warning.is_none());

        // Cycle the picker (focus 1) right: select "alpha" → existing vault → Unlock mode,
        // and auth_dir/path now point inside the root.
        app.auth.focus = 1;
        assert!(app.on_auth_vault_field());
        app.handle_auth_key(key(KeyCode::Right)); // 0 -> 1 (beta)
        assert_eq!(app.auth_name, "beta");
        assert_eq!(app.auth_dir, root.join("beta").display().to_string());
        assert_eq!(app.auth.mode, AuthMode::Unlock, "an existing vault flips to Unlock");
        app.handle_auth_key(key(KeyCode::Left)); // 1 -> 0 (alpha)
        assert_eq!(app.auth_name, "alpha");
        assert_eq!(app.auth_dir, root.join("alpha").display().to_string());
        assert_eq!(app.path, root.join("alpha").join("vault.pmv"));
        // Focus survived the AuthState rebuild on the mode change.
        assert!(app.on_auth_vault_field(), "focus stays on the Vault row after selecting");

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn start_page_read_only_cannot_create_in_empty_dir_tui() {
        let base = std::env::temp_dir()
            .join(format!("passmgr-ui-rodir-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&base).unwrap();
        let mut app = App::new(base.join("empty").join("vault.pmv"), false); // read-only
        assert_eq!(app.auth.mode, AuthMode::Create);
        app.auth.fields[0].value = "a".into();
        app.auth.fields[1].value = "a".into();
        app.auth.fields[2].value = "b".into();
        app.auth.fields[3].value = "b".into();
        app.submit_auth();
        assert!(app.vault.is_none(), "read-only must not create a vault");
        assert!(
            app.auth.error.as_deref().unwrap_or("").contains("--write"),
            "error explains --write is needed; got {:?}",
            app.auth.error
        );
        std::fs::remove_dir_all(&base).ok();
    }

    // `#[test]` marks a function the test runner executes; it takes no args and a
    // panic (e.g. a failed `assert_eq!`) means failure.
    #[test]
    fn cycle_filter_wraps_through_none() {
        let opts = vec!["a".to_string(), "b".to_string()];
        let s = cycle_filter(&None, &opts);
        assert_eq!(s.as_deref(), Some("a"));
        let s = cycle_filter(&s, &opts);
        assert_eq!(s.as_deref(), Some("b"));
        let s = cycle_filter(&s, &opts);
        assert_eq!(s, None); // wraps back to "no filter"
        assert_eq!(cycle_filter(&Some("gone".into()), &opts), None);
        assert_eq!(cycle_filter(&None, &[]), None);
    }

    #[test]
    fn account_username_search_via_slash_key() {
        let (mut app, path) = app_unlocked("uisearch");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            for u in ["alice", "alice2", "bob"] {
                let mut a = Account::new().unwrap();
                a.username = u.into();
                records::upsert(&mut v.accounts, a);
            }
        }
        app.tab = Tab::Accounts;
        assert_eq!(app.current_labels().len(), 3);

        // '/' enters search input mode; typed letters edit the query (not commands).
        assert!(!app.handle_key(key(KeyCode::Char('/'))));
        assert!(app.search_active);
        for c in "ali".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.current_labels().len(), 2, "matches alice + alice2");

        // Enter keeps the query and exits input mode.
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.search_active);
        assert_eq!(app.acct_search, "ali");
        assert_eq!(app.current_labels().len(), 2, "query persists after Enter");

        // Re-enter and Esc CLEARS the query without quitting the app.
        app.handle_key(key(KeyCode::Char('/')));
        let quit = app.handle_key(key(KeyCode::Esc));
        assert!(!quit, "Esc in search mode must not quit");
        assert!(!app.search_active && app.acct_search.is_empty());
        assert_eq!(app.current_labels().len(), 3, "cleared → all accounts");
        cleanup(&path);
    }

    #[test]
    fn account_search_matches_title_too() {
        let (mut app, path) = app_unlocked("uisearchtitle");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut a = Account::new().unwrap();
            a.username = "u1".into();
            a.title = "Brokerage account".into();
            records::upsert(&mut v.accounts, a);
            let mut b = Account::new().unwrap();
            b.username = "u2".into();
            b.title = "Email".into();
            records::upsert(&mut v.accounts, b);
        }
        app.tab = Tab::Accounts;
        assert_eq!(app.current_labels().len(), 2);
        // The free-text search matches the TITLE as well as the username.
        app.acct_search = "broker".into();
        let labels = app.current_labels();
        assert_eq!(labels.len(), 1, "title substring matches");
        assert!(labels[0].1.contains("Brokerage"), "the brokerage account: {labels:?}");
        // And still matches by username.
        app.acct_search = "u2".into();
        assert_eq!(app.current_labels().len(), 1, "username substring still matches");
        cleanup(&path);
    }

    #[test]
    fn bool_choice_round_trips() {
        assert_eq!(bool_choice(true), "Yes");
        assert_eq!(bool_choice(false), "No");
        assert_eq!(yes_no(), vec!["No".to_string(), "Yes".to_string()]);
    }

    #[test]
    fn new_account_prepopulates_from_active_filters() {
        let (mut app, path) = app_unlocked("uifilterprefill");
        app.tab = Tab::Accounts;
        app.acct_filter_title = Some("Bank login".into());
        app.acct_filter_type = Some("Financial".into());
        app.acct_filter_subtype = Some("IRA".into());
        app.acct_filter_owner = Some("Alice".into());
        app.acct_search = "alice99".into();
        app.start_edit(false); // "New"
        let es = app.edit.as_ref().unwrap();
        // Account fields: [0] title, [1] type, [2] subtype, [3] owner, [4] username.
        assert_eq!(es.fields[0].value, "Bank login", "title prefilled from filter");
        assert_eq!(es.fields[1].value, "Financial", "type prefilled from filter");
        assert_eq!(es.fields[2].value, "IRA", "subtype prefilled from filter");
        assert_eq!(es.fields[3].value, "Alice", "owner prefilled from filter");
        assert_eq!(es.fields[4].value, "alice99", "username prefilled from search");
        assert!(es.id.is_none(), "still a new (unsaved) record");
        assert!(app.vault.as_ref().unwrap().vault.accounts.is_empty(), "nothing persisted yet");

        // With no filters/search active, a new account starts blank.
        app.acct_filter_title = None;
        app.acct_filter_type = None;
        app.acct_filter_subtype = None;
        app.acct_filter_owner = None;
        app.acct_search.clear();
        app.start_edit(false);
        let es = app.edit.as_ref().unwrap();
        assert_eq!(es.fields[0].value, "", "title blank");
        assert_eq!(es.fields[1].value, "", "type blank");
        assert_eq!(es.fields[4].value, "", "username blank");
        cleanup(&path);
    }

    #[test]
    fn saving_account_moves_active_filter_to_keep_it_visible() {
        let (mut app, path) = app_unlocked("uifsync");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut a = Account::new().unwrap();
            a.account_type = "Email".into();
            a.username = "existing".into();
            records::upsert(&mut v.accounts, a);
        }
        app.tab = Tab::Accounts;
        app.acct_filter_type = Some("Email".into()); // active filter
        app.start_edit(false); // New (prefills type=Email from the filter)
        // Title is mandatory; change the type and give it a username.
        app.edit.as_mut().unwrap().fields[0].value = "Work".into(); // title (field 0)
        app.edit.as_mut().unwrap().fields[1].value = "Bank".into(); // type (field 1)
        app.edit.as_mut().unwrap().fields[3].value = "Alice".into(); // owner (field 3, mandatory)
        app.edit.as_mut().unwrap().fields[4].value = "newuser".into(); // username (field 4)
        app.save_edit();
        // The active type filter followed the saved entry instead of hiding it.
        assert_eq!(app.acct_filter_type.as_deref(), Some("Bank"));
        let labels = app.current_labels();
        assert!(labels.iter().any(|(_, l)| l.contains("newuser")), "saved account is visible: {labels:?}");
        cleanup(&path);
    }

    #[test]
    fn saving_account_relaxes_review_and_search_to_keep_it_visible() {
        let (mut app, path) = app_unlocked("uirelax");
        app.tab = Tab::Accounts;
        app.acct_filter_review = true; // review-only active
        app.acct_search = "alice".into(); // username search active
        app.start_edit(false); // New (prefills username=alice from the search)
        app.edit.as_mut().unwrap().fields[0].value = "Mail".into(); // title (mandatory)
        app.edit.as_mut().unwrap().fields[3].value = "Alice".into(); // owner (mandatory)
        app.edit.as_mut().unwrap().fields[4].value = "bob".into(); // username (no longer matches)
        // review (field 9) stays default "No" — saved record is NOT flagged.
        app.save_edit();
        assert!(!app.acct_filter_review, "review-only relaxed so a non-flagged save stays visible");
        assert_eq!(app.acct_search, "", "username search relaxed when it no longer matches the save");
        let labels = app.current_labels();
        assert!(labels.iter().any(|(_, l)| l.contains("bob")), "saved account is visible: {labels:?}");
        cleanup(&path);
    }

    #[test]
    fn reveal_all_overrides_per_account_masking_in_tui() {
        let (mut app, path) = app_unlocked("uirevealall");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut a = Account::new().unwrap();
            a.username = "u".into();
            a.password = "SECRETPW".into();
            records::upsert(&mut v.accounts, a);
        }
        app.tab = Tab::Accounts;
        app.selected = 0;
        app.start_edit(true);
        // Masked by default (per-record reveal is off).
        assert!(!render_to_string(&app).contains("SECRETPW"), "password masked by default");
        // The global reveal-all overrides the per-record reveal.
        app.reveal_all = true;
        assert!(render_to_string(&app).contains("SECRETPW"), "reveal-all shows the password");
        cleanup(&path);
    }

    #[test]
    fn re_reveal_all_overrides_portal_masking_and_is_scoped_in_tui() {
        let (mut app, path) = app_unlocked("uirereveal");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut r = RealEstate::new().unwrap();
            r.address = "1 Main St".into();
            r.property_mgmt_password = "PORTALPW".into();
            records::upsert(&mut v.real_estate, r);
        }
        app.tab = Tab::RealEstate;
        app.selected = 0;
        app.start_edit(true);
        // Masked by default (global reveal off).
        assert!(!render_to_string(&app).contains("PORTALPW"), "portal password masked by default");
        // The ACCOUNT reveal-all must NOT reveal RE portals (scoped per tab).
        app.reveal_all = true;
        assert!(!render_to_string(&app).contains("PORTALPW"), "account reveal-all does not leak into RE");
        // The RE reveal-all does reveal them.
        app.re_reveal_all = true;
        assert!(render_to_string(&app).contains("PORTALPW"), "re reveal-all shows the portal password");
        cleanup(&path);
    }

    #[test]
    fn switching_tabs_resets_reveal_all_toggles() {
        // Reveal is momentary: switching tabs must clear `reveal_all`/`re_reveal_all`
        // so a sticky toggle can't silently expose every password on a later visit.
        let (mut app, path) = app_unlocked("revealreset");
        app.tab = Tab::Accounts;
        app.reveal_all = true;
        app.re_reveal_all = true;
        // Any tab-change key routes through `switch_tab`, which clears both toggles.
        app.handle_key(key(KeyCode::Char('5'))); // jump to the Real Estate tab
        assert_eq!(app.tab, Tab::RealEstate);
        assert!(!app.reveal_all, "reveal_all cleared on tab switch");
        assert!(!app.re_reveal_all, "re_reveal_all cleared on tab switch");
        // Arrow-key tab navigation clears them too.
        app.re_reveal_all = true;
        app.handle_key(key(KeyCode::Right));
        assert!(!app.re_reveal_all, "arrow tab-switch also clears reveal");
        cleanup(&path);
    }

    #[test]
    fn generate_reveals_via_the_global_toggle_in_tui() {
        // Reveal is global-only now: generating a password turns on the single global
        // reveal (`reveal_all` on Accounts) so the new value is visible — there is no
        // per-record reveal to flip.
        let (mut app, path) = app_unlocked("genglobal");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts
        app.handle_key(key(KeyCode::Char('n'))); // new record
        assert!(!app.reveal_all, "reveal starts off");
        app.handle_key(ctrl('g')); // generate into the account's password field
        assert!(app.reveal_all, "generate turns on the global reveal");
        assert!(
            !app.edit.as_ref().unwrap().fields[5].value.is_empty(),
            "a password was generated into the password field"
        );
        cleanup(&path);
    }

    #[test]
    fn copy_generate_target_the_focused_password_field() {
        // Mirrors the Real Estate edit form: text fields interleaved with THREE
        // independent portal password fields. The FOCUSED password must be the one
        // copied/generated — not always the first (which would leak/overwrite the
        // Property Mgmt password regardless of which portal the user is editing).
        let fields = vec![
            Field::text("Address", String::new()),
            Field::password("Property Mgmt password", "pm".into()), // index 1
            Field::text("Insurance URL", String::new()),
            Field::password("Insurance password", "ins".into()), // index 3
            Field::password("HOA password", "hoa".into()),       // index 4
        ];
        // Focused on a specific portal password → that exact field.
        assert_eq!(target_password_index(&fields, 3), Some(3), "Insurance focused → Insurance");
        assert_eq!(target_password_index(&fields, 4), Some(4), "HOA focused → HOA");
        // Focused on a non-password field → fall back to the first password.
        assert_eq!(target_password_index(&fields, 0), Some(1));
        assert_eq!(target_password_index(&fields, 2), Some(1));
        // Out-of-range focus → first password (no panic).
        assert_eq!(target_password_index(&fields, 99), Some(1));
        // No password fields at all → None.
        let no_pw = vec![Field::text("a", String::new()), Field::text("b", String::new())];
        assert_eq!(target_password_index(&no_pw, 0), None);
    }

    #[test]
    fn parse_doc_index_validates_one_based_range() {
        // 1-based user input → 0-based index, accepted only within 1..=len.
        assert_eq!(parse_doc_index("1", 3), Some(0));
        assert_eq!(parse_doc_index("3", 3), Some(2));
        assert_eq!(parse_doc_index(" 2 ", 3), Some(1)); // surrounding whitespace trimmed
        assert_eq!(parse_doc_index("0", 3), None); // below range (no zero-based input)
        assert_eq!(parse_doc_index("4", 3), None); // above range
        assert_eq!(parse_doc_index("1", 0), None); // empty list: nothing is valid
        assert_eq!(parse_doc_index("x", 3), None); // not a number
        assert_eq!(parse_doc_index("", 3), None);
    }

    #[test]
    fn tab_titles_are_correct_and_unique() {
        // Pins each tab's on-screen title (kills the "" / "xyzzy" title mutants).
        let titles: Vec<&str> = Tab::ALL.iter().map(|t| t.title()).collect();
        assert_eq!(
            titles,
            vec![
                "Instructions",
                "Trust and Will",
                "Assets & Liabilities",
                "Accounts",
                "Real Estate",
                "Taxes",
                "General Documents",
            ]
        );
        for t in Tab::ALL {
            assert!(!t.title().is_empty());
        }
        let mut uniq = titles.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), titles.len(), "every tab title is distinct");
    }

    /// Render the current screen to a flat string of cell symbols, so tests can
    /// assert on what is actually drawn (a draw fn replaced by a no-op then fails).
    fn render_to_string(app: &App) -> String {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(160, 200)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
        term.backend().buffer().content().iter().map(|c| c.symbol()).collect()
    }

    #[test]
    fn real_estate_edit_screen_renders_its_fields() {
        let (mut app, path) = app_unlocked("uirerender");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            records::upsert(&mut v.real_estate, RealEstate::new().unwrap());
        }
        app.tab = Tab::RealEstate;
        app.selected = 0;
        app.start_edit(true);
        let screen = render_to_string(&app);
        // Real-Estate-specific labels must be drawn (kills the tab_realestate /
        // draw_edit / portal-rendering no-op mutants).
        assert!(screen.contains("Financing balance"), "RE edit form renders its fields");
        assert!(screen.contains("Property Mgmt"), "RE edit form renders the portal sections");
        cleanup(&path);
    }

    #[test]
    fn taxes_edit_screen_renders_its_fields() {
        let (mut app, path) = app_unlocked("uitaxrender");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            records::upsert(&mut v.tax_filings, TaxFiling::new().unwrap());
        }
        app.tab = Tab::Taxes;
        app.selected = 0;
        app.start_edit(true);
        let screen = render_to_string(&app);
        assert!(screen.contains("Filing year"), "Taxes edit form renders its fields");
        cleanup(&path);
    }

    #[test]
    fn tax_document_attach_export_remove_round_trip() {
        let (mut app, path) = app_unlocked("uitaxdoc");
        let dir = path.parent().unwrap().to_path_buf();
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            records::upsert(&mut v.tax_filings, TaxFiling::new().unwrap());
        }
        app.tab = Tab::Taxes;
        app.selected = 0;
        app.start_edit(true);
        let rc = app.edit.as_ref().unwrap().record_fields;
        app.edit.as_mut().unwrap().fields[0].value = "2024".into(); // filing year

        // --- attach ---
        let src = dir.join("w2.txt");
        std::fs::write(&src, b"taxable income").unwrap();
        {
            let es = app.edit.as_mut().unwrap();
            es.fields[rc].value = "w2.txt".into(); // doc filename
            es.fields[rc + 1].value = src.to_string_lossy().into(); // upload from
        }
        app.attach_tax_document();
        assert_eq!(app.edit.as_ref().unwrap().tax_docs.len(), 1, "attached one document");
        assert_eq!(app.vault.as_ref().unwrap().vault.tax_filings[0].documents.len(), 1, "and persisted it");

        // --- export: an out-of-range number exports nothing ---
        // Export goes to the configured export dir, recreating the volume folder structure.
        let export_root = dir.join("exports");
        app.cfg_export_dir = export_root.to_string_lossy().into();
        let tax_id = app.vault.as_ref().unwrap().vault.tax_filings[0].documents[0].clone();
        let vpath = app.vault.as_ref().unwrap().doc_path(&tax_id).unwrap();
        app.edit.as_mut().unwrap().fields[rc + 3].value = "2".into(); // doc # (only 1 exists)
        app.export_tax_document();
        assert!(!export_root.exists(), "out-of-range doc # exports nothing");
        assert!(app.status.contains("between 1 and 1"));

        app.edit.as_mut().unwrap().fields[rc + 3].value = "1".into();
        app.export_tax_document();
        let exported = export_root.join(vpath.trim_start_matches('/'));
        assert_eq!(std::fs::read(&exported).unwrap(), b"taxable income", "exported bytes round-trip (status: {})", app.status);

        // --- remove ---
        app.edit.as_mut().unwrap().fields[rc + 3].value = "1".into();
        app.remove_tax_document();
        assert!(app.edit.as_ref().unwrap().tax_docs.is_empty(), "removed the document");
        assert!(app.vault.as_ref().unwrap().vault.tax_filings[0].documents.is_empty(), "and unlinked it");
        cleanup(&path);
    }

    #[test]
    fn real_estate_document_attach_export_remove_round_trip() {
        let (mut app, path) = app_unlocked("uiredoc");
        let dir = path.parent().unwrap().to_path_buf();
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut re = RealEstate::new().unwrap();
            re.address = "1 Main".into();
            records::upsert(&mut v.real_estate, re);
        }
        app.tab = Tab::RealEstate;
        app.selected = 0;
        app.start_edit(true);
        let rc = app.edit.as_ref().unwrap().record_fields;

        let src = dir.join("deed.txt");
        std::fs::write(&src, b"the deed").unwrap();
        {
            let es = app.edit.as_mut().unwrap();
            es.fields[rc].value = "deed.txt".into();
            es.fields[rc + 1].value = src.to_string_lossy().into();
        }
        app.attach_re_document();
        assert_eq!(app.edit.as_ref().unwrap().re_docs.len(), 1, "attached one document");
        assert_eq!(app.vault.as_ref().unwrap().vault.real_estate[0].documents.len(), 1, "and persisted it");

        // Export into the configured export dir, recreating the volume folder structure.
        let export_root = dir.join("exports");
        app.cfg_export_dir = export_root.to_string_lossy().into();
        let re_id = app.vault.as_ref().unwrap().vault.real_estate[0].documents[0].clone();
        let vpath = app.vault.as_ref().unwrap().doc_path(&re_id).unwrap();
        app.edit.as_mut().unwrap().fields[rc + 3].value = "1".into();
        app.export_re_document();
        let exported = export_root.join(vpath.trim_start_matches('/'));
        assert_eq!(std::fs::read(&exported).unwrap(), b"the deed", "exported bytes round-trip (status: {})", app.status);

        app.edit.as_mut().unwrap().fields[rc + 3].value = "1".into();
        app.remove_re_document();
        assert!(app.edit.as_ref().unwrap().re_docs.is_empty(), "removed the document");
        assert!(app.vault.as_ref().unwrap().vault.real_estate[0].documents.is_empty(), "and unlinked it");
        cleanup(&path);
    }

    #[test]
    fn general_document_attach_export_detach_and_path_layout() {
        let (mut app, path) = app_unlocked("uigendoc");
        let dir = path.parent().unwrap().to_path_buf();
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            records::upsert(&mut v.general_documents, GeneralDocument::new().unwrap());
        }
        app.tab = Tab::GeneralDocuments;
        app.selected = 0;
        app.start_edit(true);
        let rc = app.edit.as_ref().unwrap().record_fields; // Title, Description -> rc == 2
        app.edit.as_mut().unwrap().fields[0].value = "Passport".into(); // drives the auto-group

        let src = dir.join("passport.pdf");
        std::fs::write(&src, b"passport bytes").unwrap();
        {
            let es = app.edit.as_mut().unwrap();
            es.fields[rc].value = "passport.pdf".into(); // filename
            es.fields[rc + 1].value = src.to_string_lossy().into(); // upload from
            es.fields[rc + 2].value = "ids".into(); // subfolder
        }
        app.attach_document();
        let id = app.edit.as_ref().unwrap().attached_file_id.clone();
        assert!(id.is_some(), "attached; status: {}", app.status);
        let id = id.unwrap();

        // Uniform layout: /general-documents/<title>/<timestamp>/<subfolder>/<filename>
        // (virtual paths are normalized with a leading slash).
        let vpath = app.vault.as_ref().unwrap().doc_path(&id).unwrap();
        let parts: Vec<&str> = vpath.trim_start_matches('/').split('/').collect();
        assert_eq!(parts[0], "general-documents");
        assert_eq!(parts[1], "passport", "auto-group from title");
        assert_eq!(parts[2].len(), 15, "timestamp folder YYYYMMDD-HHMMSS, got {:?}", parts.get(2));
        assert_eq!(parts[3], "ids", "user subfolder");
        assert_eq!(parts[4], "passport.pdf", "user filename");

        // Export into the configured export dir, recreating the volume folder structure.
        let export_root = dir.join("exports");
        app.cfg_export_dir = export_root.to_string_lossy().into();
        app.export_document();
        let exported = export_root.join(vpath.trim_start_matches('/'));
        assert_eq!(std::fs::read(&exported).unwrap(), b"passport bytes", "exported bytes round-trip (status: {})", app.status);

        app.detach_document();
        assert!(app.edit.as_ref().unwrap().attached_file_id.is_none(), "detached");
        assert!(!app.vault.as_ref().unwrap().has_document(&id), "blob reclaimed");
        assert!(app.vault.as_ref().unwrap().vault.general_documents[0].file.is_none(), "unlinked + persisted");
        cleanup(&path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn attach_document_reports_failure_when_save_fails_in_tui() {
        // Regression (deep-search HIGH): attach_document set "Document uploaded"
        // unconditionally even when persist() failed — a false success that lost the
        // record→document link. With the disk full at the vault write, the status
        // must report the failure and the link must NOT be persisted.
        let (mut app, path) = app_unlocked("uifailattach");
        let dir = path.parent().unwrap().to_path_buf();
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            records::upsert(&mut v.general_documents, GeneralDocument::new().unwrap());
        }
        app.vault.as_mut().unwrap().save().unwrap(); // persist the seed cleanly first
        app.tab = Tab::GeneralDocuments;
        app.selected = 0;
        app.start_edit(true);
        let rc = app.edit.as_ref().unwrap().record_fields;
        app.edit.as_mut().unwrap().fields[0].value = "Passport".into();
        let src = dir.join("p.pdf");
        std::fs::write(&src, b"bytes").unwrap();
        {
            let es = app.edit.as_mut().unwrap();
            es.fields[rc].value = "p.pdf".into();
            es.fields[rc + 1].value = src.to_string_lossy().into();
        }
        // Fail the vault.pmv write (add_document's blob write still succeeds first).
        crate::fault::fail_at("vault.write", 1);
        app.attach_document();
        crate::fault::clear();
        assert!(app.status.contains("Save failed"), "must report failure, not success; was: {}", app.status);
        drop(app); // release the lock
        // The link never reached disk: reopening shows no attached file (no false link).
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(re.vault.general_documents[0].file.is_none(), "no false link persisted");
        let _ = std::fs::remove_file(&src);
        cleanup(&path);
    }

    #[test]
    fn start_edit_loads_the_selected_taxes_record() {
        let (mut app, path) = app_unlocked("uitaxsel");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            for y in ["2020", "2021", "2022"] {
                let mut tf = TaxFiling::new().unwrap();
                tf.year = y.into();
                records::upsert(&mut v.tax_filings, tf);
            }
        }
        app.tab = Tab::Taxes;
        let labels = app.current_labels();
        assert_eq!(labels.len(), 3);
        let target_id = labels[1].0.clone();
        app.selected = 1;
        app.start_edit(true);
        let es = app.edit.as_ref().unwrap();
        // Must edit the *selected* record, not a different one (kills the id-lookup
        // `==`→`!=` mutant, which would resolve to the wrong filing).
        assert_eq!(es.id.as_deref(), Some(target_id.as_str()));
        let expected =
            app.vault.as_ref().unwrap().vault.tax_filings.iter().find(|r| r.id == target_id).unwrap().year.clone();
        assert_eq!(es.fields[0].value, expected, "loads the selected record's fields");
        cleanup(&path);
    }

    #[test]
    fn start_edit_loads_the_selected_real_estate_record() {
        let (mut app, path) = app_unlocked("uiresel");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            for a in ["1 First St", "2 Second St", "3 Third St"] {
                let mut re = RealEstate::new().unwrap();
                re.address = a.into();
                records::upsert(&mut v.real_estate, re);
            }
        }
        app.tab = Tab::RealEstate;
        let labels = app.current_labels();
        assert_eq!(labels.len(), 3);
        let target_id = labels[1].0.clone();
        app.selected = 1;
        app.start_edit(true);
        let es = app.edit.as_ref().unwrap();
        assert_eq!(es.id.as_deref(), Some(target_id.as_str()));
        let expected =
            app.vault.as_ref().unwrap().vault.real_estate.iter().find(|r| r.id == target_id).unwrap().address.clone();
        assert_eq!(es.fields[0].value, expected, "loads the selected property's fields");
        cleanup(&path);
    }

    #[test]
    fn real_estate_tax_portal_and_comments_round_trip_in_tui() {
        // Pins the RealEstate build↔commit field-index mapping for the NEW fields:
        // edit a property, fill the tax portal + every per-portal comment by LABEL
        // (so the test doesn't hard-code indices), save, and confirm each lands in the
        // right struct field. A build/commit index mismatch would cross the values.
        let (mut app, path) = app_unlocked("uitaxportal");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut re = RealEstate::new().unwrap();
            re.address = "9 Audit Ave".into();
            records::upsert(&mut v.real_estate, re);
        }
        app.tab = Tab::RealEstate;
        app.selected = 0;
        app.start_edit(true);
        // Set fields by label so the assertion below is index-agnostic.
        let set = |app: &mut App, label: &str, val: &str| {
            let es = app.edit.as_mut().unwrap();
            let f = es.fields.iter_mut().find(|f| f.label == label).unwrap_or_else(|| panic!("no field {label:?}"));
            f.value = val.into();
        };
        set(&mut app, "Tax URL", "https://tax.example");
        set(&mut app, "Tax username", "taxuser");
        set(&mut app, "Tax password", "taxpw");
        set(&mut app, "Tax comment", "tax notes");
        set(&mut app, "Property Mgmt comment", "pm notes");
        set(&mut app, "Insurance comment", "ins notes");
        set(&mut app, "HOA comment", "hoa notes");
        app.handle_key(ctrl('s'));
        let re = &app.vault.as_ref().unwrap().vault.real_estate[0];
        assert_eq!(re.tax_portal_url, "https://tax.example");
        assert_eq!(re.tax_portal_username, "taxuser");
        assert_eq!(re.tax_portal_password, "taxpw");
        assert_eq!(re.tax_portal_comment, "tax notes");
        assert_eq!(re.property_mgmt_comment, "pm notes");
        assert_eq!(re.insurance_comment, "ins notes");
        assert_eq!(re.hoa_comment, "hoa notes");
        // The address (field 0) must be untouched — i.e. no field shifted onto another.
        assert_eq!(re.address, "9 Audit Ave");
        cleanup(&path);
    }

    #[test]
    fn tax_attach_requires_filename_and_source() {
        let (mut app, path) = app_unlocked("uitaxreq");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            records::upsert(&mut v.tax_filings, TaxFiling::new().unwrap());
        }
        app.tab = Tab::Taxes;
        app.selected = 0;
        app.start_edit(true);
        let rc = app.edit.as_ref().unwrap().record_fields;
        // Filename present, source empty → rejected as missing input, nothing attached
        // (kills the `||`→`&&` mutant, which would let a one-sided-empty input through).
        app.edit.as_mut().unwrap().fields[rc].value = "w2.txt".into();
        app.edit.as_mut().unwrap().fields[rc + 1].value = String::new();
        app.attach_tax_document();
        assert!(app.edit.as_ref().unwrap().tax_docs.is_empty(), "missing source → no upload");
        assert!(app.status.contains("required"), "rejected as a missing-input error");
        cleanup(&path);
    }

    #[test]
    fn re_attach_requires_source_and_defaults_filename_in_tui() {
        let (mut app, path) = app_unlocked("uirereq");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut re = RealEstate::new().unwrap();
            re.address = "1 Main".into();
            records::upsert(&mut v.real_estate, re);
        }
        app.tab = Tab::RealEstate;
        app.selected = 0;
        app.start_edit(true);
        let rc = app.edit.as_ref().unwrap().record_fields;
        // (1) A source is required even when a filename IS given.
        app.edit.as_mut().unwrap().fields[rc].value = "deed.pdf".into();
        app.edit.as_mut().unwrap().fields[rc + 1].value = String::new();
        app.attach_re_document();
        assert!(app.edit.as_ref().unwrap().re_docs.is_empty(), "missing source → no upload");
        assert!(app.status.contains("required"), "rejected as a missing-input error");
        // (2) Empty filename + a real source file → uploads using the source's basename.
        let src = path.parent().unwrap().join("Deed.PDF");
        std::fs::write(&src, b"x").unwrap();
        app.edit.as_mut().unwrap().fields[rc].value = String::new();
        app.edit.as_mut().unwrap().fields[rc + 1].value = src.to_string_lossy().into();
        app.attach_re_document();
        assert_eq!(app.edit.as_ref().unwrap().re_docs.len(), 1, "uploaded with defaulted filename (status: {})", app.status);
        let id = app.edit.as_ref().unwrap().re_docs[0].clone();
        let vpath = app.vault.as_ref().unwrap().doc_path(&id).unwrap();
        assert!(vpath.ends_with("/Deed.PDF"), "empty filename used the source basename: {vpath}");
        cleanup(&path);
    }

    #[test]
    fn formats_timestamps() {
        assert_eq!(format_time(0), "never");
        assert_eq!(format_time(-5), "never");
        assert_eq!(format_time(1_609_459_200), "2021-01-01 00:00:00 UTC");
        assert_eq!(format_time(1_609_459_201), "2021-01-01 00:00:01 UTC");
    }

    #[test]
    fn tabs_cycle_and_number_select() {
        let (mut app, path) = app_unlocked("tabs");
        assert_eq!(app.tab, Tab::Instructions);
        app.handle_key(key(KeyCode::Right));
        assert_eq!(app.tab, Tab::TrustWill);
        app.handle_key(key(KeyCode::Left));
        assert_eq!(app.tab, Tab::Instructions);
        app.handle_key(key(KeyCode::Char('4')));
        assert_eq!(app.tab, Tab::Accounts);
        cleanup(&path);
    }

    #[test]
    fn create_account_via_keys_persists_fields_in_order() {
        let (mut app, path) = app_unlocked("acct");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts tab
        app.handle_key(key(KeyCode::Char('n'))); // new -> Edit screen
        assert_eq!(app.screen, Screen::Edit);

        // Field order: 0 title 1 type(choice) 2 subtype(choice) 3 owner 4 username
        // 5 password 6 url 7 closed_as_of 8 description 9 review(choice).
        let typ = |app: &mut App, c: char| app.handle_key(key(KeyCode::Char(c)));
        // title (focus 0) — mandatory.
        for c in "My login".chars() { typ(&mut app, c); }
        // owner (focus 3)
        app.handle_key(key(KeyCode::Down)); // 0->1
        app.handle_key(key(KeyCode::Down)); // 1->2
        app.handle_key(key(KeyCode::Down)); // 2->3 owner
        for c in "Jane".chars() { typ(&mut app, c); }
        app.handle_key(key(KeyCode::Down)); // username
        for c in "jane".chars() { typ(&mut app, c); }
        app.handle_key(key(KeyCode::Down)); // password
        for c in "pw".chars() { typ(&mut app, c); }
        app.handle_key(key(KeyCode::Down)); // url
        app.handle_key(key(KeyCode::Down)); // closed_as_of (focus 7)
        for c in "2026-06-18".chars() { typ(&mut app, c); }
        app.handle_key(ctrl('s')); // save

        assert_eq!(app.screen, Screen::Browse);
        let v = &app.vault.as_ref().unwrap().vault;
        assert_eq!(v.accounts.len(), 1);
        // Verify field-index mapping: owner/username/password/closed_as_of landed correctly.
        assert_eq!(v.accounts[0].title, "My login");
        assert_eq!(v.accounts[0].owner, "Jane");
        assert_eq!(v.accounts[0].username, "jane");
        assert_eq!(v.accounts[0].password, "pw");
        assert_eq!(v.accounts[0].closed_as_of, "2026-06-18");
        cleanup(&path);
    }

    #[test]
    fn saving_an_account_trims_every_field_in_tui() {
        let (mut app, path) = app_unlocked("trimsave");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts
        app.handle_key(key(KeyCode::Char('n'))); // new
        // title (focus 0) — mandatory; also exercises trimming.
        for c in "  Brokerage  ".chars() { app.handle_key(key(KeyCode::Char(c))); }
        // owner (focus 3) with surrounding spaces
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Down));
        for c in "  Jane  ".chars() { app.handle_key(key(KeyCode::Char(c))); }
        app.handle_key(key(KeyCode::Down)); // username
        for c in " jane ".chars() { app.handle_key(key(KeyCode::Char(c))); }
        app.handle_key(key(KeyCode::Down)); // password
        for c in "  pw  ".chars() { app.handle_key(key(KeyCode::Char(c))); }
        app.handle_key(ctrl('s'));
        let a = &app.vault.as_ref().unwrap().vault.accounts[0];
        assert_eq!(a.title, "Brokerage");
        assert_eq!(a.owner, "Jane");
        assert_eq!(a.username, "jane");
        assert_eq!(a.password, "pw", "the password is trimmed too (configured policy)");
        cleanup(&path);
    }

    #[test]
    fn trim_all_key_bulk_trims_every_tab_in_tui() {
        let (mut app, path) = app_unlocked("trimallkey");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut a = Account::new().unwrap();
            a.owner = "  Alice  ".into();
            a.title = " Brokerage ".into();
            a.password = "  s3cret  ".into();
            records::upsert(&mut v.accounts, a);
            // A dirty record on a DIFFERENT tab must be trimmed by the same key.
            let mut re = RealEstate::new().unwrap();
            re.address = "  1 Main St  ".into();
            re.hoa_password = "  hoapw  ".into();
            records::upsert(&mut v.real_estate, re);
        }
        // Press T from a tab OTHER than the records being trimmed — it is whole-vault.
        app.handle_key(key(KeyCode::Char('6'))); // Taxes tab
        app.handle_key(key(KeyCode::Char('T'))); // one-off trim-all (whole vault)
        let a = &app.vault.as_ref().unwrap().vault.accounts[0];
        assert_eq!(a.owner, "Alice");
        assert_eq!(a.title, "Brokerage");
        assert_eq!(a.password, "s3cret");
        let re = &app.vault.as_ref().unwrap().vault.real_estate[0];
        assert_eq!(re.address, "1 Main St");
        assert_eq!(re.hoa_password, "hoapw", "portal passwords are trimmed too");
        assert!(app.status.contains("Trimmed 2"), "status reports the count: {}", app.status);
        // Idempotent: a second pass finds nothing to trim.
        app.handle_key(key(KeyCode::Char('T')));
        assert!(app.status.contains("Nothing to trim"), "second pass is a no-op: {}", app.status);
        cleanup(&path);
    }

    #[test]
    fn trim_all_key_is_blocked_in_read_only_tui() {
        let (mut app, path) = app_read_only("trimro");
        app.handle_key(key(KeyCode::Char('4')));
        app.handle_key(key(KeyCode::Char('T')));
        assert!(app.status.contains("Read-only"), "read-only blocks the bulk trim: {}", app.status);
        cleanup(&path);
    }

    #[test]
    fn tui_config_delete_type_unused_blocked_when_used_or_has_subtypes() {
        let (mut app, path) = app_unlocked("cfgdel");
        {
            let v = app.vault.as_mut().unwrap();
            v.add_asset_type("Crypto").unwrap();
            v.add_account_type("Bank").unwrap();
            v.add_account_subtype("Bank", "Checking").unwrap();
            v.save().unwrap();
        }
        app.screen = Screen::Config;

        // Delete an UNUSED asset type (focus 0, type the name, Del).
        app.cfg_focus = 0;
        app.cfg_asset_type = "Crypto".into();
        app.handle_config_key(key(KeyCode::Delete));
        assert!(app.status.contains("Deleted asset"), "status: {}", app.status);
        assert!(!app.vault.as_ref().unwrap().categories().asset.contains(&"Crypto".to_string()));
        assert!(app.cfg_asset_type.is_empty(), "field cleared on success");

        // Deleting an account type WITH subtypes is blocked.
        app.cfg_focus = 1;
        app.cfg_account_type = "Bank".into();
        app.handle_config_key(key(KeyCode::Delete));
        assert!(app.status.contains("delete its subtypes first"), "status: {}", app.status);
        assert!(app.vault.as_ref().unwrap().categories().account_type_names().contains(&"Bank".to_string()));

        // A subtype IN USE by a live account is blocked.
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut a = Account::new().unwrap();
            a.account_type = "Bank".into();
            a.account_subtype = "Checking".into();
            records::upsert(&mut v.accounts, a);
        }
        app.vault.as_mut().unwrap().save().unwrap();
        app.cfg_focus = 2;
        app.cfg_subtype_type = "Bank".into();
        app.cfg_subtype_name = "Checking".into();
        app.handle_config_key(key(KeyCode::Delete));
        assert!(app.status.contains("still used by 1"), "status: {}", app.status);
        assert_eq!(app.vault.as_ref().unwrap().categories().subtypes_for("Bank"), vec!["Checking".to_string()]);
        cleanup(&path);
    }

    #[test]
    fn tui_config_delete_is_blocked_read_only() {
        let (mut app, path) = app_read_only("cfgdelro");
        app.screen = Screen::Config;
        app.cfg_focus = 1;
        app.cfg_account_type = "Email".into();
        app.handle_config_key(key(KeyCode::Delete));
        assert!(app.status.contains("Read-only"), "read-only blocks delete: {}", app.status);
        cleanup(&path);
    }

    #[test]
    fn review_choice_maps_to_bool_on_save() {
        let (mut app, path) = app_unlocked("review");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts
        app.handle_key(key(KeyCode::Char('n')));
        // title (focus 0) — mandatory.
        for c in "Acct".chars() { app.handle_key(key(KeyCode::Char(c))); }
        // owner (field 3) is also mandatory — set it directly.
        app.edit.as_mut().unwrap().fields[3].value = "Alice".into();
        // focus 9 = review choice (0 title .. 7 closed_as_of, 8 description); cycle to "Yes".
        for _ in 0..9 {
            app.handle_key(key(KeyCode::Down));
        }
        app.handle_key(key(KeyCode::Right)); // cycle choice No -> Yes
        app.handle_key(ctrl('s'));
        assert!(app.vault.as_ref().unwrap().vault.accounts[0].review);
        cleanup(&path);
    }

    #[test]
    fn account_save_requires_a_title_in_tui() {
        let (mut app, path) = app_unlocked("titlereq");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts
        app.handle_key(key(KeyCode::Char('n'))); // new
        // Fill the username but leave the title (field 0) blank.
        for _ in 0..4 {
            app.handle_key(key(KeyCode::Down));
        }
        for c in "notitle".chars() { app.handle_key(key(KeyCode::Char(c))); }
        app.handle_key(ctrl('s')); // save — must be rejected
        assert_eq!(app.screen, Screen::Edit, "stays in the edit form when the title is blank");
        assert!(app.status.contains("Title is required"), "status: {}", app.status);
        assert!(app.vault.as_ref().unwrap().vault.accounts.is_empty(), "nothing saved without a title");
        cleanup(&path);
    }

    #[test]
    fn account_save_requires_an_owner_in_tui() {
        let (mut app, path) = app_unlocked("ownerreq");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts
        app.handle_key(key(KeyCode::Char('n'))); // new
        // Give a title (field 0) but leave the owner (field 3) blank.
        for c in "Acct".chars() { app.handle_key(key(KeyCode::Char(c))); }
        app.handle_key(ctrl('s')); // save — must be rejected for the missing owner
        assert_eq!(app.screen, Screen::Edit, "stays in the edit form when the owner is blank");
        assert!(app.status.contains("Owner is required"), "status: {}", app.status);
        assert!(app.vault.as_ref().unwrap().vault.accounts.is_empty(), "nothing saved without an owner");
        // Supplying an owner lets it save.
        app.edit.as_mut().unwrap().fields[3].value = "Alice".into();
        app.handle_key(ctrl('s'));
        assert_eq!(app.screen, Screen::Browse, "saves once title + owner are present");
        assert_eq!(app.vault.as_ref().unwrap().vault.accounts.len(), 1);
        cleanup(&path);
    }

    #[test]
    fn read_only_edit_form_is_not_editable() {
        let (mut app, path) = app_read_only("roedit");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts
        app.selected = 0;
        app.handle_key(key(KeyCode::Enter)); // Enter opens the record as a VIEW
        assert_eq!(app.screen, Screen::Edit);

        // Typing + backspace into the focused (title) text field is inert.
        for c in "HACK".chars() { app.handle_key(key(KeyCode::Char(c))); }
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.edit.as_ref().unwrap().fields[0].value, "", "text field not editable in read-only");

        // Cycling a Choice field (account type, field 1) is inert too.
        app.handle_key(key(KeyCode::Down)); // focus -> 1 (account type choice)
        let before = app.edit.as_ref().unwrap().fields[1].value.clone();
        app.handle_key(key(KeyCode::Right));
        assert_eq!(app.edit.as_ref().unwrap().fields[1].value, before, "choice not cyclable in read-only");

        // Reads still work: Ctrl+R flips the global reveal (the only reveal control) even
        // in read-only — on the Accounts tab that is `reveal_all`.
        assert!(!app.reveal_all);
        app.handle_key(ctrl('r'));
        assert!(app.reveal_all, "global reveal still works in read-only");
        cleanup(&path);
    }

    #[test]
    fn tui_accounts_grouped_tree_expands_then_edits_leaf() {
        let (mut app, path) = app_unlocked("uitree");
        let want_id = {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut a = Account::new().unwrap();
            a.account_type = "Financial".into();
            a.account_subtype = "Bank".into();
            a.owner = "Alice".into();
            a.title = "Joint brokerage".into();
            let id = a.id.clone();
            records::upsert(&mut v.accounts, a);
            id
        };
        app.handle_key(key(KeyCode::Char('4'))); // Accounts tab
        app.handle_key(key(KeyCode::Char('g'))); // switch to grouped
        assert!(app.acct_grouped);
        // Collapsed by default: only the top-level owner row is visible, and the leaf
        // title is NOT shown yet.
        assert_eq!(app.account_rows().len(), 1);
        assert!(!render_to_string(&app).contains("Joint brokerage"), "leaf hidden while collapsed");
        // Expand owner → type → subtype, stepping down to each newly revealed child.
        app.handle_key(key(KeyCode::Enter)); // expand Alice (selected 0)
        app.handle_key(key(KeyCode::Down)); // -> Financial
        app.handle_key(key(KeyCode::Enter)); // expand Financial
        app.handle_key(key(KeyCode::Down)); // -> Bank
        app.handle_key(key(KeyCode::Enter)); // expand Bank
        app.handle_key(key(KeyCode::Down)); // -> the leaf
        assert!(render_to_string(&app).contains("Joint brokerage"), "leaf title shown when expanded");
        // Enter on the leaf edits that account.
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Edit);
        assert_eq!(app.edit.as_ref().unwrap().id.as_deref(), Some(want_id.as_str()));
        cleanup(&path);
    }

    #[test]
    fn grouped_tree_expand_keys_do_not_collide_in_tui() {
        // Regression for the expand-key collision (audit fix): keying `acct_expanded`
        // on a separator-JOINED string let two distinct group paths share state — a
        // nested ["Alice","Bank"] collided with a single top-level owner label
        // "Alice\x1fBank". Keying on the label STACK (Vec) makes them distinct.
        let (mut app, path) = app_unlocked("treekeycollide");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut a = Account::new().unwrap();
            a.owner = "Alice".into();
            a.account_type = "Bank".into();
            a.title = "Nested".into();
            records::upsert(&mut v.accounts, a);
            let mut b = Account::new().unwrap();
            b.owner = "Alice\u{1f}Bank".into(); // ONE owner label containing the old separator
            b.title = "TopLevel".into();
            records::upsert(&mut v.accounts, b);
        }
        app.tab = Tab::Accounts;
        app.acct_grouped = true;
        // Expand owner "Alice" and then the NESTED "Bank" group beneath it.
        app.acct_expanded.insert(vec!["Alice".to_string()]);
        app.acct_expanded.insert(vec!["Alice".to_string(), "Bank".to_string()]);
        let labels: Vec<String> = app.account_rows().iter().map(|r| r.label.clone()).collect();
        // The nested group's leaf is visible (its path IS expanded)...
        assert!(labels.iter().any(|l| l == "Nested"), "nested expanded group shows its leaf: {labels:?}");
        // ...but the separate top-level "Alice\x1fBank" group must stay COLLAPSED — if its
        // key collided with ["Alice","Bank"] it would wrongly expand and show "TopLevel".
        assert!(!labels.iter().any(|l| l == "TopLevel"), "colliding top-level group must stay collapsed: {labels:?}");
        cleanup(&path);
    }

    #[test]
    fn edit_existing_resolves_by_id_under_filter() {
        let (mut app, path) = app_unlocked("filteredit");
        // Two accounts: one flagged for review, one not.
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            let mut a1 = Account::new().unwrap();
            a1.owner = "Plain".into();
            let mut a2 = Account::new().unwrap();
            a2.owner = "Flagged".into();
            a2.review = true;
            records::upsert(&mut v.accounts, a1);
            records::upsert(&mut v.accounts, a2);
        }
        app.handle_key(key(KeyCode::Char('4'))); // Accounts
        app.handle_key(key(KeyCode::Char('v'))); // review-only filter
        assert!(app.acct_filter_review);
        assert_eq!(app.current_labels().len(), 1); // only the flagged one
        app.selected = 0;
        app.handle_key(key(KeyCode::Enter)); // edit selected (filtered index 0)
        assert_eq!(app.screen, Screen::Edit);
        // The edit buffer must be the *flagged* account, not accounts[0].
        let es = app.edit.as_ref().unwrap();
        assert_eq!(es.id.as_deref(), Some(app.vault.as_ref().unwrap().vault.accounts.iter().find(|a| a.review).unwrap().id.as_str()));
        cleanup(&path);
    }

    #[test]
    fn delete_via_key_removes_record() {
        let (mut app, path) = app_unlocked("del");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            records::upsert(&mut v.instructions, Instruction::new().unwrap());
        }
        assert_eq!(app.current_labels().len(), 1);
        app.selected = 0;
        app.handle_key(key(KeyCode::Char('d')));
        assert!(app.vault.as_ref().unwrap().vault.instructions.is_empty());
        cleanup(&path);
    }

    #[test]
    fn config_screen_adds_type_and_subtype() {
        let (mut app, path) = app_unlocked("cfg");
        app.handle_key(key(KeyCode::Char('c'))); // open Config
        assert_eq!(app.screen, Screen::Config);
        // focus 0 = new asset type
        for c in "Annuity".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));
        assert!(app.vault.as_ref().unwrap().categories().asset.contains(&"Annuity".to_string()));
        // focus 2/3 = subtype type + name
        app.handle_key(key(KeyCode::Down)); // 0->1
        app.handle_key(key(KeyCode::Down)); // 1->2 subtype type
        for c in "Financial".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Down)); // 2->3 subtype name
        for c in "HSA".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));
        assert!(
            app.vault
                .as_ref()
                .unwrap()
                .categories()
                .subtypes_for("Financial")
                .contains(&"HSA".to_string())
        );
        cleanup(&path);
    }

    #[test]
    fn tui_subtype_reconstrains_on_type_change() {
        let (mut app, path) = app_unlocked("subrecon");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts tab
        app.handle_key(key(KeyCode::Char('n'))); // new record -> Edit
        assert_eq!(app.screen, Screen::Edit);
        {
            let es = app.edit.as_ref().unwrap();
            // Field 0 is now Title; type/subtype follow.
            assert_eq!(es.fields[0].label, "Title");
            assert_eq!(es.fields[1].label, "Account type");
            assert_eq!(es.fields[2].label, "Subtype");
        }
        // Move focus to the account-type field, then cycle it; this must reconstrain
        // the dependent subtype field's options to the newly-selected type.
        app.handle_key(key(KeyCode::Down)); // Title -> Account type
        app.handle_key(key(KeyCode::Right));
        let es = app.edit.as_ref().unwrap();
        let chosen_type = es.fields[1].value.clone();
        let expected = app.vault.as_ref().unwrap().categories().subtypes_for(&chosen_type);
        match &es.fields[2].kind {
            FieldKind::Choice(opts) => assert_eq!(opts, &expected),
            _ => panic!("subtype field is not a Choice"),
        }
        cleanup(&path);
    }

    #[test]
    fn detach_on_non_doc_tab_is_noop() {
        let (mut app, path) = app_unlocked("detachnoop");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts (no docs)
        app.handle_key(key(KeyCode::Char('n')));
        app.handle_key(ctrl('k')); // detach — should be a harmless no-op
        // Still on the edit screen with an intact buffer; no account created yet.
        assert_eq!(app.screen, Screen::Edit);
        assert!(app.vault.as_ref().unwrap().vault.accounts.is_empty());
        cleanup(&path);
    }

    #[test]
    fn read_only_keys_are_inert_but_reads_work() {
        let (mut app, path) = app_read_only("ro");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts tab
        assert_eq!(app.current_labels().len(), 1, "existing record is viewable");

        // New / delete / change-password do nothing and report read-only.
        app.handle_key(key(KeyCode::Char('n')));
        assert_eq!(app.screen, Screen::Browse, "new is inert in read-only");
        assert!(app.status.contains("Read-only"));
        app.selected = 0;
        app.handle_key(key(KeyCode::Char('d')));
        assert_eq!(app.vault.as_ref().unwrap().vault.accounts.len(), 1, "delete is inert");

        // Viewing (Enter -> Edit) is allowed; saving is not.
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Edit);
        app.handle_key(ctrl('s'));
        assert!(app.status.contains("Read-only"), "save is inert in read-only");
        cleanup(&path);
    }

    #[test]
    fn read_only_config_blocks_type_add() {
        let (mut app, path) = app_read_only("rocfg");
        app.handle_key(key(KeyCode::Char('c')));
        assert_eq!(app.screen, Screen::Config);
        for c in "Annuity".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter)); // focus 0 = add asset type
        assert!(
            !app.vault.as_ref().unwrap().categories().asset.contains(&"Annuity".to_string()),
            "type add blocked in read-only"
        );
        assert!(app.status.contains("Read-only"));
        cleanup(&path);
    }

    #[test]
    fn over_long_filename_is_capped_in_tui() {
        // The uniform layout caps every path component (filename 120, group/subfolder
        // 40, timestamp fixed), so a huge filename can no longer push the virtual path
        // past MAX_PATH_LEN — it is sanitized and truncated, and the upload succeeds.
        let (mut app, path) = app_unlocked("uipath");
        app.tab = Tab::Assets;
        app.start_edit(false); // builds the edit form, appending the doc fields
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let src = std::env::temp_dir().join(format!("passmgr-uipath-{nanos}.txt"));
        std::fs::write(&src, b"x").unwrap();
        {
            let es = app.edit.as_mut().unwrap();
            let rc = es.record_fields;
            es.fields[rc].value = "f".repeat(crate::storage::MAX_PATH_LEN); // filename (huge)
            es.fields[rc + 1].value = src.display().to_string(); // upload from
        }
        app.attach_document();
        let id = app.edit.as_ref().unwrap().attached_file_id.clone();
        assert!(id.is_some(), "upload should succeed with a capped name; status: {}", app.status);
        let vpath = app.vault.as_ref().unwrap().doc_path(&id.unwrap()).unwrap_or_default();
        assert!(vpath.len() <= crate::storage::MAX_PATH_LEN, "vpath within limit: {} bytes", vpath.len());
        let _ = std::fs::remove_file(&src);
        cleanup(&path);
    }

    #[test]
    fn volume_size_config_sets_cap_in_tui() {
        let (mut app, path) = app_unlocked("uivol");
        app.cfg_focus = 4; // the volume-size field
        app.cfg_volume_size = "8".into();
        app.submit_config();
        assert_eq!(app.vault.as_ref().unwrap().volume_max_size(), 8 * 1024 * 1024);
        assert!(app.cfg_volume_size.is_empty(), "input cleared on success");
        // A non-numeric value is rejected and leaves the cap unchanged.
        app.cfg_volume_size = "abc".into();
        app.submit_config();
        assert_eq!(app.vault.as_ref().unwrap().volume_max_size(), 8 * 1024 * 1024);
        assert!(app.status.contains("MiB"), "status was: {}", app.status);
        cleanup(&path);
    }

    #[test]
    fn read_only_config_typing_gated_to_export_and_backup_fields() {
        // Regression (deep-hunt): in read-only, typing must only edit the fields whose
        // action is reachable read-only — backup dest (5) and export dir (7). The
        // write-only fields (volume size, etc.) must stay inert, matching submit_config's
        // allow-list and the GUI which hides them.
        let (mut app, path) = app_read_only("rocfgtype");
        app.handle_key(key(KeyCode::Char('c'))); // Config
        assert_eq!(app.screen, Screen::Config);

        // Write-only field (volume size, focus 4): typing is ignored.
        app.cfg_focus = 4;
        for c in "8".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert!(app.cfg_volume_size.is_empty(), "read-only can't type into the volume-size field");

        // Export dir (focus 7): typing IS allowed (a local, non-vault preference).
        app.cfg_focus = 7;
        for c in "/tmp/exp".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        assert_eq!(app.cfg_export_dir, "/tmp/exp", "read-only can edit the export directory");
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.cfg_export_dir, "/tmp/ex", "backspace works on the export-dir field");
        cleanup(&path);
    }

    #[test]
    fn read_only_config_blocks_volume_size() {
        let (mut app, path) = app_read_only("rovol");
        app.handle_key(key(KeyCode::Char('c'))); // Config
        app.cfg_focus = 4;
        app.cfg_volume_size = "8".into();
        app.submit_config();
        assert_eq!(
            app.vault.as_ref().unwrap().volume_max_size(),
            crate::storage::DEFAULT_VOLUME_MAX_SIZE,
            "volume size change blocked in read-only"
        );
        assert!(app.status.contains("Read-only"));
        cleanup(&path);
    }

    /// Render the current screen to an in-memory backend; asserts no panic.
    fn render(app: &App) {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;
        let mut term = Terminal::new(TestBackend::new(120, 40)).unwrap();
        term.draw(|f| app.draw(f)).unwrap();
    }

    #[test]
    fn renders_every_screen_without_panicking() {
        // Auth screen, all three modes.
        let path = tmp_vault("render");
        for mode in [AuthMode::Create, AuthMode::Unlock, AuthMode::ChangePassword] {
            let mut app = App::new(path.clone(), true);
            app.auth = AuthState::new(mode);
            app.auth.error = Some("err".into());
            render(&app);
        }

        let (mut app, _p) = app_unlocked("render2");
        // Populate one record per tab so list/label rendering is exercised.
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            records::upsert(&mut v.instructions, Instruction::new().unwrap());
            records::upsert(&mut v.trust_wills, TrustWill::new().unwrap());
            records::upsert(&mut v.assets, AssetLiability::new().unwrap());
            let mut acc = Account::new().unwrap();
            acc.account_type = "Financial".into();
            acc.review = true;
            records::upsert(&mut v.accounts, acc);
            records::upsert(&mut v.real_estate, RealEstate::new().unwrap());
        }
        // Browse each tab.
        for t in Tab::ALL {
            app.tab = t;
            app.selected = 0;
            render(&app);
        }
        // Browse with Accounts filters active (exercises the filter title).
        app.tab = Tab::Accounts;
        app.acct_filter_type = Some("Financial".into());
        app.acct_filter_review = true;
        render(&app);
        app.tab = Tab::Assets;
        app.asset_filter_review = true;
        render(&app);

        // Edit screen for a doc-bearing tab (history + attached-doc lines) and a
        // plain tab; plus the config screen.
        app.tab = Tab::Assets;
        app.selected = 0;
        app.start_edit(true);
        render(&app);
        app.screen = Screen::Browse;
        app.tab = Tab::Accounts;
        app.start_edit(false);
        render(&app);
        app.screen = Screen::Config;
        render(&app);
        cleanup(&path);
    }
}
