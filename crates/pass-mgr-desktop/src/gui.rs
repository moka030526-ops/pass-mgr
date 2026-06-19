//! Graphical interface (egui/eframe): a tabbed estate vault.
//!
//! Five tabs map to the five record types in [`crate::records`]; each tab is a
//! list of records on the left and an edit form on the right. The Trust & Will
//! and Asset/Liability tabs can attach documents, which are uploaded into the
//! encrypted volume via [`OpenVault::add_document`].
//!
//! egui is immediate-mode, so all vault-mutating side effects (save, delete,
//! attach, …) are recorded as flags while rendering and applied *after* the
//! panel closures return, which keeps borrows of `self` disjoint and simple.
//!
//! Rust orientation for non-Rust readers of this file:
//! - `&T` is a *shared* (read-only) borrow of a value; `&mut T` is an
//!   *exclusive* (read/write) borrow. Rust allows many `&T` xor one `&mut T` at
//!   a time, which is why this file defers writes (see above).
//! - `String` is an owned, growable, heap-allocated UTF-8 string; `&str` is a
//!   borrowed string slice (a view into a `String` or a literal).
//! - `Option<T>` is "maybe a T": `Some(x)` or `None`. `Result<T, E>` is
//!   "success `Ok(x)` or failure `Err(e)`". The `?` operator early-returns the
//!   error/`None` from the enclosing function. `.unwrap()`/`.expect("msg")`
//!   extract the inner value but *panic* (abort) if it is absent.
//! - "Closures" are inline anonymous functions written `|args| body`; egui's
//!   `.show(ui, |ui| { ... })` calls our closure to draw a panel's contents.

use std::path::Path;
use std::time::{Duration, Instant};

// `use` brings names into scope (like an import). `eframe`/`egui` are the
// GUI framework; `zeroize` provides helpers that wipe secrets from memory.
use eframe::egui;
// `Zeroize` is a trait giving values a `.zeroize()` method (overwrite with
// zeros); `Zeroizing<T>` is a wrapper that auto-zeroes its contents on drop.
use zeroize::{Zeroize, Zeroizing};

use crate::password::{self, GenOptions};
use crate::records::{
    self, Account, AssetLiability, GeneralDocument, Instruction, RealEstate, Record, TaxFiling, TrustWill,
};
use crate::ui::format_time;
use crate::vault::{self, CategoryRemoval, OpenVault, VaultError};
use crate::crypto::KdfParams;

/// Launch the graphical app and block until the window is closed. `writable`
/// enables mutations; when false the vault is opened read-only and write
/// controls are hidden.
///
/// `pub` makes this callable from outside this module. `PathBuf` is an owned,
/// heap-allocated filesystem path (the borrowed view is `&Path`). The return
/// type `anyhow::Result<()>` means "succeeds with the empty value `()` or fails
/// with a boxed error".
pub fn run(path: std::path::PathBuf, writable: bool) -> anyhow::Result<()> {
    // Single-instance guard: if a window for this vault is already open, ask it to
    // come to the front and exit instead of stacking another window the user would
    // have to close one by one (see `crate::single_instance`). `_guard` holds an OS
    // lock for the lifetime of this function — i.e. the whole GUI session — and
    // releases it on return; `focus` is moved into the creation closure so later
    // launches can raise this window.
    let (_guard, focus) = match crate::single_instance::acquire(&path) {
        crate::single_instance::Instance::AlreadyRunning => {
            eprintln!("pass-mgr is already open for this vault; raising the existing window.");
            return Ok(());
        }
        crate::single_instance::Instance::Primary { guard, focus } => (guard, focus),
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("pass-mgr"),
        ..Default::default()
    };
    eframe::run_native(
        "pass-mgr",
        options,
        // `Box::new(...)` heap-allocates; `Box<T>` is an owning pointer to a
        // heap value. `move |cc| ...` is a closure that *takes ownership* of the
        // captured `path`/`writable`/`focus` (the `move` keyword) so they outlive `run`.
        Box::new(move |cc| {
            // Now that the egui context exists, let later launches raise this window.
            focus.serve(cc.egui_ctx.clone());
            // Apply the saved color theme before the first frame (avoids a flash of
            // the default theme); the app re-applies it live when the user changes it.
            cc.egui_ctx.set_visuals(visuals_for(load_theme()));
            Ok(Box::new(GuiApp::new(path, writable)))
        }),
    )
    // `.map_err(|e| ...)` transforms only the error case of a `Result`; here it
    // wraps eframe's error into an `anyhow` error with context.
    .map_err(|e| anyhow::anyhow!("GUI error: {e}"))
}

/// A light egui theme — brighter than the default light visuals (panels and
/// widget faces lifted toward white for a lighter overall feel).
fn light_visuals() -> egui::Visuals {
    // `let mut v` declares a mutable local; without `mut`, bindings are
    // read-only in Rust. We tweak fields of the default light theme below.
    let mut v = egui::Visuals::light();
    v.panel_fill = egui::Color32::from_rgb(252, 253, 255);
    v.window_fill = egui::Color32::from_rgb(255, 255, 255);
    v.extreme_bg_color = egui::Color32::from_rgb(255, 255, 255);
    v.faint_bg_color = egui::Color32::from_rgb(248, 250, 253);
    // Lift the widget backgrounds (inactive/hovered/active) so controls read lighter.
    v.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(250, 251, 253);
    v.widgets.inactive.bg_fill = egui::Color32::from_rgb(244, 247, 251);
    v.widgets.inactive.weak_bg_fill = egui::Color32::from_rgb(248, 250, 253);
    v.widgets.hovered.bg_fill = egui::Color32::from_rgb(232, 240, 252);
    v.selection.bg_fill = egui::Color32::from_rgb(198, 222, 255);
    v.selection.stroke = egui::Stroke::new(1.0_f32, egui::Color32::from_rgb(40, 90, 170));
    v
}

/// The selectable GUI color themes (curated palettes). The chosen theme is
/// remembered in a small **non-secret** preferences file (`load_theme`/`save_theme`)
/// — it holds no vault data, so it can apply on the lock screen too.
#[derive(PartialEq, Eq, Clone, Copy, Default, Debug)]
enum Theme {
    #[default]
    Light,
    Dark,
    HighContrast,
    Solarized,
    Sepia,
}

impl Theme {
    /// Every theme, in menu order.
    const ALL: [Theme; 5] = [Theme::Light, Theme::Dark, Theme::HighContrast, Theme::Solarized, Theme::Sepia];

    /// Stable on-disk id (kept separate from the display label so relabelling
    /// never invalidates a saved preference).
    fn id(self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
            Theme::HighContrast => "high-contrast",
            Theme::Solarized => "solarized",
            Theme::Sepia => "sepia",
        }
    }

    /// Human-readable name for the dropdown.
    fn label(self) -> &'static str {
        match self {
            Theme::Light => "Light",
            Theme::Dark => "Dark",
            Theme::HighContrast => "High contrast",
            Theme::Solarized => "Solarized",
            Theme::Sepia => "Sepia",
        }
    }

    /// Parse a saved id back into a theme (`None` for an unknown id).
    fn from_id(id: &str) -> Option<Theme> {
        Theme::ALL.into_iter().find(|t| t.id() == id)
    }
}

/// Build the egui visuals for a theme. Each curated palette starts from egui's
/// light or dark base and overrides the panel/widget fills, the text color, and
/// the selection color for a coherent look.
fn visuals_for(theme: Theme) -> egui::Visuals {
    use egui::Color32;
    let rgb = Color32::from_rgb;
    match theme {
        Theme::Light => light_visuals(),
        Theme::Dark => {
            let mut v = egui::Visuals::dark();
            v.selection.bg_fill = rgb(40, 80, 140);
            v.selection.stroke = egui::Stroke::new(1.0, rgb(120, 170, 240));
            v.hyperlink_color = rgb(110, 170, 240);
            v
        }
        Theme::HighContrast => {
            let mut v = egui::Visuals::dark();
            v.panel_fill = Color32::BLACK;
            v.window_fill = Color32::BLACK;
            v.extreme_bg_color = Color32::BLACK;
            v.faint_bg_color = rgb(18, 18, 18);
            v.override_text_color = Some(Color32::WHITE);
            v.widgets.noninteractive.bg_fill = rgb(14, 14, 14);
            v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.4, Color32::WHITE);
            v.widgets.inactive.bg_fill = rgb(32, 32, 32);
            v.widgets.inactive.weak_bg_fill = rgb(24, 24, 24);
            v.widgets.hovered.bg_fill = rgb(64, 64, 64);
            v.widgets.active.bg_fill = rgb(0, 120, 215);
            v.selection.bg_fill = rgb(0, 90, 180);
            v.selection.stroke = egui::Stroke::new(1.2, rgb(140, 200, 255));
            v.hyperlink_color = rgb(120, 200, 255);
            v
        }
        Theme::Solarized => {
            // Ethan Schoonover's Solarized Dark palette.
            let base03 = rgb(0, 43, 54);
            let base02 = rgb(7, 54, 66);
            let base01 = rgb(88, 110, 117);
            let base1 = rgb(147, 161, 161);
            let blue = rgb(38, 139, 210);
            let mut v = egui::Visuals::dark();
            v.panel_fill = base03;
            v.window_fill = base03;
            v.extreme_bg_color = rgb(0, 33, 43);
            v.faint_bg_color = base02;
            v.override_text_color = Some(base1);
            v.widgets.noninteractive.bg_fill = base02;
            v.widgets.inactive.bg_fill = base02;
            v.widgets.inactive.weak_bg_fill = base02;
            v.widgets.hovered.bg_fill = base01;
            v.widgets.active.bg_fill = blue;
            v.selection.bg_fill = base01;
            v.selection.stroke = egui::Stroke::new(1.0, blue);
            v.hyperlink_color = blue;
            v
        }
        Theme::Sepia => {
            // Warm, paper-like light theme.
            let ink = rgb(60, 46, 33);
            let mut v = egui::Visuals::light();
            v.panel_fill = rgb(244, 236, 216);
            v.window_fill = rgb(250, 244, 228);
            v.extreme_bg_color = rgb(252, 248, 236);
            v.faint_bg_color = rgb(240, 231, 210);
            v.override_text_color = Some(ink);
            v.widgets.noninteractive.bg_fill = rgb(243, 234, 213);
            v.widgets.inactive.bg_fill = rgb(236, 226, 203);
            v.widgets.inactive.weak_bg_fill = rgb(243, 234, 213);
            v.widgets.hovered.bg_fill = rgb(226, 212, 182);
            v.selection.bg_fill = rgb(214, 196, 158);
            v.selection.stroke = egui::Stroke::new(1.0, rgb(120, 90, 50));
            v
        }
    }
}

/// Path to the small non-secret GUI preferences file (theme choice) in the
/// per-user config directory. `None` if no config dir is available.
fn theme_pref_path() -> Option<std::path::PathBuf> {
    directories::ProjectDirs::from("dev", "passmgr", "pass-mgr").map(|d| d.config_dir().join("prefs.json"))
}

/// Hard cap on the preferences file size. It holds one short JSON object, so a
/// larger file is corrupt or hostile; bounding the read before allocating means a
/// huge or symlinked `prefs.json` can never stall or OOM the UI thread at startup
/// (mirrors the bounded reads in the storage layer).
const MAX_PREFS_SIZE: u64 = 64 * 1024;

/// Load the saved theme from the standard preferences path.
fn load_theme() -> Theme {
    theme_pref_path().map(|p| load_theme_from(&p)).unwrap_or_default()
}

/// Load the theme from a specific path. Best-effort and bounded: a missing file, a
/// **symlink**, an over-cap size, or any parse error all fall back to the default —
/// a UI preference must never block (or slow) startup.
fn load_theme_from(path: &std::path::Path) -> Theme {
    // `symlink_metadata` does not follow links, so a symlinked prefs file fails the
    // `is_file()` check; the size check rejects an oversized file BEFORE reading it.
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && m.len() <= MAX_PREFS_SIZE => {}
        _ => return Theme::default(),
    }
    // `let Ok(x) = expr else { return ... }` (let-else) takes the success value or
    // runs the diverging `else`, keeping the happy path unindented.
    let Ok(bytes) = std::fs::read(path) else { return Theme::default() };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return Theme::default() };
    value.get("theme").and_then(|t| t.as_str()).and_then(Theme::from_id).unwrap_or_default()
}

/// Persist the chosen theme to the standard preferences path.
fn save_theme(theme: Theme) {
    if let Some(path) = theme_pref_path() {
        save_theme_to(&path, theme);
    }
}

/// Persist the theme to a specific path. Best-effort: a write failure is ignored
/// (the theme is non-critical and trivially re-picked).
fn save_theme_to(path: &std::path::Path, theme: Theme) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let value = serde_json::json!({ "theme": theme.id() });
    if let Ok(bytes) = serde_json::to_vec_pretty(&value) {
        let _ = std::fs::write(path, bytes);
    }
}

// `enum` is a closed set of named alternatives (a tagged union). `#[derive(...)]`
// auto-generates trait implementations: `PartialEq`/`Eq` enable `==`/`!=`
// comparisons; `Clone` enables explicit `.clone()`; `Copy` makes the value
// trivially duplicated on assignment (so passing it around does not "move" it).
#[derive(PartialEq, Eq, Clone, Copy)]
enum Screen {
    Auth,
    Main,
    Config,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum AuthMode {
    Create,
    Unlock,
    ChangePassword,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Instructions,
    TrustWill,
    Assets,
    Accounts,
    RealEstate,
    Taxes,
    GeneralDocuments,
}

/// Deferred form action gathered during rendering, applied afterwards.
#[derive(PartialEq, Eq, Clone, Copy)]
enum FormAction {
    None,
    Save,
    Delete,
}

/// Deferred document action gathered during rendering.
#[derive(PartialEq, Eq, Clone, Copy)]
enum DocReq {
    None,
    Attach,
    Export,
    Remove,
}

/// Deferred Taxes-tab document action gathered during rendering. `Export`/`Remove`
/// carry the index of the document within the filing's `documents` list.
#[derive(PartialEq, Eq, Clone, Copy)]
enum TaxDocReq {
    None,
    Upload,
    Export(usize),
    Remove(usize),
}

/// Deferred Real-Estate document action. `Export`/`Remove` carry the index into
/// the property's `documents` list.
#[derive(PartialEq, Eq, Clone, Copy)]
enum ReDocReq {
    None,
    Upload,
    Export(usize),
    Remove(usize),
}

// `struct` is a record of named fields — the whole application state lives here.
// Field types tell you the shape of each piece: `String` (owned text),
// `bool` (flag), `Option<T>` (maybe present). egui calls our `ui()` method each
// frame with `&mut GuiApp`, so every field is freely readable/writable there.
struct GuiApp {
    path: std::path::PathBuf,
    /// When false the vault is opened read-only and write controls are hidden.
    writable: bool,
    screen: Screen,
    // Auth.
    auth_mode: AuthMode,
    pw1: String,
    confirm1: String,
    pw2: String,
    confirm2: String,
    auth_error: Option<String>,
    // Unlocked vault. `Option<OpenVault>` is `None` until the user authenticates,
    // then `Some(vault)`; this is how Rust models "may or may not be present"
    // without null pointers.
    vault: Option<OpenVault>,
    // Tabs + per-tab working edit buffer. Each `edit_*` is the record currently
    // being edited on that tab, or `None` when nothing is selected.
    tab: Tab,
    edit_instruction: Option<Instruction>,
    edit_trustwill: Option<TrustWill>,
    edit_asset: Option<AssetLiability>,
    edit_account: Option<Account>,
    edit_realestate: Option<RealEstate>,
    edit_taxfiling: Option<TaxFiling>,
    edit_general: Option<GeneralDocument>,
    reveal_pw: bool,
    // Global "reveal" toggle on the Accounts screen: when on, account passwords are
    // shown regardless of the per-record `reveal_pw` (it overrides it).
    reveal_all: bool,
    // The same idea for the Real Estate screen's three portal passwords: a top-level
    // toggle that overrides the per-record "Reveal portal passwords" (`reveal_pw`).
    // Kept separate from `reveal_all` so the two screens don't reveal each other.
    re_reveal_all: bool,
    // Accounts-tab display filters ("" = no filter).
    acct_filter_type: String,
    acct_filter_subtype: String,
    acct_filter_owner: String,
    acct_filter_title: String,
    acct_filter_review: bool,
    // Free-text, case-insensitive substring search over account usernames.
    acct_search_user: String,
    // Accounts view: false = flat filtered list, true = grouped tree
    // (type → subtype → owner → title).
    acct_grouped: bool,
    // Assets-tab "review only" filter.
    asset_filter_review: bool,
    // Config screen inputs.
    new_asset_type: String,
    new_account_type: String,
    new_subtype_for: String,
    new_subtype_name: String,
    backup_dest: String,
    // Volume-size config input (whole MiB).
    cfg_volume_size: String,
    /// The redundancy-depth picker's selection (persistent across frames — egui's
    /// ComboBox closure only runs while the popup is open, so a frame-local would
    /// reset before Apply and the control would be dead). Re-seeded from the vault
    /// each time the Config screen is opened.
    cfg_redundancy: u32,
    // Shared document-attach input buffers. The storage location is auto-derived
    // (<root>/<auto-group>/<timestamp>/[subfolder]); the user controls only the
    // optional subfolder and the filename.
    doc_subfolder: String,
    doc_filename: String,
    doc_source: String,
    doc_dest: String,
    status: String,
    clipboard_dirty: bool,
    // When set, the clipboard should be wiped at/after this instant.
    // `Option<Instant>`: `None` = no pending wipe, `Some(t)` = wipe at time `t`.
    clipboard_clear_at: Option<Instant>,
    /// The selected color theme, and the one currently applied to egui — so we
    /// only call `set_visuals` (and persist) when the selection actually changes.
    theme: Theme,
    applied_theme: Theme,
}

/// How long a copied password stays on the clipboard before it is auto-cleared.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(15);

// `impl Trait for Type` provides a trait's methods for a type (like implementing
// an interface). `Drop` runs `drop()` automatically when a `GuiApp` goes out of
// scope (e.g. on quit) — used here to wipe the in-memory password buffers and
// clear the OS clipboard so secrets do not linger after exit.
impl Drop for GuiApp {
    // `&mut self` is an exclusive borrow of the value being dropped, so we can
    // overwrite its fields. `.zeroize()` overwrites the heap bytes with zeros.
    fn drop(&mut self) {
        self.pw1.zeroize();
        self.confirm1.zeroize();
        self.pw2.zeroize();
        self.confirm2.zeroize();
        if self.clipboard_dirty {
            clear_clipboard();
        }
    }
}

// Inherent methods of `GuiApp` (its own functions, not from a trait). `Self`
// inside this block is shorthand for the type `GuiApp`.
impl GuiApp {
    // A constructor by convention; `-> Self` returns a new `GuiApp`. There is no
    // `new` keyword in Rust — this is just a regular function.
    fn new(path: std::path::PathBuf, writable: bool) -> Self {
        // `if ... { } else { }` is an expression here: its value initializes
        // `auth_mode` (unlock an existing vault file, else offer to create one).
        let auth_mode = if path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        // Load the saved theme; `applied_theme` starts equal to it so the first
        // frame doesn't needlessly re-apply/re-save (the same value `run` already set).
        let theme = load_theme();
        GuiApp {
            path,
            writable,
            screen: Screen::Auth,
            auth_mode,
            // Pre-reserve generous capacity so typing a password never grows (and so
            // reallocates) these buffers, which would strand un-zeroized fragments of
            // the master password in freed heap. `wipe_passwords`/`Drop` wipe the live
            // buffer; pre-sizing removes the reallocation leak in between.
            pw1: String::with_capacity(256),
            confirm1: String::with_capacity(256),
            pw2: String::with_capacity(256),
            confirm2: String::with_capacity(256),
            auth_error: None,
            vault: None,
            tab: Tab::Instructions,
            edit_instruction: None,
            edit_trustwill: None,
            edit_asset: None,
            edit_account: None,
            edit_realestate: None,
            edit_taxfiling: None,
            edit_general: None,
            reveal_pw: false,
            reveal_all: false,
            re_reveal_all: false,
            acct_filter_type: String::new(),
            acct_filter_subtype: String::new(),
            acct_filter_owner: String::new(),
            acct_filter_title: String::new(),
            acct_filter_review: false,
            acct_search_user: String::new(),
            acct_grouped: false,
            asset_filter_review: false,
            new_asset_type: String::new(),
            new_account_type: String::new(),
            new_subtype_for: String::new(),
            new_subtype_name: String::new(),
            backup_dest: String::new(),
            cfg_volume_size: String::new(),
            cfg_redundancy: 0,
            doc_subfolder: String::new(),
            doc_filename: String::new(),
            doc_source: String::new(),
            doc_dest: String::new(),
            status: String::new(),
            clipboard_dirty: false,
            clipboard_clear_at: None,
            theme,
            applied_theme: theme,
        }
    }

    /// Wipe the clipboard once the auto-clear deadline has passed; otherwise
    /// schedule a repaint so the deadline fires even with no user interaction.
    fn tick_clipboard(&mut self, ctx: &egui::Context) {
        // `if let Some(x) = opt { ... }` runs the block only when `opt` is
        // `Some`, binding its inner value to `x`. Here: only act if a wipe
        // deadline has been scheduled. `&egui::Context` is a shared borrow.
        if let Some(deadline) = self.clipboard_clear_at {
            let now = Instant::now();
            if now >= deadline {
                clear_clipboard();
                self.clipboard_dirty = false;
                self.clipboard_clear_at = None;
                self.status = "Clipboard cleared.".into();
            } else {
                ctx.request_repaint_after(deadline - now);
            }
        }
    }

    // Returns a shared borrow (`&OpenVault`) of the open vault. `.as_ref()` turns
    // `&Option<T>` into `Option<&T>` (borrow without taking ownership);
    // `.expect("…")` then unwraps it, panicking with this message if `None` —
    // safe here because this is only called on the Main screen where the vault
    // is guaranteed open.
    fn vault_ref(&self) -> &OpenVault {
        self.vault.as_ref().expect("vault is open on the main screen")
    }

    /// Persist the in-memory vault, reporting any error to the status bar.
    /// Save the open vault. Returns `true` only if the vault was actually written
    /// to disk. Callers that reclaim a document blob AFTER persisting MUST gate the
    /// reclaim on this: if the save failed (e.g. a full disk), `vault.pmv` still
    /// references the doc, so dropping its blob would leave a dangling reference
    /// (`ArchiveMismatch` — an unopenable vault) on the next open.
    fn persist(&mut self) -> bool {
        // A "let-chain": both conditions must hold to enter the block. First
        // `.as_mut()` borrows the vault mutably if present (binding `ov`); then
        // `ov.save()` runs and we match its `Err(e)` case. `&&` short-circuits,
        // so save is only attempted when the vault exists.
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

    fn clear_doc_inputs(&mut self) {
        self.doc_subfolder.clear();
        self.doc_filename.clear();
        self.doc_source.clear();
        self.doc_dest.clear();
    }

    // --- Auth ----------------------------------------------------------------

    // Returns either `Ok((pw1, pw2))` (a 2-tuple of zeroizing strings) or
    // `Err(message)`. `&self` is a read-only borrow — this validates without
    // mutating. `.into()` converts the string literal `&str` into an owned
    // `String` to match the `Err` type.
    fn confirmed_passwords(&self) -> Result<(Zeroizing<String>, Zeroizing<String>), String> {
        if self.pw1.is_empty() || self.pw2.is_empty() {
            return Err("Both passwords are required.".into());
        }
        if self.pw1 != self.confirm1 || self.pw2 != self.confirm2 {
            return Err("Password confirmations do not match.".into());
        }
        // `.clone()` makes owned copies of the password strings; wrapping them in
        // `Zeroizing` means those copies are wiped from the heap when dropped.
        Ok((Zeroizing::new(self.pw1.clone()), Zeroizing::new(self.pw2.clone())))
    }

    fn submit_auth(&mut self) {
        // `match` dispatches on the value, like a switch but exhaustive: every
        // variant must be handled. Each `Variant => { ... }` is an arm.
        match self.auth_mode {
            AuthMode::ChangePassword => {
                // Destructure the success tuple into `pw1`/`pw2`; on `Err`, record
                // the message and `return` early from the whole method.
                let (pw1, pw2) = match self.confirmed_passwords() {
                    Ok(p) => p,
                    Err(m) => {
                        self.auth_error = Some(m);
                        return;
                    }
                };
                if let Some(ov) = self.vault.as_mut() {
                    // `.as_bytes()` views the string as a read-only byte slice
                    // (`&[u8]`), which the crypto layer expects.
                    match ov.change_password(pw1.as_bytes(), pw2.as_bytes()) {
                        Ok(()) => {
                            self.status = "Master passwords changed.".into();
                            self.auth_error = None;
                            self.wipe_passwords();
                            self.screen = Screen::Main;
                        }
                        Err(e) => {
                            // The rekey may have left the handle poisoned (read-only)
                            // with a pending `.rekey` on disk. Drop the handle to
                            // release the single-writer lock, then return to the
                            // unlock screen: reopening runs recover_pending_rekey,
                            // which finishes or discards the interrupted rekey
                            // idempotently. Without this the dead handle keeps the
                            // lock and the session can't recover in place.
                            self.vault = None;
                            self.auth_mode = AuthMode::Unlock;
                            self.screen = Screen::Auth;
                            self.wipe_passwords();
                            self.auth_error =
                                Some(format!("Password change interrupted: {e}. Unlock again to recover."));
                        }
                    }
                }
            }
            // `A | B =>` matches either variant with one arm.
            AuthMode::Create | AuthMode::Unlock => self.submit_open_or_create(),
        }
    }

    fn submit_open_or_create(&mut self) {
        let creating = self.auth_mode == AuthMode::Create;
        if creating && !self.writable {
            self.auth_error =
                Some("No vault here, and this is read-only. Relaunch with --write to create one.".into());
            return;
        }
        // `result` is assigned from an `if/else` expression: create a new vault
        // or open an existing one. `self.path.clone()` hands an owned copy of the
        // path to the call (the original stays in `self`).
        let result = if creating {
            let (pw1, pw2) = match self.confirmed_passwords() {
                Ok(p) => p,
                Err(m) => {
                    self.auth_error = Some(m);
                    return;
                }
            };
            OpenVault::create(self.path.clone(), pw1.as_bytes(), pw2.as_bytes(), KdfParams::default())
        } else {
            OpenVault::open_with(
                self.path.clone(),
                self.pw1.as_bytes(),
                self.pw2.as_bytes(),
                !self.writable,
            )
        };

        match result {
            Ok(v) => {
                // If the live vault.pmv was unreadable and we recovered from an
                // in-place redundant copy (§12.8), that notice takes priority — the
                // user needs to know a roll-forward/rollback happened.
                let recovered = v.recovery_notice().map(|s| s.to_string());
                self.status = if let Some(notice) = recovered {
                    notice
                } else if creating {
                    "New vault created.".to_string()
                } else if v.previous_access() == 0 {
                    "Vault unlocked.".to_string()
                } else {
                    // Show the write-generation so a rollback to an older snapshot
                    // is noticeable (§9.12).
                    format!(
                        "Unlocked. Last opened: {} (generation {})",
                        format_time(v.previous_access()),
                        v.opened_generation()
                    )
                };
                self.vault = Some(v);
                self.auth_error = None;
                self.wipe_passwords();
                self.screen = Screen::Main;
            }
            // Match a specific error variant; `(_)` ignores its inner payload so
            // the wrong-password case is reported generically (no detail leak).
            Err(VaultError::Crypto(_)) => {
                self.auth_error = Some("Wrong password(s) or corrupted vault.".into());
                // Wipe the entered passwords on failure too (not just on success), so
                // they don't linger in memory after a failed attempt — the moment a
                // user is most likely to step away. Mirrors the TUI, which rebuilds
                // (and thus zeroizes) its AuthState on a failed unlock.
                self.wipe_passwords();
            }
            // `Err(e)` catches every other error variant.
            Err(e) => {
                self.auth_error = Some(format!("{e}"));
                self.wipe_passwords();
            }
        }
    }

    fn wipe_passwords(&mut self) {
        self.pw1.zeroize();
        self.confirm1.zeroize();
        self.pw2.zeroize();
        self.confirm2.zeroize();
    }

    // `&mut egui::Ui` is the drawing surface, borrowed mutably so widgets can be
    // added to it. egui is immediate-mode: this method re-runs every frame.
    fn ui_auth(&mut self, ui: &mut egui::Ui) {
        // `match` used as an expression: it yields a `(heading, help)` pair which
        // we immediately destructure into two named bindings.
        let (heading, help) = match self.auth_mode {
            AuthMode::Create => ("Create vault", "Choose two passwords. Both are required to open this vault."),
            AuthMode::Unlock => ("Unlock vault", "Enter both passwords to unlock."),
            AuthMode::ChangePassword => ("Change master passwords", "Set two new passwords."),
        };
        let confirm = self.auth_mode != AuthMode::Unlock;

        ui.add_space(28.0);
        // `|ui| { ... }` is a closure (anonymous function). egui passes a child
        // `ui` into it so everything inside is laid out vertically and centered.
        ui.vertical_centered(|ui| {
            ui.heading(heading);
            ui.label(egui::RichText::new(format!("Vault: {}", self.path.display())).weak());
            ui.label(help);
        });
        ui.add_space(16.0);

        // Track whether the user requested submission; `|=` ORs in `true` if any
        // password field had Enter pressed (see `password_field`'s return value).
        let mut submit = false;
        egui::Grid::new("auth_grid").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
            ui.label("Password 1");
            // `&mut self.pw1` lends the field to the widget so typing updates it.
            submit |= password_field(ui, "auth_pw1", &mut self.pw1);
            ui.end_row();
            if confirm {
                ui.label("Confirm password 1");
                submit |= password_field(ui, "auth_confirm1", &mut self.confirm1);
                ui.end_row();
            }
            ui.label("Password 2");
            submit |= password_field(ui, "auth_pw2", &mut self.pw2);
            ui.end_row();
            if confirm {
                ui.label("Confirm password 2");
                submit |= password_field(ui, "auth_confirm2", &mut self.confirm2);
                ui.end_row();
            }
        });

        ui.add_space(8.0);
        // `&self.auth_error` borrows the Option so we can read the message
        // without moving it out; show it only when an error is present.
        if let Some(err) = &self.auth_error {
            ui.colored_label(egui::Color32::from_rgb(190, 50, 50), err);
            ui.add_space(4.0);
        }

        ui.horizontal(|ui| {
            let label = match self.auth_mode {
                AuthMode::Create => "Create vault",
                AuthMode::Unlock => "Unlock",
                AuthMode::ChangePassword => "Change passwords",
            };
            if ui.button(label).clicked() {
                submit = true;
            }
            if self.auth_mode == AuthMode::ChangePassword && ui.button("Cancel").clicked() {
                self.auth_error = None;
                self.wipe_passwords();
                self.screen = Screen::Main;
            }
        });

        if submit {
            self.submit_auth();
        }
    }

    // --- Main: top bar + active tab -----------------------------------------

    fn ui_top_bar(&mut self, ui: &mut egui::Ui) {
        // Remember the active tab so a tab switch can reset the password-reveal flag
        // below: `reveal_pw` is a single global toggle, so without this, revealing
        // an Account password then switching to Real Estate would immediately show
        // that property's portal passwords unmasked (the TUI scopes reveal per edit
        // buffer; this keeps the GUI from leaking more than the user asked for).
        let prev_tab = self.tab;
        // Horizontal scroll so the tab/action row stays fully reachable when the
        // window is narrower than the toolbar (otherwise the rightmost tabs would be
        // clipped and unselectable). No vertical scroll — the row is one line tall.
        egui::ScrollArea::horizontal().id_salt("topbar_scroll").show(ui, |ui| {
            ui.horizontal(|ui| {
                tab_button(ui, &mut self.tab, Tab::Instructions, "Instructions");
                tab_button(ui, &mut self.tab, Tab::TrustWill, "Trust and Will");
                tab_button(ui, &mut self.tab, Tab::Assets, "Assets and Liabilities");
                tab_button(ui, &mut self.tab, Tab::Accounts, "Accounts");
                tab_button(ui, &mut self.tab, Tab::RealEstate, "Real Estate");
                tab_button(ui, &mut self.tab, Tab::Taxes, "Taxes");
                tab_button(ui, &mut self.tab, Tab::GeneralDocuments, "General Documents");
                ui.separator();
                // Change-password is a write; only offer it when writable.
                // `&&` short-circuits: the button is only drawn/evaluated when
                // `self.writable` is true, so read-only mode hides it entirely.
                if self.writable
                    && ui.button("🔑 Passwords").clicked()
                {
                    self.auth_mode = AuthMode::ChangePassword;
                    self.auth_error = None;
                    self.wipe_passwords();
                    self.screen = Screen::Auth;
                }
                if ui.button("⚙ Config").clicked() {
                    // Seed the redundancy picker from the live setting each time Config
                    // opens, so the combo reflects the current value (and its selection
                    // survives across frames until Apply).
                    self.cfg_redundancy = self.vault_ref().redundancy();
                    self.screen = Screen::Config;
                }
                if ui.button("Quit").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                if !self.writable {
                    ui.separator();
                    ui.label(
                        egui::RichText::new("🔒 READ-ONLY")
                            .strong()
                            .color(egui::Color32::from_rgb(170, 90, 0)),
                    );
                }
            });
        });
        // Re-mask passwords when the user switches tabs (see prev_tab above).
        if self.tab != prev_tab {
            self.reveal_pw = false;
        }
    }

    // --- Config screen -------------------------------------------------------

    fn ui_config(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Configuration");
            if ui.button("⬅ Back").clicked() {
                self.screen = Screen::Main;
            }
        });
        ui.separator();
        // Show where this vault lives on disk (the vault.pmv path; its parent dir holds
        // the manifest/ and volume/ too).
        ui.horizontal(|ui| {
            ui.label("Vault location:");
            ui.label(egui::RichText::new(self.path.display().to_string()).strong());
        });
        if !self.writable {
            ui.label(
                egui::RichText::new(
                    "Read-only: no field can be edited. Only the color theme can be changed; \
                     backup and document export are still available.",
                )
                .color(egui::Color32::from_rgb(170, 90, 0)),
            );
        }

        // These `bool` flags are the deferred-action pattern: rendering only
        // *sets* them; the actual vault mutations happen after the closures below
        // return, so we never hold a render-time borrow of `self` and a write
        // borrow at the same time.
        let mut add_asset = false;
        let mut add_account = false;
        let mut add_subtype = false;
        let mut do_backup = false;
        let mut set_volume = false;
        let mut set_redundancy = false;
        // Deferred DELETE actions: which category the user clicked × on (handled after
        // the render closures, same borrow-discipline as the add_* flags).
        let mut remove_asset: Option<String> = None;
        let mut remove_account: Option<String> = None;
        let mut remove_subtype: Option<(String, String)> = None;
        // Snapshot the category lists + volume cap (from the open vault) before the
        // render closure borrows `self` mutably for the text inputs.
        let cur_volume_mib = self.vault_ref().volume_max_size() / (1024 * 1024);
        // The current on-disk depth, to skip a no-op Apply. The picker's selection
        // lives in the PERSISTENT `self.cfg_redundancy` (seeded when Config opened),
        // not a frame-local, so it survives until the user clicks Apply.
        let cur_redundancy = self.vault_ref().redundancy();
        let cats = self.vault_ref().categories();
        let type_names = cats.account_type_names();
        // Owned snapshots so the render closures don't hold a borrow of `self`/`cats`.
        let asset_names: Vec<String> = cats.asset.clone();
        // Each account type with its subtypes kept as a list (so each gets its own ×).
        let account_list: Vec<(String, Vec<String>)> =
            cats.account.iter().map(|t| (t.name.clone(), t.subtypes.clone())).collect();

        egui::ScrollArea::both().auto_shrink([false, false]).id_salt("config_scroll").show(ui, |ui| {
            // Appearance: a color-theme picker. Changing it applies live and is
            // saved to a small preferences file (it carries no vault data), so it
            // works in read-only mode too and persists to the next launch.
            ui.label(egui::RichText::new("Appearance").strong());
            egui::ComboBox::from_label("Color theme").selected_text(self.theme.label()).show_ui(ui, |ui| {
                for t in Theme::ALL {
                    ui.selectable_value(&mut self.theme, t, t.label());
                }
            });
            ui.add_space(14.0);

            ui.label(egui::RichText::new("Asset / Liability types").strong());
            // One chip per type with a delete (×) button. The × only deletes when the
            // type is unused by a live record (else a status message explains why).
            ui.horizontal_wrapped(|ui| {
                for name in &asset_names {
                    ui.label(egui::RichText::new(name).weak());
                    if self.writable
                        && ui.small_button("×").on_hover_text(format!("Delete “{name}” (only if unused)")).clicked()
                    {
                        remove_asset = Some(name.clone());
                    }
                    ui.add_space(8.0);
                }
            });
            ui.horizontal(|ui| {
                ui.add_enabled(
                    self.writable,
                    egui::TextEdit::singleline(&mut self.new_asset_type).hint_text("New type").desired_width(240.0),
                );
                if self.writable && ui.button("Add type").clicked() {
                    add_asset = true;
                }
            });

            ui.add_space(14.0);
            ui.label(egui::RichText::new("Account types & subtypes").strong());
            // Each type on its own row: a × to delete the type (blocked while it has
            // subtypes or is in use), then each subtype with its own × (blocked if used).
            for (name, subs) in &account_list {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new(name).strong());
                    if self.writable
                        && ui
                            .small_button("×")
                            .on_hover_text("Delete type (only if it has no subtypes and is unused)")
                            .clicked()
                    {
                        remove_account = Some(name.clone());
                    }
                    ui.label(":");
                    if subs.is_empty() {
                        ui.label(egui::RichText::new("—").weak());
                    }
                    for sub in subs {
                        ui.label(egui::RichText::new(sub).weak());
                        if self.writable
                            && ui.small_button("×").on_hover_text(format!("Delete subtype “{sub}” (only if unused)")).clicked()
                        {
                            remove_subtype = Some((name.clone(), sub.clone()));
                        }
                        ui.add_space(6.0);
                    }
                });
            }
            ui.horizontal(|ui| {
                ui.add_enabled(
                    self.writable,
                    egui::TextEdit::singleline(&mut self.new_account_type)
                        .hint_text("New account type")
                        .desired_width(220.0),
                );
                if self.writable && ui.button("Add type").clicked() {
                    add_account = true;
                }
            });
            ui.horizontal(|ui| {
                ui.label("Add subtype to:");
                // Pick the type the subtype belongs to.
                let cur = if self.new_subtype_for.is_empty() { "(choose type)".to_string() } else { self.new_subtype_for.clone() };
                ui.add_enabled_ui(self.writable, |ui| {
                    egui::ComboBox::from_id_salt("subtype_for").selected_text(cur).show_ui(ui, |ui| {
                        for name in &type_names {
                            ui.selectable_value(&mut self.new_subtype_for, name.clone(), name);
                        }
                    });
                });
                ui.add_enabled(
                    self.writable,
                    egui::TextEdit::singleline(&mut self.new_subtype_name).hint_text("New subtype").desired_width(180.0),
                );
                if self.writable && ui.button("Add subtype").clicked() {
                    add_subtype = true;
                }
            });

            ui.add_space(16.0);
            ui.separator();
            ui.label(egui::RichText::new("Backup").strong());
            ui.label(
                egui::RichText::new(
                    "Copies the encrypted vault and its document archive into a directory, \
                     timestamped to the second. Nothing is decrypted.",
                )
                .weak(),
            );
            ui.horizontal(|ui| {
                ui.label("Destination directory:");
                ui.add(egui::TextEdit::singleline(&mut self.backup_dest).hint_text("/path/to/backups").desired_width(340.0));
                if ui.button("Backup now").clicked() {
                    do_backup = true;
                }
            });

            if self.writable {
                ui.add_space(16.0);
                ui.separator();
                ui.label(egui::RichText::new("Storage — volume size").strong());
                ui.label(
                    egui::RichText::new(format!(
                        "New documents roll into a fresh volume once a partition passes this size. \
                         Current: {cur_volume_mib} MiB. Changing it affects only future placement."
                    ))
                    .weak(),
                );
                ui.horizontal(|ui| {
                    ui.label("New size (MiB):");
                    ui.add(egui::TextEdit::singleline(&mut self.cfg_volume_size).hint_text("e.g. 256").desired_width(140.0));
                    if ui.button("Set volume size").clicked() {
                        set_volume = true;
                    }
                });

                ui.add_space(16.0);
                ui.separator();
                ui.label(egui::RichText::new("Vault file redundancy (advanced)").strong());
                ui.label(
                    egui::RichText::new(
                        "Keeps extra encrypted copies of the small vault file so a damaged \
                         vault.pmv can be recovered in place: a same-generation mirror plus N \
                         prior generations (also an 'undo last save'). 0 = off. This does NOT \
                         replace off-device backups, and it leaves more old encrypted data on disk.",
                    )
                    .weak(),
                );
                ui.horizontal(|ui| {
                    ui.label("Copies to keep:");
                    egui::ComboBox::from_id_salt("redundancy")
                        .selected_text(if self.cfg_redundancy == 0 { "Off".to_string() } else { self.cfg_redundancy.to_string() })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.cfg_redundancy, 0, "Off");
                            for n in 1..=5u32 {
                                ui.selectable_value(&mut self.cfg_redundancy, n, n.to_string());
                            }
                        });
                    if ui.button("Apply").clicked() {
                        set_redundancy = true;
                    }
                });
            }
        });

        // Deferred actions (kept out of the closures to keep borrows simple).
        if add_asset {
            // `.trim()` returns a trimmed `&str`; `.to_string()` makes it owned.
            let name = self.new_asset_type.trim().to_string();
            // `.expect(...)` unwraps the open vault (safe on the config screen).
            // The call returns `Result<bool, _>`: `Ok(true)` = added,
            // `Ok(false)` = no-op (duplicate/empty), `Err` = save failure.
            match self.vault.as_mut().expect("vault open on config").add_asset_type(&name) {
                Ok(true) => {
                    self.status = format!("Added asset/liability type “{name}”.");
                    self.new_asset_type.clear();
                }
                Ok(false) => self.status = "Type is empty or already exists.".into(),
                Err(e) => self.status = format!("Save failed: {e}"),
            }
        }
        if add_account {
            let name = self.new_account_type.trim().to_string();
            match self.vault.as_mut().expect("vault open on config").add_account_type(&name) {
                Ok(true) => {
                    self.status = format!("Added account type “{name}”.");
                    self.new_account_type.clear();
                }
                Ok(false) => self.status = "Type is empty or already exists.".into(),
                Err(e) => self.status = format!("Save failed: {e}"),
            }
        }
        if add_subtype {
            let ty = self.new_subtype_for.clone();
            let sub = self.new_subtype_name.trim().to_string();
            if ty.is_empty() {
                self.status = "Choose an account type for the subtype.".into();
            } else {
                match self
                    .vault
                    .as_mut()
                    .expect("vault open on config")
                    .add_account_subtype(&ty, &sub)
                {
                    Ok(true) => {
                        self.status = format!("Added subtype “{sub}” under “{ty}”.");
                        self.new_subtype_name.clear();
                    }
                    Ok(false) => self.status = "Subtype is empty or already exists.".into(),
                    Err(e) => self.status = format!("Save failed: {e}"),
                }
            }
        }
        // Deferred DELETE handlers. A refusal (in use / has subtypes) is a normal
        // status message, not a failure; only a real save error reads as "failed".
        if let Some(name) = remove_asset {
            let outcome = self.vault.as_mut().expect("vault open on config").remove_asset_type(&name);
            self.status = match outcome {
                Ok(CategoryRemoval::Removed) => format!("Deleted asset/liability type “{name}”."),
                Ok(CategoryRemoval::InUse(n)) => format!("Can’t delete “{name}”: still used by {n} record(s)."),
                Ok(CategoryRemoval::NotFound) => format!("“{name}” was not found."),
                Ok(CategoryRemoval::HasSubtypes) => unreachable!("asset types have no subtypes"),
                Err(e) => format!("Delete failed: {e}"),
            };
        }
        if let Some(name) = remove_account {
            let outcome = self.vault.as_mut().expect("vault open on config").remove_account_type(&name);
            self.status = match outcome {
                Ok(CategoryRemoval::Removed) => format!("Deleted account type “{name}”."),
                Ok(CategoryRemoval::HasSubtypes) => format!("Can’t delete “{name}”: delete its subtypes first."),
                Ok(CategoryRemoval::InUse(n)) => format!("Can’t delete “{name}”: still used by {n} account(s)."),
                Ok(CategoryRemoval::NotFound) => format!("“{name}” was not found."),
                Err(e) => format!("Delete failed: {e}"),
            };
        }
        if let Some((ty, sub)) = remove_subtype {
            let outcome = self.vault.as_mut().expect("vault open on config").remove_account_subtype(&ty, &sub);
            self.status = match outcome {
                Ok(CategoryRemoval::Removed) => format!("Deleted subtype “{sub}” under “{ty}”."),
                Ok(CategoryRemoval::InUse(n)) => format!("Can’t delete “{sub}”: still used by {n} account(s)."),
                Ok(CategoryRemoval::NotFound) => format!("“{sub}” was not found under “{ty}”."),
                Ok(CategoryRemoval::HasSubtypes) => unreachable!("a subtype has no subtypes"),
                Err(e) => format!("Delete failed: {e}"),
            };
        }
        if do_backup {
            let dest = self.backup_dest.trim().to_string();
            if dest.is_empty() {
                self.status = "Enter a backup destination directory.".into();
            } else if let Some(ov) = self.vault.as_ref() {
                // Use the OPEN handle's backup (reuses this session's write lock).
                // Calling the free `vault::backup` here would self-deadlock: it tries
                // to re-acquire the per-fd flock this session already holds → Locked.
                match ov.backup(Path::new(&dest)) {
                    Ok(p) => self.status = format!("Backed up to {}", p.display()),
                    Err(e) => self.status = format!("Backup failed: {e}"),
                }
            }
        }
        if set_volume {
            // `.parse::<u64>()` parses text into an unsigned 64-bit integer,
            // returning a `Result` (`Err` if the text is not a number).
            match self.cfg_volume_size.trim().parse::<u64>() {
                // A "match guard": this arm matches `Ok(mib)` only if `mib >= 1`.
                Ok(mib) if mib >= 1 => {
                    // `.saturating_mul` multiplies but clamps at the max instead
                    // of overflowing/panicking.
                    let bytes = mib.saturating_mul(1024 * 1024);
                    match self.vault.as_mut().expect("vault open on config").set_volume_max_size(bytes) {
                        Ok(()) => {
                            self.status = format!("Volume size set to {mib} MiB (applies to future documents).");
                            self.cfg_volume_size.clear();
                        }
                        Err(e) => self.status = format!("Save failed: {e}"),
                    }
                }
                // `_` is the catch-all arm: any other case (parse error, or 0).
                _ => self.status = "Enter a whole number of MiB (at least 1).".into(),
            }
        }
        if set_redundancy && self.cfg_redundancy != cur_redundancy {
            let choice = self.cfg_redundancy;
            match self.vault.as_mut().expect("vault open on config").set_redundancy(choice) {
                Ok(()) => {
                    self.status = if choice == 0 {
                        "Vault file redundancy turned off (extra copies removed).".into()
                    } else {
                        format!("Vault file redundancy set to {choice} (mirror + {choice} prior generation(s)).")
                    };
                }
                Err(e) => self.status = format!("Save failed: {e}"),
            }
        }

        if !self.status.is_empty() {
            ui.separator();
            ui.label(egui::RichText::new(&self.status).weak());
        }
    }

    // --- Tab: Instructions ---------------------------------------------------

    fn tab_instructions(&mut self, ui: &mut egui::Ui) {
        // Build the left-hand list (id+label pairs) from the vault's records.
        let labels = label_list(&self.vault_ref().vault.instructions);
        // `cur` = id of the record being edited, if any. `.as_ref()` borrows the
        // Option's contents; `.map(|r| r.id.clone())` runs the closure only when
        // `Some`, producing `Option<String>` (an owned copy of the id).
        let cur = self.edit_instruction.as_ref().map(|r| r.id.clone());
        // Deferred-action flags (filled during rendering, acted on afterwards).
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;

        // `ui.columns(2, |c| ...)`: `c` is a slice of two child UIs (left/right).
        ui.columns(2, |c| {
            // Destructuring assignment into the outer `new`/`select` vars.
            // `cur.as_deref()` turns `Option<String>` into `Option<&str>` (a
            // borrowed view) without consuming `cur`.
            (new, select) = list_panel(&mut c[0], "Instructions", "➕ New", &labels, cur.as_deref(), self.writable);
            // Shadow `ui` with a mutable borrow of the right column. "Shadowing"
            // reuses the name `ui` for a new binding within this block.
            let ui = &mut c[1];
            // `.as_mut()` borrows the edited record mutably so the form widgets
            // below can write directly into its fields.
            if let Some(r) = self.edit_instruction.as_mut() {
                egui::Grid::new("instr_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Title");
                    ui.add_enabled(self.writable, egui::TextEdit::singleline(&mut r.title).desired_width(420.0));
                    ui.end_row();
                });
                ui.label("Description");
                ui.add_enabled(
                    self.writable,
                    egui::TextEdit::multiline(&mut r.description).desired_rows(12).desired_width(f32::INFINITY),
                );
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                ui.label("Select an instruction or click “New”.");
            }
        });

        // Now apply the deferred actions outside the render closure.
        if new {
            // `Instruction::new()` returns a `Result`; `.ok()` discards any error
            // and yields `Option<Instruction>` (Some on success, None on error).
            self.edit_instruction = Instruction::new().ok();
        }
        if let Some(i) = select {
            // `.get(i)` returns `Option<&Instruction>` (None if out of range);
            // `.cloned()` turns that into an owned `Option<Instruction>`.
            self.edit_instruction = self.vault_ref().vault.instructions.get(i).cloned();
        }
        match action {
            FormAction::Save => {
                // Let-chain: take an owned clone of the edited record AND a mutable
                // borrow of the vault, then upsert (insert-or-update) into it.
                if let Some(r) = self.edit_instruction.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.instructions, r);
                }
                if self.persist() {
                    self.status = "Saved.".into();
                }
                // On failure persist() has already set the "Save failed: …" status.
            }
            FormAction::Delete => self.delete_current(Tab::Instructions),
            // `_ => {}` handles the remaining `FormAction::None` with a no-op.
            _ => {}
        }
    }

    // --- Tab: Trust and Will -------------------------------------------------

    fn tab_trustwill(&mut self, ui: &mut egui::Ui) {
        let labels = label_list(&self.vault_ref().vault.trust_wills);
        let cur = self.edit_trustwill.as_ref().map(|r| r.id.clone());
        // `.and_then(|r| r.file.clone())` chains two Options: only if a record is
        // being edited AND it has an attached `file` do we get `Some(id)`. (Using
        // `.map` here would give a nested `Option<Option<…>>`; `and_then`
        // flattens it.)
        let attached: Vec<String> =
            self.attached_label(self.edit_trustwill.as_ref().and_then(|r| r.file.clone())).into_iter().collect();
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut docreq = DocReq::None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Trust and Will", "➕ New", &labels, cur.as_deref(), self.writable);
            let ui = &mut c[1];
            if let Some(r) = self.edit_trustwill.as_mut() {
                egui::Grid::new("tw_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Document");
                    ui.add_enabled(self.writable, egui::TextEdit::singleline(&mut r.document).desired_width(420.0));
                    ui.end_row();
                });
                ui.label("Usage");
                ui.add_enabled(
                    self.writable,
                    egui::TextEdit::multiline(&mut r.usage).desired_rows(8).desired_width(f32::INFINITY),
                );
                ui.separator();
                docreq = doc_section(
                    ui,
                    &attached,
                    &mut self.doc_subfolder,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    &mut self.doc_dest,
                    self.writable,
                )
                .to_single();
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                ui.label("Select a document or click “New”.");
            }
        });

        if new {
            self.edit_trustwill = TrustWill::new().ok();
            self.clear_doc_inputs();
        }
        if let Some(i) = select {
            self.edit_trustwill = self.vault_ref().vault.trust_wills.get(i).cloned();
            self.clear_doc_inputs();
        }
        self.handle_doc(docreq, DocTarget::TrustWill);
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_trustwill.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.trust_wills, r);
                }
                if self.persist() {
                    self.status = "Saved.".into();
                }
                // On failure persist() has already set the "Save failed: …" status.
            }
            FormAction::Delete => self.delete_current(Tab::TrustWill),
            _ => {}
        }
    }

    // --- Tab: General Documents ----------------------------------------------

    fn tab_general(&mut self, ui: &mut egui::Ui) {
        let labels = label_list(&self.vault_ref().vault.general_documents);
        let cur = self.edit_general.as_ref().map(|r| r.id.clone());
        let attached: Vec<String> =
            self.attached_label(self.edit_general.as_ref().and_then(|r| r.file.clone())).into_iter().collect();
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut docreq = DocReq::None;

        ui.columns(2, |c| {
            (new, select) =
                list_panel(&mut c[0], "General Documents", "➕ New", &labels, cur.as_deref(), self.writable);
            let ui = &mut c[1];
            if let Some(r) = self.edit_general.as_mut() {
                egui::Grid::new("gen_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Title");
                    ui.add_enabled(self.writable, egui::TextEdit::singleline(&mut r.title).desired_width(420.0));
                    ui.end_row();
                });
                ui.label("Description");
                ui.add_enabled(
                    self.writable,
                    egui::TextEdit::multiline(&mut r.description).desired_rows(8).desired_width(f32::INFINITY),
                );
                ui.separator();
                docreq = doc_section(
                    ui,
                    &attached,
                    &mut self.doc_subfolder,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    &mut self.doc_dest,
                    self.writable,
                )
                .to_single();
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                ui.label("Select a document or click “New”.");
            }
        });

        if new {
            self.edit_general = GeneralDocument::new().ok();
            self.clear_doc_inputs();
        }
        if let Some(i) = select {
            self.edit_general = self.vault_ref().vault.general_documents.get(i).cloned();
            self.clear_doc_inputs();
        }
        self.handle_doc(docreq, DocTarget::General);
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_general.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.general_documents, r);
                }
                if self.persist() {
                    self.status = "Saved.".into();
                }
            }
            FormAction::Delete => self.delete_current(Tab::GeneralDocuments),
            _ => {}
        }
    }

    // --- Tab: Assets and Liabilities ----------------------------------------

    fn tab_assets(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.asset_filter_review, "Show only items flagged for review");
        });
        let fr = self.asset_filter_review;
        // Iterator pipeline: walk assets by reference, keep only those passing the
        // filter closure (`!fr` = filter off, or the item is flagged), turn each
        // into an `(id, label)` tuple, and collect into a `Vec`.
        let labels: Vec<(String, String)> = self
            .vault_ref()
            .vault
            .assets
            .iter()
            .filter(|a| !fr || a.review)
            .map(|a| (a.id.clone(), a.label()))
            .collect();
        let cur = self.edit_asset.as_ref().map(|r| r.id.clone());
        let attached: Vec<String> =
            self.attached_label(self.edit_asset.as_ref().and_then(|r| r.statement.clone())).into_iter().collect();
        let asset_types = self.vault_ref().categories().asset.clone();
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut docreq = DocReq::None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Assets and Liabilities", "➕ New", &labels, cur.as_deref(), self.writable);
            let ui = &mut c[1];
            if let Some(r) = self.edit_asset.as_mut() {
                let w = self.writable;
                egui::Grid::new("asset_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Asset / Liability");
                    combo(ui, "asset_kind", &mut r.kind, &["Asset".to_string(), "Liability".to_string()], w);
                    ui.end_row();
                    ui.label("Owner");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.owner).desired_width(420.0));
                    ui.end_row();
                    ui.label("Beneficiary");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.beneficiary).desired_width(420.0));
                    ui.end_row();
                    ui.label("Approximate value");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.approx_value).desired_width(420.0));
                    ui.end_row();
                    ui.label("As-of date");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.as_of_date).hint_text("YYYY-MM-DD").desired_width(420.0));
                    ui.end_row();
                    ui.label("Institution");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.institution).desired_width(420.0));
                    ui.end_row();
                    ui.label("Type");
                    combo(ui, "asset_type", &mut r.asset_type, &asset_types, w);
                    ui.end_row();
                    ui.label("URL");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.url).desired_width(420.0));
                    ui.end_row();
                    ui.label("Review");
                    ui.add_enabled(w, egui::Checkbox::new(&mut r.review, "flag for review"));
                    ui.end_row();
                });
                ui.label("Description");
                ui.add_enabled(
                    self.writable,
                    egui::TextEdit::multiline(&mut r.description).desired_rows(4).desired_width(f32::INFINITY),
                );
                ui.separator();
                docreq = doc_section(
                    ui,
                    &attached,
                    &mut self.doc_subfolder,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    &mut self.doc_dest,
                    self.writable,
                )
                .to_single();
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                ui.label("Select an asset/liability or click “New”.");
            }
        });

        if new {
            self.edit_asset = AssetLiability::new().ok();
            self.clear_doc_inputs();
        }
        if let Some(i) = select
            && let Some((id, _)) = labels.get(i)
        {
            // Resolve by id (the list may be filtered by the review flag). The
            // `(id, _)` pattern keeps the id and ignores the label. `.find(|a|
            // ...)` returns the first matching element (`&a.id == id` compares the
            // borrowed ids); `.cloned()` makes an owned copy for the edit buffer.
            self.edit_asset = self.vault_ref().vault.assets.iter().find(|a| &a.id == id).cloned();
            self.clear_doc_inputs();
        }
        self.handle_doc(docreq, DocTarget::Asset);
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_asset.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.assets, r);
                }
                if self.persist() {
                    self.status = "Saved.".into();
                }
                // On failure persist() has already set the "Save failed: …" status.
            }
            FormAction::Delete => self.delete_current(Tab::Assets),
            _ => {}
        }
    }

    // --- Tab: Accounts -------------------------------------------------------

    /// The Accounts that pass the current filters (type/subtype/owner/review) and
    /// the username search, as `(id, label)` pairs. Extracted from the render so it
    /// can be unit-tested; the search uses [`records::matches_search`].
    fn filtered_account_labels(&self) -> Vec<(String, String)> {
        self.vault_ref()
            .vault
            .accounts
            .iter()
            .filter(|a| self.account_passes_filters(a))
            .map(|a| (a.id.clone(), a.label()))
            .collect()
    }

    /// Whether an account passes the current Accounts filters (type/subtype/owner/
    /// title/review + the free-text search, which matches the username OR the title).
    /// Shared by the flat list and the grouped tree so both honour the same filters.
    fn account_passes_filters(&self, a: &Account) -> bool {
        (self.acct_filter_type.is_empty() || a.account_type == self.acct_filter_type)
            && (self.acct_filter_subtype.is_empty() || a.account_subtype == self.acct_filter_subtype)
            && (self.acct_filter_owner.is_empty() || a.owner == self.acct_filter_owner)
            && (self.acct_filter_title.is_empty() || a.title == self.acct_filter_title)
            && (!self.acct_filter_review || a.review)
            // Free-text search matches the username OR the title (empty query = all).
            && (records::matches_search(&a.username, &self.acct_search_user)
                || records::matches_search(&a.title, &self.acct_search_user))
    }

    /// Build a fresh Account for the "New" button, pre-populated from the active
    /// Accounts filters / username search so the entry starts in the bucket the user
    /// is viewing. The filter fields are "" when unset, leaving those fields blank.
    /// Nothing is persisted — this only seeds the edit buffer.
    fn new_account_from_filters(&self) -> Option<Account> {
        let mut a = Account::new().ok()?;
        a.title = self.acct_filter_title.clone();
        a.account_type = self.acct_filter_type.clone();
        a.account_subtype = self.acct_filter_subtype.clone();
        a.owner = self.acct_filter_owner.clone();
        a.username = self.acct_search_user.clone();
        Some(a)
    }

    /// After saving an account, move any ACTIVE field filter to the saved record's
    /// value so the entry stays visible in the filtered list (changing a filtered
    /// field follows the entry rather than hiding it). Unset filters stay unset.
    fn sync_account_filters_to(&mut self, a: &Account) {
        if !self.acct_filter_type.is_empty() {
            self.acct_filter_type = a.account_type.clone();
        }
        if !self.acct_filter_subtype.is_empty() {
            self.acct_filter_subtype = a.account_subtype.clone();
        }
        if !self.acct_filter_owner.is_empty() {
            self.acct_filter_owner = a.owner.clone();
        }
        if !self.acct_filter_title.is_empty() {
            self.acct_filter_title = a.title.clone();
        }
        // Also relax the NON-facet constraints, or the just-saved record can still
        // vanish: clear the review-only filter if the saved record isn't flagged, and
        // clear the username search if it no longer matches the saved username.
        if self.acct_filter_review && !a.review {
            self.acct_filter_review = false;
        }
        if !self.acct_search_user.is_empty() && !records::matches_search(&a.username, &self.acct_search_user) {
            self.acct_search_user.clear();
        }
    }

    /// One-off maintenance: left/right-trim every field on every account, persist,
    /// and report the count. Each change is recorded in that account's history.
    /// Returns the number of accounts changed.
    fn trim_all_accounts(&mut self) -> usize {
        let n = match self.vault.as_mut() {
            Some(ov) => records::trim_all_accounts(&mut ov.vault.accounts),
            None => return 0,
        };
        if n == 0 {
            self.status = "Nothing to trim — all account fields are already clean.".into();
        } else if self.persist() {
            self.status = format!("Trimmed {n} account(s).");
        }
        n
    }

    fn tab_accounts(&mut self, ui: &mut egui::Ui) {
        // Configured account types for the EDIT form's type dropdown (offers every
        // configured type, not just the ones currently in use).
        let type_names = self.vault_ref().categories().account_type_names();
        // Cross-filtered (faceted) options: each dropdown offers only values present
        // on accounts matching ALL the OTHER active filters. Recompute to a fixpoint,
        // auto-clearing any selection that is no longer one of its narrowed options
        // (so a stale pick never leaves the list silently empty).
        let facets = loop {
            let f = records::account_facets(
                &self.vault_ref().vault.accounts,
                &self.acct_filter_type,
                &self.acct_filter_subtype,
                &self.acct_filter_owner,
                &self.acct_filter_title,
                &self.acct_search_user,
                self.acct_filter_review,
            );
            let mut changed = false;
            if !self.acct_filter_type.is_empty() && !f.types.contains(&self.acct_filter_type) {
                self.acct_filter_type.clear();
                changed = true;
            }
            if !self.acct_filter_subtype.is_empty() && !f.subtypes.contains(&self.acct_filter_subtype) {
                self.acct_filter_subtype.clear();
                changed = true;
            }
            if !self.acct_filter_owner.is_empty() && !f.owners.contains(&self.acct_filter_owner) {
                self.acct_filter_owner.clear();
                changed = true;
            }
            if !self.acct_filter_title.is_empty() && !f.titles.contains(&self.acct_filter_title) {
                self.acct_filter_title.clear();
                changed = true;
            }
            if !changed {
                break f;
            }
        };

        // Set inside the filter row's closure when the one-off trim button is clicked;
        // handled just after so the bulk vault mutation isn't tangled in the UI borrow.
        let mut trim_all = false;
        ui.horizontal_wrapped(|ui| {
            ui.label("Filter — type:");
            filter_combo(ui, "acct_ftype", &mut self.acct_filter_type, &facets.types);
            ui.label("subtype:");
            filter_combo(ui, "acct_fsub", &mut self.acct_filter_subtype, &facets.subtypes);
            ui.label("owner:");
            filter_combo(ui, "acct_fowner", &mut self.acct_filter_owner, &facets.owners);
            ui.label("title:");
            filter_combo(ui, "acct_ftitle", &mut self.acct_filter_title, &facets.titles);
            ui.checkbox(&mut self.acct_filter_review, "review only");
            // Global reveal: overrides the per-record "reveal" toggle below.
            ui.checkbox(&mut self.reveal_all, "reveal all");
            // Flat filtered list ⇄ grouped tree (type → subtype → owner → title).
            ui.checkbox(&mut self.acct_grouped, "grouped");
            ui.label("search:");
            ui.add(
                egui::TextEdit::singleline(&mut self.acct_search_user)
                    .hint_text("username or title…")
                    .desired_width(160.0),
            );
            if ui.button("Clear").clicked() {
                self.acct_filter_type.clear();
                self.acct_filter_subtype.clear();
                self.acct_filter_owner.clear();
                self.acct_filter_title.clear();
                self.acct_filter_review = false;
                self.acct_search_user.clear();
            }
            // One-off maintenance: left/right-trim every field on every account.
            if self.writable
                && ui
                    .button("Trim all fields")
                    .on_hover_text("One-off: left/right-trim every field on every account (recorded in history)")
                    .clicked()
            {
                trim_all = true;
            }
        });

        // Perform the one-off bulk trim (after the filter row, before the list is
        // built, so the cleaned values show this frame).
        if trim_all {
            self.trim_all_accounts();
        }

        // Filtered list (after the filter row, so a change applies this frame).
        let labels = self.filtered_account_labels();
        // In grouped mode, the same filtered accounts as a type→subtype→owner→title
        // tree (built here so the render closure doesn't re-borrow `self`).
        let tree = if self.acct_grouped {
            Some(records::account_tree(self.vault_ref().vault.accounts.iter().filter(|a| self.account_passes_filters(a))))
        } else {
            None
        };
        let cur = self.edit_account.as_ref().map(|r| r.id.clone());
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut generate = false;
        // Deferred password-copy: `None` unless the user clicks copy, in which
        // case it holds the secret in a self-wiping `Zeroizing<String>`.
        let mut copy_pw: Option<Zeroizing<String>> = None;
        // Subtypes for the record under edit, looked up from the vault's category
        // lists before the mutable borrow of `edit_account` below. The record's
        // current subtype is kept selectable even if it is a free-text value not
        // in the configured list (e.g. legacy/imported data).
        // `.map(|r| { ... last expr is the value })` builds the list when a record
        // is being edited; `.unwrap_or_default()` yields an empty `Vec` otherwise.
        let subtypes: Vec<String> = self
            .edit_account
            .as_ref()
            .map(|r| {
                let mut s = self.vault_ref().categories().subtypes_for(&r.account_type);
                if !r.account_subtype.is_empty() && !s.contains(&r.account_subtype) {
                    s.insert(0, r.account_subtype.clone());
                }
                s
            })
            .unwrap_or_default();

        // Recursive render of one grouped-tree node: child groups (each an
        // expandable CollapsingHeader) followed by this node's leaf accounts (shown
        // by title only). Returns the index into `labels` of a clicked leaf, if any.
        // `id_path` keeps egui's per-header id stable/unique across the tree.
        fn render_acct_node(
            ui: &mut egui::Ui,
            node: &records::AcctNode,
            id_path: &str,
            cur: Option<&str>,
            labels: &[(String, String)],
        ) -> Option<usize> {
            let mut select = None;
            for child in &node.children {
                let child_path = format!("{id_path}/{}", child.label);
                let resp = egui::CollapsingHeader::new(&child.label)
                    .id_salt(("acct_node", &child_path))
                    .show(ui, |ui| render_acct_node(ui, child, &child_path, cur, labels));
                if let Some(s) = resp.body_returned.flatten() {
                    select = Some(s);
                }
            }
            for leaf in &node.leaves {
                let sel = cur == Some(leaf.id.as_str());
                let title = if leaf.title.is_empty() { "(no title)".to_string() } else { leaf.title.clone() };
                if ui.selectable_label(sel, title).clicked() {
                    // `select` is an index into `labels` (the same filtered set as the
                    // tree), matching the flat-list model used by the form below.
                    select = labels.iter().position(|(id, _)| *id == leaf.id);
                }
            }
            select
        }

        ui.columns(2, |c| {
            match &tree {
                // Grouped tree: owner → type → subtype → title (leaf), with empty
                // levels skipped. egui's CollapsingHeader gives the +/- expand control.
                Some(root) => {
                    let lp = &mut c[0];
                    lp.horizontal(|ui| {
                        ui.heading("Accounts");
                        if self.writable && ui.button("➕ New").clicked() {
                            new = true;
                        }
                    });
                    egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("acct_tree").show(lp, |ui| {
                        if let Some(s) = render_acct_node(ui, root, "acct", cur.as_deref(), &labels) {
                            select = Some(s);
                        }
                    });
                }
                None => {
                    (new, select) = list_panel(&mut c[0], "Accounts", "➕ New", &labels, cur.as_deref(), self.writable);
                }
            }
            let ui = &mut c[1];
            if let Some(r) = self.edit_account.as_mut() {
                let w = self.writable;
                egui::Grid::new("acct_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    text_row(ui, "Title", &mut r.title, w);
                    ui.label("Account type");
                    let prev_type = r.account_type.clone();
                    combo(ui, "acct_type", &mut r.account_type, &type_names, w);
                    if r.account_type != prev_type {
                        // Subtypes are type-specific; drop a now-mismatched subtype.
                        r.account_subtype.clear();
                    }
                    ui.end_row();
                    ui.label("Subtype");
                    combo(ui, "acct_subtype", &mut r.account_subtype, &subtypes, w);
                    ui.end_row();
                    ui.label("Owner");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.owner).desired_width(420.0));
                    ui.end_row();
                    ui.label("Username");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.username).desired_width(420.0));
                    ui.end_row();
                    ui.label("Password");
                    ui.horizontal(|ui| {
                        // Masked unless the per-record reveal OR the global "reveal all" is on.
                        let revealed = self.reveal_pw || self.reveal_all;
                        // `secret_text_edit` (audit R-7 fix) scrubs egui's undo buffer of
                        // secret snapshots and re-routes the built-in copy through the
                        // history-excluded clipboard path — so a revealed field is no longer
                        // a residue/clipboard-history leak. Read-only: the field is shown but
                        // not editable; reveal + copy stay available (they are reads).
                        secret_text_edit(ui, "acct_pw", &mut r.password, revealed, w, 280.0);
                        ui.add_enabled(!self.reveal_all, egui::Checkbox::new(&mut self.reveal_pw, "reveal"));
                        // Generate is only useful when you can save; copy is a read.
                        if w && ui.button("🎲").on_hover_text("Generate").clicked() {
                            generate = true;
                        }
                        if ui.button("📋").on_hover_text("Copy").clicked() {
                            // Stash a self-wiping copy to act on after rendering.
                            copy_pw = Some(Zeroizing::new(r.password.clone()));
                        }
                    });
                    ui.end_row();
                    ui.label("URL");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.url).desired_width(420.0));
                    ui.end_row();
                    ui.label("Closed as of");
                    ui.add_enabled(w, egui::TextEdit::singleline(&mut r.closed_as_of).hint_text("YYYY-MM-DD").desired_width(420.0));
                    ui.end_row();
                    ui.label("Review");
                    ui.add_enabled(w, egui::Checkbox::new(&mut r.review, "flag for review"));
                    ui.end_row();
                });
                ui.label("Description");
                ui.add_enabled(
                    self.writable,
                    egui::TextEdit::multiline(&mut r.description).desired_rows(4).desired_width(f32::INFINITY),
                );
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                ui.label("Select an account or click “New”.");
            }
        });

        if new {
            self.edit_account = self.new_account_from_filters();
            self.reveal_pw = false;
        }
        if let Some(i) = select {
            // `labels` is the FILTERED list, so resolve the clicked row to its id
            // and look the account up by id (a positional index into the
            // unfiltered vector would select the wrong record when filtering).
            if let Some((id, _)) = labels.get(i) {
                self.edit_account =
                    self.vault_ref().vault.accounts.iter().find(|a| &a.id == id).cloned();
                self.reveal_pw = false;
            }
        }
        // Pre-size the password buffer so typing in the egui field doesn't reallocate
        // and strand un-zeroized fragments of the account secret in freed heap. The
        // Account record is ZeroizeOnDrop, but that only wipes the final buffer, not
        // the copies abandoned by per-keystroke growth. `reserve` is a no-op once the
        // capacity is sufficient, so this is cheap to call each frame.
        if let Some(r) = self.edit_account.as_mut() {
            r.password.reserve(128);
        }
        if generate
            && let Some(r) = self.edit_account.as_mut()
        {
            // Wipe the previous candidate's bytes before dropping it: a plain
            // `String` reassignment frees the old buffer WITHOUT zeroizing, leaving a
            // prior password in freed heap. `.unwrap_or_default()` yields the new
            // password on success or an empty string on the (unexpected) error case.
            r.password.zeroize();
            r.password = password::generate(&GenOptions::default()).unwrap_or_default();
            self.reveal_pw = true;
        }
        if let Some(pw) = copy_pw {
            // `pw` is moved into the call and wiped when it drops there.
            self.copy_to_clipboard(pw);
        }
        match action {
            FormAction::Save => {
                // Left/right-trim every field before persisting. Trim the live edit
                // form too, so the displayed values match what was saved.
                if let Some(r) = self.edit_account.as_mut() {
                    r.trim_fields();
                }
                // Title and owner are mandatory: refuse to save an account missing
                // either (after trimming), keeping the edit form open to fill it.
                if let Some(msg) = self.edit_account.as_ref().and_then(account_required_field_error) {
                    self.status = msg.into();
                } else {
                    if let Some(r) = self.edit_account.clone()
                        && let Some(ov) = self.vault.as_mut()
                    {
                        records::upsert(&mut ov.vault.accounts, r.clone());
                        // Keep the just-saved entry visible: move any ACTIVE filter to the
                        // saved record's value (so changing a filtered field doesn't make
                        // the entry vanish from the filtered list).
                        self.sync_account_filters_to(&r);
                    }
                    if self.persist() {
                        self.status = "Saved.".into();
                    }
                    // On failure persist() has already set the "Save failed: …" status.
                }
            }
            FormAction::Delete => self.delete_current(Tab::Accounts),
            _ => {}
        }
    }

    // --- Tab: Real Estate ----------------------------------------------------

    fn tab_realestate(&mut self, ui: &mut egui::Ui) {
        let labels = label_list(&self.vault_ref().vault.real_estate);
        let cur = self.edit_realestate.as_ref().map(|r| r.id.clone());
        // Pre-compute attached document labels (needs an immutable vault borrow).
        let doc_labels: Vec<String> = match self.edit_realestate.as_ref() {
            Some(r) => r
                .documents
                .iter()
                .map(|id| self.vault_ref().doc_path(id).unwrap_or_else(|| id.clone()))
                .collect(),
            None => Vec::new(),
        };
        // Top-level "reveal all" (mirrors the Accounts screen): when on, all three
        // portal passwords are shown, overriding the per-record "Reveal portal
        // passwords" toggle in the edit form below.
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.re_reveal_all, "reveal all portal passwords");
        });
        // Portal passwords are revealed when the per-record toggle OR the screen-level
        // "reveal all" is on (matching the Accounts `reveal_pw || reveal_all`).
        let reveal = self.reveal_pw || self.re_reveal_all;
        let writable = self.writable;
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut copy_pw: Option<Zeroizing<String>> = None;
        let mut docreq = ReDocReq::None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Real Estate", "➕ New", &labels, cur.as_deref(), writable);
            let ui = &mut c[1];
            if let Some(r) = self.edit_realestate.as_mut() {
                // No inner ScrollArea here: the whole tab is already wrapped in the
                // CentralPanel's both-axis scroll. A nested vertical scroll over this
                // form would capture the wheel and (having no overflow of its own)
                // scroll nothing, while the outer area never saw the event.
                egui::Grid::new("re_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    text_row(ui, "Address", &mut r.address, writable);
                    text_row(ui, "Ownership", &mut r.ownership, writable);
                    text_row(ui, "Taxes", &mut r.taxes, writable);
                    text_row(ui, "HOA dues / info", &mut r.hoa, writable);
                    text_row(ui, "Income account", &mut r.income_account, writable);
                    text_row(ui, "Financing account", &mut r.financing_account, writable);
                    text_row(ui, "Financing balance", &mut r.financing_balance, writable);
                    text_row(ui, "Payment account", &mut r.payment_account, writable);
                });

                portal_section(ui, "Property Management portal", &mut r.property_mgmt_url, &mut r.property_mgmt_username, &mut r.property_mgmt_password, reveal, writable, &mut copy_pw);
                portal_section(ui, "Insurance portal", &mut r.insurance_url, &mut r.insurance_username, &mut r.insurance_password, reveal, writable, &mut copy_pw);
                portal_section(ui, "HOA portal", &mut r.hoa_url, &mut r.hoa_username, &mut r.hoa_password, reveal, writable, &mut copy_pw);
                // Per-record reveal; disabled while the screen-level "reveal all" is
                // on (which already overrides it), exactly like the Accounts form.
                ui.add_enabled(!self.re_reveal_all, egui::Checkbox::new(&mut self.reveal_pw, "Reveal portal passwords"));

                ui.separator();
                ui.label("Comments");
                ui.add_enabled(
                    writable,
                    egui::TextEdit::multiline(&mut r.comments).desired_rows(3).desired_width(f32::INFINITY),
                );

                ui.separator();
                ui.label(format!(
                    "Documents ({}) — under {}/<timestamp>/[subfolder]/",
                    r.documents.len(),
                    records::real_estate_doc_location(&r.address)
                ));
                // Same uniform widget as Trust & Will (multi-document: the list
                // holds every attached doc); map its request to ReDocReq.
                docreq = match doc_section(
                    ui,
                    &doc_labels,
                    &mut self.doc_subfolder,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    &mut self.doc_dest,
                    writable,
                ) {
                    DocSectionReq::Upload => ReDocReq::Upload,
                    DocSectionReq::Export(i) => ReDocReq::Export(i),
                    DocSectionReq::Remove(i) => ReDocReq::Remove(i),
                    DocSectionReq::None => ReDocReq::None,
                };

                action = form_buttons(ui, writable);
                history_view(ui, &r.history);
            } else {
                ui.label("Select a property or click “New”.");
            }
        });

        if new {
            self.edit_realestate = RealEstate::new().ok();
            self.clear_doc_inputs();
            self.reveal_pw = false;
        }
        if let Some(i) = select {
            self.edit_realestate = self.vault_ref().vault.real_estate.get(i).cloned();
            self.clear_doc_inputs();
            self.reveal_pw = false;
        }
        // Pre-size the portal password buffers so per-keystroke typing never grows
        // (and so reallocates) them — a reallocation frees the old buffer WITHOUT
        // zeroizing, stranding cleartext fragments of a portal password in freed
        // heap. RealEstate is ZeroizeOnDrop, but that only wipes the final buffer,
        // not abandoned reallocations. Same mitigation as the Accounts password
        // field; `reserve` is a no-op once capacity is sufficient.
        if let Some(r) = self.edit_realestate.as_mut() {
            r.property_mgmt_password.reserve(128);
            r.insurance_password.reserve(128);
            r.hoa_password.reserve(128);
        }
        if let Some(pw) = copy_pw {
            self.copy_to_clipboard(pw);
        }
        self.handle_re_doc(docreq);
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_realestate.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.real_estate, r);
                }
                if self.persist() {
                    self.status = "Saved.".into();
                }
                // On failure persist() has already set the "Save failed: …" status.
            }
            FormAction::Delete => self.delete_current(Tab::RealEstate),
            _ => {}
        }
    }

    // --- Tab: Taxes ----------------------------------------------------------

    fn tab_taxes(&mut self, ui: &mut egui::Ui) {
        let labels = label_list(&self.vault_ref().vault.tax_filings);
        let cur = self.edit_taxfiling.as_ref().map(|r| r.id.clone());
        // Pre-compute each attached document's "location/filename" label (needs an
        // immutable borrow of the vault, so it can't happen inside the edit form).
        let doc_labels: Vec<String> = match self.edit_taxfiling.as_ref() {
            Some(r) => r
                .documents
                .iter()
                .map(|id| self.vault_ref().doc_path(id).unwrap_or_else(|| id.clone()))
                .collect(),
            None => Vec::new(),
        };
        let writable = self.writable;
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut docreq = TaxDocReq::None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Taxes", "➕ New", &labels, cur.as_deref(), writable);
            let ui = &mut c[1];
            if let Some(r) = self.edit_taxfiling.as_mut() {
                egui::Grid::new("tax_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    text_row(ui, "Filing year", &mut r.year, writable);
                });
                ui.label("Notes");
                ui.add_enabled(
                    writable,
                    egui::TextEdit::multiline(&mut r.notes).desired_rows(4).desired_width(f32::INFINITY),
                );
                ui.separator();

                // Attached documents — all live under taxes/<year>/<timestamp>/…
                ui.label(format!(
                    "Documents ({}) — under {}/<timestamp>/[subfolder]/",
                    r.documents.len(),
                    records::tax_doc_location(&r.year)
                ));
                // Same uniform widget as Trust & Will; map its request to TaxDocReq.
                docreq = match doc_section(
                    ui,
                    &doc_labels,
                    &mut self.doc_subfolder,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    &mut self.doc_dest,
                    writable,
                ) {
                    DocSectionReq::Upload => TaxDocReq::Upload,
                    DocSectionReq::Export(i) => TaxDocReq::Export(i),
                    DocSectionReq::Remove(i) => TaxDocReq::Remove(i),
                    DocSectionReq::None => TaxDocReq::None,
                };

                action = form_buttons(ui, writable);
                history_view(ui, &r.history);
            } else {
                ui.label("Select a tax year or click “New”.");
            }
        });

        if new {
            self.edit_taxfiling = TaxFiling::new().ok();
            self.clear_doc_inputs();
        }
        if let Some(i) = select {
            self.edit_taxfiling = self.vault_ref().vault.tax_filings.get(i).cloned();
            self.clear_doc_inputs();
        }
        self.handle_tax_doc(docreq);
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_taxfiling.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.tax_filings, r);
                }
                if self.persist() {
                    self.status = "Saved.".into();
                }
                // On failure persist() has already set the "Save failed: …" status.
            }
            FormAction::Delete => self.delete_current(Tab::Taxes),
            _ => {}
        }
    }

    // Performs a Real-Estate document action (upload to real-estate/<address>/,
    // export, or remove), mirroring handle_doc's persist-then-reclaim ordering.
    fn handle_re_doc(&mut self, req: ReDocReq) {
        match req {
            ReDocReq::None => {}
            ReDocReq::Upload => {
                let name = self.doc_filename.trim().to_string();
                let src = self.doc_source.trim().to_string();
                if name.is_empty() || src.is_empty() {
                    self.status = "Filename and 'upload from' path are required.".into();
                    return;
                }
                let address = self.edit_realestate.as_ref().map(|r| r.address.clone()).unwrap_or_default();
                let prefix = records::real_estate_doc_location(&address);
                let name = records::doc_filename(&name);
                let loc =
                    records::doc_upload_dir(&prefix, &records::compact_utc(records::unix_now()), &self.doc_subfolder);
                let vpath = vault::virtual_path(&loc, &name);
                if vpath.len() > crate::storage::MAX_PATH_LEN {
                    self.status = format!(
                        "Path too long: {} bytes (max {}). Shorten the filename.",
                        vpath.len(),
                        crate::storage::MAX_PATH_LEN
                    );
                    return;
                }
                let id = match self.vault.as_mut() {
                    Some(ov) => match ov.add_document(&loc, &name, Path::new(&src)) {
                        Ok(id) => id,
                        Err(e) => {
                            self.status = format!("Upload failed: {e}");
                            return;
                        }
                    },
                    None => return,
                };
                if let Some(r) = self.edit_realestate.as_mut() {
                    r.documents.push(id);
                }
                if let Some(r) = self.edit_realestate.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.real_estate, r);
                }
                self.clear_doc_inputs();
                if self.persist() {
                    self.status = "Document uploaded to the encrypted volume.".into();
                }
            }
            ReDocReq::Export(i) => {
                let dest = self.doc_dest.trim().to_string();
                if dest.is_empty() {
                    self.status = "Enter an 'export to' path first.".into();
                    return;
                }
                let id = self.edit_realestate.as_ref().and_then(|r| r.documents.get(i).cloned());
                if let (Some(id), Some(ov)) = (id, self.vault.as_ref()) {
                    match ov.export_document(&id, Path::new(&dest)) {
                        Ok(()) => self.status = format!("Exported to {dest}"),
                        Err(e) => self.status = format!("Export failed: {e}"),
                    }
                }
            }
            ReDocReq::Remove(i) => {
                let id = self.edit_realestate.as_ref().and_then(|r| r.documents.get(i).cloned());
                if let Some(r) = self.edit_realestate.as_mut()
                    && i < r.documents.len()
                {
                    r.documents.remove(i);
                }
                if let Some(r) = self.edit_realestate.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.real_estate, r);
                }
                if !self.persist() {
                    return;
                }
                if let Some(id) = id
                    && let Some(ov) = self.vault.as_mut()
                    && let Err(e) = ov.remove_document(&id)
                {
                    self.status = format!("Unlinked, but blob cleanup failed: {e}");
                    return;
                }
                self.status = "Removed document from the vault.".into();
            }
        }
    }

    // --- Shared deferred operations -----------------------------------------

    /// Human-readable "location/filename" of an attached volume file id.
    fn attached_label(&self, file_id: Option<String>) -> Option<String> {
        // `file_id?` is the `?` operator on an Option: if `None`, return `None`
        // from this function immediately; otherwise unwrap to `id` and continue.
        let id = file_id?;
        self.vault_ref().doc_path(&id)
    }

    /// Upsert the current edit buffer for a document-bearing tab into the vault,
    /// so a document link is persisted together with its manifest entry.
    fn upsert_doc_target(&mut self, target: DocTarget) {
        match target {
            DocTarget::TrustWill => {
                if let Some(r) = self.edit_trustwill.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.trust_wills, r);
                }
            }
            DocTarget::Asset => {
                if let Some(r) = self.edit_asset.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.assets, r);
                }
            }
            DocTarget::General => {
                if let Some(r) = self.edit_general.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.general_documents, r);
                }
            }
        }
    }

    // Performs the document attach/export/detach requested during rendering.
    // Split out so the vault is borrowed mutably *here*, not while drawing.
    fn handle_doc(&mut self, req: DocReq, target: DocTarget) {
        match req {
            DocReq::None => {}
            DocReq::Attach => {
                let (name, src) = (self.doc_filename.clone(), self.doc_source.clone());
                if name.trim().is_empty() || src.trim().is_empty() {
                    self.status = "Filename and 'upload from' path are required.".into();
                    return;
                }
                // The auto-group level comes from the record's identifying field; the
                // user controls only the subfolder and filename. Build the uniform
                // <root>/<auto-group>/<timestamp>[/<subfolder>] directory.
                let prefix = match target {
                    DocTarget::TrustWill => records::trust_will_doc_location(
                        self.edit_trustwill.as_ref().map(|r| r.document.as_str()).unwrap_or(""),
                    ),
                    DocTarget::Asset => records::asset_doc_location(
                        self.edit_asset.as_ref().map(|r| r.description.as_str()).unwrap_or(""),
                    ),
                    DocTarget::General => records::general_doc_location(
                        self.edit_general.as_ref().map(|r| r.title.as_str()).unwrap_or(""),
                    ),
                };
                let fname = records::doc_filename(&name);
                let loc =
                    records::doc_upload_dir(&prefix, &records::compact_utc(records::unix_now()), &self.doc_subfolder);
                let vpath = vault::virtual_path(&loc, &fname);
                if vpath.len() > crate::storage::MAX_PATH_LEN {
                    self.status = format!(
                        "Path too long: {} bytes (max {}). Shorten the filename or subfolder.",
                        vpath.len(),
                        crate::storage::MAX_PATH_LEN
                    );
                    return;
                }
                // Nested match: get the vault (mut), then attempt the upload. Each
                // branch either yields the new document `id` or returns early.
                let id = match self.vault.as_mut() {
                    Some(ov) => match ov.add_document(&loc, &fname, Path::new(&src)) {
                        Ok(id) => id,
                        Err(e) => {
                            self.status = format!("Upload failed: {e}");
                            return;
                        }
                    },
                    None => return,
                };
                // Capture any document this record already had, so re-attaching
                // reclaims the replaced blob instead of orphaning it (matches TUI).
                let previous = match target {
                    DocTarget::TrustWill => self.edit_trustwill.as_ref().and_then(|r| r.file.clone()),
                    DocTarget::Asset => self.edit_asset.as_ref().and_then(|r| r.statement.clone()),
                    DocTarget::General => self.edit_general.as_ref().and_then(|r| r.file.clone()),
                };
                match target {
                    DocTarget::TrustWill => {
                        if let Some(r) = self.edit_trustwill.as_mut() {
                            r.file = Some(id);
                        }
                    }
                    DocTarget::Asset => {
                        if let Some(r) = self.edit_asset.as_mut() {
                            r.statement = Some(id);
                        }
                    }
                    DocTarget::General => {
                        if let Some(r) = self.edit_general.as_mut() {
                            r.file = Some(id);
                        }
                    }
                }
                // Persist the record→document link immediately so the manifest
                // entry is referenced (no orphan if the user navigates away).
                self.upsert_doc_target(target);
                self.clear_doc_inputs();
                if self.persist() {
                    // Only reclaim the replaced blob once the new link actually reached
                    // disk. If the save failed, vault.pmv still references `old`, so
                    // dropping it would create a dangling reference (ArchiveMismatch).
                    if let Some(old) = previous
                        && let Some(ov) = self.vault.as_mut()
                    {
                        // `let _ = ...` deliberately discards the `Result`: a failure
                        // here only orphans a blob (harmless), so it is not reported.
                        let _ = ov.remove_document(&old);
                    }
                    self.status = "Document uploaded to the encrypted volume.".into();
                }
                // On failure persist() has already set the "Save failed: …" status.
            }
            DocReq::Export => {
                let file_id = match target {
                    DocTarget::TrustWill => self.edit_trustwill.as_ref().and_then(|r| r.file.clone()),
                    DocTarget::Asset => self.edit_asset.as_ref().and_then(|r| r.statement.clone()),
                    DocTarget::General => self.edit_general.as_ref().and_then(|r| r.file.clone()),
                };
                let dest = self.doc_dest.clone();
                if dest.trim().is_empty() {
                    self.status = "Enter an 'export to' path first.".into();
                    return;
                }
                // Tuple pattern: this block runs only if BOTH a file id exists
                // and the vault is open (both elements are `Some`).
                if let (Some(id), Some(ov)) = (file_id, self.vault.as_ref()) {
                    match ov.export_document(&id, Path::new(&dest)) {
                        Ok(()) => self.status = format!("Exported to {dest}"),
                        Err(e) => self.status = format!("Export failed: {e}"),
                    }
                }
            }
            DocReq::Remove => {
                // Unlink from the record AND reclaim the encrypted blob, so a
                // "removed" document does not linger in the archive.
                let id = match target {
                    DocTarget::TrustWill => self.edit_trustwill.as_ref().and_then(|r| r.file.clone()),
                    DocTarget::Asset => self.edit_asset.as_ref().and_then(|r| r.statement.clone()),
                    DocTarget::General => self.edit_general.as_ref().and_then(|r| r.file.clone()),
                };
                match target {
                    DocTarget::TrustWill => {
                        if let Some(r) = self.edit_trustwill.as_mut() {
                            r.file = None;
                        }
                    }
                    DocTarget::Asset => {
                        if let Some(r) = self.edit_asset.as_mut() {
                            r.statement = None;
                        }
                    }
                    DocTarget::General => {
                        if let Some(r) = self.edit_general.as_mut() {
                            r.file = None;
                        }
                    }
                }
                self.upsert_doc_target(target);
                // Persist the unlink BEFORE reclaiming the blob, AND only reclaim if
                // the save succeeded. A crash or a failed save between the two would
                // otherwise leave vault.pmv referencing a doc whose manifest entry is
                // gone (ArchiveMismatch -> unopenable). An orphaned blob is harmless.
                if !self.persist() {
                    return; // persist() already set the "Save failed" status
                }
                // Three-part let-chain: there is an id, the vault is open, and the
                // blob removal failed — only then report the cleanup error.
                if let Some(id) = id
                    && let Some(ov) = self.vault.as_mut()
                    && let Err(e) = ov.remove_document(&id)
                {
                    self.status = format!("Unlinked, but blob cleanup failed: {e}");
                    return;
                }
                self.status = "Removed document from the vault.".into();
            }
        }
    }

    // Performs a Taxes-tab document action (upload to taxes/<year>/, export, or
    // remove). Like `handle_doc`, the vault is borrowed mutably here, not while
    // drawing, and the persist-then-reclaim ordering keeps a crash from leaving a
    // dangling reference.
    fn handle_tax_doc(&mut self, req: TaxDocReq) {
        match req {
            TaxDocReq::None => {}
            TaxDocReq::Upload => {
                let name = self.doc_filename.trim().to_string();
                let src = self.doc_source.trim().to_string();
                if name.is_empty() || src.is_empty() {
                    self.status = "Filename and 'upload from' path are required.".into();
                    return;
                }
                // The folder is derived from the filing year, NOT user-entered.
                let year = self.edit_taxfiling.as_ref().map(|r| r.year.clone()).unwrap_or_default();
                let prefix = records::tax_doc_location(&year);
                let name = records::doc_filename(&name);
                let loc =
                    records::doc_upload_dir(&prefix, &records::compact_utc(records::unix_now()), &self.doc_subfolder);
                let vpath = vault::virtual_path(&loc, &name);
                if vpath.len() > crate::storage::MAX_PATH_LEN {
                    self.status = format!(
                        "Path too long: {} bytes (max {}). Shorten the filename.",
                        vpath.len(),
                        crate::storage::MAX_PATH_LEN
                    );
                    return;
                }
                let id = match self.vault.as_mut() {
                    Some(ov) => match ov.add_document(&loc, &name, Path::new(&src)) {
                        Ok(id) => id,
                        Err(e) => {
                            self.status = format!("Upload failed: {e}");
                            return;
                        }
                    },
                    None => return,
                };
                if let Some(r) = self.edit_taxfiling.as_mut() {
                    r.documents.push(id);
                }
                // Persist the record→document link immediately so the manifest entry
                // is referenced (no orphan if the user navigates away).
                if let Some(r) = self.edit_taxfiling.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.tax_filings, r);
                }
                self.clear_doc_inputs();
                if self.persist() {
                    self.status = "Document uploaded to the encrypted volume.".into();
                }
                // On failure persist() has already set the "Save failed: …" status.
            }
            TaxDocReq::Export(i) => {
                let dest = self.doc_dest.trim().to_string();
                if dest.is_empty() {
                    self.status = "Enter an 'export to' path first.".into();
                    return;
                }
                let id = self.edit_taxfiling.as_ref().and_then(|r| r.documents.get(i).cloned());
                if let (Some(id), Some(ov)) = (id, self.vault.as_ref()) {
                    match ov.export_document(&id, Path::new(&dest)) {
                        Ok(()) => self.status = format!("Exported to {dest}"),
                        Err(e) => self.status = format!("Export failed: {e}"),
                    }
                }
            }
            TaxDocReq::Remove(i) => {
                // Unlink from the record, persist, THEN reclaim the blob — same
                // crash-safe ordering as handle_doc's Remove.
                let id = self.edit_taxfiling.as_ref().and_then(|r| r.documents.get(i).cloned());
                if let Some(r) = self.edit_taxfiling.as_mut()
                    && i < r.documents.len()
                {
                    r.documents.remove(i);
                }
                if let Some(r) = self.edit_taxfiling.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.tax_filings, r);
                }
                if !self.persist() {
                    return; // persist() already set the "Save failed" status
                }
                if let Some(id) = id
                    && let Some(ov) = self.vault.as_mut()
                    && let Err(e) = ov.remove_document(&id)
                {
                    self.status = format!("Unlinked, but blob cleanup failed: {e}");
                    return;
                }
                self.status = "Removed document from the vault.".into();
            }
        }
    }

    fn delete_current(&mut self, tab: Tab) {
        // Collect any attached document ids to reclaim after removing the record.
        let mut doc_ids: Vec<String> = Vec::new();
        if let Some(ov) = self.vault.as_mut() {
            // `&mut ov.vault` is an exclusive borrow of the in-memory vault data,
            // reused below as `v` to keep the match arms terse.
            let v = &mut ov.vault;
            match tab {
                Tab::Instructions => {
                    // `.take()` moves the edited record out of the Option, leaving
                    // `None` behind (so the form clears after deletion) and giving
                    // us owned `r` to read its id.
                    if let Some(r) = self.edit_instruction.take() {
                        records::remove(&mut v.instructions, &r.id, &mut v.audit, "Instruction");
                    }
                }
                Tab::TrustWill => {
                    if let Some(r) = self.edit_trustwill.take() {
                        if let Some(f) = &r.file {
                            doc_ids.push(f.clone());
                        }
                        records::remove(&mut v.trust_wills, &r.id, &mut v.audit, "Trust/Will");
                    }
                }
                Tab::Assets => {
                    if let Some(r) = self.edit_asset.take() {
                        if let Some(f) = &r.statement {
                            doc_ids.push(f.clone());
                        }
                        records::remove(&mut v.assets, &r.id, &mut v.audit, "Asset/Liability");
                    }
                }
                Tab::Accounts => {
                    if let Some(r) = self.edit_account.take() {
                        records::remove(&mut v.accounts, &r.id, &mut v.audit, "Account");
                    }
                }
                Tab::RealEstate => {
                    if let Some(r) = self.edit_realestate.take() {
                        // Reclaim every document attached to this property.
                        for f in &r.documents {
                            doc_ids.push(f.clone());
                        }
                        records::remove(&mut v.real_estate, &r.id, &mut v.audit, "Real Estate");
                    }
                }
                Tab::Taxes => {
                    if let Some(r) = self.edit_taxfiling.take() {
                        // Reclaim every document attached to this filing year.
                        for f in &r.documents {
                            doc_ids.push(f.clone());
                        }
                        records::remove(&mut v.tax_filings, &r.id, &mut v.audit, "Tax filing");
                    }
                }
                Tab::GeneralDocuments => {
                    if let Some(r) = self.edit_general.take() {
                        if let Some(f) = &r.file {
                            doc_ids.push(f.clone());
                        }
                        records::remove(&mut v.general_documents, &r.id, &mut v.audit, "General document");
                    }
                }
            }
        }
        // Persist the record removal BEFORE reclaiming its blobs, AND only reclaim
        // if the save succeeded — otherwise the on-disk vault still references the
        // record and dropping its blobs would make it unopenable (ArchiveMismatch).
        if self.persist() {
            for id in doc_ids {
                if let Some(ov) = self.vault.as_mut() {
                    let _ = ov.remove_document(&id);
                }
            }
            self.status = "Deleted.".into();
        }
        // On failure persist() has already set the "Save failed: …" status, and the
        // record is still on disk — so do not claim it was deleted.
    }

    fn copy_to_clipboard(&mut self, text: Zeroizing<String>) {
        // `text` is wiped on drop; the shared helper copies it into the OS clipboard
        // with the Linux history-exclusion hint so clipboard managers don't retain
        // the password (cleared on the 15s timer and on exit either way).
        match crate::copy_secret_to_clipboard(text.as_str()) {
            Ok(()) => {
                self.clipboard_dirty = true;
                self.clipboard_clear_at = Some(Instant::now() + CLIPBOARD_CLEAR_AFTER);
                self.status = "Copied (clipboard auto-clears in 15s, and on exit).".into();
            }
            Err(e) => self.status = format!("Clipboard unavailable: {e}"),
        }
    }
}

// Identifies which document-bearing tab a deferred doc action applies to.
#[derive(Clone, Copy)]
enum DocTarget {
    TrustWill,
    Asset,
    General,
}

// Implement eframe's `App` trait so `GuiApp` can be driven by the framework.
// eframe calls `ui()` on every frame to (re)draw the whole window.
impl eframe::App for GuiApp {
    // The leading `_` in `_frame` marks the parameter as intentionally unused.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.tick_clipboard(ui.ctx());
        // Apply (and persist) the color theme only when the selection changed.
        if self.theme != self.applied_theme {
            ui.ctx().set_visuals(visuals_for(self.theme));
            save_theme(self.theme);
            self.applied_theme = self.theme;
        }
        if self.screen == Screen::Auth {
            egui::CentralPanel::default().show_inside(ui, |ui| {
                egui::ScrollArea::both().auto_shrink([false, false]).id_salt("auth_scroll").show(ui, |ui| {
                    self.ui_auth(ui)
                });
            });
            return;
        }
        if self.screen == Screen::Config {
            egui::CentralPanel::default().show_inside(ui, |ui| self.ui_config(ui));
            return;
        }

        egui::Panel::top("topbar").show_inside(ui, |ui| {
            ui.add_space(4.0);
            self.ui_top_bar(ui);
            ui.add_space(4.0);
        });
        if !self.status.is_empty() {
            egui::Panel::bottom("status").show_inside(ui, |ui| {
                ui.label(egui::RichText::new(&self.status).weak());
            });
        }
        // Draw the active tab inside a both-axis scroll area, so when a tab's content
        // is larger than the window the user gets vertical AND horizontal scrollbars
        // instead of clipped content. `auto_shrink([false, false])` makes the area fill
        // the panel (so the two-column layouts get full width); egui constrains the
        // content to the viewport, so scrollbars appear only on genuine overflow.
        egui::CentralPanel::default().show_inside(ui, |ui| {
            egui::ScrollArea::both().auto_shrink([false, false]).id_salt("main_scroll").show(ui, |ui| {
                match self.tab {
                    Tab::Instructions => self.tab_instructions(ui),
                    Tab::TrustWill => self.tab_trustwill(ui),
                    Tab::Assets => self.tab_assets(ui),
                    Tab::Accounts => self.tab_accounts(ui),
                    Tab::RealEstate => self.tab_realestate(ui),
                    Tab::Taxes => self.tab_taxes(ui),
                    Tab::GeneralDocuments => self.tab_general(ui),
                }
            });
        });
    }
}

// --- Free helper widgets -----------------------------------------------------

// `current` is borrowed mutably so the click can change it. `*current` is a
// *dereference*: it reads/writes the value behind the `&mut` reference (compare
// `*current == tab`, assign `*current = tab`).
fn tab_button(ui: &mut egui::Ui, current: &mut Tab, tab: Tab, label: &str) {
    if ui.selectable_label(*current == tab, label).clicked() {
        *current = tab;
    }
}

/// Render the left list panel; return `(new_clicked, selected_index)`.
// `labels: &[(String, String)]` is a borrowed *slice* — a read-only view of a
// contiguous run of `(id, label)` tuples (no ownership taken). `Option<&str>`
// is a maybe-present borrowed string. Returning a tuple lets one call report two
// outcomes at once.
fn list_panel(
    ui: &mut egui::Ui,
    title: &str,
    new_label: &str,
    labels: &[(String, String)],
    current_id: Option<&str>,
    writable: bool,
) -> (bool, Option<usize>) {
    let mut new = false;
    let mut select = None;
    ui.horizontal(|ui| {
        ui.heading(title);
    });
    // "New" is a write; only offered when writable.
    if writable && ui.button(new_label).clicked() {
        new = true;
    }
    ui.separator();
    ui.label(egui::RichText::new(format!("{} item(s)", labels.len())).weak());
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        // `.enumerate()` pairs each item with its index `i`; the `(i, (id, label))`
        // pattern destructures the index and the inner tuple together.
        for (i, (id, label)) in labels.iter().enumerate() {
            // `id.as_str()` borrows the `String` as `&str` to compare with the
            // currently-selected id.
            let selected = current_id == Some(id.as_str());
            if ui.selectable_label(selected, label).clicked() {
                select = Some(i);
            }
        }
    });
    (new, select)
}

/// Save / Delete buttons; returns the chosen action. Renders nothing (and stays
/// `None`) in read-only mode.
fn form_buttons(ui: &mut egui::Ui, writable: bool) -> FormAction {
    if !writable {
        return FormAction::None;
    }
    let mut action = FormAction::None;
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if ui.button("💾 Save").clicked() {
            action = FormAction::Save;
        }
        if ui.button("🗑 Delete").clicked() {
            action = FormAction::Delete;
        }
    });
    action
}

/// A two-column "label + single-line edit" row inside a Grid.
// `value: &mut String` lets the text widget write the user's edits straight back
// into the caller's field.
/// Validate a to-be-saved account, returning the user-facing error for the first
/// missing mandatory field (title, then owner) or `None` when it may be saved. The
/// GUI save path and its tests share this so the rule lives in exactly one place
/// (the TUI enforces the same rule on its `fields[0]`/`fields[3]`).
fn account_required_field_error(a: &Account) -> Option<&'static str> {
    if a.title.trim().is_empty() {
        Some("Title is required — every account must have a title.")
    } else if a.owner.trim().is_empty() {
        Some("Owner is required — every account must have an owner.")
    } else {
        None
    }
}

fn text_row(ui: &mut egui::Ui, label: &str, value: &mut String, writable: bool) {
    ui.label(label);
    // In read-only mode the field shows its value but is not editable.
    ui.add_enabled(writable, egui::TextEdit::singleline(value).desired_width(420.0));
    ui.end_row();
}

/// Render one portal-login section (URL / username / masked password + copy) into
/// the Real Estate form. The password is masked unless `reveal`; `copy_pw` is set
/// when the copy button is clicked, to be acted on after rendering.
#[allow(clippy::too_many_arguments)]
fn portal_section(
    ui: &mut egui::Ui,
    title: &str,
    url: &mut String,
    username: &mut String,
    password: &mut String,
    reveal: bool,
    writable: bool,
    copy_pw: &mut Option<Zeroizing<String>>,
) {
    ui.separator();
    ui.label(egui::RichText::new(title).strong());
    egui::Grid::new(title).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
        text_row(ui, "URL", url, writable);
        text_row(ui, "Username", username, writable);
        ui.label("Password");
        ui.horizontal(|ui| {
            // `title` is unique per portal (Property Mgmt / Insurance / HOA), so it is
            // a valid per-field id salt for the secret-field hardening. Copy stays
            // available read-only (it is a read, not an edit).
            secret_text_edit(ui, title, password, reveal, writable, 260.0);
            if ui.button("📋").on_hover_text("Copy").clicked() {
                *copy_pw = Some(Zeroizing::new(password.clone()));
            }
        });
        ui.end_row();
    });
}

/// Sorted, de-duplicated, non-empty values — used to populate filter dropdowns.
// `impl Iterator<Item = String>` is a generic parameter: accept *any* iterator
// yielding `String`s (the caller decides the concrete type). `.dedup()` removes
// *consecutive* duplicates, which is why it follows `.sort()`.
/// A filter dropdown: "All" (empty value) plus each option.
fn filter_combo(ui: &mut egui::Ui, id: &str, value: &mut String, options: &[String]) {
    let text = if value.is_empty() { "All".to_string() } else { value.clone() };
    egui::ComboBox::from_id_salt(id).selected_text(text).show_ui(ui, |ui| {
        ui.selectable_value(value, String::new(), "All");
        for opt in options {
            ui.selectable_value(value, opt.clone(), opt);
        }
    });
}

/// A dropdown restricted to `options`. Non-interactive (display-only) in read-only mode.
fn combo(ui: &mut egui::Ui, id: &str, value: &mut String, options: &[String], writable: bool) {
    let current = if value.is_empty() { "(choose)".to_string() } else { value.clone() };
    ui.add_enabled_ui(writable, |ui| {
        egui::ComboBox::from_id_salt(id).selected_text(current).show_ui(ui, |ui| {
            for opt in options {
                ui.selectable_value(value, opt.clone(), opt);
            }
        });
    });
}

/// The document attach / export / detach section. Returns the requested action;
/// the caller performs the actual volume operation (to keep `self` borrows
/// disjoint). `attached_present` reflects whether the record currently has a file.
// `#[allow(...)]` silences a specific lint (here: the linter's "too many
// arguments" warning) — it does not change behavior. The `&mut String` inputs
// are the caller's text buffers, edited in place by the widgets below.
/// Outcome of the shared [`doc_section`] widget. Indices refer to the `attached`
/// slice passed in (single-document tabs pass at most one document).
#[derive(PartialEq, Eq, Clone, Copy)]
enum DocSectionReq {
    None,
    Upload,
    Export(usize),
    Remove(usize),
}

impl DocSectionReq {
    /// Map to the single-document [`DocReq`] (Trust & Will / Assets / General),
    /// where there is exactly one slot so the index is irrelevant.
    fn to_single(self) -> DocReq {
        match self {
            DocSectionReq::Upload => DocReq::Attach,
            DocSectionReq::Export(_) => DocReq::Export,
            DocSectionReq::Remove(_) => DocReq::Remove,
            DocSectionReq::None => DocReq::None,
        }
    }
}

/// The uniform document widget used by EVERY document tab (modeled on Trust &
/// Will): it lists the currently-attached documents — each with Export / Remove —
/// and, when writable, shows the **Subfolder / Filename / Upload-from** inputs and
/// an Attach button. Single-document tabs pass a 0-or-1-element `attached` slice;
/// the multi-document tabs pass the full list. The caller maps the returned request
/// to its own handler (so `self` borrows stay disjoint from the widget).
fn doc_section(
    ui: &mut egui::Ui,
    attached: &[String],
    subfolder: &mut String,
    filename: &mut String,
    source: &mut String,
    dest: &mut String,
    writable: bool,
) -> DocSectionReq {
    let mut req = DocSectionReq::None;
    ui.label(egui::RichText::new("Documents (encrypted volume)").strong());
    if attached.is_empty() {
        ui.label(egui::RichText::new("(no documents attached)").weak());
    } else {
        for (i, label) in attached.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(format!("• {label}"));
                // Export is a read (always allowed); Remove mutates the vault.
                if ui.button("Export").clicked() {
                    req = DocSectionReq::Export(i);
                }
                if writable && ui.button("Remove").clicked() {
                    req = DocSectionReq::Remove(i);
                }
            });
        }
        ui.horizontal(|ui| {
            ui.label("Export to:");
            ui.add(egui::TextEdit::singleline(dest).hint_text("/path/to/save/as").desired_width(300.0));
        });
    }
    if writable {
        ui.separator();
        egui::Grid::new("doc_attach").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
            ui.label("Subfolder (optional)");
            ui.add(egui::TextEdit::singleline(subfolder).hint_text("statements").desired_width(300.0));
            ui.end_row();
            ui.label("Filename");
            ui.add(egui::TextEdit::singleline(filename).hint_text("statement.pdf").desired_width(300.0));
            ui.end_row();
            ui.label("Upload from");
            ui.add(egui::TextEdit::singleline(source).hint_text("/path/on/disk/file.pdf").desired_width(300.0));
            ui.end_row();
        });
        // Approximate the virtual path length: the stored path also includes the
        // auto-group and timestamp levels (~80 bytes, not visible here), so reserve
        // for them. `handle_doc`/`handle_*_doc` do the authoritative check on write.
        let vpath_len = vault::virtual_path(subfolder, filename).len() + 80;
        let over_limit = vpath_len > crate::storage::MAX_PATH_LEN;
        if over_limit {
            ui.colored_label(
                egui::Color32::from_rgb(0xC0, 0x30, 0x30),
                format!("Path may be too long (~{vpath_len} / {} bytes) — shorten the filename or subfolder.", crate::storage::MAX_PATH_LEN),
            );
        }
        if ui.add_enabled(!over_limit, egui::Button::new("⬆ Attach (encrypt into volume)")).clicked() {
            req = DocSectionReq::Upload;
        }
    }
    req
}

/// A collapsing, timestamped history view for a record.
// `&[records::Change]` is a read-only slice of change entries.
fn history_view(ui: &mut egui::Ui, history: &[records::Change]) {
    ui.add_space(8.0);
    egui::CollapsingHeader::new("History").default_open(false).show(ui, |ui| {
        if history.is_empty() {
            ui.label(egui::RichText::new("(no changes recorded)").weak());
        }
        egui::ScrollArea::vertical().max_height(180.0).id_salt("hist").show(ui, |ui| {
            // `.iter().rev()` walks the entries newest-first (reverse order).
            for c in history.iter().rev() {
                // `display_detail` masks password before/after values so the history
                // pane never leaks a cleartext password (it can't be copied from here
                // and the live field's reveal toggle deliberately does not extend here).
                let detail =
                    if c.detail.is_empty() { c.action.clone() } else { records::display_detail(&c.detail) };
                ui.label(format!("{}  —  {detail}", format_time(c.at)));
            }
        });
    });
}

/// A single-line text field for a SECRET (a password), hardening egui's stock
/// `TextEdit` against the two residual leaks the audit flagged (R-7):
///
/// 1. **Undo residue.** egui keeps un-zeroized snapshots of the edited string in its
///    per-widget undo buffer, which would otherwise retain past values of the secret
///    for the whole process lifetime. We clear the undoer every frame (undo on a
///    password is not worth the residue), bounding it to at most the current frame.
/// 2. **Copy hint bypass.** The built-in Ctrl+C / Ctrl+X / context-menu copy queues an
///    `OutputCommand::CopyText` that eframe writes via a plain clipboard `set_text`
///    (no history-exclusion hint), unlike the dedicated 📋 button. While this field is
///    focused we intercept that command and re-route the secret through the hardened
///    [`crate::copy_secret_to_clipboard`] (Linux `exclude_from_history`).
///
/// `id_salt` MUST be unique per field (it pins a stable widget id for the state-scrub).
fn secret_text_edit(ui: &mut egui::Ui, id_salt: &str, value: &mut String, revealed: bool, writable: bool, width: f32) -> egui::Response {
    let id = ui.make_persistent_id(id_salt);
    // Read-only: still display the (masked/revealed) value, but it cannot be edited.
    let resp = ui.add_enabled(writable, egui::TextEdit::singleline(value).id(id).password(!revealed).desired_width(width));
    // (1) Never accumulate undo snapshots of a secret.
    if let Some(mut state) = egui::widgets::text_edit::TextEditState::load(ui.ctx(), id) {
        state.clear_undoer();
        state.store(ui.ctx(), id);
    }
    // (2) Re-route any built-in copy/cut of THIS focused field through the hardened
    // clipboard path. Gating on focus means we only touch a CopyText that this field
    // produced (you cannot have two focused widgets), so other widgets' copies are
    // untouched.
    if resp.has_focus() {
        let copied: Vec<String> = ui.ctx().output_mut(|o| {
            let mut taken = Vec::new();
            o.commands.retain(|c| {
                if let egui::OutputCommand::CopyText(t) = c {
                    taken.push(t.clone());
                    false // drop it so eframe's plain set_text never runs
                } else {
                    true
                }
            });
            taken
        });
        for t in copied {
            let _ = crate::copy_secret_to_clipboard(&t);
        }
    }
    resp
}

/// A masked single-line password field; returns true if Enter was pressed. `id_salt`
/// is unique per field (unlock/create/change-password use four distinct fields).
fn password_field(ui: &mut egui::Ui, id_salt: &str, value: &mut String) -> bool {
    // Always masked (revealed = false); the secret hardening (undo scrub + copy
    // re-route) still applies — a master password is the most sensitive of all.
    // Always editable (`writable = true`): this is the unlock/create field, which
    // exists before any vault is open, so the read-only mode does not apply here.
    let resp = secret_text_edit(ui, id_salt, value, false, true, 280.0);
    resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

/// Build `(id, label)` pairs for a record list.
// `<R: Record>` is a generic: this works for any type `R` that implements the
// `Record` trait (i.e. exposes `.id()` and `.label()`). `&[R]` is a slice of
// such records. `.to_string()` makes an owned `String` from the borrowed id.
fn label_list<R: Record>(list: &[R]) -> Vec<(String, String)> {
    list.iter().map(|r| (r.id().to_string(), r.label())).collect()
}

/// Best-effort clearing of the system clipboard on exit.
fn clear_clipboard() {
    // `let _ = ...` ignores the `Result`: if the clipboard is unavailable there
    // is nothing useful to do. Setting it to an empty `String` overwrites any
    // copied secret.
    let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(String::new()));
}

// `#[cfg(test)]` is conditional compilation: this module is compiled ONLY when
// running tests, so it adds nothing to the shipped binary. `use super::*` pulls
// in everything from the parent module (this file) for the tests to exercise.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::records::AssetLiability;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fast() -> KdfParams {
        KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
    }

    fn nanos() -> u128 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        // Unique per-test directory; the vault file name is fixed (vault.pmv),
        // matching production where the user controls only the directory.
        let dir = std::env::temp_dir().join(format!("passmgr-gui-{tag}-{}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("vault.pmv")
    }

    fn cleanup(path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// A GuiApp with a freshly-created, unlocked vault on the Main screen.
    fn app_unlocked(tag: &str) -> (GuiApp, std::path::PathBuf) {
        let path = tmp(tag);
        let ov = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut app = GuiApp::new(path.clone(), true);
        app.vault = Some(ov);
        app.screen = Screen::Main;
        (app, path)
    }

    #[test]
    fn theme_id_round_trips_and_defaults_to_light() {
        for t in Theme::ALL {
            assert_eq!(Theme::from_id(t.id()), Some(t), "{} id must round-trip", t.label());
        }
        assert_eq!(Theme::from_id("nonsense"), None);
        assert_eq!(Theme::default(), Theme::Light);
        // Every theme builds a usable Visuals (no panic / field mismatch).
        for t in Theme::ALL {
            let _ = visuals_for(t);
        }
    }

    #[test]
    fn sync_account_filters_to_follows_only_active_filters() {
        let (mut app, path) = app_unlocked("guifsync");
        app.acct_filter_type = "Email".into(); // active
        app.acct_filter_title = "Personal".into(); // active
        app.acct_filter_owner = String::new(); // inactive
        let mut a = Account::new().unwrap();
        a.account_type = "Bank".into();
        a.title = "Savings".into();
        a.owner = "Bob".into();
        app.sync_account_filters_to(&a);
        assert_eq!(app.acct_filter_type, "Bank", "active type filter follows the saved value");
        assert_eq!(app.acct_filter_title, "Savings", "active title filter follows the saved value");
        assert_eq!(app.acct_filter_owner, "", "an inactive filter stays unset");
        cleanup(&path);
    }

    #[test]
    fn sync_account_filters_relaxes_review_and_search_in_gui() {
        let (mut app, path) = app_unlocked("guirelax");
        app.acct_filter_review = true;
        app.acct_search_user = "alice".into();
        let mut a = Account::new().unwrap();
        a.review = false; // saved record is NOT flagged
        a.username = "bob".into(); // and does not match the search
        app.sync_account_filters_to(&a);
        assert!(!app.acct_filter_review, "review-only filter relaxed so a non-flagged save stays visible");
        assert_eq!(app.acct_search_user, "", "username search relaxed when it no longer matches the save");

        // A still-matching save leaves the search in place.
        app.acct_search_user = "bo".into();
        let mut keep = Account::new().unwrap();
        keep.username = "bob".into();
        app.sync_account_filters_to(&keep);
        assert_eq!(app.acct_search_user, "bo", "a still-matching search is left as-is");
        cleanup(&path);
    }

    #[test]
    fn account_search_matches_username_or_title_in_gui() {
        let (mut app, path) = app_unlocked("guisearchtitle");
        let mut by_title = Account::new().unwrap();
        by_title.username = "u1".into();
        by_title.title = "Brokerage account".into();
        let mut other = Account::new().unwrap();
        other.username = "u2".into();
        other.title = "Email".into();

        app.acct_search_user = "broker".into();
        assert!(app.account_passes_filters(&by_title), "title substring matches");
        assert!(!app.account_passes_filters(&other), "non-match excluded");
        // Still matches by username.
        app.acct_search_user = "u2".into();
        assert!(app.account_passes_filters(&other));
        assert!(!app.account_passes_filters(&by_title));
        cleanup(&path);
    }

    #[test]
    fn account_requires_title_then_owner_in_gui() {
        // The shared save-validation rule the GUI form enforces: title first, then
        // owner; only a record with both (non-blank after trim) may be saved.
        let mut a = Account::new().unwrap();
        assert_eq!(
            account_required_field_error(&a),
            Some("Title is required — every account must have a title.")
        );
        a.title = "  Brokerage  ".into(); // whitespace-only would still fail; real text passes
        assert_eq!(
            account_required_field_error(&a),
            Some("Owner is required — every account must have an owner."),
            "title satisfied, owner still missing"
        );
        a.owner = "   ".into(); // whitespace-only owner is still missing
        assert_eq!(account_required_field_error(&a), Some("Owner is required — every account must have an owner."));
        a.owner = "Alice".into();
        assert_eq!(account_required_field_error(&a), None, "title + owner present -> savable");
    }

    #[test]
    fn trim_all_accounts_bulk_trims_and_reports_in_gui() {
        let (mut app, path) = app_unlocked("guitrimall");
        {
            let ov = app.vault.as_mut().unwrap();
            let mut a = Account::new().unwrap();
            a.owner = "  Alice  ".into();
            a.title = " Brokerage ".into();
            a.password = "  s3cret  ".into();
            records::upsert(&mut ov.vault.accounts, a);
            let b = Account::new().unwrap(); // already clean (all empty)
            records::upsert(&mut ov.vault.accounts, b);
        }
        let n = app.trim_all_accounts();
        assert_eq!(n, 1, "only the dirty account is counted");
        let a = &app.vault.as_ref().unwrap().vault.accounts[0];
        assert_eq!(a.owner, "Alice");
        assert_eq!(a.title, "Brokerage");
        assert_eq!(a.password, "s3cret", "the password is trimmed too (configured policy)");
        assert!(app.status.contains("Trimmed 1"), "status: {}", app.status);
        // Idempotent.
        assert_eq!(app.trim_all_accounts(), 0);
        assert!(app.status.contains("Nothing to trim"), "status: {}", app.status);
        cleanup(&path);
    }

    #[test]
    fn new_account_from_filters_prepopulates() {
        let (mut app, path) = app_unlocked("guifilterprefill");
        app.acct_filter_title = "Bank login".into();
        app.acct_filter_type = "Financial".into();
        app.acct_filter_subtype = "IRA".into();
        app.acct_filter_owner = "Alice".into();
        app.acct_search_user = "alice99".into();
        let a = app.new_account_from_filters().unwrap();
        assert_eq!(a.title, "Bank login");
        assert_eq!(a.account_type, "Financial");
        assert_eq!(a.account_subtype, "IRA");
        assert_eq!(a.owner, "Alice");
        assert_eq!(a.username, "alice99");
        assert!(a.password.is_empty(), "no secret invented");
        // Empty filters -> blank new account.
        app.acct_filter_title.clear();
        app.acct_filter_type.clear();
        app.acct_filter_subtype.clear();
        app.acct_filter_owner.clear();
        app.acct_search_user.clear();
        let b = app.new_account_from_filters().unwrap();
        assert_eq!(b.title, "");
        assert_eq!(b.account_type, "");
        assert_eq!(b.owner, "");
        assert_eq!(b.username, "");
        cleanup(&path);
    }

    #[test]
    fn gui_general_document_upload_export_remove() {
        let (mut app, path) = app_unlocked("guigendoc");
        let dir = path.parent().unwrap().to_path_buf();
        let mut g = GeneralDocument::new().unwrap();
        g.title = "Passport".into();
        app.edit_general = Some(g);

        let src = dir.join("p.pdf");
        std::fs::write(&src, b"passport").unwrap();
        app.doc_filename = "p.pdf".into();
        app.doc_source = src.to_string_lossy().into();
        app.doc_subfolder = "ids".into();
        app.handle_doc(DocReq::Attach, DocTarget::General);
        let id = app.edit_general.as_ref().unwrap().file.clone();
        assert!(id.is_some(), "uploaded; status: {}", app.status);
        let id = id.unwrap();
        assert_eq!(
            app.vault.as_ref().unwrap().vault.general_documents[0].file.as_deref(),
            Some(id.as_str()),
            "persisted"
        );
        // Uniform layout: /general-documents/<title>/<timestamp>/<subfolder>/<filename>.
        let vpath = app.vault.as_ref().unwrap().doc_path(&id).unwrap();
        assert!(vpath.trim_start_matches('/').starts_with("general-documents/passport/"), "got {vpath}");
        assert!(vpath.ends_with("/ids/p.pdf"), "got {vpath}");

        let dest = dir.join("out.pdf");
        app.doc_dest = dest.to_string_lossy().into();
        app.handle_doc(DocReq::Export, DocTarget::General);
        assert_eq!(std::fs::read(&dest).unwrap(), b"passport", "exported bytes round-trip");

        app.handle_doc(DocReq::Remove, DocTarget::General);
        assert!(app.edit_general.as_ref().unwrap().file.is_none(), "removed");
        assert!(!app.vault.as_ref().unwrap().has_document(&id), "blob reclaimed");
        cleanup(&path);
    }

    #[test]
    fn gui_real_estate_document_upload_export_remove() {
        let (mut app, path) = app_unlocked("guiredoc");
        let dir = path.parent().unwrap().to_path_buf();
        let mut re = RealEstate::new().unwrap();
        re.address = "1 Main".into();
        app.edit_realestate = Some(re);

        // --- upload ---
        let src = dir.join("deed.txt");
        std::fs::write(&src, b"the deed").unwrap();
        app.doc_filename = "deed.txt".into();
        app.doc_source = src.to_string_lossy().into();
        app.handle_re_doc(ReDocReq::Upload);
        assert_eq!(app.edit_realestate.as_ref().unwrap().documents.len(), 1, "uploaded one doc");
        assert_eq!(app.vault.as_ref().unwrap().vault.real_estate[0].documents.len(), 1, "persisted");

        // --- export ---
        let dest = dir.join("deed-out.txt");
        app.doc_dest = dest.to_string_lossy().into();
        app.handle_re_doc(ReDocReq::Export(0));
        assert_eq!(std::fs::read(&dest).unwrap(), b"the deed", "exported bytes round-trip");

        // --- remove ---
        app.handle_re_doc(ReDocReq::Remove(0));
        assert!(app.edit_realestate.as_ref().unwrap().documents.is_empty(), "removed the doc");
        assert!(app.vault.as_ref().unwrap().vault.real_estate[0].documents.is_empty(), "unlinked");
        cleanup(&path);
    }

    #[test]
    fn gui_tax_document_upload_export_remove() {
        let (mut app, path) = app_unlocked("guitaxdoc");
        let dir = path.parent().unwrap().to_path_buf();
        let mut tf = TaxFiling::new().unwrap();
        tf.year = "2024".into();
        app.edit_taxfiling = Some(tf);

        let src = dir.join("w2.txt");
        std::fs::write(&src, b"taxable income").unwrap();
        app.doc_filename = "w2.txt".into();
        app.doc_source = src.to_string_lossy().into();
        app.handle_tax_doc(TaxDocReq::Upload);
        assert_eq!(app.edit_taxfiling.as_ref().unwrap().documents.len(), 1, "uploaded one doc");
        assert_eq!(app.vault.as_ref().unwrap().vault.tax_filings[0].documents.len(), 1, "persisted");

        let dest = dir.join("out.txt");
        app.doc_dest = dest.to_string_lossy().into();
        app.handle_tax_doc(TaxDocReq::Export(0));
        assert_eq!(std::fs::read(&dest).unwrap(), b"taxable income", "exported bytes round-trip");

        app.handle_tax_doc(TaxDocReq::Remove(0));
        assert!(app.edit_taxfiling.as_ref().unwrap().documents.is_empty(), "removed the doc");
        assert!(app.vault.as_ref().unwrap().vault.tax_filings[0].documents.is_empty(), "unlinked");
        cleanup(&path);
    }

    #[test]
    fn load_theme_from_round_trips_and_is_bounded_and_symlink_safe() {
        let dir = std::env::temp_dir().join(format!("pmprefs-{}", nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("prefs.json");
        // A valid small prefs file round-trips through save/load.
        save_theme_to(&p, Theme::Solarized);
        assert_eq!(load_theme_from(&p), Theme::Solarized);
        // Unknown id falls back to the default.
        std::fs::write(&p, br#"{"theme":"nope"}"#).unwrap();
        assert_eq!(load_theme_from(&p), Theme::Light);
        // Over-cap file is rejected before the body is parsed (DoS guard).
        std::fs::write(&p, vec![b'{'; (MAX_PREFS_SIZE as usize) + 1]).unwrap();
        assert_eq!(load_theme_from(&p), Theme::Light);
        // Missing file -> default.
        assert_eq!(load_theme_from(&dir.join("absent.json")), Theme::Light);
        // A symlinked prefs file is refused even if its target is a valid prefs file.
        #[cfg(unix)]
        {
            let real = dir.join("real.json");
            save_theme_to(&real, Theme::Dark);
            let link = dir.join("link.json");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(load_theme_from(&link), Theme::Light, "symlinked prefs refused");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_flow_builds_vault() {
        let path = tmp("create");
        let mut app = GuiApp::new(path.clone(), true);
        app.auth_mode = AuthMode::Create;
        app.pw1 = "a".into();
        app.confirm1 = "a".into();
        app.pw2 = "b".into();
        app.confirm2 = "b".into();
        app.submit_auth();
        assert!(app.vault.is_some());
        assert!(app.screen == Screen::Main);
        assert!(app.pw1.is_empty(), "passwords wiped after submit");
        cleanup(&path);
    }

    #[test]
    fn account_username_search_filters() {
        let (mut app, path) = app_unlocked("usersearch");
        {
            let v = &mut app.vault.as_mut().unwrap().vault;
            for u in ["alice", "alice2", "bob"] {
                let mut a = Account::new().unwrap();
                a.username = u.into();
                records::upsert(&mut v.accounts, a);
            }
        }
        assert_eq!(app.filtered_account_labels().len(), 3, "no search → all");
        app.acct_search_user = "ALI".into(); // case-insensitive substring
        assert_eq!(app.filtered_account_labels().len(), 2, "alice + alice2");
        app.acct_search_user = "bob".into();
        assert_eq!(app.filtered_account_labels().len(), 1);
        app.acct_search_user = "zzz".into();
        assert_eq!(app.filtered_account_labels().len(), 0, "no match");
        cleanup(&path);
    }

    #[test]
    fn mismatched_confirmation_is_rejected() {
        let path = tmp("mismatch");
        let mut app = GuiApp::new(path.clone(), true);
        app.auth_mode = AuthMode::Create;
        app.pw1 = "a".into();
        app.confirm1 = "a".into();
        app.pw2 = "b".into();
        app.confirm2 = "WRONG".into();
        app.submit_auth();
        assert!(app.vault.is_none());
        assert!(app.auth_error.is_some());
        cleanup(&path);
    }

    #[test]
    fn attach_then_detach_document_round_trip() {
        let (mut app, path) = app_unlocked("doc");
        let src = std::env::temp_dir().join(format!("passmgr-guisrc-{}.txt", nanos()));
        std::fs::write(&src, b"will body").unwrap();

        app.edit_asset = Some(AssetLiability::new().unwrap());
        app.doc_subfolder = "wills".into();
        app.doc_filename = "will.txt".into();
        app.doc_source = src.display().to_string();
        app.handle_doc(DocReq::Attach, DocTarget::Asset);

        let id = app.edit_asset.as_ref().unwrap().statement.clone();
        assert!(id.is_some(), "statement linked to the uploaded doc");
        let id = id.unwrap();
        let ov = app.vault.as_ref().unwrap();
        assert!(ov.has_document(&id));
        assert_eq!(&ov.read_document(&id).unwrap()[..], b"will body");

        // Detach reclaims the blob and unlinks the record.
        app.handle_doc(DocReq::Remove, DocTarget::Asset);
        assert!(app.edit_asset.as_ref().unwrap().statement.is_none());
        assert!(!app.vault.as_ref().unwrap().has_document(&id));

        let _ = std::fs::remove_file(&src);
        cleanup(&path);
    }

    #[test]
    fn over_long_filename_is_capped_not_rejected_in_gui() {
        // With the uniform layout every path component is length-capped (filename to
        // 120 bytes, group/subfolder to 40, timestamp fixed), so a huge filename can
        // no longer push the virtual path over MAX_PATH_LEN — it is sanitized and
        // truncated, and the upload succeeds rather than being rejected.
        let (mut app, path) = app_unlocked("guipath");
        let src = std::env::temp_dir().join(format!("passmgr-guipath-{}.txt", nanos()));
        std::fs::write(&src, b"x").unwrap();
        app.edit_asset = Some(AssetLiability::new().unwrap());
        app.doc_subfolder = "d".into();
        app.doc_filename = "f".repeat(crate::storage::MAX_PATH_LEN);
        app.doc_source = src.display().to_string();
        app.handle_doc(DocReq::Attach, DocTarget::Asset);
        let id = app.edit_asset.as_ref().unwrap().statement.clone();
        assert!(id.is_some(), "upload should succeed with a capped name; status: {}", app.status);
        // The stored virtual path stays within the limit.
        let vpath = app.vault.as_ref().unwrap().doc_path(&id.unwrap()).unwrap_or_default();
        assert!(vpath.len() <= crate::storage::MAX_PATH_LEN, "path within limit: {} bytes", vpath.len());
        let _ = std::fs::remove_file(&src);
        cleanup(&path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn detach_skips_blob_reclaim_when_save_fails_keeping_vault_openable() {
        // The cross-confirmed HIGH fix: if the vault save fails (full disk), the
        // blob reclaim must be SKIPPED, or the on-disk vault would reference a
        // dropped doc (ArchiveMismatch -> unopenable). Here the doc must survive.
        let (mut app, path) = app_unlocked("faildetach");
        let src = std::env::temp_dir().join(format!("passmgr-faild-{}.txt", nanos()));
        std::fs::write(&src, b"statement body").unwrap();
        let id = {
            let ov = app.vault.as_mut().unwrap();
            let id = ov.add_document("/a", "stmt.txt", std::path::Path::new(&src)).unwrap();
            let mut a = AssetLiability::new().unwrap();
            a.statement = Some(id.clone());
            records::upsert(&mut ov.vault.assets, a.clone());
            ov.save().unwrap();
            app.edit_asset = Some(a);
            id
        };
        // Detach with the disk full at the vault save.
        crate::fault::fail_at("vault.write", 1);
        app.handle_doc(DocReq::Remove, DocTarget::Asset);
        crate::fault::clear();
        assert!(app.status.contains("Save failed"), "status was: {}", app.status);
        drop(app); // release the lock
        // The save failed, so the on-disk vault still references the doc; because the
        // reclaim was skipped, the doc is still present -> the vault opens cleanly.
        let re = OpenVault::open(path.clone(), b"a", b"b").unwrap();
        assert!(re.has_document(&id), "blob retained; vault openable");
        let _ = std::fs::remove_file(&src);
        cleanup(&path);
    }

    #[test]
    fn delete_current_removes_record_and_reclaims_blob() {
        let (mut app, path) = app_unlocked("del");
        let src = std::env::temp_dir().join(format!("passmgr-guidel-{}.txt", nanos()));
        std::fs::write(&src, b"stmt").unwrap();
        // Build an asset with an attached statement, saved into the vault.
        let id = app.vault.as_mut().unwrap().add_document("/s", "s.txt", std::path::Path::new(&src)).unwrap();
        let mut a = AssetLiability::new().unwrap();
        a.statement = Some(id.clone());
        records::upsert(&mut app.vault.as_mut().unwrap().vault.assets, a.clone());
        app.edit_asset = Some(a);

        app.delete_current(Tab::Assets);
        assert!(app.vault.as_ref().unwrap().vault.assets.is_empty());
        assert!(app.vault.as_ref().unwrap().read_document(&id).is_err(), "blob reclaimed");

        let _ = std::fs::remove_file(&src);
        cleanup(&path);
    }

    #[test]
    fn change_password_via_auth_rekeys() {
        let (mut app, path) = app_unlocked("rekey");
        app.auth_mode = AuthMode::ChangePassword;
        app.pw1 = "c".into();
        app.confirm1 = "c".into();
        app.pw2 = "d".into();
        app.confirm2 = "d".into();
        app.submit_auth();
        assert!(app.screen == Screen::Main);
        drop(app); // release the single-writer lock before reopening
        // Reopens only with the new passwords.
        assert!(OpenVault::open(path.clone(), b"a", b"b").is_err());
        assert!(OpenVault::open(path.clone(), b"c", b"d").is_ok());
        cleanup(&path);
    }
}
