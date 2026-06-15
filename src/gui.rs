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
use crate::records::{self, Account, AssetLiability, Instruction, RealEstate, Record, TrustWill};
use crate::ui::format_time;
use crate::vault::{self, OpenVault, VaultError};
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
        // captured `path`/`writable` (the `move` keyword) so they outlive `run`.
        Box::new(move |cc| {
            // Lighter, higher-contrast theme.
            cc.egui_ctx.set_visuals(light_visuals());
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
    reveal_pw: bool,
    // Accounts-tab display filters ("" = no filter).
    acct_filter_type: String,
    acct_filter_subtype: String,
    acct_filter_owner: String,
    acct_filter_review: bool,
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
    // Shared document-attach input buffers.
    doc_location: String,
    doc_filename: String,
    doc_source: String,
    doc_dest: String,
    status: String,
    clipboard_dirty: bool,
    // When set, the clipboard should be wiped at/after this instant.
    // `Option<Instant>`: `None` = no pending wipe, `Some(t)` = wipe at time `t`.
    clipboard_clear_at: Option<Instant>,
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
        GuiApp {
            path,
            writable,
            screen: Screen::Auth,
            auth_mode,
            pw1: String::new(),
            confirm1: String::new(),
            pw2: String::new(),
            confirm2: String::new(),
            auth_error: None,
            vault: None,
            tab: Tab::Instructions,
            edit_instruction: None,
            edit_trustwill: None,
            edit_asset: None,
            edit_account: None,
            edit_realestate: None,
            reveal_pw: false,
            acct_filter_type: String::new(),
            acct_filter_subtype: String::new(),
            acct_filter_owner: String::new(),
            acct_filter_review: false,
            asset_filter_review: false,
            new_asset_type: String::new(),
            new_account_type: String::new(),
            new_subtype_for: String::new(),
            new_subtype_name: String::new(),
            backup_dest: String::new(),
            cfg_volume_size: String::new(),
            doc_location: String::new(),
            doc_filename: String::new(),
            doc_source: String::new(),
            doc_dest: String::new(),
            status: String::new(),
            clipboard_dirty: false,
            clipboard_clear_at: None,
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
        self.doc_location.clear();
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
                self.status = if creating {
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
            }
            // `Err(e)` catches every other error variant.
            Err(e) => self.auth_error = Some(format!("{e}")),
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
            submit |= password_field(ui, &mut self.pw1);
            ui.end_row();
            if confirm {
                ui.label("Confirm password 1");
                submit |= password_field(ui, &mut self.confirm1);
                ui.end_row();
            }
            ui.label("Password 2");
            submit |= password_field(ui, &mut self.pw2);
            ui.end_row();
            if confirm {
                ui.label("Confirm password 2");
                submit |= password_field(ui, &mut self.confirm2);
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
        ui.horizontal(|ui| {
            tab_button(ui, &mut self.tab, Tab::Instructions, "Instructions");
            tab_button(ui, &mut self.tab, Tab::TrustWill, "Trust and Will");
            tab_button(ui, &mut self.tab, Tab::Assets, "Assets and Liabilities");
            tab_button(ui, &mut self.tab, Tab::Accounts, "Accounts");
            tab_button(ui, &mut self.tab, Tab::RealEstate, "Real Estate");
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
        if !self.writable {
            ui.label(
                egui::RichText::new("Read-only: type editing is disabled (backup is still available).")
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
        // Snapshot the category lists + volume cap (from the open vault) before the
        // render closure borrows `self` mutably for the text inputs.
        let cur_volume_mib = self.vault_ref().volume_max_size() / (1024 * 1024);
        let cats = self.vault_ref().categories();
        let type_names = cats.account_type_names();
        let asset_list = cats.asset.join(" · ");
        // Iterator pipeline: `.iter()` walks the account types by reference;
        // `.map(|t| ...)` transforms each into an `(name, subtypes)` tuple via a
        // closure; `.collect()` gathers them into a `Vec` (growable array). The
        // type annotation `Vec<(String, String)>` tells `collect` what to build.
        let account_list: Vec<(String, String)> = cats
            .account
            .iter()
            .map(|t| {
                let subs = if t.subtypes.is_empty() { "—".to_string() } else { t.subtypes.join(", ") };
                // `.clone()` because the snapshot must own its strings (the
                // borrow of `cats` ends when this function's closures run).
                (t.name.clone(), subs)
            })
            .collect();

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.label(egui::RichText::new("Asset / Liability types").strong());
            ui.label(egui::RichText::new(asset_list).weak());
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.new_asset_type).hint_text("New type").desired_width(240.0));
                if self.writable && ui.button("Add type").clicked() {
                    add_asset = true;
                }
            });

            ui.add_space(14.0);
            ui.label(egui::RichText::new("Account types & subtypes").strong());
            // `for (name, subs) in &account_list` iterates by reference and
            // destructures each tuple into its two parts.
            for (name, subs) in &account_list {
                ui.label(egui::RichText::new(format!("{name}: {subs}")).weak());
            }
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.new_account_type).hint_text("New account type").desired_width(220.0));
                if self.writable && ui.button("Add type").clicked() {
                    add_account = true;
                }
            });
            ui.horizontal(|ui| {
                ui.label("Add subtype to:");
                // Pick the type the subtype belongs to.
                let cur = if self.new_subtype_for.is_empty() { "(choose type)".to_string() } else { self.new_subtype_for.clone() };
                egui::ComboBox::from_id_salt("subtype_for").selected_text(cur).show_ui(ui, |ui| {
                    for name in &type_names {
                        ui.selectable_value(&mut self.new_subtype_for, name.clone(), name);
                    }
                });
                ui.add(egui::TextEdit::singleline(&mut self.new_subtype_name).hint_text("New subtype").desired_width(180.0));
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
        if do_backup {
            let dest = self.backup_dest.trim().to_string();
            if dest.is_empty() {
                self.status = "Enter a backup destination directory.".into();
            } else {
                // `Path::new(&dest)` makes a borrowed `&Path` view of the string.
                match vault::backup(&self.path, Path::new(&dest)) {
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
                    ui.add(egui::TextEdit::singleline(&mut r.title).desired_width(420.0));
                    ui.end_row();
                });
                ui.label("Description");
                ui.add(egui::TextEdit::multiline(&mut r.description).desired_rows(12).desired_width(f32::INFINITY));
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
                self.persist();
                self.status = "Saved.".into();
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
        let attached = self.attached_label(self.edit_trustwill.as_ref().and_then(|r| r.file.clone()));
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
                    ui.add(egui::TextEdit::singleline(&mut r.document).desired_width(420.0));
                    ui.end_row();
                });
                ui.label("Usage");
                ui.add(egui::TextEdit::multiline(&mut r.usage).desired_rows(8).desired_width(f32::INFINITY));
                ui.separator();
                docreq = doc_section(
                    ui,
                    "File",
                    r.file.is_some(),
                    attached.as_deref(),
                    &mut self.doc_location,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    &mut self.doc_dest,
                    self.writable,
                );
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
                self.persist();
                self.status = "Saved.".into();
            }
            FormAction::Delete => self.delete_current(Tab::TrustWill),
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
        let attached = self.attached_label(self.edit_asset.as_ref().and_then(|r| r.statement.clone()));
        let asset_types = self.vault_ref().categories().asset.clone();
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut docreq = DocReq::None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Assets and Liabilities", "➕ New", &labels, cur.as_deref(), self.writable);
            let ui = &mut c[1];
            if let Some(r) = self.edit_asset.as_mut() {
                egui::Grid::new("asset_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Asset / Liability");
                    combo(ui, "asset_kind", &mut r.kind, &["Asset".to_string(), "Liability".to_string()]);
                    ui.end_row();
                    ui.label("Owner");
                    ui.add(egui::TextEdit::singleline(&mut r.owner).desired_width(420.0));
                    ui.end_row();
                    ui.label("Beneficiary");
                    ui.add(egui::TextEdit::singleline(&mut r.beneficiary).desired_width(420.0));
                    ui.end_row();
                    ui.label("Approximate value");
                    ui.add(egui::TextEdit::singleline(&mut r.approx_value).desired_width(420.0));
                    ui.end_row();
                    ui.label("As-of date");
                    ui.add(egui::TextEdit::singleline(&mut r.as_of_date).hint_text("YYYY-MM-DD").desired_width(420.0));
                    ui.end_row();
                    ui.label("Institution");
                    ui.add(egui::TextEdit::singleline(&mut r.institution).desired_width(420.0));
                    ui.end_row();
                    ui.label("Type");
                    combo(ui, "asset_type", &mut r.asset_type, &asset_types);
                    ui.end_row();
                    ui.label("URL");
                    ui.add(egui::TextEdit::singleline(&mut r.url).desired_width(420.0));
                    ui.end_row();
                    ui.label("Review");
                    ui.checkbox(&mut r.review, "flag for review");
                    ui.end_row();
                });
                ui.label("Description");
                ui.add(egui::TextEdit::multiline(&mut r.description).desired_rows(4).desired_width(f32::INFINITY));
                ui.separator();
                docreq = doc_section(
                    ui,
                    "Statement",
                    r.statement.is_some(),
                    attached.as_deref(),
                    &mut self.doc_location,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    &mut self.doc_dest,
                    self.writable,
                );
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
                self.persist();
                self.status = "Saved.".into();
            }
            FormAction::Delete => self.delete_current(Tab::Assets),
            _ => {}
        }
    }

    // --- Tab: Accounts -------------------------------------------------------

    fn tab_accounts(&mut self, ui: &mut egui::Ui) {
        let type_names = self.vault_ref().categories().account_type_names();
        let owners_present =
            distinct_values(self.vault_ref().vault.accounts.iter().map(|a| a.owner.clone()));
        // When a type filter is chosen, offer that type's configured subtypes
        // UNION any free-text subtypes actually present on its accounts (so a
        // hand-typed subtype is still selectable as a filter); otherwise offer the
        // distinct subtypes present across all accounts.
        let subtype_opts: Vec<String> = if self.acct_filter_type.is_empty() {
            distinct_values(self.vault_ref().vault.accounts.iter().map(|a| a.account_subtype.clone()))
        } else {
            let ft = self.acct_filter_type.clone();
            // `&ft` passes a shared borrow; the callee reads but does not own it.
            let mut opts = self.vault_ref().categories().subtypes_for(&ft);
            for a in &self.vault_ref().vault.accounts {
                if a.account_type == ft
                    && !a.account_subtype.is_empty()
                    && !opts.contains(&a.account_subtype)
                {
                    opts.push(a.account_subtype.clone());
                }
            }
            opts
        };

        ui.horizontal_wrapped(|ui| {
            ui.label("Filter — type:");
            let prev_type = self.acct_filter_type.clone();
            filter_combo(ui, "acct_ftype", &mut self.acct_filter_type, &type_names);
            if self.acct_filter_type != prev_type {
                self.acct_filter_subtype.clear(); // subtypes are type-specific
            }
            ui.label("subtype:");
            filter_combo(ui, "acct_fsub", &mut self.acct_filter_subtype, &subtype_opts);
            ui.label("owner:");
            filter_combo(ui, "acct_fowner", &mut self.acct_filter_owner, &owners_present);
            ui.checkbox(&mut self.acct_filter_review, "review only");
            if ui.button("Clear").clicked() {
                self.acct_filter_type.clear();
                self.acct_filter_subtype.clear();
                self.acct_filter_owner.clear();
                self.acct_filter_review = false;
            }
        });

        // Filtered list (after the filter row, so a change applies this frame).
        let labels: Vec<(String, String)> = {
            let ft = self.acct_filter_type.clone();
            let fs = self.acct_filter_subtype.clone();
            let fo = self.acct_filter_owner.clone();
            let fr = self.acct_filter_review;
            self.vault_ref()
                .vault
                .accounts
                .iter()
                .filter(|a| ft.is_empty() || a.account_type == ft)
                .filter(|a| fs.is_empty() || a.account_subtype == fs)
                .filter(|a| fo.is_empty() || a.owner == fo)
                .filter(|a| !fr || a.review)
                .map(|a| (a.id.clone(), a.label()))
                .collect()
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

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Accounts", "➕ New", &labels, cur.as_deref(), self.writable);
            let ui = &mut c[1];
            if let Some(r) = self.edit_account.as_mut() {
                egui::Grid::new("acct_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Account type");
                    let prev_type = r.account_type.clone();
                    combo(ui, "acct_type", &mut r.account_type, &type_names);
                    if r.account_type != prev_type {
                        // Subtypes are type-specific; drop a now-mismatched subtype.
                        r.account_subtype.clear();
                    }
                    ui.end_row();
                    ui.label("Subtype");
                    combo(ui, "acct_subtype", &mut r.account_subtype, &subtypes);
                    ui.end_row();
                    ui.label("Owner");
                    ui.add(egui::TextEdit::singleline(&mut r.owner).desired_width(420.0));
                    ui.end_row();
                    ui.label("Username");
                    ui.add(egui::TextEdit::singleline(&mut r.username).desired_width(420.0));
                    ui.end_row();
                    ui.label("Password");
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut r.password).password(!self.reveal_pw).desired_width(280.0));
                        ui.checkbox(&mut self.reveal_pw, "reveal");
                        // Generate is only useful when you can save; copy is a read.
                        if self.writable && ui.button("🎲").on_hover_text("Generate").clicked() {
                            generate = true;
                        }
                        if ui.button("📋").on_hover_text("Copy").clicked() {
                            // Stash a self-wiping copy to act on after rendering.
                            copy_pw = Some(Zeroizing::new(r.password.clone()));
                        }
                    });
                    ui.end_row();
                    ui.label("URL");
                    ui.add(egui::TextEdit::singleline(&mut r.url).desired_width(420.0));
                    ui.end_row();
                    ui.label("Review");
                    ui.checkbox(&mut r.review, "flag for review");
                    ui.end_row();
                });
                ui.label("Description");
                ui.add(egui::TextEdit::multiline(&mut r.description).desired_rows(4).desired_width(f32::INFINITY));
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                ui.label("Select an account or click “New”.");
            }
        });

        if new {
            self.edit_account = Account::new().ok();
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
        if generate
            && let Some(r) = self.edit_account.as_mut()
        {
            // `.unwrap_or_default()` yields the generated password on success or
            // an empty string on the (unexpected) error case, avoiding a panic.
            r.password = password::generate(&GenOptions::default()).unwrap_or_default();
            self.reveal_pw = true;
        }
        if let Some(pw) = copy_pw {
            // `pw` is moved into the call and wiped when it drops there.
            self.copy_to_clipboard(pw);
        }
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_account.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.accounts, r);
                }
                self.persist();
                self.status = "Saved.".into();
            }
            FormAction::Delete => self.delete_current(Tab::Accounts),
            _ => {}
        }
    }

    // --- Tab: Real Estate ----------------------------------------------------

    fn tab_realestate(&mut self, ui: &mut egui::Ui) {
        let labels = label_list(&self.vault_ref().vault.real_estate);
        let cur = self.edit_realestate.as_ref().map(|r| r.id.clone());
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Real Estate", "➕ New", &labels, cur.as_deref(), self.writable);
            let ui = &mut c[1];
            if let Some(r) = self.edit_realestate.as_mut() {
                egui::Grid::new("re_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    text_row(ui, "Address", &mut r.address);
                    text_row(ui, "Ownership", &mut r.ownership);
                    text_row(ui, "Taxes", &mut r.taxes);
                    text_row(ui, "HOA", &mut r.hoa);
                    text_row(ui, "Income account", &mut r.income_account);
                    text_row(ui, "Financing account", &mut r.financing_account);
                    text_row(ui, "Payment account", &mut r.payment_account);
                });
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                ui.label("Select a property or click “New”.");
            }
        });

        if new {
            self.edit_realestate = RealEstate::new().ok();
        }
        if let Some(i) = select {
            self.edit_realestate = self.vault_ref().vault.real_estate.get(i).cloned();
        }
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_realestate.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.real_estate, r);
                }
                self.persist();
                self.status = "Saved.".into();
            }
            FormAction::Delete => self.delete_current(Tab::RealEstate),
            _ => {}
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
        }
    }

    // Performs the document attach/export/detach requested during rendering.
    // Split out so the vault is borrowed mutably *here*, not while drawing.
    fn handle_doc(&mut self, req: DocReq, target: DocTarget) {
        match req {
            DocReq::None => {}
            DocReq::Attach => {
                // Clone the three input strings into a tuple, then destructure.
                let (loc, name, src) =
                    (self.doc_location.clone(), self.doc_filename.clone(), self.doc_source.clone());
                if name.trim().is_empty() || src.trim().is_empty() {
                    self.status = "Filename and 'upload from' path are required.".into();
                    return;
                }
                let vpath = vault::virtual_path(&loc, &name);
                if vpath.len() > crate::storage::MAX_PATH_LEN {
                    self.status = format!(
                        "Path too long: {} bytes (max {}). Shorten the location or filename.",
                        vpath.len(),
                        crate::storage::MAX_PATH_LEN
                    );
                    return;
                }
                // Nested match: get the vault (mut), then attempt the upload. Each
                // branch either yields the new document `id` or returns early.
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
                // Capture any document this record already had, so re-attaching
                // reclaims the replaced blob instead of orphaning it (matches TUI).
                let previous = match target {
                    DocTarget::TrustWill => self.edit_trustwill.as_ref().and_then(|r| r.file.clone()),
                    DocTarget::Asset => self.edit_asset.as_ref().and_then(|r| r.statement.clone()),
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
                }
                // Persist the record→document link immediately so the manifest
                // entry is referenced (no orphan if the user navigates away).
                self.upsert_doc_target(target);
                // Only reclaim the replaced blob if the new link actually reached
                // disk. If the save failed, vault.pmv still references `old`, so
                // dropping it would create a dangling reference (ArchiveMismatch).
                if self.persist()
                    && let Some(old) = previous
                    && let Some(ov) = self.vault.as_mut()
                {
                    // `let _ = ...` deliberately discards the `Result`: a failure
                    // here only orphans a blob (harmless), so it is not reported.
                    let _ = ov.remove_document(&old);
                }
                self.clear_doc_inputs();
                self.status = "Document uploaded to the encrypted volume.".into();
            }
            DocReq::Export => {
                let file_id = match target {
                    DocTarget::TrustWill => self.edit_trustwill.as_ref().and_then(|r| r.file.clone()),
                    DocTarget::Asset => self.edit_asset.as_ref().and_then(|r| r.statement.clone()),
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
                        records::remove(&mut v.real_estate, &r.id, &mut v.audit, "Real Estate");
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
        }
        self.status = "Deleted.".into();
    }

    fn copy_to_clipboard(&mut self, text: Zeroizing<String>) {
        // `text` is wiped on drop; arboard copies into the OS clipboard (cleared
        // on the 15s timer and on exit).
        // `.and_then(|mut c| ...)` on a `Result` runs the closure only if opening
        // the clipboard succeeded; `mut c` is a mutable clipboard handle, and
        // `text.as_str()` borrows the secret as `&str` to write it.
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.as_str())) {
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
}

// Implement eframe's `App` trait so `GuiApp` can be driven by the framework.
// eframe calls `ui()` on every frame to (re)draw the whole window.
impl eframe::App for GuiApp {
    // The leading `_` in `_frame` marks the parameter as intentionally unused.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.tick_clipboard(ui.ctx());
        if self.screen == Screen::Auth {
            egui::CentralPanel::default().show_inside(ui, |ui| self.ui_auth(ui));
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
        // Draw the active tab. The closure body is a `match` selecting which
        // tab-rendering method to call based on the current `self.tab`.
        egui::CentralPanel::default().show_inside(ui, |ui| match self.tab {
            Tab::Instructions => self.tab_instructions(ui),
            Tab::TrustWill => self.tab_trustwill(ui),
            Tab::Assets => self.tab_assets(ui),
            Tab::Accounts => self.tab_accounts(ui),
            Tab::RealEstate => self.tab_realestate(ui),
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
fn text_row(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(value).desired_width(420.0));
    ui.end_row();
}

/// Sorted, de-duplicated, non-empty values — used to populate filter dropdowns.
// `impl Iterator<Item = String>` is a generic parameter: accept *any* iterator
// yielding `String`s (the caller decides the concrete type). `.dedup()` removes
// *consecutive* duplicates, which is why it follows `.sort()`.
fn distinct_values(values: impl Iterator<Item = String>) -> Vec<String> {
    let mut v: Vec<String> = values.filter(|s| !s.is_empty()).collect();
    v.sort();
    v.dedup();
    v
}

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

/// A dropdown restricted to `options`.
fn combo(ui: &mut egui::Ui, id: &str, value: &mut String, options: &[String]) {
    let current = if value.is_empty() { "(choose)".to_string() } else { value.clone() };
    egui::ComboBox::from_id_salt(id).selected_text(current).show_ui(ui, |ui| {
        for opt in options {
            ui.selectable_value(value, opt.clone(), opt);
        }
    });
}

/// The document attach / export / detach section. Returns the requested action;
/// the caller performs the actual volume operation (to keep `self` borrows
/// disjoint). `attached_present` reflects whether the record currently has a file.
// `#[allow(...)]` silences a specific lint (here: the linter's "too many
// arguments" warning) — it does not change behavior. The `&mut String` inputs
// are the caller's text buffers, edited in place by the widgets below.
#[allow(clippy::too_many_arguments)]
fn doc_section(
    ui: &mut egui::Ui,
    label: &str,
    attached_present: bool,
    attached_label: Option<&str>,
    location: &mut String,
    filename: &mut String,
    source: &mut String,
    dest: &mut String,
    writable: bool,
) -> DocReq {
    let mut req = DocReq::None;
    ui.label(egui::RichText::new(format!("{label} (encrypted volume)")).strong());
    if attached_present {
        // `.unwrap_or("(unknown)")` yields the label if present, else a fallback
        // string — never panics.
        ui.label(format!("Attached: {}", attached_label.unwrap_or("(unknown)")));
        ui.horizontal(|ui| {
            // Export is a read and is always allowed; Detach mutates the vault.
            ui.label("Export to:");
            ui.add(egui::TextEdit::singleline(dest).hint_text("/path/to/save/as").desired_width(300.0));
            if ui.button("Export").clicked() {
                req = DocReq::Export;
            }
            if writable && ui.button("Detach").clicked() {
                req = DocReq::Remove;
            }
        });
    } else if writable {
        egui::Grid::new(format!("doc_{label}")).num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
            ui.label("Location");
            ui.add(egui::TextEdit::singleline(location).hint_text("/statements/2026").desired_width(300.0));
            ui.end_row();
            ui.label("Filename");
            ui.add(egui::TextEdit::singleline(filename).hint_text("statement.pdf").desired_width(300.0));
            ui.end_row();
            ui.label("Upload from");
            ui.add(egui::TextEdit::singleline(source).hint_text("/path/on/disk/file.pdf").desired_width(300.0));
            ui.end_row();
        });
        // Validate the virtual path length live (same check the core enforces) so
        // the limit is surfaced before attaching, and block the button if over.
        let vpath_len = vault::virtual_path(location, filename).len();
        let over_limit = vpath_len > crate::storage::MAX_PATH_LEN;
        if over_limit {
            ui.colored_label(
                egui::Color32::from_rgb(0xC0, 0x30, 0x30),
                format!("Path too long: {vpath_len} / {} bytes — shorten the location or filename.", crate::storage::MAX_PATH_LEN),
            );
        }
        if ui.add_enabled(!over_limit, egui::Button::new("⬆ Attach (encrypt into volume)")).clicked() {
            req = DocReq::Attach;
        }
    } else {
        ui.label(egui::RichText::new("(no document attached)").weak());
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
                let detail = if c.detail.is_empty() { c.action.clone() } else { c.detail.clone() };
                ui.label(format!("{}  —  {detail}", format_time(c.at)));
            }
        });
    });
}

/// A masked single-line password field; returns true if Enter was pressed.
fn password_field(ui: &mut egui::Ui, value: &mut String) -> bool {
    let resp = ui.add(egui::TextEdit::singleline(value).password(true).desired_width(280.0));
    // The final expression (no `;`) is the return value. `ui.input(|i| ...)`
    // passes a closure that inspects the frame's input state; this returns true
    // when the field just lost focus AND Enter was pressed.
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
        app.doc_location = "/wills".into();
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
    fn over_length_doc_path_is_rejected_in_gui() {
        let (mut app, path) = app_unlocked("guipath");
        let src = std::env::temp_dir().join(format!("passmgr-guipath-{}.txt", nanos()));
        std::fs::write(&src, b"x").unwrap();
        app.edit_asset = Some(AssetLiability::new().unwrap());
        // A filename that alone pushes the virtual path past MAX_PATH_LEN bytes.
        app.doc_location = "/d".into();
        app.doc_filename = "f".repeat(crate::storage::MAX_PATH_LEN);
        app.doc_source = src.display().to_string();
        app.handle_doc(DocReq::Attach, DocTarget::Asset);
        assert!(app.status.contains("too long"), "status was: {}", app.status);
        assert!(app.edit_asset.as_ref().unwrap().statement.is_none(), "nothing attached");
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
