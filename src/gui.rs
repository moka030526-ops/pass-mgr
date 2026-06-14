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

use std::path::Path;

use eframe::egui;
use zeroize::Zeroize;

use crate::password::{self, GenOptions};
use crate::records::{self, Account, AssetLiability, Instruction, RealEstate, Record, TrustWill};
use crate::types::TypeLists;
use crate::ui::format_time;
use crate::vault::{OpenVault, VaultError};
use crate::crypto::KdfParams;

/// Launch the graphical app and block until the window is closed.
pub fn run(path: std::path::PathBuf, types: TypeLists) -> anyhow::Result<()> {
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
        Box::new(|cc| {
            // Lighter, higher-contrast theme.
            cc.egui_ctx.set_visuals(light_visuals());
            Ok(Box::new(GuiApp::new(path, types)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {e}"))
}

/// A light egui theme, a touch warmer/brighter than the default light visuals.
fn light_visuals() -> egui::Visuals {
    let mut v = egui::Visuals::light();
    v.panel_fill = egui::Color32::from_rgb(248, 249, 251);
    v.window_fill = egui::Color32::from_rgb(252, 252, 253);
    v.extreme_bg_color = egui::Color32::from_rgb(255, 255, 255);
    v.selection.bg_fill = egui::Color32::from_rgb(180, 210, 255);
    v.selection.stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(40, 90, 170));
    v
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Screen {
    Auth,
    Main,
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

struct GuiApp {
    path: std::path::PathBuf,
    types: TypeLists,
    screen: Screen,
    // Auth.
    auth_mode: AuthMode,
    pw1: String,
    confirm1: String,
    pw2: String,
    confirm2: String,
    auth_error: Option<String>,
    // Unlocked vault.
    vault: Option<OpenVault>,
    // Tabs + per-tab working edit buffer.
    tab: Tab,
    edit_instruction: Option<Instruction>,
    edit_trustwill: Option<TrustWill>,
    edit_asset: Option<AssetLiability>,
    edit_account: Option<Account>,
    edit_realestate: Option<RealEstate>,
    reveal_pw: bool,
    // Shared document-attach input buffers.
    doc_location: String,
    doc_filename: String,
    doc_source: String,
    doc_dest: String,
    status: String,
    clipboard_dirty: bool,
}

impl Drop for GuiApp {
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

impl GuiApp {
    fn new(path: std::path::PathBuf, types: TypeLists) -> Self {
        let auth_mode = if path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        GuiApp {
            path,
            types,
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
            doc_location: String::new(),
            doc_filename: String::new(),
            doc_source: String::new(),
            doc_dest: String::new(),
            status: String::new(),
            clipboard_dirty: false,
        }
    }

    fn vault_ref(&self) -> &OpenVault {
        self.vault.as_ref().expect("vault is open on the main screen")
    }

    /// Persist the in-memory vault, reporting any error to the status bar.
    fn persist(&mut self) {
        if let Some(ov) = self.vault.as_ref()
            && let Err(e) = ov.save()
        {
            self.status = format!("Save failed: {e}");
        }
    }

    fn clear_doc_inputs(&mut self) {
        self.doc_location.clear();
        self.doc_filename.clear();
        self.doc_source.clear();
        self.doc_dest.clear();
    }

    // --- Auth ----------------------------------------------------------------

    fn confirmed_passwords(&self) -> Result<(String, String), String> {
        if self.pw1.is_empty() || self.pw2.is_empty() {
            return Err("Both passwords are required.".into());
        }
        if self.pw1 != self.confirm1 || self.pw2 != self.confirm2 {
            return Err("Password confirmations do not match.".into());
        }
        Ok((self.pw1.clone(), self.pw2.clone()))
    }

    fn submit_auth(&mut self) {
        match self.auth_mode {
            AuthMode::ChangePassword => {
                let (pw1, pw2) = match self.confirmed_passwords() {
                    Ok(p) => p,
                    Err(m) => {
                        self.auth_error = Some(m);
                        return;
                    }
                };
                if let Some(ov) = self.vault.as_mut() {
                    match ov.change_password(pw1.as_bytes(), pw2.as_bytes()) {
                        Ok(()) => {
                            self.status = "Master passwords changed.".into();
                            self.auth_error = None;
                            self.wipe_passwords();
                            self.screen = Screen::Main;
                        }
                        Err(e) => self.auth_error = Some(format!("{e}")),
                    }
                }
            }
            AuthMode::Create | AuthMode::Unlock => self.submit_open_or_create(),
        }
    }

    fn submit_open_or_create(&mut self) {
        let creating = self.auth_mode == AuthMode::Create;
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
            OpenVault::open(self.path.clone(), self.pw1.as_bytes(), self.pw2.as_bytes())
        };

        match result {
            Ok(v) => {
                self.status = if creating {
                    "New vault created.".to_string()
                } else if v.previous_access() == 0 {
                    "Vault unlocked.".to_string()
                } else {
                    format!("Unlocked. Last opened: {}", format_time(v.previous_access()))
                };
                self.vault = Some(v);
                self.auth_error = None;
                self.wipe_passwords();
                self.screen = Screen::Main;
            }
            Err(VaultError::Crypto(_)) => {
                self.auth_error = Some("Wrong password(s) or corrupted vault.".into());
            }
            Err(e) => self.auth_error = Some(format!("{e}")),
        }
    }

    fn wipe_passwords(&mut self) {
        self.pw1.zeroize();
        self.confirm1.zeroize();
        self.pw2.zeroize();
        self.confirm2.zeroize();
    }

    fn ui_auth(&mut self, ui: &mut egui::Ui) {
        let (heading, help) = match self.auth_mode {
            AuthMode::Create => ("Create vault", "Choose two passwords. Both are required to open this vault."),
            AuthMode::Unlock => ("Unlock vault", "Enter both passwords to unlock."),
            AuthMode::ChangePassword => ("Change master passwords", "Set two new passwords."),
        };
        let confirm = self.auth_mode != AuthMode::Unlock;

        ui.add_space(28.0);
        ui.vertical_centered(|ui| {
            ui.heading(heading);
            ui.label(egui::RichText::new(format!("Vault: {}", self.path.display())).weak());
            ui.label(help);
        });
        ui.add_space(16.0);

        let mut submit = false;
        egui::Grid::new("auth_grid").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
            ui.label("Password 1");
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
            if ui.button("🔑 Passwords").clicked() {
                self.auth_mode = AuthMode::ChangePassword;
                self.auth_error = None;
                self.wipe_passwords();
                self.screen = Screen::Auth;
            }
            if ui.button("Quit").clicked() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });
    }

    // --- Tab: Instructions ---------------------------------------------------

    fn tab_instructions(&mut self, ui: &mut egui::Ui) {
        let labels = label_list(&self.vault_ref().vault.instructions);
        let cur = self.edit_instruction.as_ref().map(|r| r.id.clone());
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Instructions", "➕ New", &labels, cur.as_deref());
            let ui = &mut c[1];
            if let Some(r) = self.edit_instruction.as_mut() {
                egui::Grid::new("instr_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Title");
                    ui.add(egui::TextEdit::singleline(&mut r.title).desired_width(420.0));
                    ui.end_row();
                });
                ui.label("Description");
                ui.add(egui::TextEdit::multiline(&mut r.description).desired_rows(12).desired_width(f32::INFINITY));
                action = form_buttons(ui);
                history_view(ui, &r.history);
            } else {
                ui.label("Select an instruction or click “New”.");
            }
        });

        if new {
            self.edit_instruction = Instruction::new().ok();
        }
        if let Some(i) = select {
            self.edit_instruction = self.vault_ref().vault.instructions.get(i).cloned();
        }
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_instruction.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.instructions, r);
                }
                self.persist();
                self.status = "Saved.".into();
            }
            FormAction::Delete => self.delete_current(Tab::Instructions),
            _ => {}
        }
    }

    // --- Tab: Trust and Will -------------------------------------------------

    fn tab_trustwill(&mut self, ui: &mut egui::Ui) {
        let labels = label_list(&self.vault_ref().vault.trust_wills);
        let cur = self.edit_trustwill.as_ref().map(|r| r.id.clone());
        let attached = self.attached_label(self.edit_trustwill.as_ref().and_then(|r| r.file.clone()));
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut docreq = DocReq::None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Trust and Will", "➕ New", &labels, cur.as_deref());
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
                );
                action = form_buttons(ui);
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
        let labels = label_list(&self.vault_ref().vault.assets);
        let cur = self.edit_asset.as_ref().map(|r| r.id.clone());
        let attached = self.attached_label(self.edit_asset.as_ref().and_then(|r| r.statement.clone()));
        let asset_types = self.types.asset.clone();
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut docreq = DocReq::None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Assets and Liabilities", "➕ New", &labels, cur.as_deref());
            let ui = &mut c[1];
            if let Some(r) = self.edit_asset.as_mut() {
                egui::Grid::new("asset_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Asset / Liability");
                    combo(ui, "asset_kind", &mut r.kind, &["Asset".to_string(), "Liability".to_string()]);
                    ui.end_row();
                    ui.label("Description");
                    ui.add(egui::TextEdit::singleline(&mut r.description).desired_width(420.0));
                    ui.end_row();
                    ui.label("Owner");
                    ui.add(egui::TextEdit::singleline(&mut r.owner).desired_width(420.0));
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
                });
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
                );
                action = form_buttons(ui);
                history_view(ui, &r.history);
            } else {
                ui.label("Select an asset/liability or click “New”.");
            }
        });

        if new {
            self.edit_asset = AssetLiability::new().ok();
            self.clear_doc_inputs();
        }
        if let Some(i) = select {
            self.edit_asset = self.vault_ref().vault.assets.get(i).cloned();
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
        let labels = label_list(&self.vault_ref().vault.accounts);
        let cur = self.edit_account.as_ref().map(|r| r.id.clone());
        let account_types = self.types.account.clone();
        let mut new = false;
        let mut select = None;
        let mut action = FormAction::None;
        let mut generate = false;
        let mut copy_pw: Option<String> = None;

        ui.columns(2, |c| {
            (new, select) = list_panel(&mut c[0], "Accounts", "➕ New", &labels, cur.as_deref());
            let ui = &mut c[1];
            if let Some(r) = self.edit_account.as_mut() {
                egui::Grid::new("acct_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Account type");
                    combo(ui, "acct_type", &mut r.account_type, &account_types);
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
                        if ui.button("🎲").on_hover_text("Generate").clicked() {
                            generate = true;
                        }
                        if ui.button("📋").on_hover_text("Copy").clicked() {
                            copy_pw = Some(r.password.clone());
                        }
                    });
                    ui.end_row();
                    ui.label("URL");
                    ui.add(egui::TextEdit::singleline(&mut r.url).desired_width(420.0));
                    ui.end_row();
                });
                ui.label("Description");
                ui.add(egui::TextEdit::multiline(&mut r.description).desired_rows(4).desired_width(f32::INFINITY));
                action = form_buttons(ui);
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
            self.edit_account = self.vault_ref().vault.accounts.get(i).cloned();
            self.reveal_pw = false;
        }
        if generate
            && let Some(r) = self.edit_account.as_mut()
        {
            r.password = password::generate(&GenOptions::default()).unwrap_or_default();
            self.reveal_pw = true;
        }
        if let Some(pw) = copy_pw {
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
            (new, select) = list_panel(&mut c[0], "Real Estate", "➕ New", &labels, cur.as_deref());
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
                action = form_buttons(ui);
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
        let id = file_id?;
        let f = self.vault_ref().vault.volume.file(&id)?;
        let loc = if f.location.is_empty() { "/".to_string() } else { f.location.clone() };
        Some(format!("{loc}/{}  ({} bytes)", f.filename, f.size))
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

    fn handle_doc(&mut self, req: DocReq, target: DocTarget) {
        match req {
            DocReq::None => {}
            DocReq::Attach => {
                let (loc, name, src) =
                    (self.doc_location.clone(), self.doc_filename.clone(), self.doc_source.clone());
                if name.trim().is_empty() || src.trim().is_empty() {
                    self.status = "Filename and 'upload from' path are required.".into();
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
                self.persist();
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
                if let Some(id) = id
                    && let Some(ov) = self.vault.as_mut()
                    && let Err(e) = ov.remove_document(&id)
                {
                    self.status = format!("Unlinked, but blob cleanup failed: {e}");
                    return;
                }
                self.persist();
                self.status = "Removed document from the vault.".into();
            }
        }
    }

    fn delete_current(&mut self, tab: Tab) {
        // Collect any attached document ids to reclaim after removing the record.
        let mut doc_ids: Vec<String> = Vec::new();
        if let Some(ov) = self.vault.as_mut() {
            let v = &mut ov.vault;
            match tab {
                Tab::Instructions => {
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
        for id in doc_ids {
            if let Some(ov) = self.vault.as_mut() {
                let _ = ov.remove_document(&id);
            }
        }
        self.persist();
        self.status = "Deleted.".into();
    }

    fn copy_to_clipboard(&mut self, text: String) {
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(text)) {
            Ok(()) => {
                self.clipboard_dirty = true;
                self.status = "Copied (clipboard clears on exit).".into();
            }
            Err(e) => self.status = format!("Clipboard unavailable: {e}"),
        }
    }
}

#[derive(Clone, Copy)]
enum DocTarget {
    TrustWill,
    Asset,
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if self.screen == Screen::Auth {
            egui::CentralPanel::default().show_inside(ui, |ui| self.ui_auth(ui));
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

fn tab_button(ui: &mut egui::Ui, current: &mut Tab, tab: Tab, label: &str) {
    if ui.selectable_label(*current == tab, label).clicked() {
        *current = tab;
    }
}

/// Render the left list panel; return `(new_clicked, selected_index)`.
fn list_panel(
    ui: &mut egui::Ui,
    title: &str,
    new_label: &str,
    labels: &[(String, String)],
    current_id: Option<&str>,
) -> (bool, Option<usize>) {
    let mut new = false;
    let mut select = None;
    ui.horizontal(|ui| {
        ui.heading(title);
    });
    if ui.button(new_label).clicked() {
        new = true;
    }
    ui.separator();
    ui.label(egui::RichText::new(format!("{} item(s)", labels.len())).weak());
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        for (i, (id, label)) in labels.iter().enumerate() {
            let selected = current_id == Some(id.as_str());
            if ui.selectable_label(selected, label).clicked() {
                select = Some(i);
            }
        }
    });
    (new, select)
}

/// Save / Delete buttons; returns the chosen action.
fn form_buttons(ui: &mut egui::Ui) -> FormAction {
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
fn text_row(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(value).desired_width(420.0));
    ui.end_row();
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
) -> DocReq {
    let mut req = DocReq::None;
    ui.label(egui::RichText::new(format!("{label} (encrypted volume)")).strong());
    if attached_present {
        ui.label(format!("Attached: {}", attached_label.unwrap_or("(unknown)")));
        ui.horizontal(|ui| {
            ui.label("Export to:");
            ui.add(egui::TextEdit::singleline(dest).hint_text("/path/to/save/as").desired_width(300.0));
            if ui.button("Export").clicked() {
                req = DocReq::Export;
            }
            if ui.button("Detach").clicked() {
                req = DocReq::Remove;
            }
        });
    } else {
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
        if ui.button("⬆ Attach (encrypt into volume)").clicked() {
            req = DocReq::Attach;
        }
    }
    req
}

/// A collapsing, timestamped history view for a record.
fn history_view(ui: &mut egui::Ui, history: &[records::Change]) {
    ui.add_space(8.0);
    egui::CollapsingHeader::new("History").default_open(false).show(ui, |ui| {
        if history.is_empty() {
            ui.label(egui::RichText::new("(no changes recorded)").weak());
        }
        egui::ScrollArea::vertical().max_height(180.0).id_salt("hist").show(ui, |ui| {
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
    resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

/// Build `(id, label)` pairs for a record list.
fn label_list<R: Record>(list: &[R]) -> Vec<(String, String)> {
    list.iter().map(|r| (r.id().to_string(), r.label())).collect()
}

/// Best-effort clearing of the system clipboard on exit.
fn clear_clipboard() {
    let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(String::new()));
}
