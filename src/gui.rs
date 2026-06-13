//! Graphical interface for pass-mgr, built with egui/eframe.
//!
//! This is an alternative front-end to the terminal UI in [`crate::ui`]; both
//! drive the exact same [`OpenVault`] API, so all crypto and data-model logic is
//! shared and untouched. Like the TUI it is a small state machine over four
//! screens (Auth / List / Detail / Edit). egui is immediate-mode: each frame
//! rebuilds the widgets and handles events inline.

use std::path::PathBuf;

use eframe::egui;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::KdfParams;
use crate::password::{self, GenOptions};
use crate::ui::format_time;
use crate::vault::{Entry, OpenVault, VaultError};

/// Launch the graphical app and block until the window is closed.
pub fn run(path: PathBuf) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 620.0])
            .with_min_inner_size([600.0, 400.0])
            .with_title("pass-mgr"),
        ..Default::default()
    };
    eframe::run_native(
        "pass-mgr",
        options,
        Box::new(|_cc| Ok(Box::new(GuiApp::new(path)))),
    )
    .map_err(|e| anyhow::anyhow!("GUI error: {e}"))
}

#[derive(PartialEq, Eq)]
enum Screen {
    Auth,
    List,
    Detail,
    Edit,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum AuthMode {
    Create,
    Unlock,
    ChangePassword,
}

/// Working copy of the entry being edited (`id` = None for a new entry). Holds
/// an entry's plaintext password while editing, so it wipes its fields on drop.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct EditState {
    id: Option<String>,
    title: String,
    kind: String,
    description: String,
    username: String,
    password: String,
    url: String,
    reveal: bool,
}

struct GuiApp {
    path: PathBuf,
    screen: Screen,
    // Auth screen.
    auth_mode: AuthMode,
    pw1: String,
    confirm1: String,
    pw2: String,
    confirm2: String,
    auth_error: Option<String>,
    // The unlocked vault (None until authenticated).
    vault: Option<OpenVault>,
    // List screen.
    search: String,
    filter_kind: Option<String>,
    // Detail screen.
    selected_id: Option<String>,
    reveal: bool,
    // Edit screen.
    edit: EditState,
    // Transient feedback shown in the status bar.
    status: String,
    // Set once a password has been copied, so we clear the clipboard on exit.
    clipboard_dirty: bool,
}

impl Drop for GuiApp {
    fn drop(&mut self) {
        // Wipe the password input buffers and clear a copied password from the
        // clipboard when the window closes (the vault/edit zeroize themselves).
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
    fn new(path: PathBuf) -> Self {
        let auth_mode = if path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        GuiApp {
            path,
            screen: Screen::Auth,
            auth_mode,
            pw1: String::new(),
            confirm1: String::new(),
            pw2: String::new(),
            confirm2: String::new(),
            auth_error: None,
            vault: None,
            search: String::new(),
            filter_kind: None,
            selected_id: None,
            reveal: false,
            edit: EditState::default(),
            status: String::new(),
            clipboard_dirty: false,
        }
    }

    fn clear_passwords(&mut self) {
        // zeroize() overwrites the heap bytes before clearing (unlike clear()).
        self.pw1.zeroize();
        self.confirm1.zeroize();
        self.pw2.zeroize();
        self.confirm2.zeroize();
    }

    fn selected_entry(&self) -> Option<&Entry> {
        let id = self.selected_id.as_ref()?;
        self.vault.as_ref()?.vault.entries.iter().find(|e| &e.id == id)
    }

    // --- Auth ----------------------------------------------------------------

    /// Validate the confirmed-password fields, returning `(pw1, pw2)` or an error.
    fn confirmed_passwords(&self) -> Result<(Zeroizing<String>, Zeroizing<String>), String> {
        if self.pw1.is_empty() || self.pw2.is_empty() {
            return Err("Both passwords are required.".into());
        }
        if self.pw1 != self.confirm1 || self.pw2 != self.confirm2 {
            return Err("Password confirmations do not match.".into());
        }
        Ok((Zeroizing::new(self.pw1.clone()), Zeroizing::new(self.pw2.clone())))
    }

    fn submit_auth(&mut self) {
        match self.auth_mode {
            AuthMode::ChangePassword => self.submit_change_password(),
            AuthMode::Create | AuthMode::Unlock => self.submit_open_or_create(),
        }
    }

    fn submit_open_or_create(&mut self) {
        let creating = self.auth_mode == AuthMode::Create;
        let result = if creating {
            let (pw1, pw2) = match self.confirmed_passwords() {
                Ok(pair) => pair,
                Err(msg) => {
                    self.auth_error = Some(msg);
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
                    format!("Vault unlocked. Last opened: {}", format_time(v.previous_access()))
                };
                self.vault = Some(v);
                self.auth_error = None;
                self.clear_passwords();
                self.screen = Screen::List;
            }
            Err(VaultError::Crypto(_)) => {
                self.auth_error = Some("Wrong password(s) or corrupted vault.".into());
            }
            Err(e) => self.auth_error = Some(format!("{e}")),
        }
    }

    fn submit_change_password(&mut self) {
        let (pw1, pw2) = match self.confirmed_passwords() {
            Ok(pair) => pair,
            Err(msg) => {
                self.auth_error = Some(msg);
                return;
            }
        };
        let Some(v) = self.vault.as_mut() else { return };
        match v.change_password(pw1.as_bytes(), pw2.as_bytes()) {
            Ok(()) => {
                self.status = "Master passwords changed.".into();
                self.auth_error = None;
                self.clear_passwords();
                self.screen = Screen::List;
            }
            Err(e) => self.auth_error = Some(format!("{e}")),
        }
    }

    fn begin_change_password(&mut self) {
        self.auth_mode = AuthMode::ChangePassword;
        self.auth_error = None;
        self.clear_passwords();
        self.screen = Screen::Auth;
    }

    // --- Edit ----------------------------------------------------------------

    fn begin_new_entry(&mut self) {
        self.edit = EditState::default();
        self.screen = Screen::Edit;
    }

    fn begin_edit_selected(&mut self) {
        if let Some(e) = self.selected_entry() {
            self.edit = EditState {
                id: Some(e.id.clone()),
                title: e.title.clone(),
                kind: e.kind.clone(),
                description: e.description.clone(),
                username: e.username.clone(),
                password: e.password.clone(),
                url: e.url.clone(),
                reveal: false,
            };
            self.screen = Screen::Edit;
        }
    }

    fn generate_password(&mut self) {
        match password::generate(&GenOptions::default()) {
            Ok(pw) => {
                self.edit.password = pw;
                self.edit.reveal = true;
                self.status = "Generated a random password.".into();
            }
            Err(e) => self.status = format!("Generation failed: {e}"),
        }
    }

    fn save_edit(&mut self) {
        if self.edit.title.trim().is_empty() {
            self.status = "Title is required.".into();
            return;
        }
        let Some(v) = self.vault.as_mut() else { return };

        let mut entry = match &self.edit.id {
            Some(id) => v
                .vault
                .entries
                .iter()
                .find(|e| &e.id == id)
                .cloned()
                .unwrap_or_default(),
            None => match Entry::new(self.edit.title.clone()) {
                Ok(e) => e,
                Err(e) => {
                    self.status = format!("Could not create entry: {e}");
                    return;
                }
            },
        };
        entry.title = self.edit.title.clone();
        entry.kind = self.edit.kind.clone();
        entry.description = self.edit.description.clone();
        entry.username = self.edit.username.clone();
        entry.password = self.edit.password.clone();
        entry.url = self.edit.url.clone();

        let new_id = entry.id.clone();
        v.vault.upsert(entry);
        match v.save() {
            Ok(()) => {
                self.status = "Saved.".into();
                self.selected_id = Some(new_id);
                self.screen = Screen::Detail;
            }
            Err(e) => self.status = format!("Save failed: {e}"),
        }
    }

    fn delete_selected(&mut self) {
        let Some(id) = self.selected_id.clone() else { return };
        if let Some(v) = self.vault.as_mut() {
            v.vault.remove(&id);
            match v.save() {
                Ok(()) => self.status = "Entry deleted.".into(),
                Err(e) => self.status = format!("Save failed: {e}"),
            }
        }
        self.selected_id = None;
        self.screen = Screen::List;
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

    // --- Drawing -------------------------------------------------------------

    fn ui_auth(&mut self, ui: &mut egui::Ui) {
        let (heading, help) = match self.auth_mode {
            AuthMode::Create => (
                "Create vault",
                "Choose two passwords. Both are required to open this vault.",
            ),
            AuthMode::Unlock => ("Unlock vault", "Enter both passwords to unlock."),
            AuthMode::ChangePassword => (
                "Change master passwords",
                "Set two new passwords. They replace the current ones immediately.",
            ),
        };
        let confirm = self.auth_mode != AuthMode::Unlock;

        ui.add_space(24.0);
        ui.vertical_centered(|ui| {
            ui.heading(heading);
            ui.label(egui::RichText::new(format!("Vault: {}", self.path.display())).weak());
            ui.label(help);
        });
        ui.add_space(16.0);

        let mut submit = false;
        egui::Grid::new("auth_grid")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
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
            ui.colored_label(egui::Color32::from_rgb(220, 80, 80), err);
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
                self.clear_passwords();
                self.screen = Screen::List;
            }
        });

        if submit {
            self.submit_auth();
        }
    }

    fn ui_list(&mut self, ui: &mut egui::Ui) {
        // Snapshot what we need so we don't hold a vault borrow across closures
        // that also mutate `self`.
        let types: Vec<String> = self.vault.as_ref().map(|v| v.vault.types.clone()).unwrap_or_default();
        let rows: Vec<(String, String)> = match &self.vault {
            Some(v) => v
                .vault
                .filter(&self.search, self.filter_kind.as_deref())
                .iter()
                .map(|e| {
                    let prefix = if e.kind.is_empty() { String::new() } else { format!("[{}] ", e.kind) };
                    let user = if e.username.is_empty() { String::new() } else { format!("   ({})", e.username) };
                    (e.id.clone(), format!("{prefix}{}{user}", e.title))
                })
                .collect(),
            None => Vec::new(),
        };

        ui.horizontal(|ui| {
            ui.label("Search:");
            ui.add(egui::TextEdit::singleline(&mut self.search).desired_width(240.0));
            if ui.button("➕ New entry").clicked() {
                self.begin_new_entry();
            }
            if ui.button("🔑 Change passwords").clicked() {
                self.begin_change_password();
            }
            if ui.button("Quit").clicked() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        });

        ui.horizontal_wrapped(|ui| {
            ui.label("Type:");
            if ui.selectable_label(self.filter_kind.is_none(), "All").clicked() {
                self.filter_kind = None;
            }
            for t in &types {
                let selected = self.filter_kind.as_deref() == Some(t.as_str());
                if ui.selectable_label(selected, t).clicked() {
                    self.filter_kind = Some(t.clone());
                }
            }
        });

        ui.separator();
        ui.label(egui::RichText::new(format!("{} entr{}", rows.len(), if rows.len() == 1 { "y" } else { "ies" })).weak());

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if rows.is_empty() {
                ui.label(egui::RichText::new("No entries. Click “New entry” to add one.").weak());
            }
            for (id, label) in rows {
                if ui.add(egui::Button::selectable(false, label)).clicked() {
                    self.selected_id = Some(id);
                    self.reveal = false;
                    self.screen = Screen::Detail;
                }
            }
        });
    }

    fn ui_detail(&mut self, ui: &mut egui::Ui) {
        // Clone the entry so we can render and mutate `self` (buttons) freely.
        let Some(entry) = self.selected_entry().cloned() else {
            self.screen = Screen::List;
            return;
        };

        ui.horizontal(|ui| {
            if ui.button("⬅ Back").clicked() {
                self.screen = Screen::List;
            }
            if ui.button("✏ Edit").clicked() {
                self.begin_edit_selected();
            }
            if ui.button("🗑 Delete").clicked() {
                self.delete_selected();
            }
        });
        ui.separator();
        ui.heading(&entry.title);

        let shown_pw = if self.reveal {
            entry.password.clone()
        } else {
            "•".repeat(entry.password.chars().count())
        };

        egui::Grid::new("detail_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
            detail_row(ui, "Type", &entry.kind);
            detail_row(ui, "Username", &entry.username);

            ui.label(egui::RichText::new("Password").strong());
            ui.horizontal(|ui| {
                ui.monospace(&shown_pw);
                ui.checkbox(&mut self.reveal, "reveal");
                if ui.button("📋 Copy").clicked() {
                    self.copy_to_clipboard(entry.password.clone());
                }
            });
            ui.end_row();

            detail_row(ui, "URL", &entry.url);
            detail_row(ui, "Description", &entry.description);
            ui.end_row();
        });

        ui.add_space(6.0);
        ui.label(
            egui::RichText::new(format!(
                "Created {}    Updated {}",
                format_time(entry.created_at),
                format_time(entry.updated_at)
            ))
            .weak(),
        );

        ui.add_space(8.0);
        egui::CollapsingHeader::new("History").default_open(false).show(ui, |ui| {
            if entry.history.is_empty() {
                ui.label(egui::RichText::new("(no changes recorded)").weak());
            }
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                for change in entry.history.iter().rev() {
                    let detail = if change.detail.is_empty() { change.action.clone() } else { change.detail.clone() };
                    ui.label(format!("{}  —  {detail}", format_time(change.at)));
                }
            });
        });
    }

    fn ui_edit(&mut self, ui: &mut egui::Ui) {
        let heading = if self.edit.id.is_some() { "Edit entry" } else { "New entry" };
        ui.heading(heading);
        ui.separator();

        egui::Grid::new("edit_grid").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
            ui.label("Title");
            ui.add(egui::TextEdit::singleline(&mut self.edit.title).desired_width(360.0));
            ui.end_row();

            ui.label("Type");
            ui.add(egui::TextEdit::singleline(&mut self.edit.kind).desired_width(360.0).hint_text("e.g. Login, Server, Card"));
            ui.end_row();

            ui.label("Description");
            ui.add(egui::TextEdit::multiline(&mut self.edit.description).desired_width(360.0).desired_rows(2));
            ui.end_row();

            ui.label("Username");
            ui.add(egui::TextEdit::singleline(&mut self.edit.username).desired_width(360.0));
            ui.end_row();

            ui.label("Password");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.edit.password)
                        .desired_width(280.0)
                        .password(!self.edit.reveal),
                );
                ui.checkbox(&mut self.edit.reveal, "reveal");
            });
            ui.end_row();

            ui.label("");
            if ui.button("🎲 Generate random password").clicked() {
                self.generate_password();
            }
            ui.end_row();

            ui.label("URL");
            ui.add(egui::TextEdit::singleline(&mut self.edit.url).desired_width(360.0));
            ui.end_row();
        });

        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("💾 Save").clicked() {
                self.save_edit();
            }
            if ui.button("Cancel").clicked() {
                self.screen = if self.edit.id.is_some() { Screen::Detail } else { Screen::List };
            }
        });
    }
}

impl eframe::App for GuiApp {
    // eframe 0.34 hands the app a root `Ui`; panels are nested with show_inside.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Status bar at the bottom (shown once a vault is open).
        if self.vault.is_some() && !self.status.is_empty() {
            egui::Panel::bottom("status_bar").show_inside(ui, |ui| {
                ui.label(egui::RichText::new(&self.status).weak());
            });
        }

        egui::CentralPanel::default().show_inside(ui, |ui| match self.screen {
            Screen::Auth => self.ui_auth(ui),
            Screen::List => self.ui_list(ui),
            Screen::Detail => self.ui_detail(ui),
            Screen::Edit => self.ui_edit(ui),
        });
    }
}

/// Best-effort overwrite of the system clipboard with empty text, so a copied
/// password does not linger after the window is closed.
fn clear_clipboard() {
    let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(String::new()));
}

/// A masked single-line password field. Returns true if Enter was pressed in it
/// (so the caller can submit the form).
fn password_field(ui: &mut egui::Ui, value: &mut String) -> bool {
    let resp = ui.add(egui::TextEdit::singleline(value).password(true).desired_width(280.0));
    resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

/// A `Label: value` row inside a detail Grid.
fn detail_row(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(egui::RichText::new(label).strong());
    ui.label(value);
    ui.end_row();
}
