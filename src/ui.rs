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

use std::path::{Path, PathBuf};

use ratatui::DefaultTerminal;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::KdfParams;
use crate::password::{self, GenOptions};
use crate::records::{
    self, Account, AssetLiability, Change, Instruction, RealEstate, Record, TrustWill,
};
use crate::types::TypeLists;
use crate::vault::{OpenVault, VaultError};

/// Run the UI event loop until the user quits.
pub fn run(terminal: &mut DefaultTerminal, path: PathBuf, types: TypeLists) -> anyhow::Result<()> {
    let mut app = App::new(path, types);
    loop {
        terminal.draw(|frame| app.draw(frame))?;
        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && app.handle_key(key)
        {
            break;
        }
    }
    Ok(())
}

#[derive(PartialEq, Eq)]
enum Screen {
    Auth,
    Browse,
    Edit,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Instructions,
    TrustWill,
    Assets,
    Accounts,
    RealEstate,
}

impl Tab {
    const ALL: [Tab; 5] =
        [Tab::Instructions, Tab::TrustWill, Tab::Assets, Tab::Accounts, Tab::RealEstate];

    fn title(self) -> &'static str {
        match self {
            Tab::Instructions => "Instructions",
            Tab::TrustWill => "Trust and Will",
            Tab::Assets => "Assets & Liabilities",
            Tab::Accounts => "Accounts",
            Tab::RealEstate => "Real Estate",
        }
    }

    fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    fn shifted(self, delta: isize) -> Tab {
        let n = Tab::ALL.len() as isize;
        let i = (self.index() as isize + delta).rem_euclid(n) as usize;
        Tab::ALL[i]
    }
}

// --- Auth state --------------------------------------------------------------

#[derive(PartialEq, Eq, Clone, Copy)]
enum AuthMode {
    Create,
    Unlock,
    ChangePassword,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct AuthField {
    #[zeroize(skip)]
    label: &'static str,
    value: String,
}

struct AuthState {
    mode: AuthMode,
    fields: Vec<AuthField>,
    focus: usize,
    error: Option<String>,
}

impl AuthState {
    fn new(mode: AuthMode) -> Self {
        let labels: &[&'static str] = if mode == AuthMode::Unlock {
            &["Password 1", "Password 2"]
        } else {
            &["Password 1", "Confirm password 1", "Password 2", "Confirm password 2"]
        };
        AuthState {
            mode,
            fields: labels.iter().map(|l| AuthField { label: l, value: String::new() }).collect(),
            focus: 0,
            error: None,
        }
    }
}

// --- Edit form ---------------------------------------------------------------

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
impl Zeroize for FieldKind {
    fn zeroize(&mut self) {}
}

impl Field {
    fn text(label: &str, value: String) -> Field {
        Field { label: label.into(), value, kind: FieldKind::Text }
    }
    fn multiline(label: &str, value: String) -> Field {
        Field { label: label.into(), value, kind: FieldKind::Multiline }
    }
    fn password(label: &str, value: String) -> Field {
        Field { label: label.into(), value, kind: FieldKind::Password }
    }
    fn choice(label: &str, value: String, options: Vec<String>) -> Field {
        Field { label: label.into(), value, kind: FieldKind::Choice(options) }
    }

    /// Cycle a Choice field's value by `delta` (no-op for other kinds).
    fn cycle(&mut self, delta: isize) {
        if let FieldKind::Choice(opts) = &self.kind
            && !opts.is_empty()
        {
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
    id: Option<String>,
    created_at: i64,
    fields: Vec<Field>,
    record_fields: usize,
    focus: usize,
    attached_file_id: Option<String>,
    reveal: bool,
    history: Vec<Change>,
}

impl EditState {
    fn has_docs(&self) -> bool {
        matches!(self.tab, Tab::TrustWill | Tab::Assets)
    }
}

struct App {
    path: PathBuf,
    types: TypeLists,
    screen: Screen,
    auth: AuthState,
    vault: Option<OpenVault>,
    tab: Tab,
    selected: usize,
    edit: Option<EditState>,
    status: String,
    clipboard_dirty: bool,
}

impl Drop for App {
    fn drop(&mut self) {
        if self.clipboard_dirty {
            clear_clipboard();
        }
    }
}

impl App {
    fn new(path: PathBuf, types: TypeLists) -> Self {
        let mode = if path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        App {
            path,
            types,
            screen: Screen::Auth,
            auth: AuthState::new(mode),
            vault: None,
            tab: Tab::Instructions,
            selected: 0,
            edit: None,
            status: String::new(),
            clipboard_dirty: false,
        }
    }

    fn vault_ref(&self) -> &OpenVault {
        self.vault.as_ref().expect("vault open on browse/edit")
    }

    /// `(id, label)` pairs for the current tab's records.
    fn current_labels(&self) -> Vec<(String, String)> {
        let v = &self.vault_ref().vault;
        match self.tab {
            Tab::Instructions => label_list(&v.instructions),
            Tab::TrustWill => label_list(&v.trust_wills),
            Tab::Assets => label_list(&v.assets),
            Tab::Accounts => label_list(&v.accounts),
            Tab::RealEstate => label_list(&v.real_estate),
        }
    }

    fn clamp_selection(&mut self) {
        let n = self.current_labels().len();
        if n == 0 {
            self.selected = 0;
        } else if self.selected >= n {
            self.selected = n - 1;
        }
    }

    fn persist(&mut self) {
        if let Some(ov) = self.vault.as_ref()
            && let Err(e) = ov.save()
        {
            self.status = format!("Save failed: {e}");
        }
    }

    // --- Key handling: returns true to quit ---------------------------------

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.screen {
            Screen::Auth => self.handle_auth_key(key),
            Screen::Browse => self.handle_browse_key(key),
            Screen::Edit => self.handle_edit_key(key),
        }
    }

    fn handle_auth_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                if self.auth.mode == AuthMode::ChangePassword {
                    self.screen = Screen::Browse;
                    return false;
                }
                return true;
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.auth.fields[self.auth.focus].value.push(c);
            }
            KeyCode::Backspace => {
                self.auth.fields[self.auth.focus].value.pop();
            }
            KeyCode::Tab | KeyCode::Down => {
                self.auth.focus = (self.auth.focus + 1) % self.auth.fields.len();
            }
            KeyCode::BackTab | KeyCode::Up => {
                let n = self.auth.fields.len();
                self.auth.focus = (self.auth.focus + n - 1) % n;
            }
            KeyCode::Enter => {
                if self.auth.focus + 1 < self.auth.fields.len() {
                    self.auth.focus += 1;
                } else {
                    self.submit_auth();
                }
            }
            _ => {}
        }
        false
    }

    fn confirmed_passwords(&self) -> Result<(Zeroizing<String>, Zeroizing<String>), String> {
        let f = &self.auth.fields;
        let (pw1, c1, pw2, c2) = (&f[0].value, &f[1].value, &f[2].value, &f[3].value);
        if pw1.is_empty() || pw2.is_empty() {
            return Err("Both passwords are required.".into());
        }
        if pw1 != c1 || pw2 != c2 {
            return Err("Password confirmations do not match.".into());
        }
        Ok((Zeroizing::new(pw1.clone()), Zeroizing::new(pw2.clone())))
    }

    fn submit_auth(&mut self) {
        match self.auth.mode {
            AuthMode::ChangePassword => {
                let (pw1, pw2) = match self.confirmed_passwords() {
                    Ok(p) => p,
                    Err(m) => {
                        self.auth.error = Some(m);
                        return;
                    }
                };
                if let Some(ov) = self.vault.as_mut() {
                    match ov.change_password(pw1.as_bytes(), pw2.as_bytes()) {
                        Ok(()) => {
                            self.status = "Master passwords changed.".into();
                            self.screen = Screen::Browse;
                        }
                        Err(e) => self.auth.error = Some(format!("{e}")),
                    }
                }
            }
            AuthMode::Create | AuthMode::Unlock => self.submit_open_or_create(),
        }
    }

    fn submit_open_or_create(&mut self) {
        let creating = self.auth.mode == AuthMode::Create;
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
            OpenVault::open(self.path.clone(), f[0].value.as_bytes(), f[1].value.as_bytes())
        };
        match result {
            Ok(v) => {
                self.status = if creating {
                    "New vault created.".into()
                } else if v.previous_access() == 0 {
                    "Vault unlocked.".into()
                } else {
                    format!("Unlocked. Last opened: {}", format_time(v.previous_access()))
                };
                self.vault = Some(v);
                self.screen = Screen::Browse;
            }
            Err(VaultError::Crypto(_)) => {
                self.auth = AuthState::new(self.auth.mode);
                self.auth.error = Some("Wrong password(s) or corrupted vault.".into());
            }
            Err(e) => {
                self.auth = AuthState::new(self.auth.mode);
                self.auth.error = Some(format!("{e}"));
            }
        }
    }

    fn handle_browse_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Right | KeyCode::Tab => {
                self.tab = self.tab.shifted(1);
                self.selected = 0;
            }
            KeyCode::Left | KeyCode::BackTab => {
                self.tab = self.tab.shifted(-1);
                self.selected = 0;
            }
            KeyCode::Char(c @ '1'..='5') => {
                self.tab = Tab::ALL[c as usize - '1' as usize];
                self.selected = 0;
            }
            KeyCode::Down => {
                let n = self.current_labels().len();
                if n > 0 {
                    self.selected = (self.selected + 1).min(n - 1);
                }
            }
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Enter => {
                if !self.current_labels().is_empty() {
                    self.start_edit(true);
                }
            }
            KeyCode::Char('n') => self.start_edit(false),
            KeyCode::Char('d') => self.delete_selected(),
            KeyCode::Char('p') => {
                self.auth = AuthState::new(AuthMode::ChangePassword);
                self.screen = Screen::Auth;
            }
            _ => {}
        }
        false
    }

    // --- Editing -------------------------------------------------------------

    /// Build the edit form for the current tab, from the selected record
    /// (`existing = true`) or a fresh one.
    fn start_edit(&mut self, existing: bool) {
        let tab = self.tab;
        let idx = self.selected;
        let v = &self.vault_ref().vault;

        let (id, created_at, mut fields, attached, history): (
            Option<String>,
            i64,
            Vec<Field>,
            Option<String>,
            Vec<Change>,
        ) = match tab {
            Tab::Instructions => {
                let r = if existing { v.instructions.get(idx).cloned() } else { None }
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
                let r = if existing { v.trust_wills.get(idx).cloned() } else { None }
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
                let r = if existing { v.assets.get(idx).cloned() } else { None }
                    .unwrap_or_else(|| AssetLiability::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::choice("Asset/Liability", r.kind.clone(), vec!["Asset".into(), "Liability".into()]),
                        Field::text("Description", r.description.clone()),
                        Field::text("Owner", r.owner.clone()),
                        Field::text("Approx. value", r.approx_value.clone()),
                        Field::text("As-of date", r.as_of_date.clone()),
                        Field::text("Institution", r.institution.clone()),
                        Field::choice("Type", r.asset_type.clone(), self.types.asset.clone()),
                    ],
                    r.statement.clone(),
                    r.history.clone(),
                )
            }
            Tab::Accounts => {
                let r = if existing { v.accounts.get(idx).cloned() } else { None }
                    .unwrap_or_else(|| Account::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::choice("Account type", r.account_type.clone(), self.types.account.clone()),
                        Field::text("Owner", r.owner.clone()),
                        Field::text("Username", r.username.clone()),
                        Field::password("Password", r.password.clone()),
                        Field::text("URL", r.url.clone()),
                        Field::multiline("Description", r.description.clone()),
                    ],
                    None,
                    r.history.clone(),
                )
            }
            Tab::RealEstate => {
                let r = if existing { v.real_estate.get(idx).cloned() } else { None }
                    .unwrap_or_else(|| RealEstate::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::text("Address", r.address.clone()),
                        Field::text("Ownership", r.ownership.clone()),
                        Field::text("Taxes", r.taxes.clone()),
                        Field::text("HOA", r.hoa.clone()),
                        Field::text("Income account", r.income_account.clone()),
                        Field::text("Financing account", r.financing_account.clone()),
                        Field::text("Payment account", r.payment_account.clone()),
                    ],
                    None,
                    r.history.clone(),
                )
            }
        };

        let record_fields = fields.len();
        // Append document-upload inputs for the doc-bearing tabs.
        if matches!(tab, Tab::TrustWill | Tab::Assets) {
            fields.push(Field::text("Doc location", String::new()));
            fields.push(Field::text("Doc filename", String::new()));
            fields.push(Field::text("Upload from", String::new()));
            fields.push(Field::text("Export to", String::new()));
        }

        self.edit = Some(EditState {
            tab,
            id,
            created_at,
            fields,
            record_fields,
            focus: 0,
            attached_file_id: attached,
            reveal: false,
            history,
        });
        self.screen = Screen::Edit;
    }

    fn handle_edit_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let Some(es) = self.edit.as_mut() else {
            self.screen = Screen::Browse;
            return false;
        };
        match key.code {
            KeyCode::Esc => {
                self.edit = None;
                self.screen = Screen::Browse;
            }
            KeyCode::Char('s') if ctrl => self.save_edit(),
            KeyCode::Char('g') if ctrl => {
                if let Some(f) = es.fields.iter_mut().find(|f| matches!(f.kind, FieldKind::Password)) {
                    f.value = password::generate(&GenOptions::default()).unwrap_or_default();
                    es.reveal = true;
                    self.status = "Generated a random password.".into();
                }
            }
            KeyCode::Char('r') if ctrl => es.reveal = !es.reveal,
            KeyCode::Char('y') if ctrl => {
                if let Some(f) = es.fields.iter().find(|f| matches!(f.kind, FieldKind::Password)) {
                    let pw = f.value.clone();
                    self.copy_to_clipboard(pw);
                }
            }
            KeyCode::Char('u') if ctrl => self.attach_document(),
            KeyCode::Char('e') if ctrl => self.export_document(),
            KeyCode::Char('k') if ctrl => self.detach_document(),
            KeyCode::Tab | KeyCode::Down => {
                es.focus = (es.focus + 1) % es.fields.len();
            }
            KeyCode::BackTab | KeyCode::Up => {
                let n = es.fields.len();
                es.focus = (es.focus + n - 1) % n;
            }
            KeyCode::Left => es.fields[es.focus].cycle(-1),
            KeyCode::Right => es.fields[es.focus].cycle(1),
            KeyCode::Char(c) if !ctrl => {
                let f = &mut es.fields[es.focus];
                if !matches!(f.kind, FieldKind::Choice(_)) {
                    f.value.push(c);
                }
            }
            KeyCode::Backspace => {
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
    fn ensure_id(es: &mut EditState) -> Result<(), String> {
        if es.id.is_none() {
            es.id = Some(records::random_id().map_err(|e| e.to_string())?);
        }
        Ok(())
    }

    /// Read the doc-input fields, upload the document into the volume, and
    /// immediately persist the record→document link so there is no orphan.
    fn attach_document(&mut self) {
        let Some(mut es) = self.edit.take() else { return };
        if !es.has_docs() {
            self.edit = Some(es);
            return;
        }
        let rc = es.record_fields;
        let location = es.fields[rc].value.clone();
        let filename = es.fields[rc + 1].value.clone();
        let source = es.fields[rc + 2].value.clone();
        if filename.trim().is_empty() || source.trim().is_empty() {
            self.status = "Doc filename and 'upload from' are required.".into();
            self.edit = Some(es);
            return;
        }
        let id = match self.vault.as_mut() {
            Some(ov) => match ov.add_document(&location, &filename, Path::new(&source)) {
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
        es.attached_file_id = Some(id);
        for i in rc..rc + 3 {
            es.fields[i].value.clear();
        }
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        self.persist();
        self.status = "Document uploaded to the encrypted volume.".into();
        self.edit = Some(es);
    }

    /// Detach the current record's document AND reclaim its encrypted blob, then
    /// persist (so a "removed" document does not linger in the archive).
    fn detach_document(&mut self) {
        let Some(mut es) = self.edit.take() else { return };
        let id = es.attached_file_id.take();
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        if let Some(id) = id
            && let Some(ov) = self.vault.as_mut()
        {
            let _ = ov.remove_document(&id);
        }
        self.persist();
        self.status = "Removed document from the vault.".into();
        self.edit = Some(es);
    }

    fn export_document(&mut self) {
        let Some(es) = self.edit.as_ref() else { return };
        if !es.has_docs() {
            return;
        }
        let rc = es.record_fields;
        let dest = es.fields[rc + 3].value.clone();
        let Some(id) = es.attached_file_id.clone() else {
            self.status = "No document attached to export.".into();
            return;
        };
        if dest.trim().is_empty() {
            self.status = "Enter an 'export to' path first.".into();
            return;
        }
        if let Some(ov) = self.vault.as_ref() {
            match ov.export_document(&id, Path::new(&dest)) {
                Ok(()) => self.status = format!("Exported to {dest}"),
                Err(e) => self.status = format!("Export failed: {e}"),
            }
        }
    }

    /// Rebuild the typed record from the edit fields (using the buffer's stable
    /// id, which must already be set) and upsert it into the vault.
    fn commit_edit_record(&mut self, es: &EditState) {
        let f = |i: usize| es.fields[i].value.clone();
        let id = es.id.clone().unwrap_or_default();
        let Some(ov) = self.vault.as_mut() else { return };
        let v = &mut ov.vault;
        match es.tab {
            Tab::Instructions => {
                let mut r = Instruction::default();
                r.id = id;
                r.created_at = es.created_at;
                r.title = f(0);
                r.description = f(1);
                records::upsert(&mut v.instructions, r);
            }
            Tab::TrustWill => {
                let mut r = TrustWill::default();
                r.id = id;
                r.created_at = es.created_at;
                r.document = f(0);
                r.usage = f(1);
                r.file = es.attached_file_id.clone();
                records::upsert(&mut v.trust_wills, r);
            }
            Tab::Assets => {
                let mut r = AssetLiability::default();
                r.id = id;
                r.created_at = es.created_at;
                r.kind = f(0);
                r.description = f(1);
                r.owner = f(2);
                r.approx_value = f(3);
                r.as_of_date = f(4);
                r.institution = f(5);
                r.asset_type = f(6);
                r.statement = es.attached_file_id.clone();
                records::upsert(&mut v.assets, r);
            }
            Tab::Accounts => {
                let mut r = Account::default();
                r.id = id;
                r.created_at = es.created_at;
                r.account_type = f(0);
                r.owner = f(1);
                r.username = f(2);
                r.password = f(3);
                r.url = f(4);
                r.description = f(5);
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
                r.payment_account = f(6);
                records::upsert(&mut v.real_estate, r);
            }
        }
    }

    /// Save the current edit form back into the vault.
    fn save_edit(&mut self) {
        let Some(mut es) = self.edit.take() else { return };
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = format!("Could not create id: {e}");
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        self.persist();
        self.status = "Saved.".into();
        self.screen = Screen::Browse;
        self.clamp_selection();
    }

    fn delete_selected(&mut self) {
        let labels = self.current_labels();
        let Some((id, _)) = labels.get(self.selected).cloned() else { return };
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
                    records::remove(&mut v.real_estate, &id, &mut v.audit, "Real Estate");
                }
            }
        }
        for fid in doc_ids {
            if let Some(ov) = self.vault.as_mut() {
                let _ = ov.remove_document(&fid);
            }
        }
        self.persist();
        self.clamp_selection();
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

    // --- Drawing -------------------------------------------------------------

    fn draw(&self, frame: &mut Frame) {
        match self.screen {
            Screen::Auth => self.draw_auth(frame),
            Screen::Browse => self.draw_browse(frame),
            Screen::Edit => self.draw_edit(frame),
        }
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
        for (i, field) in self.auth.fields.iter().enumerate() {
            let focused = i == self.auth.focus;
            let marker = if focused { "> " } else { "  " };
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
        lines.push(Line::from(Span::styled(
            format!("Tab/↑↓ move · Enter next/submit · {esc}"),
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

        let tabs = Tabs::new(Tab::ALL.iter().map(|t| t.title()).collect::<Vec<_>>())
            .select(self.tab.index())
            .block(Block::default().borders(Borders::ALL).title(" Tabs (←/→ or 1-5) "))
            .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD));
        frame.render_widget(tabs, chunks[0]);

        let labels = self.current_labels();
        let items: Vec<ListItem> =
            labels.iter().map(|(_, l)| ListItem::new(Line::from(l.clone()))).collect();
        let count = items.len();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!(" {} ({count}) ", self.tab.title())))
            .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");
        let mut state = ListState::default();
        if count > 0 {
            state.select(Some(self.selected.min(count - 1)));
        }
        frame.render_stateful_widget(list, chunks[1], &mut state);

        self.draw_footer(frame, chunks[2], "↑↓ move · Enter edit · n new · d delete · ←/→ tab · p passwords · q quit");
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
            let shown = match &field.kind {
                FieldKind::Password if !es.reveal => "•".repeat(field.value.chars().count()),
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
            let attached = es
                .attached_file_id
                .as_ref()
                .and_then(|id| self.vault_ref().vault.volume.file(id))
                .map(|f| {
                    let loc = if f.location.is_empty() { "/".into() } else { f.location.clone() };
                    format!("{loc}/{}", f.filename)
                })
                .unwrap_or_else(|| "(none)".into());
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("Attached document: {attached}"),
                Style::default().fg(Color::Cyan),
            )));
        }
        if !es.history.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("History:", Style::default().add_modifier(Modifier::BOLD))));
            for c in es.history.iter().rev().take(6) {
                let detail = if c.detail.is_empty() { c.action.clone() } else { c.detail.clone() };
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

        let hints = if es.has_docs() {
            "Tab/↑↓ field · ←/→ choice · Ctrl+S save · Ctrl+U upload · Ctrl+E export · Ctrl+K detach · Esc cancel"
        } else {
            "Tab/↑↓ field · ←/→ choice · Ctrl+S save · Ctrl+G gen · Ctrl+R reveal · Ctrl+Y copy · Esc cancel"
        };
        self.draw_footer(frame, chunks[1], hints);
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect, hints: &str) {
        let text = if self.status.is_empty() {
            hints.to_string()
        } else {
            format!("{}  —  {hints}", self.status)
        };
        let footer = Paragraph::new(text)
            .style(Style::default().fg(Color::Gray))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, area);
    }
}

fn label_list<R: Record>(list: &[R]) -> Vec<(String, String)> {
    list.iter().map(|r| (r.id().to_string(), r.label())).collect()
}

fn clear_clipboard() {
    let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(String::new()));
}

/// Format a unix-seconds timestamp as `YYYY-MM-DD HH:MM:SS UTC` (no date crate).
/// Returns "never" for a zero/negative timestamp. Shared with the GUI.
pub(crate) fn format_time(ts: i64) -> String {
    if ts <= 0 {
        return "never".to_string();
    }
    let days = ts.div_euclid(86_400);
    let secs_of_day = ts.rem_euclid(86_400);
    let (h, m, s) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::format_time;

    #[test]
    fn formats_epoch_zero_as_never() {
        assert_eq!(format_time(0), "never");
        assert_eq!(format_time(-5), "never");
    }

    #[test]
    fn formats_known_timestamp() {
        assert_eq!(format_time(1_609_459_200), "2021-01-01 00:00:00 UTC");
        assert_eq!(format_time(1_609_459_201), "2021-01-01 00:00:01 UTC");
    }
}
