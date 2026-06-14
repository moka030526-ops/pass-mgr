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
use crate::vault::{self, OpenVault, VaultError};

/// Run the UI event loop until the user quits. `writable` enables mutations;
/// when false the vault is opened read-only and write keys are inert.
pub fn run(
    terminal: &mut DefaultTerminal,
    path: PathBuf,
    types: TypeLists,
    writable: bool,
) -> anyhow::Result<()> {
    let mut app = App::new(path, types, writable);
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

#[derive(PartialEq, Eq, Debug)]
enum Screen {
    Auth,
    Browse,
    Edit,
    Config,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
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

/// The tabs whose records can carry an attached document (single source of truth).
fn tab_has_docs(tab: Tab) -> bool {
    matches!(tab, Tab::TrustWill | Tab::Assets)
}

impl EditState {
    fn has_docs(&self) -> bool {
        tab_has_docs(self.tab)
    }
}

struct App {
    path: PathBuf,
    types: TypeLists,
    /// When false the vault is opened read-only and mutating keys are inert.
    writable: bool,
    screen: Screen,
    auth: AuthState,
    vault: Option<OpenVault>,
    tab: Tab,
    selected: usize,
    edit: Option<EditState>,
    // Accounts-tab display filters (None = no filter).
    acct_filter_type: Option<String>,
    acct_filter_subtype: Option<String>,
    acct_filter_owner: Option<String>,
    acct_filter_review: bool,
    // Assets-tab "review only" filter.
    asset_filter_review: bool,
    // Config screen inputs.
    cfg_focus: usize,
    cfg_asset_type: String,
    cfg_account_type: String,
    cfg_subtype_type: String,
    cfg_subtype_name: String,
    cfg_backup_dest: String,
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
    fn new(path: PathBuf, types: TypeLists, writable: bool) -> Self {
        let mode = if path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        App {
            path,
            types,
            writable,
            screen: Screen::Auth,
            auth: AuthState::new(mode),
            vault: None,
            tab: Tab::Instructions,
            selected: 0,
            edit: None,
            acct_filter_type: None,
            acct_filter_subtype: None,
            acct_filter_owner: None,
            acct_filter_review: false,
            asset_filter_review: false,
            cfg_focus: 0,
            cfg_asset_type: String::new(),
            cfg_account_type: String::new(),
            cfg_subtype_type: String::new(),
            cfg_subtype_name: String::new(),
            cfg_backup_dest: String::new(),
            status: String::new(),
            clipboard_dirty: false,
        }
    }

    fn vault_ref(&self) -> &OpenVault {
        self.vault.as_ref().expect("vault open on browse/edit")
    }

    /// `(id, label)` pairs for the current tab's records. The Accounts tab is
    /// additionally filtered by the active type/subtype/owner/review filters, and
    /// the Assets tab by the review filter.
    fn current_labels(&self) -> Vec<(String, String)> {
        let v = &self.vault_ref().vault;
        match self.tab {
            Tab::Instructions => label_list(&v.instructions),
            Tab::TrustWill => label_list(&v.trust_wills),
            Tab::Assets => v
                .assets
                .iter()
                .filter(|a| !self.asset_filter_review || a.review)
                .map(|a| (a.id.clone(), a.label()))
                .collect(),
            Tab::Accounts => v
                .accounts
                .iter()
                .filter(|a| self.acct_filter_type.as_deref().is_none_or(|t| a.account_type == t))
                .filter(|a| self.acct_filter_subtype.as_deref().is_none_or(|s| a.account_subtype == s))
                .filter(|a| self.acct_filter_owner.as_deref().is_none_or(|o| a.owner == o))
                .filter(|a| !self.acct_filter_review || a.review)
                .map(|a| (a.id.clone(), a.label()))
                .collect(),
            Tab::RealEstate => label_list(&v.real_estate),
        }
    }

    /// Distinct, sorted, non-empty values of an account field (for filter cycling).
    fn account_values(&self, field: impl Fn(&Account) -> &str) -> Vec<String> {
        let mut v: Vec<String> = self
            .vault_ref()
            .vault
            .accounts
            .iter()
            .map(|a| field(a).to_string())
            .filter(|s| !s.is_empty())
            .collect();
        v.sort();
        v.dedup();
        v
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
        if let Some(ov) = self.vault.as_mut()
            && let Err(e) = ov.save()
        {
            self.status = format!("Save failed: {e}");
        }
    }

    /// Gate a mutating action: returns true if writable, else sets a status hint.
    fn require_writable(&mut self) -> bool {
        if self.writable {
            return true;
        }
        self.status = "Read-only — relaunch with --write to make changes.".into();
        false
    }

    // --- Key handling: returns true to quit ---------------------------------

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.screen {
            Screen::Auth => self.handle_auth_key(key),
            Screen::Browse => self.handle_browse_key(key),
            Screen::Edit => self.handle_edit_key(key),
            Screen::Config => self.handle_config_key(key),
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
        if creating && !self.writable {
            self.auth.error =
                Some("No vault here, and this is read-only. Relaunch with --write to create one.".into());
            return;
        }
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
            if self.writable {
                OpenVault::open(self.path.clone(), p1, p2)
            } else {
                OpenVault::open_read_only(self.path.clone(), p1, p2)
            }
        };
        match result {
            Ok(v) => {
                self.status = if creating {
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
            KeyCode::Char('t') if self.tab == Tab::Accounts => {
                let opts = self.account_values(|a| &a.account_type);
                self.acct_filter_type = cycle_filter(&self.acct_filter_type, &opts);
                self.acct_filter_subtype = None; // subtypes are type-specific
                self.selected = 0;
            }
            KeyCode::Char('s') if self.tab == Tab::Accounts => {
                // When a type filter is set, offer that type's configured subtypes
                // UNION any free-text subtypes actually present on its accounts;
                // otherwise cycle the subtypes present across all accounts.
                let opts = match self.acct_filter_type.clone() {
                    Some(t) => {
                        let mut opts = self.types.subtypes_for(&t);
                        for a in &self.vault_ref().vault.accounts {
                            if a.account_type == t
                                && !a.account_subtype.is_empty()
                                && !opts.contains(&a.account_subtype)
                            {
                                opts.push(a.account_subtype.clone());
                            }
                        }
                        opts.sort();
                        opts.dedup();
                        opts
                    }
                    None => self.account_values(|a| &a.account_subtype),
                };
                self.acct_filter_subtype = cycle_filter(&self.acct_filter_subtype, &opts);
                self.selected = 0;
            }
            KeyCode::Char('o') if self.tab == Tab::Accounts => {
                let opts = self.account_values(|a| &a.owner);
                self.acct_filter_owner = cycle_filter(&self.acct_filter_owner, &opts);
                self.selected = 0;
            }
            // Review-only filter toggle (Accounts and Assets tabs).
            KeyCode::Char('v') if self.tab == Tab::Accounts => {
                self.acct_filter_review = !self.acct_filter_review;
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
        const CFG_FIELDS: usize = 5;
        match key.code {
            KeyCode::Esc => self.screen = Screen::Browse,
            KeyCode::Tab | KeyCode::Down => self.cfg_focus = (self.cfg_focus + 1) % CFG_FIELDS,
            KeyCode::BackTab | KeyCode::Up => self.cfg_focus = (self.cfg_focus + CFG_FIELDS - 1) % CFG_FIELDS,
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.cfg_field_mut().push(c);
            }
            KeyCode::Backspace => {
                self.cfg_field_mut().pop();
            }
            KeyCode::Enter => self.submit_config(),
            _ => {}
        }
        false
    }

    fn cfg_field_mut(&mut self) -> &mut String {
        match self.cfg_focus {
            0 => &mut self.cfg_asset_type,
            1 => &mut self.cfg_account_type,
            2 => &mut self.cfg_subtype_type,
            3 => &mut self.cfg_subtype_name,
            _ => &mut self.cfg_backup_dest,
        }
    }

    /// Perform the focused config action: add a type/subtype or run a backup.
    fn submit_config(&mut self) {
        // Backup (focus 4) is a read/copy and always allowed; the type/subtype
        // adds (focus 0..3) write to config files and need --write.
        if self.cfg_focus != 4 && !self.require_writable() {
            return;
        }
        match self.cfg_focus {
            0 => {
                let name = self.cfg_asset_type.trim().to_string();
                if self.types.add_asset_type(&name) {
                    self.status = format!("Added asset/liability type “{name}”.");
                    self.cfg_asset_type.clear();
                } else {
                    self.status = "Type is empty or already exists.".into();
                }
            }
            1 => {
                let name = self.cfg_account_type.trim().to_string();
                if self.types.add_account_type(&name) {
                    self.status = format!("Added account type “{name}”.");
                    self.cfg_account_type.clear();
                } else {
                    self.status = "Type is empty or already exists.".into();
                }
            }
            2 | 3 => {
                let ty = self.cfg_subtype_type.trim().to_string();
                let sub = self.cfg_subtype_name.trim().to_string();
                if self.types.add_account_subtype(&ty, &sub) {
                    self.status = format!("Added subtype “{sub}” under “{ty}”.");
                    self.cfg_subtype_name.clear();
                } else {
                    self.status = "Unknown type, or subtype empty/duplicate.".into();
                }
            }
            _ => {
                let dest = self.cfg_backup_dest.trim().to_string();
                if dest.is_empty() {
                    self.status = "Enter a backup destination directory.".into();
                } else {
                    match vault::backup(&self.path, Path::new(&dest)) {
                        Ok(p) => self.status = format!("Backed up to {}", p.display()),
                        Err(e) => self.status = format!("Backup failed: {e}"),
                    }
                }
            }
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
        let sel_id: Option<String> = if existing {
            self.current_labels().get(self.selected).map(|(id, _)| id.clone())
        } else {
            None
        };
        let v = &self.vault_ref().vault;

        let (id, created_at, mut fields, attached, history): (
            Option<String>,
            i64,
            Vec<Field>,
            Option<String>,
            Vec<Change>,
        ) = match tab {
            Tab::Instructions => {
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
                        Field::choice("Type", r.asset_type.clone(), self.types.asset.clone()),
                        Field::text("URL", r.url.clone()),
                        Field::choice("Review", bool_choice(r.review), yes_no()),
                    ],
                    r.statement.clone(),
                    r.history.clone(),
                )
            }
            Tab::Accounts => {
                let r = sel_id
                    .as_ref()
                    .and_then(|id| v.accounts.iter().find(|r| &r.id == id).cloned())
                    .unwrap_or_else(|| Account::new().unwrap_or_default());
                let id = if existing { Some(r.id.clone()) } else { None };
                (
                    id,
                    r.created_at,
                    vec![
                        Field::choice("Account type", r.account_type.clone(), self.types.account_type_names()),
                        // Subtype is a dependent dropdown of the chosen type's
                        // subtypes; the current value is kept selectable even if
                        // it is not in the configured list (e.g. legacy data).
                        Field::choice("Subtype", r.account_subtype.clone(), {
                            let mut s = self.types.subtypes_for(&r.account_type);
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
        if tab_has_docs(tab) {
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
            // Write actions are gated by --write; reads (reveal/copy/export) are not.
            KeyCode::Char('s') if ctrl => {
                if self.require_writable() {
                    self.save_edit();
                }
            }
            KeyCode::Char('g') if ctrl => {
                if self.writable
                    && let Some(f) = es.fields.iter_mut().find(|f| matches!(f.kind, FieldKind::Password))
                {
                    f.value = password::generate(&GenOptions::default()).unwrap_or_default();
                    es.reveal = true;
                    self.status = "Generated a random password.".into();
                } else if !self.writable {
                    self.require_writable();
                }
            }
            KeyCode::Char('r') if ctrl => es.reveal = !es.reveal,
            KeyCode::Char('y') if ctrl => {
                if let Some(f) = es.fields.iter().find(|f| matches!(f.kind, FieldKind::Password)) {
                    let pw = f.value.clone();
                    self.copy_to_clipboard(pw);
                }
            }
            KeyCode::Char('u') if ctrl => {
                if self.require_writable() {
                    self.attach_document();
                }
            }
            KeyCode::Char('e') if ctrl => self.export_document(),
            KeyCode::Char('k') if ctrl => {
                if self.require_writable() {
                    self.detach_document();
                }
            }
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
        // Replacing an existing attachment: reclaim the previous blob so it does
        // not become an orphan in the archive.
        let previous = es.attached_file_id.replace(id);
        for i in rc..rc + 3 {
            es.fields[i].value.clear();
        }
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        if let Some(old) = previous
            && let Some(ov) = self.vault.as_mut()
        {
            let _ = ov.remove_document(&old);
        }
        self.persist();
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
        let id = es.attached_file_id.take();
        if let Err(e) = Self::ensure_id(&mut es) {
            self.status = e;
            self.edit = Some(es);
            return;
        }
        self.commit_edit_record(&es);
        let mut cleanup_err = None;
        if let Some(id) = id
            && let Some(ov) = self.vault.as_mut()
            && let Err(e) = ov.remove_document(&id)
        {
            cleanup_err = Some(e);
        }
        self.persist();
        // Surface a failed blob reclaim instead of silently reporting success.
        self.status = match cleanup_err {
            Some(e) => format!("Unlinked, but blob cleanup failed: {e}"),
            None => "Removed document from the vault.".into(),
        };
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
                r.beneficiary = f(3);
                r.approx_value = f(4);
                r.as_of_date = f(5);
                r.institution = f(6);
                r.asset_type = f(7);
                r.url = f(8);
                r.review = f(9) == "Yes";
                r.statement = es.attached_file_id.clone();
                records::upsert(&mut v.assets, r);
            }
            Tab::Accounts => {
                let mut r = Account::default();
                r.id = id;
                r.created_at = es.created_at;
                r.account_type = f(0);
                r.account_subtype = f(1);
                r.owner = f(2);
                r.username = f(3);
                r.password = f(4);
                r.url = f(5);
                r.description = f(6);
                r.review = f(7) == "Yes";
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
            Screen::Config => self.draw_config(frame),
        }
    }

    fn draw_config(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(frame.area());

        let inputs = [
            ("New asset/liability type", &self.cfg_asset_type),
            ("New account type", &self.cfg_account_type),
            ("Subtype — account type", &self.cfg_subtype_type),
            ("Subtype — name", &self.cfg_subtype_name),
            ("Backup destination dir", &self.cfg_backup_dest),
        ];
        let mut lines = vec![
            Line::from(Span::styled("Asset/Liability types:", Style::default().add_modifier(Modifier::BOLD))),
            Line::from(Span::styled(self.types.asset.join(" · "), Style::default().fg(Color::Gray))),
            Line::from(""),
            Line::from(Span::styled("Account types (with subtypes):", Style::default().add_modifier(Modifier::BOLD))),
        ];
        for t in &self.types.account {
            let subs = if t.subtypes.is_empty() { "—".to_string() } else { t.subtypes.join(", ") };
            lines.push(Line::from(Span::styled(format!("  {}: {subs}", t.name), Style::default().fg(Color::Gray))));
        }
        lines.push(Line::from(""));
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
            "Tab/↑↓ field · type to edit · Enter = add type / backup · Esc back",
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
        // Show any active filters in the title.
        let title = if self.tab == Tab::Accounts
            && (self.acct_filter_type.is_some()
                || self.acct_filter_subtype.is_some()
                || self.acct_filter_owner.is_some()
                || self.acct_filter_review)
        {
            let t = self.acct_filter_type.as_deref().unwrap_or("any");
            let s = self.acct_filter_subtype.as_deref().unwrap_or("any");
            let o = self.acct_filter_owner.as_deref().unwrap_or("any");
            let r = if self.acct_filter_review { " · review" } else { "" };
            format!(" Accounts ({count})  [type={t} · subtype={s} · owner={o}{r}] ")
        } else if self.tab == Tab::Assets && self.asset_filter_review {
            format!(" Assets & Liabilities ({count})  [review only] ")
        } else {
            format!(" {} ({count}) ", self.tab.title())
        };
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");
        let mut state = ListState::default();
        if count > 0 {
            state.select(Some(self.selected.min(count - 1)));
        }
        frame.render_stateful_widget(list, chunks[1], &mut state);

        let hints = match self.tab {
            Tab::Accounts => "↑↓ · Enter edit · n new · d del · t/s/o filter · v review · ←→ tab · c config · p pw · q quit",
            Tab::Assets => "↑↓ · Enter edit · n new · d del · v review filter · ←→ tab · c config · p pw · q quit",
            _ => "↑↓ · Enter edit · n new · d del · ←→ tab · c config · p passwords · q quit",
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

/// Advance a filter through: None → opts[0] → opts[1] → … → None (wrap to off).
fn cycle_filter(current: &Option<String>, opts: &[String]) -> Option<String> {
    match current {
        None => opts.first().cloned(),
        Some(cur) => match opts.iter().position(|o| o == cur) {
            Some(i) if i + 1 < opts.len() => Some(opts[i + 1].clone()),
            _ => None,
        },
    }
}

fn clear_clipboard() {
    let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(String::new()));
}

/// Format a unix-seconds timestamp as `YYYY-MM-DD HH:MM:SS UTC` (no date crate).
/// Returns "never" for a zero/negative timestamp. Shared with the GUI; the
/// calendar math lives once in [`crate::records::civil_from_unix`].
pub(crate) fn format_time(ts: i64) -> String {
    if ts <= 0 {
        return "never".to_string();
    }
    let (year, mo, d, h, m, s) = records::civil_from_unix(ts);
    format!("{year:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;
    use crate::types::TypeLists;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fast() -> KdfParams {
        KdfParams { m_cost: 256, t_cost: 1, p_cost: 1 }
    }

    fn tmp_vault(tag: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("passmgr-ui-{tag}-{nanos}.pmv"))
    }

    /// An `App` with a freshly-created, unlocked vault on the Browse screen — the
    /// state a user reaches after a successful create/unlock, without rendering.
    fn app_unlocked(tag: &str) -> (App, PathBuf) {
        let path = tmp_vault(tag);
        let ov = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
        let mut app = App::new(path.clone(), TypeLists::in_memory(), true);
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
        let mut app = App::new(path.clone(), TypeLists::in_memory(), false);
        app.vault = Some(ov);
        app.screen = Screen::Browse;
        (app, path)
    }

    fn cleanup(path: &PathBuf) {
        let _ = std::fs::remove_file(path);
        // best-effort: remove a `.vol` companion if any test created documents
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            let _ = std::fs::remove_file(path.with_file_name(format!("{name}.vol")));
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

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
    fn bool_choice_round_trips() {
        assert_eq!(bool_choice(true), "Yes");
        assert_eq!(bool_choice(false), "No");
        assert_eq!(yes_no(), vec!["No".to_string(), "Yes".to_string()]);
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

        // Field order: 0 type(choice) 1 subtype(choice) 2 owner 3 username
        // 4 password 5 url 6 description 7 review(choice).
        let typ = |app: &mut App, c: char| app.handle_key(key(KeyCode::Char(c)));
        // owner (focus 2)
        app.handle_key(key(KeyCode::Down)); // 0->1
        app.handle_key(key(KeyCode::Down)); // 1->2 owner
        for c in "Jane".chars() { typ(&mut app, c); }
        app.handle_key(key(KeyCode::Down)); // username
        for c in "jane".chars() { typ(&mut app, c); }
        app.handle_key(key(KeyCode::Down)); // password
        for c in "pw".chars() { typ(&mut app, c); }
        app.handle_key(ctrl('s')); // save

        assert_eq!(app.screen, Screen::Browse);
        let v = &app.vault.as_ref().unwrap().vault;
        assert_eq!(v.accounts.len(), 1);
        // Verify field-index mapping: owner/username/password landed correctly.
        assert_eq!(v.accounts[0].owner, "Jane");
        assert_eq!(v.accounts[0].username, "jane");
        assert_eq!(v.accounts[0].password, "pw");
        cleanup(&path);
    }

    #[test]
    fn review_choice_maps_to_bool_on_save() {
        let (mut app, path) = app_unlocked("review");
        app.handle_key(key(KeyCode::Char('4'))); // Accounts
        app.handle_key(key(KeyCode::Char('n')));
        // focus 7 = review choice; cycle to "Yes".
        for _ in 0..7 {
            app.handle_key(key(KeyCode::Down));
        }
        app.handle_key(key(KeyCode::Right)); // cycle choice No -> Yes
        app.handle_key(ctrl('s'));
        assert!(app.vault.as_ref().unwrap().vault.accounts[0].review);
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
        assert!(app.types.asset.contains(&"Annuity".to_string()));
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
        assert!(app.types.subtypes_for("Financial").contains(&"HSA".to_string()));
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
        assert!(!app.types.asset.contains(&"Annuity".to_string()), "type add blocked in read-only");
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
            let mut app = App::new(path.clone(), TypeLists::in_memory(), true);
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
