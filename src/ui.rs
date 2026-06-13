//! Ratatui terminal interface for pass-mgr.
//!
//! The UI is a small state machine over four screens (see [`Screen`]):
//! Auth (unlock / create), List (filter + search), Detail (view one entry),
//! and Edit (add / modify). All app state lives in one [`App`] struct; each
//! screen has a `draw_*` function and the key handling is one match per screen.
//!
//! Conventions:
//! - On Auth/List/Detail, typing flows into the focused text field / search box.
//! - Because plain letters are captured as text, screen *actions* use Ctrl
//!   chords (shown in the footer) so they never collide with typing.

use std::path::PathBuf;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::KdfParams;
use crate::password::{self, GenOptions};
use crate::vault::{Entry, OpenVault, VaultError};

/// Run the UI event loop until the user quits. Returns once the terminal should
/// be restored by the caller.
pub fn run(terminal: &mut DefaultTerminal, path: PathBuf) -> anyhow::Result<()> {
    let mut app = App::new(path);
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
    List,
    Detail,
    Edit,
}

/// What the Auth screen is currently doing.
#[derive(PartialEq, Eq, Clone, Copy)]
enum AuthMode {
    /// No vault file exists yet — set two new passwords (with confirmation).
    Create,
    /// A vault exists — enter both passwords to unlock.
    Unlock,
    /// Vault is open — re-key it under two new passwords (with confirmation).
    ChangePassword,
}

/// One masked text field on the Auth screen. Holds a master password while the
/// user types, so it wipes its value on drop (the label is a static str).
#[derive(Zeroize, ZeroizeOnDrop)]
struct AuthField {
    #[zeroize(skip)]
    label: &'static str,
    value: String,
}

/// State for the unlock / create / change-password screen.
struct AuthState {
    mode: AuthMode,
    fields: Vec<AuthField>,
    focus: usize,
    error: Option<String>,
}

impl AuthState {
    fn new(mode: AuthMode) -> Self {
        // Create and ChangePassword confirm each password; Unlock does not.
        let labels: &[&'static str] = if mode == AuthMode::Unlock {
            &["Password 1", "Password 2"]
        } else {
            &["Password 1", "Confirm password 1", "Password 2", "Confirm password 2"]
        };
        AuthState {
            mode,
            fields: labels
                .iter()
                .map(|l| AuthField { label: l, value: String::new() })
                .collect(),
            focus: 0,
            error: None,
        }
    }
}

/// The edit form. `id` is `None` for a brand-new entry. Holds an entry's
/// plaintext password while editing, so it wipes its fields on drop.
#[derive(Default, Zeroize, ZeroizeOnDrop)]
struct EditState {
    id: Option<String>,
    title: String,
    kind: String,
    description: String,
    username: String,
    password: String,
    url: String,
    focus: usize,
    reveal: bool,
}

impl EditState {
    const FIELD_COUNT: usize = 6;

    fn field_mut(&mut self, idx: usize) -> &mut String {
        match idx {
            0 => &mut self.title,
            1 => &mut self.kind,
            2 => &mut self.description,
            3 => &mut self.username,
            4 => &mut self.password,
            _ => &mut self.url,
        }
    }

    fn labels() -> [&'static str; Self::FIELD_COUNT] {
        ["Title", "Type", "Description", "Username", "Password", "URL"]
    }
}

struct App {
    path: PathBuf,
    screen: Screen,
    auth: AuthState,
    vault: Option<OpenVault>,
    // List screen state.
    search: String,
    /// Index into `vault.types` of the active type filter, or `None` for "All".
    filter_idx: Option<usize>,
    selected: usize,
    // Detail screen state.
    reveal: bool,
    show_history: bool,
    // Edit screen state.
    edit: EditState,
    /// Transient one-line status / feedback message shown in the footer.
    status: String,
    /// Set once a password has been copied, so we can clear the clipboard on exit.
    clipboard_dirty: bool,
}

impl Drop for App {
    fn drop(&mut self) {
        // Don't leave a copied password lingering on the system clipboard.
        if self.clipboard_dirty {
            clear_clipboard();
        }
    }
}

impl App {
    fn new(path: PathBuf) -> Self {
        let mode = if path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        App {
            path,
            screen: Screen::Auth,
            auth: AuthState::new(mode),
            vault: None,
            search: String::new(),
            filter_idx: None,
            selected: 0,
            reveal: false,
            show_history: false,
            edit: EditState::default(),
            status: String::new(),
            clipboard_dirty: false,
        }
    }

    // --- Helpers -------------------------------------------------------------

    /// The currently active type-filter name, if any.
    fn active_kind(&self) -> Option<String> {
        let v = self.vault.as_ref()?;
        self.filter_idx.and_then(|i| v.vault.types.get(i).cloned())
    }

    /// Ids of the entries currently visible (after search + type filter), in the
    /// same sorted order the list displays them.
    fn visible_ids(&self) -> Vec<String> {
        match &self.vault {
            Some(v) => v
                .vault
                .filter(&self.search, self.active_kind().as_deref())
                .iter()
                .map(|e| e.id.clone())
                .collect(),
            None => Vec::new(),
        }
    }

    fn selected_entry(&self) -> Option<&Entry> {
        let ids = self.visible_ids();
        let id = ids.get(self.selected)?;
        self.vault.as_ref()?.vault.entries.iter().find(|e| &e.id == id)
    }

    fn clamp_selection(&mut self) {
        let len = self.visible_ids().len();
        if len == 0 {
            self.selected = 0;
        } else if self.selected >= len {
            self.selected = len - 1;
        }
    }

    // --- Key handling: returns true to quit the app --------------------------

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.screen {
            Screen::Auth => self.handle_auth_key(key),
            Screen::List => self.handle_list_key(key),
            Screen::Detail => self.handle_detail_key(key),
            Screen::Edit => self.handle_edit_key(key),
        }
    }

    fn handle_auth_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc => {
                // Cancelling a re-key returns to the list; cancelling create/unlock quits.
                if self.auth.mode == AuthMode::ChangePassword {
                    self.screen = Screen::List;
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

    fn submit_auth(&mut self) {
        match self.auth.mode {
            AuthMode::ChangePassword => self.submit_change_password(),
            AuthMode::Create | AuthMode::Unlock => self.submit_open_or_create(),
        }
    }

    /// Validate the two confirmed-password fields, returning `(pw1, pw2)` or an
    /// error message. Used by both the create and change-password flows.
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

    fn submit_open_or_create(&mut self) {
        let creating = self.auth.mode == AuthMode::Create;
        let result = if creating {
            let (pw1, pw2) = match self.confirmed_passwords() {
                Ok(pair) => pair,
                Err(msg) => {
                    self.auth.error = Some(msg);
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
                    "New vault created.".to_string()
                } else if v.previous_access() == 0 {
                    "Vault unlocked.".to_string()
                } else {
                    format!("Vault unlocked. Last opened: {}", format_time(v.previous_access()))
                };
                self.vault = Some(v);
                self.screen = Screen::List;
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

    fn submit_change_password(&mut self) {
        let (pw1, pw2) = match self.confirmed_passwords() {
            Ok(pair) => pair,
            Err(msg) => {
                self.auth.error = Some(msg);
                return;
            }
        };
        let Some(v) = self.vault.as_mut() else { return };
        match v.change_password(pw1.as_bytes(), pw2.as_bytes()) {
            Ok(()) => {
                self.status = "Master passwords changed.".into();
                self.screen = Screen::List;
            }
            Err(e) => self.auth.error = Some(format!("{e}")),
        }
    }

    fn handle_list_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('q') if ctrl => return true,
            KeyCode::Char('n') if ctrl => {
                self.edit = EditState::default();
                self.status.clear();
                self.screen = Screen::Edit;
            }
            KeyCode::Char('d') if ctrl => self.delete_selected(),
            KeyCode::Char('p') if ctrl => {
                self.auth = AuthState::new(AuthMode::ChangePassword);
                self.status.clear();
                self.screen = Screen::Auth;
            }
            KeyCode::Char('f') if ctrl => self.cycle_filter(),
            KeyCode::Char(c) if !ctrl => {
                self.search.push(c);
                self.clamp_selection();
            }
            KeyCode::Backspace => {
                self.search.pop();
                self.clamp_selection();
            }
            KeyCode::Tab => self.cycle_filter(),
            KeyCode::Down => {
                let len = self.visible_ids().len();
                if len > 0 {
                    self.selected = (self.selected + 1).min(len - 1);
                }
            }
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if self.selected_entry().is_some() {
                    self.reveal = false;
                    self.show_history = false;
                    self.screen = Screen::Detail;
                }
            }
            KeyCode::Esc => {
                if self.search.is_empty() {
                    return true;
                }
                self.search.clear();
                self.clamp_selection();
            }
            _ => {}
        }
        false
    }

    /// Cycle the type filter: All -> type[0] -> type[1] -> ... -> All.
    fn cycle_filter(&mut self) {
        let count = self.vault.as_ref().map_or(0, |v| v.vault.types.len());
        self.filter_idx = match self.filter_idx {
            None if count > 0 => Some(0),
            Some(i) if i + 1 < count => Some(i + 1),
            _ => None,
        };
        self.clamp_selection();
    }

    fn delete_selected(&mut self) {
        let Some(id) = self.visible_ids().get(self.selected).cloned() else {
            return;
        };
        if let Some(v) = self.vault.as_mut() {
            v.vault.remove(&id);
            match v.save() {
                Ok(()) => self.status = "Entry deleted.".into(),
                Err(e) => self.status = format!("Save failed: {e}"),
            }
        }
        self.clamp_selection();
    }

    fn handle_detail_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => self.screen = Screen::List,
            KeyCode::Char('r') if !ctrl => self.reveal = !self.reveal,
            KeyCode::Char('h') if !ctrl => self.show_history = !self.show_history,
            KeyCode::Char('c') if !ctrl => self.copy_password(),
            KeyCode::Char('e') if !ctrl => self.begin_edit_selected(),
            KeyCode::Char('d') if ctrl => {
                self.delete_selected();
                self.screen = Screen::List;
            }
            _ => {}
        }
        false
    }

    fn copy_password(&mut self) {
        let Some(pw) = self.selected_entry().map(|e| e.password.clone()) else {
            return;
        };
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(pw)) {
            Ok(()) => {
                self.clipboard_dirty = true;
                self.status = "Password copied (clipboard clears on exit).".into();
            }
            Err(e) => self.status = format!("Clipboard unavailable: {e}"),
        }
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
                focus: 0,
                reveal: false,
            };
            self.screen = Screen::Edit;
        }
    }

    fn handle_edit_key(&mut self, key: KeyEvent) -> bool {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Esc => {
                self.screen = if self.edit.id.is_some() { Screen::Detail } else { Screen::List };
            }
            KeyCode::Char('s') if ctrl => self.save_edit(),
            KeyCode::Char('g') if ctrl => self.generate_password(),
            KeyCode::Char('r') if ctrl => self.edit.reveal = !self.edit.reveal,
            KeyCode::Tab | KeyCode::Down => {
                self.edit.focus = (self.edit.focus + 1) % EditState::FIELD_COUNT;
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.edit.focus = (self.edit.focus + EditState::FIELD_COUNT - 1) % EditState::FIELD_COUNT;
            }
            KeyCode::Char(c) if !ctrl => self.edit.field_mut(self.edit.focus).push(c),
            KeyCode::Backspace => {
                self.edit.field_mut(self.edit.focus).pop();
            }
            _ => {}
        }
        false
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

        // Build the entry, preserving id/created_at/history for an existing one.
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

        v.vault.upsert(entry);
        match v.save() {
            Ok(()) => {
                self.status = "Saved.".into();
                self.clamp_selection();
                self.screen = Screen::List;
            }
            Err(e) => self.status = format!("Save failed: {e}"),
        }
    }

    // --- Drawing -------------------------------------------------------------

    fn draw(&self, frame: &mut Frame) {
        match self.screen {
            Screen::Auth => self.draw_auth(frame),
            Screen::List => self.draw_list(frame),
            Screen::Detail => self.draw_detail(frame),
            Screen::Edit => self.draw_edit(frame),
        }
    }

    fn draw_auth(&self, frame: &mut Frame) {
        let area = frame.area();
        let (title, help) = match self.auth.mode {
            AuthMode::Create => (
                " Create vault — set two passwords ",
                "Choose two passwords. Both will be required to open this vault.",
            ),
            AuthMode::Unlock => (" Unlock vault ", "Enter both passwords to unlock."),
            AuthMode::ChangePassword => (
                " Change master passwords ",
                "Set two new passwords. They replace the current ones immediately.",
            ),
        };
        let mut lines: Vec<Line> = Vec::new();
        // Show which file we are operating on (req. 11 — identifiable vault file).
        lines.push(Line::from(Span::styled(
            format!("Vault: {}", self.path.display()),
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(help, Style::default().fg(Color::Gray))));
        lines.push(Line::from(""));
        for (i, field) in self.auth.fields.iter().enumerate() {
            let focused = i == self.auth.focus;
            let marker = if focused { "> " } else { "  " };
            let masked: String = "*".repeat(field.value.chars().count());
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
            lines.push(Line::from(Span::styled(
                err.clone(),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
        }
        lines.push(Line::from(""));
        let esc_hint = if self.auth.mode == AuthMode::ChangePassword { "Esc cancel" } else { "Esc quit" };
        lines.push(Line::from(Span::styled(
            format!("Tab/↑↓ move · Enter next/submit · {esc_hint}"),
            Style::default().fg(Color::DarkGray),
        )));

        let block = Block::default().borders(Borders::ALL).title(title);
        frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: true }), area);
    }

    fn draw_list(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // search
                Constraint::Length(3), // filters
                Constraint::Min(1),    // list
                Constraint::Length(3), // footer
            ])
            .split(frame.area());

        // Search box.
        let search = Paragraph::new(self.search.as_str())
            .block(Block::default().borders(Borders::ALL).title(" Search (type to filter) "));
        frame.render_widget(search, chunks[0]);

        // Filter chips: All + each custom type.
        let mut spans = vec![chip("All", self.filter_idx.is_none())];
        if let Some(v) = &self.vault {
            for (i, t) in v.vault.types.iter().enumerate() {
                spans.push(Span::raw(" "));
                spans.push(chip(t, self.filter_idx == Some(i)));
            }
        }
        let filters = Paragraph::new(Line::from(spans))
            .block(Block::default().borders(Borders::ALL).title(" Type filter (Tab to cycle) "));
        frame.render_widget(filters, chunks[1]);

        // Entry list.
        let entries: Vec<&Entry> = match &self.vault {
            Some(v) => v.vault.filter(&self.search, self.active_kind().as_deref()),
            None => Vec::new(),
        };
        let items: Vec<ListItem> = entries
            .iter()
            .map(|e| {
                let kind = if e.kind.is_empty() { String::new() } else { format!("[{}] ", e.kind) };
                ListItem::new(Line::from(vec![
                    Span::styled(kind, Style::default().fg(Color::Cyan)),
                    Span::styled(e.title.clone(), Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        if e.username.is_empty() { String::new() } else { format!("  ({})", e.username) },
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            })
            .collect();

        let count = items.len();
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!(" Entries ({count}) ")))
            .highlight_style(Style::default().bg(Color::Blue).add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");
        let mut state = ListState::default();
        if count > 0 {
            state.select(Some(self.selected.min(count - 1)));
        }
        frame.render_stateful_widget(list, chunks[2], &mut state);

        self.draw_footer(
            frame,
            chunks[3],
            "↑↓ move · Enter open · Ctrl+N new · Ctrl+D del · Tab filter · Ctrl+P passwords · Esc clear/quit",
        );
    }

    fn draw_detail(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(frame.area());

        let Some(e) = self.selected_entry() else {
            frame.render_widget(Paragraph::new("No entry selected."), chunks[0]);
            return;
        };

        let body = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(if self.show_history {
                [Constraint::Percentage(55), Constraint::Percentage(45)]
            } else {
                [Constraint::Percentage(100), Constraint::Length(0)]
            })
            .split(chunks[0]);

        let pw = if self.reveal { e.password.clone() } else { "•".repeat(e.password.chars().count()) };
        let fields = vec![
            field_line("Title", &e.title),
            field_line("Type", &e.kind),
            field_line("Username", &e.username),
            field_line("Password", &pw),
            field_line("URL", &e.url),
            field_line("Description", &e.description),
            Line::from(""),
            Line::from(Span::styled(
                format!("Created {}   Updated {}", format_time(e.created_at), format_time(e.updated_at)),
                Style::default().fg(Color::DarkGray),
            )),
        ];
        frame.render_widget(
            Paragraph::new(fields)
                .block(Block::default().borders(Borders::ALL).title(" Entry "))
                .wrap(Wrap { trim: true }),
            body[0],
        );

        if self.show_history {
            let mut hist: Vec<Line> = e
                .history
                .iter()
                .rev()
                .map(|c| {
                    Line::from(vec![
                        Span::styled(format!("{}  ", format_time(c.at)), Style::default().fg(Color::DarkGray)),
                        Span::raw(if c.detail.is_empty() { c.action.clone() } else { c.detail.clone() }),
                    ])
                })
                .collect();
            if hist.is_empty() {
                hist.push(Line::from(Span::styled("(no changes recorded)", Style::default().fg(Color::DarkGray))));
            }
            frame.render_widget(
                Paragraph::new(hist)
                    .block(Block::default().borders(Borders::ALL).title(" History "))
                    .wrap(Wrap { trim: true }),
                body[1],
            );
        }

        self.draw_footer(
            frame,
            chunks[1],
            "r reveal · c copy · h history · e edit · Ctrl+D delete · Esc back",
        );
    }

    fn draw_edit(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(3)])
            .split(frame.area());

        let labels = EditState::labels();
        let values = [
            &self.edit.title,
            &self.edit.kind,
            &self.edit.description,
            &self.edit.username,
            &self.edit.password,
            &self.edit.url,
        ];
        let mut lines: Vec<Line> = Vec::new();
        for i in 0..EditState::FIELD_COUNT {
            let focused = i == self.edit.focus;
            let marker = if focused { "> " } else { "  " };
            let is_password = i == 4;
            let shown = if is_password && !self.edit.reveal {
                "•".repeat(values[i].chars().count())
            } else {
                values[i].clone()
            };
            let label_style = if focused {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("{marker}{:<13}", labels[i]), label_style),
                Span::raw(shown),
            ]));
            lines.push(Line::from(""));
        }

        let title = if self.edit.id.is_some() { " Edit entry " } else { " New entry " };
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title(title))
                .wrap(Wrap { trim: true }),
            chunks[0],
        );

        self.draw_footer(
            frame,
            chunks[1],
            "Tab/↑↓ move · Ctrl+S save · Ctrl+G generate password · Ctrl+R reveal · Esc cancel",
        );
    }

    fn draw_footer(&self, frame: &mut Frame, area: Rect, hints: &str) {
        let text = if self.status.is_empty() {
            hints.to_string()
        } else {
            format!("{}  —  {hints}", self.status)
        };
        let footer = Paragraph::new(text)
            .style(Style::default().fg(Color::Gray))
            .alignment(Alignment::Left)
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, area);
    }
}

/// Best-effort overwrite of the system clipboard with empty text, so a copied
/// password does not linger after the app exits.
fn clear_clipboard() {
    let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(String::new()));
}

/// A filter chip span, highlighted when active.
fn chip(label: &str, active: bool) -> Span<'static> {
    let style = if active {
        Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    };
    Span::styled(format!(" {label} "), style)
}

/// A "Label: value" line for the detail view.
fn field_line<'a>(label: &'a str, value: &str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<13}"), Style::default().fg(Color::Cyan)),
        Span::raw(value.to_string()),
    ])
}

/// Format a unix-seconds timestamp as `YYYY-MM-DD HH:MM:SS UTC`, with no
/// external date dependency. Uses Howard Hinnant's civil-from-days algorithm.
/// Returns "never" for a zero/negative timestamp. Shared with the GUI.
pub(crate) fn format_time(ts: i64) -> String {
    if ts <= 0 {
        return "never".to_string();
    }
    let days = ts.div_euclid(86_400);
    let secs_of_day = ts.rem_euclid(86_400);
    let (h, m, s) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);

    // days since 1970-01-01 -> civil (y, m, d)
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
        // 2021-01-01 00:00:00 UTC = 1609459200
        assert_eq!(format_time(1_609_459_200), "2021-01-01 00:00:00 UTC");
        // 2021-01-01 00:00:01 UTC
        assert_eq!(format_time(1_609_459_201), "2021-01-01 00:00:01 UTC");
    }
}
