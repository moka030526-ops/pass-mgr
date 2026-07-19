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

use crate::csv;
use crate::password::{self, GenOptions};
use crate::records::{
    self, Account, AssetLiability, GeneralDocument, Instruction, RealEstate, Record, TaxFiling, TrustWill, Urgent,
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
            // A low floor on purpose: every pane now scrolls on its own axis, so the
            // window stays usable when it is squeezed. The old 720x480 floor meant a
            // small screen could not shrink the window to fit at all.
            .with_min_inner_size([560.0, 400.0])
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
            apply_theme(&cc.egui_ctx, load_theme());
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
    Nord,
    Dracula,
    GruvboxDark,
    GruvboxLight,
    RosePine,
}

impl Theme {
    /// Every theme, in menu order.
    const ALL: [Theme; 10] = [
        Theme::Light,
        Theme::Dark,
        Theme::HighContrast,
        Theme::Solarized,
        Theme::Sepia,
        Theme::Nord,
        Theme::Dracula,
        Theme::GruvboxDark,
        Theme::GruvboxLight,
        Theme::RosePine,
    ];

    /// Stable on-disk id (kept separate from the display label so relabelling
    /// never invalidates a saved preference).
    fn id(self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
            Theme::HighContrast => "high-contrast",
            Theme::Solarized => "solarized",
            Theme::Sepia => "sepia",
            Theme::Nord => "nord",
            Theme::Dracula => "dracula",
            Theme::GruvboxDark => "gruvbox-dark",
            Theme::GruvboxLight => "gruvbox-light",
            Theme::RosePine => "rose-pine",
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
            Theme::Nord => "Nord",
            Theme::Dracula => "Dracula",
            Theme::GruvboxDark => "Gruvbox Dark",
            Theme::GruvboxLight => "Gruvbox Light",
            Theme::RosePine => "Rosé Pine",
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
        Theme::Nord => {
            // Nord — cool, muted polar palette.
            let (bg, bg2, bg3) = (rgb(46, 52, 64), rgb(59, 66, 82), rgb(67, 76, 94));
            let (txt, frost, blue) = (rgb(216, 222, 233), rgb(136, 192, 208), rgb(129, 161, 193));
            let mut v = egui::Visuals::dark();
            v.panel_fill = bg;
            v.window_fill = bg;
            v.extreme_bg_color = rgb(38, 43, 54);
            v.faint_bg_color = bg2;
            v.override_text_color = Some(txt);
            v.widgets.noninteractive.bg_fill = bg2;
            v.widgets.inactive.bg_fill = bg2;
            v.widgets.inactive.weak_bg_fill = bg2;
            v.widgets.hovered.bg_fill = bg3;
            v.widgets.active.bg_fill = blue;
            v.selection.bg_fill = bg3;
            v.selection.stroke = egui::Stroke::new(1.0, frost);
            v.hyperlink_color = frost;
            v
        }
        Theme::Dracula => {
            // Dracula — dark with vivid purple/cyan accents.
            let (bg, panel, sel) = (rgb(40, 42, 54), rgb(48, 50, 64), rgb(68, 71, 90));
            let (fg, purple, cyan) = (rgb(248, 248, 242), rgb(189, 147, 249), rgb(139, 233, 253));
            let mut v = egui::Visuals::dark();
            v.panel_fill = bg;
            v.window_fill = bg;
            v.extreme_bg_color = rgb(33, 34, 44);
            v.faint_bg_color = panel;
            v.override_text_color = Some(fg);
            v.widgets.noninteractive.bg_fill = panel;
            v.widgets.inactive.bg_fill = panel;
            v.widgets.inactive.weak_bg_fill = panel;
            v.widgets.hovered.bg_fill = sel;
            v.widgets.active.bg_fill = purple;
            v.selection.bg_fill = sel;
            v.selection.stroke = egui::Stroke::new(1.0, purple);
            v.hyperlink_color = cyan;
            v
        }
        Theme::GruvboxDark => {
            // Gruvbox — warm retro dark.
            let (bg, bg1, bg2) = (rgb(40, 40, 40), rgb(60, 56, 54), rgb(80, 73, 69));
            let (fg, orange, aqua) = (rgb(235, 219, 178), rgb(254, 128, 25), rgb(142, 192, 124));
            let mut v = egui::Visuals::dark();
            v.panel_fill = bg;
            v.window_fill = bg;
            v.extreme_bg_color = rgb(29, 32, 33);
            v.faint_bg_color = bg1;
            v.override_text_color = Some(fg);
            v.widgets.noninteractive.bg_fill = bg1;
            v.widgets.inactive.bg_fill = bg1;
            v.widgets.inactive.weak_bg_fill = bg1;
            v.widgets.hovered.bg_fill = bg2;
            v.widgets.active.bg_fill = orange;
            v.selection.bg_fill = bg2;
            v.selection.stroke = egui::Stroke::new(1.0, aqua);
            v.hyperlink_color = aqua;
            v
        }
        Theme::GruvboxLight => {
            // Gruvbox — warm retro light.
            let (bg, bg1, bg2) = (rgb(251, 241, 199), rgb(235, 219, 178), rgb(213, 196, 161));
            let (fg, orange) = (rgb(60, 56, 54), rgb(214, 93, 14));
            let mut v = egui::Visuals::light();
            v.panel_fill = bg;
            v.window_fill = rgb(249, 245, 215);
            v.extreme_bg_color = rgb(252, 248, 227);
            v.faint_bg_color = bg1;
            v.override_text_color = Some(fg);
            v.widgets.noninteractive.bg_fill = bg1;
            v.widgets.inactive.bg_fill = bg1;
            v.widgets.inactive.weak_bg_fill = bg1;
            v.widgets.hovered.bg_fill = bg2;
            v.widgets.active.bg_fill = orange;
            v.selection.bg_fill = bg2;
            v.selection.stroke = egui::Stroke::new(1.0, rgb(175, 58, 3));
            v
        }
        Theme::RosePine => {
            // Rosé Pine — soft, moody low-contrast dark.
            let (base, surface, overlay) = (rgb(25, 23, 36), rgb(31, 29, 46), rgb(38, 35, 58));
            let (text, iris, foam) = (rgb(224, 222, 244), rgb(196, 167, 231), rgb(156, 207, 216));
            let mut v = egui::Visuals::dark();
            v.panel_fill = base;
            v.window_fill = base;
            v.extreme_bg_color = rgb(20, 18, 30);
            v.faint_bg_color = surface;
            v.override_text_color = Some(text);
            v.widgets.noninteractive.bg_fill = surface;
            v.widgets.inactive.bg_fill = surface;
            v.widgets.inactive.weak_bg_fill = surface;
            v.widgets.hovered.bg_fill = overlay;
            v.widgets.active.bg_fill = iris;
            v.selection.bg_fill = overlay;
            v.selection.stroke = egui::Stroke::new(1.0, foam);
            v.hyperlink_color = foam;
            v
        }
    }
}

// --- The visual design system ------------------------------------------------
//
// Everything below shapes how the app LOOKS, and nothing below changes what any
// control does. It is kept in one block so the whole app restyles from a single
// place: `apply_theme` sets both the palette (`visuals_for`, above) and the
// typography/spacing/shape rules (`apply_style`), and `accent` gives each palette
// one signature color used for headings, section labels, and the active tab.

/// The signature color of a theme. Used for headings, the active tab's underline,
/// section labels, and list badges — the small amount of color that tells the eye
/// where the structure of a screen is.
fn accent(theme: Theme) -> egui::Color32 {
    use egui::Color32;
    let rgb = Color32::from_rgb;
    match theme {
        Theme::Light => rgb(21, 92, 170),
        Theme::Dark => rgb(110, 170, 240),
        Theme::HighContrast => rgb(120, 200, 255),
        Theme::Solarized => rgb(38, 139, 210),
        Theme::Sepia => rgb(140, 88, 38),
        Theme::Nord => rgb(136, 192, 208),
        Theme::Dracula => rgb(189, 147, 249),
        Theme::GruvboxDark => rgb(254, 128, 25),
        Theme::GruvboxLight => rgb(175, 58, 3),
        Theme::RosePine => rgb(196, 167, 231),
    }
}

/// Apply a theme to the egui context: its palette AND the shared typography and
/// spacing rules. Called once before the first frame and again whenever the user
/// picks a different theme.
fn apply_theme(ctx: &egui::Context, theme: Theme) {
    ctx.set_visuals(visuals_for(theme));
    apply_style(ctx, theme);
}

/// The typography, spacing, and shape rules shared by every screen.
///
/// egui's defaults are tuned for debug tooling: 14 px text, tight 8/3 spacing, and
/// small corner radii. This is a document-shaped application that people read, so
/// the scale is opened up — larger body text, a real heading step, roomier control
/// padding, and softer corners — which is most of what makes the window feel less
/// like a debug panel and more like an application.
fn apply_style(ctx: &egui::Context, theme: Theme) {
    use egui::{FontFamily, FontId, TextStyle};

    let mut style = (*ctx.global_style()).clone();

    // A deliberate type scale rather than one size for everything: headings lead,
    // body text is comfortable to read for a while, and small text is genuinely
    // secondary instead of merely greyer.
    style.text_styles = [
        (TextStyle::Heading, FontId::new(21.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(14.5, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(14.5, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(12.0, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.5, FontFamily::Monospace)),
    ]
    .into();

    // Spacing: more air between rows, and buttons with enough padding to look
    // pressable. `indent` widens the step of collapsing trees so the grouped
    // Accounts/Assets views read as a hierarchy at a glance.
    let s = &mut style.spacing;
    s.item_spacing = egui::vec2(8.0, 7.0);
    s.button_padding = egui::vec2(10.0, 5.0);
    s.indent = 20.0;
    s.window_margin = egui::Margin::same(10);
    s.menu_margin = egui::Margin::same(8);
    s.interact_size.y = 24.0;
    s.scroll.bar_width = 10.0;
    s.scroll.floating = false;

    // Shape: consistently rounded controls, and a visible focus ring in the
    // accent color so keyboard focus is never guesswork.
    let v = &mut style.visuals;
    let radius = egui::CornerRadius::same(6);
    for w in [
        &mut v.widgets.noninteractive,
        &mut v.widgets.inactive,
        &mut v.widgets.hovered,
        &mut v.widgets.active,
        &mut v.widgets.open,
    ] {
        w.corner_radius = radius;
    }
    v.window_corner_radius = egui::CornerRadius::same(8);
    v.menu_corner_radius = egui::CornerRadius::same(8);
    v.selection.stroke = egui::Stroke::new(1.0, accent(theme));
    v.widgets.hovered.expansion = 1.0;
    v.widgets.active.expansion = 1.0;

    ctx.set_global_style(style);
}

/// A framed content card: a subtly filled, rounded, hairlined box used to group a
/// form or a panel so the eye can tell one region from the next.
///
/// Purely presentational — it wraps whatever the caller draws and returns what the
/// closure returned, so wrapping an existing block in a card never changes it.
fn card<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .stroke(egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color))
        .corner_radius(8)
        .inner_margin(egui::Margin::same(12))
        .show(ui, add)
        .inner
}

/// A small filled pill — used for counts and mode badges, where a number needs to
/// read as a label rather than as body text.
fn badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.18))
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.5)))
        .corner_radius(9)
        .inner_margin(egui::Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).color(color).small().strong());
        });
}

/// A screen or panel heading in the accent color, with the vertical rhythm the
/// rest of the design system expects.
fn section_heading(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    ui.label(egui::RichText::new(text).heading().color(color));
}

// The color theme is stored in the shared, non-secret `prefs.json` alongside the
// export directory (see `crate::prefs_path` / `crate::read_prefs_obj` in lib.rs). The
// theme accessors live here because they reference the GUI-only `Theme` type; the
// generic prefs primitives and the export-dir accessors are shared in `crate`.

/// Load the saved theme from the standard preferences path.
fn load_theme() -> Theme {
    crate::prefs_path().map(|p| load_theme_from(&p)).unwrap_or_default()
}

/// Load the theme from a specific path. Best-effort/bounded: missing/symlinked/over-cap/
/// unparseable all fall back to the default — a UI preference must never block startup.
fn load_theme_from(path: &std::path::Path) -> Theme {
    crate::read_prefs_obj(path).get("theme").and_then(|t| t.as_str()).and_then(Theme::from_id).unwrap_or_default()
}

/// Persist the chosen theme to the standard preferences path.
fn save_theme(theme: Theme) {
    if let Some(path) = crate::prefs_path() {
        save_theme_to(&path, theme);
    }
}

/// Persist the theme to a specific path, preserving any other prefs keys (export_dir).
fn save_theme_to(path: &std::path::Path, theme: Theme) {
    let mut obj = crate::read_prefs_obj(path);
    obj.insert("theme".into(), serde_json::Value::String(theme.id().to_string()));
    crate::write_prefs_obj(path, &obj);
}

// `enum` is a closed set of named alternatives (a tagged union). `#[derive(...)]`
// auto-generates trait implementations: `PartialEq`/`Eq` enable `==`/`!=`
// comparisons; `Clone` enables explicit `.clone()`; `Copy` makes the value
// trivially duplicated on assignment (so passing it around does not "move" it).
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Screen {
    Auth,
    Main,
    Config,
    Help,
    /// "Update from another vault": collect the source dir + its two passwords, preview the
    /// patch, then apply. Reached from Config (writable only).
    Merge,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum AuthMode {
    Create,
    Unlock,
    ChangePassword,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Tab {
    Urgent,
    Instructions,
    TrustWill,
    Assets,
    Accounts,
    RealEstate,
    Taxes,
    GeneralDocuments,
    Summary,
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
    /// The directory whose `vault.pmv` we open/create. On the collapsed start page this is
    /// DERIVED as `<vault_root>/<vault_name>` (see `recompute_vault_path`), never edited
    /// directly. Kept in sync with `path` (`path == <vault_dir>/vault.pmv`).
    vault_dir: String,
    /// Editable ROOT directory scanned (one level deep) for vaults to populate the
    /// start-page dropdown. Seeded from the saved `vault_root` preference (else the launch
    /// dir's parent); editing it re-scans and is persisted back to prefs.
    vault_root: String,
    /// The selected/typed vault folder NAME (leaf under `vault_root`) — the editable "Vault"
    /// box. The dropdown fills it; typing a name not on disk arms Create. Empty = the root
    /// itself. Together with `vault_root` it derives `vault_dir`/`path`.
    vault_name: String,
    /// Names of the subdirectories of `vault_root` that contain a `vault.pmv`, refreshed
    /// whenever `vault_root` changes — the dropdown's items. Sorted case-insensitively.
    discovered_vaults: Vec<String>,
    /// A warning from the most recent scan (root unreadable, or some entries skipped),
    /// shown beneath the picker. `None` when the scan was clean.
    vault_scan_warning: Option<String>,
    pw1: String,
    confirm1: String,
    pw2: String,
    confirm2: String,
    auth_error: Option<String>,
    // Unlocked vault. `Option<OpenVault>` is `None` until the user authenticates,
    // then `Some(vault)`; this is how Rust models "may or may not be present"
    // without null pointers.
    vault: Option<OpenVault>,
    // "Update from another vault" (Screen::Merge) state. The source directory + its two
    // passwords are collected, then `merge_source` holds the opened (read-only) source and
    // `merge_plan` the computed patch between the preview and the apply. Passwords are
    // wiped (and pre-reserved) like the auth buffers.
    merge_src_dir: String,
    merge_pw1: String,
    merge_pw2: String,
    merge_source: Option<OpenVault>,
    merge_plan: Option<crate::merge::MergePlan>,
    merge_error: Option<String>,
    // Tabs + per-tab working edit buffer. Each `edit_*` is the record currently
    // being edited on that tab, or `None` when nothing is selected.
    tab: Tab,
    edit_urgent: Option<Urgent>,
    edit_instruction: Option<Instruction>,
    edit_trustwill: Option<TrustWill>,
    edit_asset: Option<AssetLiability>,
    edit_account: Option<Account>,
    edit_realestate: Option<RealEstate>,
    edit_taxfiling: Option<TaxFiling>,
    edit_general: Option<GeneralDocument>,
    // The ONLY reveal control on the Accounts screen: a single global toggle that
    // unmasks every account password at once (there is no per-record reveal).
    reveal_all: bool,
    // The same single global toggle for the Real Estate screen's four portal passwords.
    // Kept separate from `reveal_all` so the two screens don't reveal each other.
    re_reveal_all: bool,
    // Saved "view defaults" preferences (the three Config checkboxes, persisted in
    // prefs.json). They are kept SEPARATE from the live view state above so the Config
    // checkboxes always reflect the saved default, never a transient per-tab toggle.
    // `reveal_default` seeds `reveal_all`/`re_reveal_all` at open AND is re-applied by the
    // tab-switch reset (instead of forcing reveal back to masked); the two grouping
    // defaults seed `acct_grouped`/`asset_grouped` at open.
    reveal_default: bool,
    group_assets_default: bool,
    group_accounts_default: bool,
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
    // Assets view: false = flat filtered list, true = grouped tree (owner → Asset/Liability → type).
    asset_grouped: bool,
    // Assets-tab "review only" filter.
    asset_filter_review: bool,
    /// Account id whose Delete click is awaiting confirmation because assets still
    /// link to it: deleting such an account is allowed but never silent (the links are
    /// NOT cascaded — they render as raw ids afterwards), so the first click arms this
    /// and the form shows the linked-from count + a "Delete anyway"/"Cancel" pair.
    /// Guarded by the record id so a warning armed for one account can never confirm
    /// a delete of another; disarmed on selection change / New / cancel / confirm.
    pending_account_delete: Option<String>,
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
    // ([<owner-initials>/]<root>[/<group>][/subfolder], timestamp folded into the
    // filename as <ts>_<file>); the user controls only the optional subfolder and the
    // filename.
    doc_subfolder: String,
    doc_filename: String,
    doc_source: String,
    // Prefs-backed export destination directory (replaces the old per-export "Export to"
    // path prompt). Settable even in read-only mode — it is a local-machine preference,
    // not vault content — so read-only document export (the heir use case) keeps working.
    export_dir: String,
    status: String,
    /// When `Some`, a hard operation failure (a failed save/export/backup/upload, …) to
    /// surface in a CONSPICUOUS top banner — not just the easily-missed weak status line.
    /// Cleared on dismissal or when any later status message replaces the failure text
    /// (see [`error_banner_is_stale`]).
    error: Option<String>,
    clipboard_dirty: bool,
    // When set, the clipboard should be wiped at/after this instant.
    // `Option<Instant>`: `None` = no pending wipe, `Some(t)` = wipe at time `t`.
    clipboard_clear_at: Option<Instant>,
    /// The selected color theme, and the one currently applied to egui — so we
    /// only call `set_visuals` (and persist) when the selection actually changes.
    theme: Theme,
    applied_theme: Theme,
    /// The in-app manual's browser state (search box + selected topic), kept here
    /// so the user's place in it survives leaving and re-entering Help.
    help: crate::gui_help::HelpState,
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
        self.merge_pw1.zeroize();
        self.merge_pw2.zeroize();
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
        // Collapsed start page: the open target is `<root>/<name>`. Seed the root from the
        // saved preference (so startups share a default root), pre-selecting the launched
        // vault's folder when appropriate; then derive the directory/path from root+name.
        let saved_root = crate::load_vault_root();
        let saved_vault = crate::load_last_vault();
        let (vault_root, vault_name) =
            crate::launch::initial_root_and_name(&path, &saved_root, &saved_vault);
        // Default the backup destination to the root (see the `backup_dest` field).
        let backup_dest = vault_root.clone();
        let vault_dir = crate::launch::join_root_name(&vault_root, &vault_name);
        let path = crate::launch::vault_file(&vault_dir);
        // `if ... { } else { }` is an expression here: its value initializes
        // `auth_mode` (unlock an existing vault file, else offer to create one).
        let auth_mode = if path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        let scan = crate::launch::discover_vaults(&vault_root);
        // Load the saved theme; `applied_theme` starts equal to it so the first
        // frame doesn't needlessly re-apply/re-save (the same value `run` already set).
        let theme = load_theme();
        // Saved "view defaults" (Config checkboxes, prefs.json): seed the reveal-all
        // toggles and the grouped/flat view state so a freshly opened vault honours the
        // user's preferences. The pref values are also retained on the struct so the Config
        // checkboxes show the saved default and the tab-switch reset can re-apply reveal.
        let reveal_default = crate::load_reveal_all_default(&vault_root);
        let group_assets_default = crate::load_group_assets_default(&vault_root);
        let group_accounts_default = crate::load_group_accounts_default(&vault_root);
        // Hoisted above the struct literal because `vault_root` is moved into the struct
        // below; the vault-root fallback needs to read it before that move.
        let export_dir = crate::load_export_dir(&vault_root);
        GuiApp {
            path,
            writable,
            screen: Screen::Auth,
            auth_mode,
            vault_dir,
            vault_root,
            vault_name,
            discovered_vaults: scan.vaults,
            vault_scan_warning: scan.warning,
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
            merge_src_dir: String::new(),
            // Pre-reserve so typing the source passwords never reallocates (which would
            // strand un-zeroized fragments) — same discipline as the auth buffers.
            merge_pw1: String::with_capacity(256),
            merge_pw2: String::with_capacity(256),
            merge_source: None,
            merge_plan: None,
            merge_error: None,
            tab: Tab::Urgent,
            edit_urgent: None,
            edit_instruction: None,
            edit_trustwill: None,
            edit_asset: None,
            edit_account: None,
            edit_realestate: None,
            edit_taxfiling: None,
            edit_general: None,
            reveal_all: reveal_default,
            re_reveal_all: reveal_default,
            reveal_default,
            group_assets_default,
            group_accounts_default,
            acct_filter_type: String::new(),
            acct_filter_subtype: String::new(),
            acct_filter_owner: String::new(),
            acct_filter_title: String::new(),
            acct_filter_review: false,
            acct_search_user: String::new(),
            acct_grouped: group_accounts_default,
            asset_grouped: group_assets_default,
            asset_filter_review: false,
            pending_account_delete: None,
            new_asset_type: String::new(),
            new_account_type: String::new(),
            new_subtype_for: String::new(),
            new_subtype_name: String::new(),
            // Default the backup destination to the vault ROOT (editable in Config). It
            // tracks the root while still on the start page; once unlocked it's the user's.
            backup_dest,
            cfg_volume_size: String::new(),
            cfg_redundancy: 0,
            doc_subfolder: String::new(),
            doc_filename: String::new(),
            doc_source: String::new(),
            export_dir,
            status: String::new(),
            error: None,
            clipboard_dirty: false,
            clipboard_clear_at: None,
            theme,
            applied_theme: theme,
            help: crate::gui_help::HelpState::default(),
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
            // The deadline/status-preservation rules live in a pure, unit-tested helper
            // shared with the TUI; `Some` means "wipe now", `None` means "not yet".
            match crate::clipboard_tick_decision(Some(deadline), now, &self.status) {
                Some(status_change) => {
                    clear_clipboard();
                    self.clipboard_dirty = false;
                    self.clipboard_clear_at = None;
                    if let Some(s) = status_change {
                        self.status = s;
                    }
                }
                None => {
                    ctx.request_repaint_after(deadline - now);
                }
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
        // Borrow the vault mutably if present, attempt the save, and return early on the
        // success/absent paths. We can't call `self.fail()` (a `&mut self` method) while
        // `self.vault` is borrowed for the save, so we capture the message and report it
        // AFTER the borrow ends — surfacing a failed save in the conspicuous banner.
        let err = match self.vault.as_mut() {
            Some(ov) => match ov.save() {
                Ok(()) => return true,
                Err(e) => format!("Save failed: {e}"),
            },
            None => return false,
        };
        self.fail(err);
        false
    }

    /// Record a hard operation FAILURE: show `msg` in the CONSPICUOUS top error banner
    /// (rendered by [`GuiApp::ui`]) as well as the status line. A failed save (e.g. a full
    /// disk) must be impossible to miss — hidden in the weak status text alone, the user
    /// would believe the edit was saved when it was not. The banner clears when the user
    /// dismisses it or any later status message replaces this text (see
    /// [`error_banner_is_stale`]).
    fn fail(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.error = Some(msg.clone());
        self.status = msg;
    }

    fn clear_doc_inputs(&mut self) {
        self.doc_subfolder.clear();
        self.doc_filename.clear();
        self.doc_source.clear();
    }

    /// Build the CSV text for the current tab's records (ALL of them, ignoring any display
    /// filter), plus a base filename and the record count. The tab -> collection mapping
    /// lives in the shared `csv::build_tab_csv` core helper; this only maps the GUI's local
    /// `Tab` to `csv::CsvTab`. The `Summary => None` arm keeps the match exhaustive — Summary
    /// has no records and shows no CSV button, so it is unreachable from the GUI. Document/
    /// file columns hold file NAMES. The result is wrapped in `Zeroizing` because it can
    /// contain plaintext passwords (Accounts / Real Estate portals).
    fn build_tab_csv(&self) -> Option<(&'static str, Zeroizing<String>, usize)> {
        let ov = self.vault.as_ref()?;
        let tab = match self.tab {
            Tab::Urgent => csv::CsvTab::Urgent,
            Tab::Instructions => csv::CsvTab::Instructions,
            Tab::TrustWill => csv::CsvTab::TrustWill,
            Tab::Assets => csv::CsvTab::Assets,
            Tab::Accounts => csv::CsvTab::Accounts,
            Tab::RealEstate => csv::CsvTab::RealEstate,
            Tab::Taxes => csv::CsvTab::Taxes,
            Tab::GeneralDocuments => csv::CsvTab::GeneralDocuments,
            Tab::Summary => return None,
        };
        let name_of = |id: &str| ov.doc_path(id).map(|p| csv::basename(&p)).unwrap_or_default();
        let (base, text, n) = csv::build_tab_csv(&ov.vault, tab, name_of);
        Some((base, Zeroizing::new(text), n))
    }

    /// Export every record on the current tab to a timestamped CSV in the configured
    /// export directory (e.g. `accounts-20240628-143000.csv`). Requires WRITE mode: unlike
    /// document export (which a read-only heir may use), a CSV can hold every record's
    /// plaintext password, so a read-only session must not be able to bulk-dump it.
    fn export_current_tab_csv(&mut self) {
        // Available in READ-ONLY sessions too, at the vault owner's explicit request. The
        // file it writes is plain, unencrypted text and — on Accounts and Real Estate —
        // contains every password in the clear, so the status line below says so rather
        // than reporting a bare success.
        let dir = self.export_dir.trim().to_string();
        if dir.is_empty() {
            self.fail("Set an export directory in Config first (Config > Export directory).");
            return;
        }
        let Some((base, text, n)) = self.build_tab_csv() else {
            self.status = "Nothing to export on this tab.".into();
            return;
        };
        let filename = format!("{base}-{}.csv", records::compact_utc(records::unix_now()));
        match vault::write_export_bytes(Path::new(&dir), &filename, text.as_bytes()) {
            Ok(p) => {
                self.status =
                    format!("Exported {n} record(s) to {} — UNENCRYPTED, incl. any passwords.", p.display());
            }
            Err(e) => self.fail(format!("CSV export failed: {e}")),
        }
    }

    /// Export document `id` into the configured export directory, recreating its volume
    /// folder structure under it. Used by every tab's Export button — there is no
    /// per-export path prompt; the destination is the directory set in Config (which is
    /// editable even in read-only mode, so this works for a read-only heir).
    fn export_doc_to_config_dir(&mut self, id: &str) {
        let dir = self.export_dir.trim().to_string();
        if dir.is_empty() {
            self.status = "Set an export directory in Config first (Config > Export directory).".into();
            return;
        }
        if let Some(ov) = self.vault.as_ref() {
            match ov.export_document_into(id, Path::new(&dir)) {
                Ok(p) => self.status = format!("Exported to {}", p.display()),
                Err(e) => self.fail(format!("Export failed: {e}")),
            }
        }
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
                // Persist the chosen root so the next startup defaults to the same place (a
                // local prefs.json preference — never written into the vault). Done on a
                // successful open/create, the natural point at which the root is "confirmed".
                crate::save_vault_root(self.vault_root.trim());
                // Remember which vault was opened so the next startup pre-selects it in the
                // dropdown. Saved verbatim (the raw folder name) so it round-trips through
                // `discover_vaults`/`join_root_name`.
                crate::save_last_vault(&self.vault_name);
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
                // Start the new vault's UI from a clean slate — never inherit the previous
                // session's edit buffers/filters/reveal (see reset_per_vault_ui_state). Done
                // BEFORE installing the vault so nothing from vault A is ever rendered for B.
                self.reset_per_vault_ui_state();
                self.vault = Some(v);
                // Bring the Config type lists into line with what records actually use, so a
                // freshly opened (writable) vault's Config matches its data — types brought in
                // by an older import/merge appear without a manual "sync". This is ADD-ONLY:
                // `sync_types_from_records` only inserts missing types/subtypes, it never
                // deletes a configured entry. Read-only sessions skip it; with no drift it adds
                // nothing and writes nothing. Appended to the open message so a recovery/unlock
                // notice is never clobbered.
                if self.writable {
                    match self.vault.as_mut().map(|ov| ov.sync_types_from_records()) {
                        Some(Ok(n)) if n > 0 => {
                            self.status = format!("{} · Synced {n} type(s) from records.", self.status)
                        }
                        Some(Err(e)) => self.status = format!("{} · Type sync failed: {e}", self.status),
                        _ => {}
                    }
                }
                self.auth_error = None;
                self.wipe_passwords();
                self.screen = Screen::Main;
            }
            // Collapse every CORRECT-password-reachable failure into ONE message so the
            // unlock screen can't be used as a "this password is correct" oracle: a
            // wrong password yields `Crypto`, while a missing/rolled-back document
            // (`ArchiveMismatch`), corrupt plaintext (`Json`), or storage error are
            // reachable ONLY after a successful decrypt, so a distinct message for them
            // would reveal the password was right (audit O-1; mirrors the FFI collapse).
            // Structural, password-INDEPENDENT errors (bad magic/version/truncated/
            // params/too-large, not-found, locked, rekey-pending) keep their specific,
            // useful messages below — they leak nothing about password correctness.
            Err(VaultError::Crypto(_) | VaultError::ArchiveMismatch | VaultError::Json(_) | VaultError::Storage(_)) => {
                self.auth_error = Some("Wrong password(s) or corrupted/unreadable vault.".into());
                // Wipe the entered passwords on failure too (not just on success), so
                // they don't linger in memory after a failed attempt — the moment a
                // user is most likely to step away. Mirrors the TUI, which rebuilds
                // (and thus zeroizes) its AuthState on a failed unlock.
                self.wipe_passwords();
            }
            // `Err(e)` catches every other (password-independent) error variant.
            Err(e) => {
                self.auth_error = Some(format!("{e}"));
                self.wipe_passwords();
            }
        }
    }

    /// Re-derive the open target from `<vault_root>/<vault_name>`: rebuild `vault_dir` and
    /// `path`, then flip the mode — Unlock if a `vault.pmv` already exists there, else Create
    /// (which, in --write mode, creates the directory + vault on submit). Called whenever the
    /// root, the vault name, or the dropdown selection changes.
    fn recompute_vault_path(&mut self) {
        self.vault_dir = crate::launch::join_root_name(&self.vault_root, &self.vault_name);
        self.path = crate::launch::vault_file(&self.vault_dir);
        self.auth_mode = if self.path.exists() { AuthMode::Unlock } else { AuthMode::Create };
        self.auth_error = None;
    }

    /// Re-scan `vault_root` for vaults (one level deep) and refresh the dropdown items
    /// plus any access warning. Called when the root field changes.
    fn refresh_discovered_vaults(&mut self) {
        let scan = crate::launch::discover_vaults(&self.vault_root);
        self.discovered_vaults = scan.vaults;
        self.vault_scan_warning = scan.warning;
    }

    /// Pick a vault `name` from the dropdown: set the vault name and re-derive the
    /// path/mode so the user lands ready to unlock it.
    fn select_vault(&mut self, name: &str) {
        self.vault_name = name.to_string();
        self.recompute_vault_path();
    }

    fn wipe_passwords(&mut self) {
        self.pw1.zeroize();
        self.confirm1.zeroize();
        self.pw2.zeroize();
        self.confirm2.zeroize();
        self.merge_pw1.zeroize();
        self.merge_pw2.zeroize();
    }

    /// Clear every piece of PER-VAULT UI state to its fresh-launch default. Called on each
    /// successful open so a newly-unlocked vault never inherits the previous session's edit
    /// buffers (which can hold cleartext passwords), armed delete, active filters/search, or
    /// reveal toggles. Without this, an error path that drops the vault back to the unlock
    /// screen WITHOUT going through the constructor (e.g. a change-password or merge-apply
    /// failure) leaves vault A's state visible after vault B is opened — cross-vault secret
    /// leakage and confusing filter carryover. The edit buffers are `Zeroize`-on-drop, so
    /// replacing them here also wipes any secret they held.
    fn reset_per_vault_ui_state(&mut self) {
        self.tab = Tab::Urgent;
        self.edit_urgent = None;
        self.edit_instruction = None;
        self.edit_trustwill = None;
        self.edit_asset = None;
        self.edit_account = None;
        self.edit_realestate = None;
        self.edit_taxfiling = None;
        self.edit_general = None;
        self.pending_account_delete = None;
        // Reveal + grouping return to the saved view DEFAULTS (not hard false), matching the
        // constructor and the tab-switch reset.
        self.reveal_all = self.reveal_default;
        self.re_reveal_all = self.reveal_default;
        self.acct_grouped = self.group_accounts_default;
        self.asset_grouped = self.group_assets_default;
        // Filters + searches back to "no filter".
        self.acct_filter_type.clear();
        self.acct_filter_subtype.clear();
        self.acct_filter_owner.clear();
        self.acct_filter_title.clear();
        self.acct_filter_review = false;
        self.acct_search_user.clear();
        self.asset_filter_review = false;
        // Any half-typed document-upload inputs from the prior vault.
        self.clear_doc_inputs();
    }

    /// Leave the merge flow: drop the opened source vault + computed plan and wipe the
    /// source passwords. Called on cancel, on apply, and whenever Config/Merge is entered.
    fn reset_merge(&mut self) {
        self.merge_source = None;
        self.merge_plan = None;
        self.merge_error = None;
        self.wipe_merge_pw();
    }

    /// Zeroize + clear the two source-vault password buffers.
    fn wipe_merge_pw(&mut self) {
        self.merge_pw1.zeroize();
        self.merge_pw2.zeroize();
        self.merge_pw1.clear();
        self.merge_pw2.clear();
    }

    // `&mut egui::Ui` is the drawing surface, borrowed mutably so widgets can be
    // added to it. egui is immediate-mode: this method re-runs every frame.
    fn ui_auth(&mut self, ui: &mut egui::Ui) {
        // The lock screen is the app's front door and the only screen an heir may ever
        // see, so it is presented as one centered, width-limited card rather than a
        // full-width form: a narrow measure is easier to read, and the card gives the
        // password fields a visible boundary. Purely presentational — `ui_auth_inner`
        // holds the entire flow unchanged.
        let accent = accent(self.theme);
        ui.add_space(24.0);
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new("🗄  pass-mgr").heading().color(accent));
            ui.label(egui::RichText::new("Offline, two-password estate vault").weak().small());
        });
        ui.add_space(14.0);
        ui.vertical_centered(|ui| {
            ui.set_max_width(560.0);
            card(ui, |ui| {
                self.ui_auth_inner(ui);
            });
            ui.add_space(10.0);
            // The mode the session will open in, stated before the password is typed
            // rather than discovered afterwards by a control that is missing.
            if self.writable {
                ui.label(egui::RichText::new("This session can make changes (--write).").weak().small());
            } else {
                ui.label(
                    egui::RichText::new("🔒 Read-only session — relaunch with --write to make changes.")
                        .weak()
                        .small(),
                );
            }
        });
    }

    /// The unlock/create/change-password form itself (see [`Self::ui_auth`], which
    /// frames it).
    fn ui_auth_inner(&mut self, ui: &mut egui::Ui) {
        // `match` used as an expression: it yields a `(heading, help)` pair which
        // we immediately destructure into two named bindings.
        ui.add_space(4.0);
        // On the start page (not the in-vault Change-password flow) the user picks the vault
        // by ROOT + a collapsed "Vault" box: an editable ROOT path scanned (one level deep)
        // for vaults, and a Vault box that the dropdown fills — pick an existing vault, or
        // TYPE a new folder name to create one. Both editable in read-only AND --write mode.
        // The open target is always `<root>/<name>`. Rendered FIRST so the heading/confirm
        // fields below reflect the just-updated mode.
        if self.auth_mode != AuthMode::ChangePassword {
            // Deferred edits/picks gathered during the (borrow-locked) closure, applied after
            // it returns so the handlers can take `&mut self` freely.
            let mut root_changed = false;
            let mut name_changed = false;
            let mut picked: Option<String> = None;
            // The dropdown's button text: the current name, or a placeholder.
            let current = self.vault_name.trim().to_string();
            let selected_text = if !current.is_empty() {
                current.clone()
            } else if self.discovered_vaults.is_empty() {
                "(no vaults found)".to_string()
            } else {
                "— choose —".to_string()
            };
            ui.vertical_centered(|ui| {
                // Editable ROOT path: the folder scanned (one level deep) for vaults.
                ui.label("Vault root");
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.vault_root)
                        .hint_text("/path/that/holds/vault-folders")
                        .desired_width(360.0),
                );
                root_changed = resp.changed();
                ui.add_space(4.0);
                // The "Vault" control: an editable leaf-name box plus a dropdown of the
                // vaults discovered under the root. Pick one to fill the box (→ Unlock), or
                // type a new name (→ Create, in --write mode). Empty = the root itself.
                ui.label("Vault");
                ui.horizontal(|ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.vault_name)
                            .hint_text("vault folder name")
                            .desired_width(244.0),
                    );
                    name_changed = resp.changed();
                    egui::ComboBox::from_id_salt("vault_picker")
                        .selected_text(selected_text)
                        .width(110.0)
                        .show_ui(ui, |ui| {
                            for name in &self.discovered_vaults {
                                if ui.selectable_label(current == *name, name).clicked() {
                                    picked = Some(name.clone());
                                }
                            }
                        });
                });
                // Surface a scan problem (root unreadable, or entries skipped) plainly.
                if let Some(warn) = &self.vault_scan_warning {
                    ui.colored_label(egui::Color32::from_rgb(190, 120, 50), warn);
                }
            });
            if root_changed {
                self.refresh_discovered_vaults();
                self.recompute_vault_path();
                // Keep the default backup destination tracking the root until the vault is
                // unlocked (the Config backup field is freely editable afterwards).
                self.backup_dest = self.vault_root.clone();
            }
            if name_changed {
                self.recompute_vault_path();
            }
            if let Some(name) = picked {
                self.select_vault(&name);
            }
            ui.add_space(8.0);
        }

        let (heading, help) = match self.auth_mode {
            AuthMode::Create => ("Create vault", "Choose two passwords. Both are required to open this vault."),
            AuthMode::Unlock => ("Unlock vault", "Enter both passwords to unlock."),
            AuthMode::ChangePassword => ("Change master passwords", "Set two new passwords."),
        };
        let confirm = self.auth_mode != AuthMode::Unlock;

        // `|ui| { ... }` is a closure (anonymous function). egui passes a child
        // `ui` into it so everything inside is laid out vertically and centered.
        ui.vertical_centered(|ui| {
            ui.heading(heading);
            ui.label(egui::RichText::new(format!("Vault: {}", self.path.display())).weak());
            ui.label(help);
            // In read-only mode an empty directory can't be created — say so plainly.
            if self.auth_mode == AuthMode::Create && !self.writable {
                ui.colored_label(
                    egui::Color32::from_rgb(190, 120, 50),
                    "No vault in this folder. Read-only — relaunch with --write to create one.",
                );
            }
        });
        ui.add_space(16.0);

        // Track whether the user requested submission; `|=` ORs in `true` if any
        // password field had Enter pressed (see `password_field`'s return value).
        let mut submit = false;
        // A built-in Ctrl+C/cut of a master-password field surfaces here so we can arm
        // the clipboard auto-clear/exit-wipe (the field can't reach `self` itself).
        let mut copied: Option<Zeroizing<String>> = None;
        egui::Grid::new("auth_grid").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
            ui.label("Password 1");
            // `&mut self.pw1` lends the field to the widget so typing updates it.
            submit |= password_field(ui, "auth_pw1", &mut self.pw1, &mut copied);
            ui.end_row();
            if confirm {
                ui.label("Confirm password 1");
                submit |= password_field(ui, "auth_confirm1", &mut self.confirm1, &mut copied);
                ui.end_row();
            }
            ui.label("Password 2");
            submit |= password_field(ui, "auth_pw2", &mut self.pw2, &mut copied);
            ui.end_row();
            if confirm {
                ui.label("Confirm password 2");
                submit |= password_field(ui, "auth_confirm2", &mut self.confirm2, &mut copied);
                ui.end_row();
            }
        });
        // Route a copied master password through the hardened + armed clipboard path.
        if let Some(pw) = copied {
            self.copy_to_clipboard(pw);
        }

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
                AuthMode::Unlock => "🔓 Unlock",
                AuthMode::ChangePassword => "Change passwords",
            };
            // The one action of this screen, drawn as the primary (filled) button.
            let accent = accent(self.theme);
            if ui
                .add_sized(
                    [150.0, 28.0],
                    egui::Button::new(egui::RichText::new(label).strong().color(egui::Color32::WHITE)).fill(accent),
                )
                .clicked()
            {
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
        // Remember the active tab so a tab switch can reset the global reveal toggles
        // below: reveal is meant to be a momentary, in-context action, so it must not
        // persist into a later visit and expose every password to a bystander.
        let prev_tab = self.tab;
        let accent = accent(self.theme);

        // Row 1 — identity on the left, global actions on the right. `Sides` is the
        // primitive built for exactly this: it sizes the gap between the two groups
        // from the actual available width in a single pass. `shrink_left` lays the
        // ACTIONS out first and lets the vault name give up space, so the buttons can
        // never be pushed out of the window by a long name — and, unlike a
        // right-to-left layout nested in a wrapping row, there is no width estimate to
        // disagree with itself between frames.
        // Precomputed so the two `Sides` closures capture only plain values, not
        // `self` — the actions closure needs to MUTATE self, and the file's standard
        // deferred-action pattern (record the click, act after rendering) keeps the
        // borrows disjoint.
        let vault_path = self.path.display().to_string();
        let vault_name = self
            .path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "vault".to_string());
        let writable = self.writable;
        let (mut go_help, mut go_config, mut go_passwords, mut do_quit) = (false, false, false, false);

        egui::containers::Sides::new().shrink_left().show(
            ui,
            |ui| {
                // Which vault is open — the folder name, with the full path on hover.
                // Two windows onto two vaults look identical without this.
                ui.label(egui::RichText::new("🗄").color(accent).size(16.0)).on_hover_text(&vault_path);
                ui.add(egui::Label::new(egui::RichText::new(&vault_name).strong()).truncate())
                    .on_hover_text(&vault_path);
                // The mode badge: quiet when writable, loud when not. A read-only session
                // hides its write controls, so the badge is what explains their absence.
                if writable {
                    badge(ui, "WRITE", accent);
                } else {
                    badge(ui, "🔒 READ-ONLY", egui::Color32::from_rgb(190, 105, 10));
                }
            },
            |ui| {
                // The right group is laid out right-to-left, hence the reversed order.
                do_quit = ui
                    .button("Quit")
                    .on_hover_text("Close the window (secrets are wiped and the clipboard cleared)")
                    .clicked();
                go_help = ui.button("❓ Help").on_hover_text("The built-in manual").clicked();
                go_config = ui
                    .button("⚙ Config")
                    .on_hover_text("Appearance, view defaults, type lists, export, backup, storage")
                    .clicked();
                // Change-password is a write; only offer it when writable.
                // `&&` short-circuits: the button is only drawn/evaluated when
                // `writable` is true, so read-only mode hides it entirely.
                go_passwords =
                    writable && ui.button("🔑 Passwords").on_hover_text("Change the vault's two passwords").clicked();
            },
        );

        if do_quit {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if go_help {
            self.screen = Screen::Help;
        }
        if go_config {
            // Seed the redundancy picker from the live setting each time Config opens, so
            // the combo reflects the current value (and its selection survives across
            // frames until Apply).
            self.cfg_redundancy = self.vault_ref().redundancy();
            self.screen = Screen::Config;
        }
        if go_passwords {
            self.auth_mode = AuthMode::ChangePassword;
            self.auth_error = None;
            self.wipe_passwords();
            self.screen = Screen::Auth;
        }

        ui.add_space(6.0);

        // Row 2 — the tab strip. Each tab carries a glyph so it is recognisable by
        // shape before the label is read, and the active one gets an accent
        // underline. Kept in a horizontal ScrollArea so a narrow window scrolls the
        // strip rather than clipping the tabs off the end.
        egui::ScrollArea::horizontal().id_salt("topbar_tabs_scroll").show(ui, |ui| {
            ui.horizontal(|ui| {
                tab_button(ui, &mut self.tab, Tab::Urgent, "❗ URGENT", accent);
                tab_button(ui, &mut self.tab, Tab::Instructions, "📝 Instructions", accent);
                tab_button(ui, &mut self.tab, Tab::TrustWill, "⚖ Trust and Will", accent);
                tab_button(ui, &mut self.tab, Tab::Assets, "💰 Assets and Liabilities", accent);
                tab_button(ui, &mut self.tab, Tab::Accounts, "🔑 Accounts", accent);
                tab_button(ui, &mut self.tab, Tab::RealEstate, "🏠 Real Estate", accent);
                tab_button(ui, &mut self.tab, Tab::Taxes, "📃 Taxes", accent);
                tab_button(ui, &mut self.tab, Tab::GeneralDocuments, "📁 General Documents", accent);
                tab_button(ui, &mut self.tab, Tab::Summary, "📊 Summary", accent);
            });
        });
        // Reset the global reveal toggles when the user switches tabs (see prev_tab above):
        // reveal is momentary, so a stale "reveal all" must not persist into a later tab
        // visit. The reset target is the saved "reveal all by default" preference, not a
        // hardcoded `false`: when that pref is OFF this re-masks exactly as before, and when
        // it is ON every tab re-opens revealed (the user's chosen default). Also clear the
        // shared document-input buffers so a half-typed "Upload from" path / name / subfolder
        // from one tab does not linger in the next tab's attach form.
        if self.tab != prev_tab {
            self.reveal_all = self.reveal_default;
            self.re_reveal_all = self.reveal_default;
            self.clear_doc_inputs();
        }
    }

    // --- Help screen ---------------------------------------------------------

    /// The in-app manual: a searchable, topic-navigated browser over the content in
    /// [`crate::gui_help`]. Reachable from the top-bar "Help" button.
    ///
    /// All of the text (and the search) lives in `gui_help`; this only supplies the
    /// live facts the manual quotes back — where this vault and the preferences file
    /// are — and routes the Back button.
    fn ui_help(&mut self, ui: &mut egui::Ui) {
        let ctx = crate::gui_help::HelpContext {
            vault: self.path.display().to_string(),
            prefs: crate::prefs_path().map(|p| p.display().to_string()).unwrap_or_else(|| "(unavailable)".into()),
            writable: self.writable,
        };
        if crate::gui_help::ui(ui, &mut self.help, &ctx, accent(self.theme)) {
            self.screen = Screen::Main;
        }
    }

    // --- Config screen -------------------------------------------------------

    fn ui_config(&mut self, ui: &mut egui::Ui) {
        let accent = accent(self.theme);
        // Back sits FIRST, at the left edge where a back control is looked for, and
        // the heading follows it — the old order put the way out after the title.
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("⬅ Back").clicked() {
                self.screen = Screen::Main;
            }
            ui.add_space(4.0);
            section_heading(ui, "Configuration", accent);
        });
        ui.add_space(4.0);
        ui.separator();
        // Show where this vault lives on disk (the vault.pmv path; its parent dir holds
        // the manifest/ and volume/ too).
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Vault location").weak().small());
            ui.label(egui::RichText::new(self.path.display().to_string()).monospace().small());
        });
        if !self.writable {
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(
                    "🔒  Read-only: no vault field can be edited. The color theme and the view \
                     defaults below can still be changed (they are local preferences); \
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
        let mut set_export = false;
        let mut set_volume = false;
        let mut set_redundancy = false;
        let mut start_merge = false;
        let mut sync_types = false;
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
            config_heading(ui, "Appearance");
            egui::ComboBox::from_label("Color theme").selected_text(self.theme.label()).show_ui(ui, |ui| {
                for t in Theme::ALL {
                    ui.selectable_value(&mut self.theme, t, t.label());
                }
            });
            ui.add_space(14.0);

            // View defaults: local UI preferences (prefs.json), not vault content — so they
            // work in read-only mode too and persist to the next launch. Each checkbox binds
            // to the saved-default field, saves the preference on change, and applies it to
            // the live view state so the effect is immediate; the saved value re-seeds these
            // on the next vault open (see `GuiApp::new` and the tab-switch reset).
            config_heading(ui, "View defaults");
            if ui
                .checkbox(&mut self.reveal_default, "Reveal all passwords by default")
                .changed()
            {
                crate::save_reveal_all_default(self.reveal_default);
                self.reveal_all = self.reveal_default;
                self.re_reveal_all = self.reveal_default;
            }
            if ui
                .checkbox(&mut self.group_assets_default, "Group assets by default")
                .changed()
            {
                crate::save_group_assets_default(self.group_assets_default);
                self.asset_grouped = self.group_assets_default;
            }
            if ui
                .checkbox(&mut self.group_accounts_default, "Group accounts by default")
                .changed()
            {
                crate::save_group_accounts_default(self.group_accounts_default);
                self.acct_grouped = self.group_accounts_default;
            }
            ui.add_space(14.0);

            config_heading(ui, "Asset / Liability types");
            // One chip per type with a delete (×) button. The × only deletes when the
            // type is unused by a live record (else a status message explains why).
            ui.horizontal_wrapped(|ui| {
                for name in &asset_names {
                    ui.label(egui::RichText::new(name).weak());
                    // The category list is stored independently of records; tag entries no
                    // live record uses so the user can see what's safe to delete.
                    if self.vault_ref().asset_type_usage(name) == 0 {
                        ui.label(egui::RichText::new("· unused").weak().italics());
                    }
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
            config_heading(ui, "Account types & subtypes");
            // Each type on its own row: a × to delete the type (blocked while it has
            // subtypes or is in use), then each subtype with its own × (blocked if used).
            for (name, subs) in &account_list {
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new(name).strong());
                    if self.vault_ref().account_type_usage(name) == 0 {
                        ui.label(egui::RichText::new("· unused").weak().italics());
                    }
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
                        if self.vault_ref().account_subtype_usage(name, sub) == 0 {
                            ui.label(egui::RichText::new("· unused").weak().italics());
                        }
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
            config_heading(ui, "Export directory");
            ui.label(
                egui::RichText::new(
                    "Where the per-document Export buttons write the decrypted file. Each export \
                     is saved under this directory, recreating the document's folder structure from \
                     inside the vault — you are never asked for a path at export time. Stored as a \
                     local preference (not in the vault), so it can be set even in read-only mode.",
                )
                .weak(),
            );
            ui.horizontal(|ui| {
                ui.label("Export directory:");
                // Deliberately NOT gated on `writable`: the export dir is a local preference,
                // so a read-only session (e.g. an heir) can set where to extract documents.
                ui.add(egui::TextEdit::singleline(&mut self.export_dir).hint_text("/path/to/exports").desired_width(340.0));
                if ui.button("Set").clicked() {
                    set_export = true;
                }
            });

            ui.add_space(16.0);
            ui.separator();
            config_heading(ui, "Backup");
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
                config_heading(ui, "Storage — volume size");
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
                config_heading(ui, "Vault file redundancy (advanced)");
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

                ui.add_space(16.0);
                ui.separator();
                config_heading(ui, "Update from another vault");
                ui.label(
                    egui::RichText::new(
                        "Pull records that are newer (or new) in ANOTHER vault — together with the \
                         documents they reference — into this one. One-way and additive: it never \
                         deletes anything here. You'll choose the other vault's folder and enter its \
                         two passwords, then preview the exact changes before applying.",
                    )
                    .weak(),
                );
                if ui.button("Update from another vault…").clicked() {
                    start_merge = true;
                }

                ui.add_space(16.0);
                ui.separator();
                config_heading(ui, "Sync types from records");
                ui.label(
                    egui::RichText::new(
                        "Scan every record and add any asset/account type or subtype it uses that \
                         is missing from the lists above — useful after pulling in records (from a \
                         merge or import) whose types aren't yet listed here.",
                    )
                    .weak(),
                );
                if ui.button("Sync types from records").clicked() {
                    sync_types = true;
                }
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
                Err(e) => self.fail(format!("Save failed: {e}")),
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
                Err(e) => self.fail(format!("Save failed: {e}")),
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
                    Err(e) => self.fail(format!("Save failed: {e}")),
                }
            }
        }
        // Deferred DELETE handlers. A refusal (in use / has subtypes) is a normal
        // status message, not a failure; only a real save error reads as "failed".
        if let Some(name) = remove_asset {
            // A save failure must surface in the conspicuous banner (via `fail`), not just the
            // weak status line — a refusal (in use / not found) is an ordinary status message.
            match self.vault.as_mut().expect("vault open on config").remove_asset_type(&name) {
                Ok(CategoryRemoval::Removed) => self.status = format!("Deleted asset/liability type “{name}”."),
                Ok(CategoryRemoval::InUse(n)) => self.status = format!("Can’t delete “{name}”: still used by {n} record(s)."),
                Ok(CategoryRemoval::NotFound) => self.status = format!("“{name}” was not found."),
                Ok(CategoryRemoval::HasSubtypes) => unreachable!("asset types have no subtypes"),
                Err(e) => self.fail(format!("Delete failed: {e}")),
            }
        }
        if let Some(name) = remove_account {
            match self.vault.as_mut().expect("vault open on config").remove_account_type(&name) {
                Ok(CategoryRemoval::Removed) => self.status = format!("Deleted account type “{name}”."),
                Ok(CategoryRemoval::HasSubtypes) => self.status = format!("Can’t delete “{name}”: delete its subtypes first."),
                Ok(CategoryRemoval::InUse(n)) => self.status = format!("Can’t delete “{name}”: still used by {n} account(s)."),
                Ok(CategoryRemoval::NotFound) => self.status = format!("“{name}” was not found."),
                Err(e) => self.fail(format!("Delete failed: {e}")),
            }
        }
        if let Some((ty, sub)) = remove_subtype {
            match self.vault.as_mut().expect("vault open on config").remove_account_subtype(&ty, &sub) {
                Ok(CategoryRemoval::Removed) => self.status = format!("Deleted subtype “{sub}” under “{ty}”."),
                Ok(CategoryRemoval::InUse(n)) => self.status = format!("Can’t delete “{sub}”: still used by {n} account(s)."),
                Ok(CategoryRemoval::NotFound) => self.status = format!("“{sub}” was not found under “{ty}”."),
                Ok(CategoryRemoval::HasSubtypes) => unreachable!("a subtype has no subtypes"),
                Err(e) => self.fail(format!("Delete failed: {e}")),
            }
        }
        if set_export {
            // Persist the export directory to the local prefs file (non-secret; no vault
            // write, so this works in read-only mode). Trim and normalize the stored value.
            let dir = self.export_dir.trim().to_string();
            self.export_dir = dir.clone();
            crate::save_export_dir(&dir);
            self.status = if dir.is_empty() {
                "Export directory cleared.".into()
            } else {
                format!("Export directory set to {dir} (used by every Export button).")
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
                    Err(e) => self.fail(format!("Backup failed: {e}")),
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
                        Err(e) => self.fail(format!("Save failed: {e}")),
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
                Err(e) => self.fail(format!("Save failed: {e}")),
            }
        }
        if start_merge {
            // Enter the merge flow with fresh state. Pre-fill the source folder with the
            // vault root (the folder that holds vaults) as a convenient starting point.
            self.reset_merge();
            self.merge_src_dir = self.vault_root.trim().to_string();
            self.screen = Screen::Merge;
        }
        if sync_types {
            match self.vault.as_mut().expect("vault open on config").sync_types_from_records() {
                Ok(0) => self.status = "Types already in sync — nothing to add.".into(),
                Ok(n) => self.status = format!("Added {n} type(s) from records to the lists."),
                Err(e) => self.fail(format!("Sync failed: {e}")),
            }
        }

        if !self.status.is_empty() {
            ui.separator();
            ui.label(egui::RichText::new(&self.status).weak());
        }
    }

    /// The "Update from another vault" screen: collect the source directory + its two
    /// passwords, preview the patch (`plan_merge_from`), then apply (`apply_merge_from`).
    /// Only reachable in `--write` mode (the entry button is gated). The opened source
    /// handle + computed plan live in `self.merge_*` between the preview and the apply.
    fn ui_merge(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("⬅ Back to Config").clicked() {
                self.reset_merge();
                self.screen = Screen::Config;
            }
            ui.add_space(4.0);
            section_heading(ui, "Update from another vault", accent(self.theme));
        });
        ui.add_space(2.0);
        ui.label(
            egui::RichText::new("One-way and additive — nothing in this vault is ever deleted by an update.")
                .weak()
                .small(),
        );
        ui.add_space(4.0);
        ui.separator();

        // Deferred actions (set in the render below, run after to avoid borrow clashes).
        let mut do_preview = false;
        let mut do_apply = false;
        let mut do_reset = false;
        let mut copied: Option<Zeroizing<String>> = None;

        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("merge_scroll").show(ui, |ui| {
            if self.merge_plan.is_none() {
                // --- Phase 1: collect the source folder + its two passwords. ---
                ui.label(
                    egui::RichText::new(
                        "Choose the OTHER vault's folder and enter ITS two passwords. The other vault \
                         is opened read-only; this vault is only changed when you click Apply on the \
                         next screen. Nothing here is deleted — only newer/new records are pulled in.",
                    )
                    .weak(),
                );
                ui.add_space(8.0);
                egui::Grid::new("merge_form").num_columns(2).spacing([12.0, 10.0]).show(ui, |ui| {
                    ui.label("Other vault folder");
                    ui.add(egui::TextEdit::singleline(&mut self.merge_src_dir).hint_text("/path/to/other-vault-folder").desired_width(360.0));
                    ui.end_row();
                    ui.label("Other password 1");
                    password_field(ui, "merge_pw1", &mut self.merge_pw1, &mut copied);
                    ui.end_row();
                    ui.label("Other password 2");
                    password_field(ui, "merge_pw2", &mut self.merge_pw2, &mut copied);
                    ui.end_row();
                });
                ui.add_space(10.0);
                if ui.button("Preview update").clicked() {
                    do_preview = true;
                }
                if let Some(err) = &self.merge_error {
                    ui.add_space(8.0);
                    ui.colored_label(egui::Color32::from_rgb(200, 80, 80), err);
                }
            } else if let Some(plan) = self.merge_plan.as_ref() {
                // --- Phase 2: show the computed plan; Apply or Cancel. ---
                let short = plan.source_vault_id.get(..8).unwrap_or(plan.source_vault_id.as_str());
                ui.label(egui::RichText::new(format!("From vault {short}")).weak());
                if plan.is_empty() && plan.skipped.is_empty() {
                    ui.add_space(6.0);
                    ui.label("Already up to date — no records in the other vault are newer or new.");
                } else {
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new(format!(
                        "{} record(s) to change ({} new, {} updated) · {} document(s) to copy ({} bytes)",
                        plan.records.len(),
                        plan.new_count(),
                        plan.updated_count(),
                        plan.blobs_to_copy(),
                        plan.bytes_to_copy(),
                    )).strong());
                    ui.add_space(6.0);
                    egui::Grid::new("merge_records").striped(true).num_columns(3).show(ui, |ui| {
                        ui.label(egui::RichText::new("Change").strong());
                        ui.label(egui::RichText::new("Type").strong());
                        ui.label(egui::RichText::new("Record / recency").strong());
                        ui.end_row();
                        for r in &plan.records {
                            ui.label(r.change.as_str());
                            ui.label(r.kind.as_str());
                            let recency = match r.current_updated_at {
                                Some(cur) => format!("{} ({} -> {})", r.label, format_time(cur), format_time(r.source_updated_at)),
                                None => format!("{} (new @ {})", r.label, format_time(r.source_updated_at)),
                            };
                            ui.label(recency);
                            ui.end_row();
                        }
                    });
                    if !plan.blobs.is_empty() {
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("Documents").strong());
                        for b in &plan.blobs {
                            let tag = if b.already_present { "already here" } else { "copy" };
                            ui.label(format!("  [{tag}] {} ({} bytes)", b.path, b.size));
                        }
                    }
                    if !plan.new_categories.is_empty() {
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("Category types to add (so the merged types show in Config)").strong());
                        for c in &plan.new_categories {
                            ui.label(format!("  + {c}"));
                        }
                    }
                    if !plan.skipped.is_empty() {
                        ui.add_space(8.0);
                        ui.colored_label(egui::Color32::from_rgb(190, 120, 50), "Skipped (not applied):");
                        for s in &plan.skipped {
                            ui.label(format!("  {} — {} — {}", s.kind.as_str(), s.label, s.reason));
                        }
                    }
                }
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let can_apply = !plan.is_empty();
                    if ui.add_enabled(can_apply, egui::Button::new("Apply update")).clicked() {
                        do_apply = true;
                    }
                    if ui.button("Cancel").clicked() {
                        do_reset = true;
                    }
                });
            }
        });

        // A copied source-vault password (built-in Ctrl+C) routes through the hardened,
        // auto-clearing clipboard path, exactly like the unlock screen.
        if let Some(text) = copied {
            self.copy_to_clipboard(text);
        }

        if do_preview {
            self.merge_preview();
        }
        if do_apply {
            self.merge_apply();
        }
        if do_reset {
            // Cancel the preview but stay on the screen to re-enter credentials.
            self.reset_merge();
        }
    }

    /// Open the source vault read-only and compute the patch into `self.merge_plan`.
    /// Collapses the source's open errors into ONE generic message so this screen can't be
    /// used as a password-correctness oracle for the other vault (mirrors the unlock screen).
    fn merge_preview(&mut self) {
        self.merge_error = None;
        // The just-typed source-vault passwords are secrets: wipe them on EVERY exit path
        // (each validation early-return below, the open failure, the plan error, and success),
        // never leaving them resident in the heap buffers after this call.
        let dir = self.merge_src_dir.trim();
        if dir.is_empty() {
            self.merge_error = Some("Enter the other vault's folder.".into());
            self.wipe_merge_pw();
            return;
        }
        let src_path = crate::launch::vault_file(dir);
        if !src_path.exists() {
            self.merge_error = Some("No vault found in that folder.".into());
            self.wipe_merge_pw();
            return;
        }
        // Guard against merging this vault into itself.
        if same_vault_path(&src_path, &self.path) {
            self.merge_error = Some("That is this same vault — choose a different one.".into());
            self.wipe_merge_pw();
            return;
        }
        let source = match OpenVault::open_read_only(src_path, self.merge_pw1.as_bytes(), self.merge_pw2.as_bytes()) {
            Ok(v) => v,
            Err(_) => {
                // Single generic message for EVERY failure (wrong password, corrupt, etc.)
                // so the screen never confirms whether the entered passwords were right.
                self.merge_error = Some("Could not open that vault — wrong password(s) or unreadable.".into());
                self.wipe_merge_pw();
                return;
            }
        };
        let plan = match self.vault_ref().plan_merge_from(&source) {
            Ok(p) => p,
            Err(e) => {
                self.merge_error = Some(format!("Could not build the update: {e}"));
                self.wipe_merge_pw();
                return;
            }
        };
        // Keep the opened source + plan for the apply step; wipe the entered passwords now.
        self.merge_source = Some(source);
        self.merge_plan = Some(plan);
        self.wipe_merge_pw();
    }

    /// Apply the previewed patch (copy blobs, replace/insert records, save), then return to
    /// Config with a status summary. Recomputes against the held source handle internally.
    fn merge_apply(&mut self) {
        // Disjoint field borrows: `self.vault` (mut) and `self.merge_source` (shared).
        let result = match (self.vault.as_mut(), self.merge_source.as_ref()) {
            (Some(cur), Some(src)) => cur.apply_merge_from(src),
            _ => {
                self.merge_error = Some("Nothing to apply.".into());
                return;
            }
        };
        match result {
            Ok(report) => {
                self.status = format!(
                    "Updated from another vault: {} new, {} updated record(s); {} document(s) copied; {} type(s) added.{}",
                    report.records_added,
                    report.records_updated,
                    report.blobs_copied,
                    report.categories_added,
                    if report.records_skipped > 0 { format!(" {} skipped.", report.records_skipped) } else { String::new() },
                );
                self.reset_merge();
                self.screen = Screen::Config;
            }
            Err(e) => {
                // A failed apply may have poisoned the handle (the in-memory merge can no
                // longer be saved — see apply_merge_from's save-failure poisoning). Drop it
                // and return to the unlock screen so reopening loads the clean on-disk vault,
                // mirroring the change-password recovery path. Nothing committed is lost: the
                // merge did not persist, and any prior edits were already saved.
                self.vault = None;
                self.reset_merge();
                self.auth_mode = AuthMode::Unlock;
                self.screen = Screen::Auth;
                self.wipe_passwords();
                self.auth_error = Some(format!("Update interrupted: {e}. Unlock again to recover."));
            }
        }
    }

    // --- Tab: Instructions ---------------------------------------------------

    fn tab_urgent(&mut self, ui: &mut egui::Ui) {
        // Same shape as tab_instructions — a title + free-text-body note list — but for the
        // separate, first-in-order URGENT collection.
        let labels = label_list(&self.vault_ref().vault.urgent);
        let cur = self.edit_urgent.as_ref().map(|r| r.id.clone());
        let mut new = false;
        let mut select = None;
        let mut export = false;
        let mut action = FormAction::None;

        ui.columns(2, |c| {
            (new, select, export) = list_panel(&mut c[0], "URGENT", "➕ New", &labels, cur.as_deref(), self.writable, None);
            // The form pane scrolls on its OWN axis. Previously the whole tab sat inside
            // one both-axis ScrollArea, so this vertical scroller was nested inside
            // another one and was handed unbounded height — the layout could not settle
            // on a scrollbar, which is what flickered on a small window.
            egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("form_pane_urgent").show(&mut c[1], |ui| {
            if let Some(r) = self.edit_urgent.as_mut() {
                egui::Grid::new("urgent_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Title");
                    field_singleline(ui, &mut r.title, self.writable, 420.0);
                    ui.end_row();
                });
                ui.label("Details");
                field_multiline(ui, &mut r.description, self.writable, 12);
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                empty_form_hint(ui, "an urgent note");
            }
        });
        });

        if export {
            self.export_current_tab_csv();
        }
        if new {
            self.edit_urgent = Urgent::new().ok();
        }
        if let Some(i) = select {
            self.edit_urgent = self.vault_ref().vault.urgent.get(i).cloned();
        }
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_urgent.as_mut() {
                    r.trim_fields();
                }
                if let Some(r) = self.edit_urgent.clone()
                    && let Some(ov) = self.vault.as_mut()
                {
                    records::upsert(&mut ov.vault.urgent, r);
                }
                if self.persist() {
                    self.status = "Saved.".into();
                }
            }
            FormAction::Delete => self.delete_current(Tab::Urgent),
            _ => {}
        }
    }

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
        let mut export = false;
        let mut action = FormAction::None;

        // `ui.columns(2, |c| ...)`: `c` is a slice of two child UIs (left/right).
        ui.columns(2, |c| {
            // Destructuring assignment into the outer `new`/`select` vars.
            // `cur.as_deref()` turns `Option<String>` into `Option<&str>` (a
            // borrowed view) without consuming `cur`.
            (new, select, export) = list_panel(&mut c[0], "Instructions", "➕ New", &labels, cur.as_deref(), self.writable, None);
            // Shadow `ui` with a mutable borrow of the right column. "Shadowing"
            // reuses the name `ui` for a new binding within this block.
            // The form pane scrolls on its OWN axis. Previously the whole tab sat inside
            // one both-axis ScrollArea, so this vertical scroller was nested inside
            // another one and was handed unbounded height — the layout could not settle
            // on a scrollbar, which is what flickered on a small window.
            egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("form_pane_instructions").show(&mut c[1], |ui| {
            // `.as_mut()` borrows the edited record mutably so the form widgets
            // below can write directly into its fields.
            if let Some(r) = self.edit_instruction.as_mut() {
                egui::Grid::new("instr_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Title");
                    field_singleline(ui, &mut r.title, self.writable, 420.0);
                    ui.end_row();
                });
                ui.label("Description");
                field_multiline(ui, &mut r.description, self.writable, 12);
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                empty_form_hint(ui, "an instruction");
            }
        });
        });

        // Now apply the deferred actions outside the render closure.
        if export {
            self.export_current_tab_csv();
        }
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
                // Left/right-trim every field before persisting (whole-vault policy);
                // trim the live form too so the displayed values match what was saved.
                if let Some(r) = self.edit_instruction.as_mut() {
                    r.trim_fields();
                }
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
        let mut export = false;
        let mut action = FormAction::None;
        let mut docreq = DocReq::None;

        ui.columns(2, |c| {
            (new, select, export) = list_panel(&mut c[0], "Trust and Will", "➕ New", &labels, cur.as_deref(), self.writable, None);
            // The form pane scrolls on its OWN axis. Previously the whole tab sat inside
            // one both-axis ScrollArea, so this vertical scroller was nested inside
            // another one and was handed unbounded height — the layout could not settle
            // on a scrollbar, which is what flickered on a small window.
            egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("form_pane_trustwill").show(&mut c[1], |ui| {
            if let Some(r) = self.edit_trustwill.as_mut() {
                egui::Grid::new("tw_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Document");
                    field_singleline(ui, &mut r.document, self.writable, 420.0);
                    ui.end_row();
                });
                ui.label("Usage");
                field_multiline(ui, &mut r.usage, self.writable, 8);
                ui.separator();
                docreq = doc_section(
                    ui,
                    &attached,
                    &mut self.doc_subfolder,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    self.writable,
                )
                .to_single();
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                empty_form_hint(ui, "a document");
            }
        });
        });

        if export {
            self.export_current_tab_csv();
        }
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
                if let Some(r) = self.edit_trustwill.as_mut() {
                    r.trim_fields();
                }
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
        let mut export = false;
        let mut action = FormAction::None;
        let mut docreq = DocReq::None;

        ui.columns(2, |c| {
            (new, select, export) =
                list_panel(&mut c[0], "General Documents", "➕ New", &labels, cur.as_deref(), self.writable, None);
            // The form pane scrolls on its OWN axis. Previously the whole tab sat inside
            // one both-axis ScrollArea, so this vertical scroller was nested inside
            // another one and was handed unbounded height — the layout could not settle
            // on a scrollbar, which is what flickered on a small window.
            egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("form_pane_general").show(&mut c[1], |ui| {
            if let Some(r) = self.edit_general.as_mut() {
                egui::Grid::new("gen_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Title");
                    field_singleline(ui, &mut r.title, self.writable, 420.0);
                    ui.end_row();
                });
                ui.label("Description");
                field_multiline(ui, &mut r.description, self.writable, 8);
                ui.separator();
                docreq = doc_section(
                    ui,
                    &attached,
                    &mut self.doc_subfolder,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    self.writable,
                )
                .to_single();
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                empty_form_hint(ui, "a document");
            }
        });
        });

        if export {
            self.export_current_tab_csv();
        }
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
                if let Some(r) = self.edit_general.as_mut() {
                    r.trim_fields();
                }
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
        // Same card treatment as the Accounts filter row, so the two list tabs have
        // the same control strip in the same place.
        let accent_c = accent(self.theme);
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("View").strong().small().color(accent_c));
                // Grouped tree: owner → Asset/Liability → type (empty levels skipped).
                ui.checkbox(&mut self.asset_grouped, "grouped tree")
                    .on_hover_text("Group the list by owner > asset/liability > type");
                ui.checkbox(&mut self.asset_filter_review, "review only")
                    .on_hover_text("Show only items flagged for review");
                if self.asset_filter_review {
                    badge(ui, "filtered", egui::Color32::from_rgb(190, 105, 10));
                }
            });
        });
        ui.add_space(6.0);
        let fr = self.asset_filter_review;
        // In grouped mode, the same review-filtered assets as an owner→kind→type tree
        // (built here so the render closure doesn't re-borrow `self`).
        let tree = if self.asset_grouped {
            Some(records::asset_tree(self.vault_ref().vault.assets.iter().filter(|a| !fr || a.review)))
        } else {
            None
        };
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
        // Flat-list arrow navigation: when not grouped, ↑/↓ move to the prev/next item.
        let nav_target = list_nav_target(ui, !self.asset_grouped, &labels, cur.as_deref());
        let attached: Vec<String> =
            self.attached_label(self.edit_asset.as_ref().and_then(|r| r.statement.clone())).into_iter().collect();
        let asset_types = self.vault_ref().categories().asset.clone();
        // Linked-accounts data for the record under edit, resolved BEFORE the mutable
        // `edit_asset` borrow inside the columns closure (same borrow discipline as the
        // Accounts tab's `subtypes` precompute): the linked ids with display labels — a
        // dangling id renders as the RAW id, see `linked_account_rows` — plus the
        // not-yet-linked accounts offered by the "add link" dropdown.
        let linked_rows: Vec<(String, String)> = self
            .edit_asset
            .as_ref()
            .map(|r| linked_account_rows(&self.vault_ref().vault.accounts, &r.linked_accounts))
            .unwrap_or_default();
        let link_candidates: Vec<(String, String)> = self
            .edit_asset
            .as_ref()
            .map(|r| link_candidates(&self.vault_ref().vault.accounts, &r.linked_accounts))
            .unwrap_or_default();
        let mut new = false;
        let mut select = None;
        let mut export = false;
        let mut action = FormAction::None;
        let mut docreq = DocReq::None;
        let mut linkreq = LinkReq::None;

        ui.columns(2, |c| {
            match &tree {
                // Grouped tree: owner → Asset/Liability → type → entry (leaf), empty levels
                // skipped. egui's CollapsingHeader gives the +/- expand control.
                Some(root) => {
                    let lp = &mut c[0];
                    // Same header as the flat `list_panel`, so switching to the tree
                    // does not change what the top of the pane looks like.
                    lp.horizontal_wrapped(|ui| {
                        let accent = ui_accent(ui);
                        section_heading(ui, "Assets and Liabilities", accent);
                        badge(ui, &format!("{}", labels.len()), accent);
                        ui.add_space(4.0);
                        if self.writable && ui.button("➕ New").clicked() {
                            new = true;
                        }
                        if ui
                            .button("⬇ CSV")
                            .on_hover_text(
                                "Export every row on this tab to a timestamped CSV in the export directory.\n\
                                 The file is UNENCRYPTED and includes passwords in plain text.",
                            )
                            .clicked()
                        {
                            export = true;
                        }
                    });
                    lp.add_space(4.0);
                    lp.separator();
                    egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("asset_tree").show(lp, |ui| {
                        let mut path: Vec<String> = Vec::new();
                        if let Some(s) = render_acct_node(ui, root, &mut path, cur.as_deref(), &labels, "asset") {
                            select = Some(s);
                        }
                    });
                }
                None => {
                    (new, select, export) =
                        list_panel(&mut c[0], "Assets and Liabilities", "➕ New", &labels, cur.as_deref(), self.writable, nav_target);
                }
            }
            // The form pane scrolls on its OWN axis. Previously the whole tab sat inside
            // one both-axis ScrollArea, so this vertical scroller was nested inside
            // another one and was handed unbounded height — the layout could not settle
            // on a scrollbar, which is what flickered on a small window.
            egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("form_pane_assets").show(&mut c[1], |ui| {
            if let Some(r) = self.edit_asset.as_mut() {
                let w = self.writable;
                egui::Grid::new("asset_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    ui.label("Asset / Liability");
                    combo(ui, "asset_kind", &mut r.kind, &["Asset".to_string(), "Liability".to_string()], w);
                    ui.end_row();
                    ui.label("Owner");
                    field_singleline(ui, &mut r.owner, w, 420.0);
                    ui.end_row();
                    ui.label("Title");
                    field_singleline(ui, &mut r.title, w, 420.0);
                    ui.end_row();
                    ui.label("Beneficiary");
                    field_singleline(ui, &mut r.beneficiary, w, 420.0);
                    ui.end_row();
                    ui.label("Approximate value");
                    field_singleline(ui, &mut r.approx_value, w, 420.0);
                    ui.end_row();
                    ui.label("As-of date");
                    field_singleline_hint(ui, &mut r.as_of_date, w, 420.0, "YYYY-MM-DD");
                    ui.end_row();
                    ui.label("Institution");
                    field_singleline(ui, &mut r.institution, w, 420.0);
                    ui.end_row();
                    ui.label("Type");
                    combo(ui, "asset_type", &mut r.asset_type, &asset_types, w);
                    ui.end_row();
                    ui.label("URL");
                    field_singleline(ui, &mut r.url, w, 420.0);
                    ui.end_row();
                    ui.label("Review");
                    ui.add_enabled(w, egui::Checkbox::new(&mut r.review, "flag for review"));
                    ui.end_row();
                });
                ui.label("Description");
                field_multiline(ui, &mut r.description, self.writable, 4);
                ui.separator();
                // Cross-record links to Accounts (edited on the asset side ONLY; the
                // Accounts form shows the read-only reverse view). Deferred like docreq.
                linkreq = linked_accounts_section(ui, &linked_rows, &link_candidates, self.writable);
                ui.separator();
                docreq = doc_section(
                    ui,
                    &attached,
                    &mut self.doc_subfolder,
                    &mut self.doc_filename,
                    &mut self.doc_source,
                    self.writable,
                )
                .to_single();
                action = form_buttons(ui, self.writable);
                history_view(ui, &r.history);
            } else {
                empty_form_hint(ui, "an asset or liability");
            }
        });
        });

        if export {
            self.export_current_tab_csv();
        }
        if new {
            self.edit_asset = AssetLiability::new().ok();
            self.clear_doc_inputs();
        }
        // A click wins over keyboard nav (they can't both happen in one frame, but be safe).
        select = select.or(nav_target);
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
        self.handle_link_req(linkreq);
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_asset.as_mut() {
                    r.trim_fields();
                }
                // Validate before saving: every Asset/Liability must have an owner and a
                // NUMERIC approximate value, so the Summary tab can aggregate it. On failure,
                // surface the reason in the conspicuous banner and do NOT save the bad record.
                let invalid = self.edit_asset.as_ref().and_then(records::asset_validation_error);
                if let Some(msg) = invalid {
                    self.fail(msg);
                } else {
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
            }
            FormAction::Delete => self.delete_current(Tab::Assets),
            _ => {}
        }
    }

    // --- Tab: Summary --------------------------------------------------------

    /// The "Summary" tab: a flat table aggregating every Asset/Liability's approximate value
    /// by owner, split into asset buckets (Real Estate / Before Tax / After Tax) and liability
    /// buckets (Before Tax / After Tax), with per-owner totals + net worth and a grand-total
    /// row. Before Tax = retirement + HSA; After Tax = everything else (records::value_bucket).
    fn tab_summary(&mut self, ui: &mut egui::Ui) {
        let accent_c = accent(self.theme);
        ui.add_space(6.0);
        section_heading(ui, "Summary of Assets & Liabilities", accent_c);
        ui.label(
            egui::RichText::new(
                "Aggregated approximate values by owner. Cash = cash/savings/checking; Before Tax = retirement + HSA; After Tax = everything else.",
            )
            .weak()
            .small(),
        );
        ui.add_space(10.0);
        let rows = records::owner_value_summary(self.vault_ref().vault.assets.iter());
        if rows.is_empty() {
            ui.add_space(30.0);
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("📊").size(28.0).color(accent_c.gamma_multiply(0.7)));
                ui.add_space(6.0);
                ui.label(egui::RichText::new("Nothing to summarise yet").strong());
                ui.label(
                    egui::RichText::new("Add records on the Assets and Liabilities tab and their values total up here.")
                        .weak()
                        .small(),
                );
            });
            return;
        }
        // Grand total across all owners.
        let mut total = records::OwnerValueRow { owner: "All owners".to_string(), ..Default::default() };
        for r in &rows {
            total.asset_real_estate += r.asset_real_estate;
            total.asset_cash += r.asset_cash; // BUG FIX: cash was omitted, understating Assets Σ / Net
            total.asset_before_tax += r.asset_before_tax;
            total.asset_after_tax += r.asset_after_tax;
            total.liability += r.liability;
        }
        // A headline row before the table: the three numbers someone opens this tab
        // to find, at a size they can read across a desk, instead of having to pick
        // them out of the bottom-right corner of an eight-column grid.
        ui.horizontal_wrapped(|ui| {
            stat_tile(ui, "Total assets", &crate::fmt_money(total.asset_total()), STAT_GOOD);
            stat_tile(ui, "Total liabilities", &crate::fmt_money(total.liability), STAT_BAD);
            // Net worth is the polarity number, so it takes the sign's color — and the
            // sign is in the text too, never color alone.
            stat_tile(
                ui,
                "Net worth",
                &crate::fmt_money(total.net()),
                if total.net() < 0.0 { STAT_BAD } else { STAT_GOOD },
            );
            stat_tile(ui, "Owners", &rows.len().to_string(), accent_c);
        });
        ui.add_space(12.0);
        egui::ScrollArea::both().auto_shrink([false, false]).id_salt("summary_scroll").show(ui, |ui| {
            egui::Grid::new("summary_grid").striped(true).num_columns(8).spacing([18.0, 6.0]).show(ui, |ui| {
                // Group header: ASSETS over its 5 value columns, LIABILITIES over its 1.
                ui.label("");
                ui.label(egui::RichText::new("ASSETS").strong().small().color(STAT_GOOD));
                ui.label("");
                ui.label("");
                ui.label("");
                ui.label("");
                ui.label(egui::RichText::new("LIABILITIES").strong().small().color(STAT_BAD));
                ui.label("");
                ui.end_row();
                // Column headers (Cash = cash/savings/checking; liabilities are not tax-split).
                for h in ["Owner", "Real Estate", "Cash", "Before Tax", "After Tax", "Assets Σ", "Liability", "Net"] {
                    ui.label(egui::RichText::new(h).strong());
                }
                ui.end_row();
                // One row per owner (monospace amounts so the digits line up).
                for r in &rows {
                    ui.label(egui::RichText::new(r.owner.as_str()).strong());
                    ui.monospace(crate::fmt_money(r.asset_real_estate));
                    ui.monospace(crate::fmt_money(r.asset_cash));
                    ui.monospace(crate::fmt_money(r.asset_before_tax));
                    ui.monospace(crate::fmt_money(r.asset_after_tax));
                    ui.monospace(crate::fmt_money(r.asset_total()));
                    // Liability and Net carry the reserved status colors; the sign is in
                    // the text as well, so the meaning never rests on color alone.
                    ui.label(egui::RichText::new(crate::fmt_money(r.liability)).monospace().color(
                        if r.liability > 0.0 { STAT_BAD } else { ui.visuals().text_color() },
                    ));
                    ui.label(
                        egui::RichText::new(crate::fmt_money(r.net()))
                            .monospace()
                            .color(if r.net() < 0.0 { STAT_BAD } else { STAT_GOOD }),
                    );
                    ui.end_row();
                }
                // Grand-total row (bold).
                ui.label(egui::RichText::new(total.owner.as_str()).strong());
                for v in [
                    total.asset_real_estate,
                    total.asset_cash,
                    total.asset_before_tax,
                    total.asset_after_tax,
                    total.asset_total(),
                    total.liability,
                    total.net(),
                ] {
                    ui.label(egui::RichText::new(crate::fmt_money(v)).strong().monospace());
                }
                ui.end_row();
            });
        });
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

    /// One-off maintenance: left/right-trim every field on every record across ALL
    /// tabs, persist, and report the count. Each change is recorded in that record's
    /// history. Returns the number of records changed.
    fn trim_all_records(&mut self) -> usize {
        let n = match self.vault.as_mut() {
            Some(ov) => records::trim_all_records(&mut ov.vault),
            None => return 0,
        };
        if n == 0 {
            self.status = "Nothing to trim — every field is already clean.".into();
        } else if self.persist() {
            self.status = format!("Trimmed {n} record(s).");
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
        // The filter row is a card with two labelled lines — the narrowing controls on
        // one, the view toggles on the other. Previously all eleven controls ran
        // together on a single wrapped line, where "reveal all" (which exposes every
        // password on screen) sat between two dropdowns and read like one of them.
        let accent_c = accent(self.theme);
        let filters_active = !self.acct_filter_type.is_empty()
            || !self.acct_filter_subtype.is_empty()
            || !self.acct_filter_owner.is_empty()
            || !self.acct_filter_title.is_empty()
            || self.acct_filter_review
            || !self.acct_search_user.is_empty();
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("Filter").strong().small().color(accent_c));
                ui.label(egui::RichText::new("type").weak().small());
                filter_combo(ui, "acct_ftype", &mut self.acct_filter_type, &facets.types);
                ui.label(egui::RichText::new("subtype").weak().small());
                filter_combo(ui, "acct_fsub", &mut self.acct_filter_subtype, &facets.subtypes);
                ui.label(egui::RichText::new("owner").weak().small());
                filter_combo(ui, "acct_fowner", &mut self.acct_filter_owner, &facets.owners);
                ui.label(egui::RichText::new("title").weak().small());
                filter_combo(ui, "acct_ftitle", &mut self.acct_filter_title, &facets.titles);
                ui.add(
                    egui::TextEdit::singleline(&mut self.acct_search_user)
                        .hint_text("🔍 username or title…")
                        .desired_width(fit(ui, 180.0)),
                );
                ui.checkbox(&mut self.acct_filter_review, "review only");
                // Only offer Clear when there is something to clear, and mark it when
                // filters are hiding rows — an unexplained short list is the single
                // most common "where did my records go" confusion.
                if ui.button("× Clear").on_hover_text("Reset every filter and the search box").clicked() {
                    self.acct_filter_type.clear();
                    self.acct_filter_subtype.clear();
                    self.acct_filter_owner.clear();
                    self.acct_filter_title.clear();
                    self.acct_filter_review = false;
                    self.acct_search_user.clear();
                }
                // A badge when filters are actually hiding rows — an unexplained short
                // list is the most common "where did my records go" confusion.
                if filters_active {
                    badge(ui, "filtered", egui::Color32::from_rgb(190, 105, 10));
                }
            });
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("View").strong().small().color(accent_c));
                // Flat filtered list ⇄ grouped tree (type → subtype → owner → title).
                ui.checkbox(&mut self.acct_grouped, "grouped tree")
                    .on_hover_text("Group the list by owner > type > subtype > title");
                // Global reveal: the ONLY reveal control on this screen.
                ui.checkbox(&mut self.reveal_all, "👁 reveal all passwords")
                    .on_hover_text("Unmask every password on this screen. Resets when you switch tabs.");
                // One-off maintenance: left/right-trim every field on every record (all tabs).
                if self.writable
                    && ui
                        .button("Trim all fields")
                        .on_hover_text("One-off: left/right-trim every field on every record in the whole vault (recorded in history)")
                        .clicked()
                {
                    trim_all = true;
                }
            });
        });
        ui.add_space(6.0);

        // Perform the one-off bulk trim (after the filter row, before the list is
        // built, so the cleaned values show this frame).
        if trim_all {
            self.trim_all_records();
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
        // Flat-list arrow navigation: when not grouped, ↑/↓ move to the prev/next item.
        let nav_target = list_nav_target(ui, !self.acct_grouped, &labels, cur.as_deref());
        let mut new = false;
        let mut select = None;
        let mut export = false;
        let mut action = FormAction::None;
        let mut generate = false;
        // Deferred password-copy: `None` unless the user clicks copy, in which
        // case it holds the secret in a self-wiping `Zeroizing<String>`.
        let mut copy_pw: Option<Zeroizing<String>> = None;
        // Deferred plain-copy for the non-secret URL / username buttons (acted on after
        // rendering, like `copy_pw`, so the clipboard call sits outside the `self` borrow
        // held by the form). A plain `String` — these are not secrets, so no zeroizing.
        let mut copy_plain: Option<String> = None;
        // Subtypes for the record under edit, looked up from the vault's category lists
        // before the mutable borrow of `edit_account` below. The record's current subtype is
        // kept selectable even when off-list — `combo` prepends the current value, so no
        // manual prepend is needed here. `.unwrap_or_default()` yields an empty `Vec` when no
        // record is being edited.
        let subtypes: Vec<String> = self
            .edit_account
            .as_ref()
            .map(|r| self.vault_ref().categories().subtypes_for(&r.account_type))
            .unwrap_or_default();
        // "Linked from": every Asset/Liability whose `linked_accounts` references the
        // record under edit, resolved before the mutable `edit_account` borrow below
        // (same borrow discipline as `subtypes`). Informational only — links are edited
        // on the ASSET side; here each row just offers Open (navigation is a read).
        let linked_from: Vec<(String, String)> = self
            .edit_account
            .as_ref()
            .map(|r| records::assets_linking_account(&self.vault_ref().vault.assets, &r.id))
            .unwrap_or_default();
        // Deferred jump to a linking asset (its id), applied after the columns closure.
        let mut open_asset: Option<String> = None;
        // Deferred resolution of an armed linked-account delete warning (see the
        // `pending_account_delete` field): confirm proceeds with the delete, cancel disarms.
        let mut confirm_delete = false;
        let mut cancel_delete = false;

        ui.columns(2, |c| {
            match &tree {
                // Grouped tree: owner → type → subtype → title (leaf), with empty
                // levels skipped. egui's CollapsingHeader gives the +/- expand control.
                Some(root) => {
                    let lp = &mut c[0];
                    // Same header as the flat `list_panel`, so switching to the tree
                    // does not change what the top of the pane looks like.
                    lp.horizontal_wrapped(|ui| {
                        let accent = ui_accent(ui);
                        section_heading(ui, "Accounts", accent);
                        badge(ui, &format!("{}", labels.len()), accent);
                        ui.add_space(4.0);
                        if self.writable && ui.button("➕ New").clicked() {
                            new = true;
                        }
                        if ui
                            .button("⬇ CSV")
                            .on_hover_text(
                                "Export every row on this tab to a timestamped CSV in the export directory.\n\
                                 The file is UNENCRYPTED and includes passwords in plain text.",
                            )
                            .clicked()
                        {
                            export = true;
                        }
                    });
                    lp.add_space(4.0);
                    lp.separator();
                    egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("acct_tree").show(lp, |ui| {
                        let mut path: Vec<String> = Vec::new();
                        if let Some(s) = render_acct_node(ui, root, &mut path, cur.as_deref(), &labels, "acct") {
                            select = Some(s);
                        }
                    });
                }
                None => {
                    (new, select, export) =
                        list_panel(&mut c[0], "Accounts", "➕ New", &labels, cur.as_deref(), self.writable, nav_target);
                }
            }
            // The form pane scrolls on its OWN axis. Previously the whole tab sat inside
            // one both-axis ScrollArea, so this vertical scroller was nested inside
            // another one and was handed unbounded height — the layout could not settle
            // on a scrollbar, which is what flickered on a small window.
            egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("form_pane_accounts").show(&mut c[1], |ui| {
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
                    field_singleline(ui, &mut r.owner, w, 420.0);
                    ui.end_row();
                    ui.label("Username");
                    ui.horizontal(|ui| {
                        field_singleline(ui, &mut r.username, w, 380.0);
                        // Copy is a read, so it stays available even in read-only mode;
                        // disabled only when the field is empty (nothing to copy).
                        if ui.add_enabled(!r.username.is_empty(), egui::Button::new("📋")).on_hover_text("Copy").clicked() {
                            copy_plain = Some(r.username.clone());
                        }
                    });
                    ui.end_row();
                    ui.label("Password");
                    ui.horizontal(|ui| {
                        // Masked unless the single global "reveal all" toggle is on (there
                        // is no per-record reveal). `secret_text_edit` (audit R-7) scrubs
                        // egui's undo buffer and re-routes the built-in copy through the
                        // history-excluded clipboard path. Read-only: the field is shown,
                        // selectable, and copyable, but not editable.
                        secret_text_edit(ui, "acct_pw", &mut r.password, self.reveal_all, w, 280.0, &mut copy_pw);
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
                    ui.horizontal(|ui| {
                        field_singleline(ui, &mut r.url, w, 380.0);
                        if ui.add_enabled(!r.url.is_empty(), egui::Button::new("📋")).on_hover_text("Copy").clicked() {
                            copy_plain = Some(r.url.clone());
                        }
                    });
                    ui.end_row();
                    ui.label("Closed as of");
                    field_singleline_hint(ui, &mut r.closed_as_of, w, 420.0, "YYYY-MM-DD");
                    ui.end_row();
                    ui.label("Review");
                    ui.add_enabled(w, egui::Checkbox::new(&mut r.review, "flag for review"));
                    ui.end_row();
                });
                ui.label("Description");
                field_multiline(ui, &mut r.description, self.writable, 4);
                // Read-only reverse view of the asset-side links (hidden when nothing
                // links here). Open stays available read-only — navigation is a read.
                if !linked_from.is_empty() {
                    ui.separator();
                    ui.label(egui::RichText::new("Linked from").strong());
                    for (id, label) in &linked_from {
                        ui.horizontal(|ui| {
                            ui.label(format!("• {label}"));
                            if ui.button("Open").clicked() {
                                open_asset = Some(id.clone());
                            }
                        });
                    }
                }
                action = form_buttons(ui, self.writable);
                // Armed by the Delete handling below when assets link this account: the
                // warning (count + consequence) with an explicit second-click pair. The
                // id guard keeps a warning armed for one record from ever rendering —
                // or confirming — against another.
                if self.pending_account_delete.as_deref() == Some(r.id.as_str())
                    && let Some(msg) = account_delete_link_warning(linked_from.len())
                {
                    ui.colored_label(egui::Color32::from_rgb(0xC0, 0x30, 0x30), msg);
                    ui.horizontal(|ui| {
                        if ui.button("Delete anyway").clicked() {
                            confirm_delete = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel_delete = true;
                        }
                    });
                }
                history_view(ui, &r.history);
            } else {
                empty_form_hint(ui, "an account");
            }
        });
        });

        if export {
            self.export_current_tab_csv();
        }
        if new {
            self.edit_account = self.new_account_from_filters();
            // Loading a different record disarms any pending delete warning: the armed
            // id no longer matches, so leaving it set could only go stale.
            self.pending_account_delete = None;
        }
        // A pointer click on a list row (`select`) wins over keyboard nav. But a keyboard
        // arrow (`nav_target`) CAN land in the same egui frame as a button click (events
        // are batched per repaint), and the deferred actions below (Delete, confirm/cancel,
        // Generate) were captured against the CURRENTLY shown record. Applying a same-frame
        // nav swap first would retarget them at the NEIGHBOR — e.g. deleting or regenerating
        // the wrong account. So suppress the keyboard nav whenever a record-targeted action
        // is pending this frame; a click (`select`) cannot co-occur with another button
        // click (one pointer), so it is always safe to honor.
        let record_action_pending =
            new || !matches!(action, FormAction::None) || confirm_delete || cancel_delete || generate;
        if !record_action_pending {
            select = select.or(nav_target);
        }
        if let Some(i) = select {
            // `labels` is the FILTERED list, so resolve the clicked row to its id
            // and look the account up by id (a positional index into the
            // unfiltered vector would select the wrong record when filtering).
            if let Some((id, _)) = labels.get(i) {
                self.edit_account =
                    self.vault_ref().vault.accounts.iter().find(|a| &a.id == id).cloned();
                self.pending_account_delete = None; // selection change disarms (see `new` above)
            }
        }
        // Pre-size the password buffer so typing in the egui field doesn't reallocate
        // and strand un-zeroized fragments of the account secret in freed heap. The
        // Account record is ZeroizeOnDrop, but that only wipes the final buffer, not
        // the copies abandoned by per-keystroke growth. `presize_secret` is a no-op once
        // the capacity is sufficient, so this is cheap to call each frame.
        if let Some(r) = self.edit_account.as_mut() {
            presize_secret(&mut r.password);
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
            // Reveal is global-only now: turn on "reveal all" so the just-generated
            // password is visible (the per-record reveal that used to do this is gone).
            self.reveal_all = true;
        }
        if let Some(pw) = copy_pw {
            // `pw` is moved into the call and wiped when it drops there.
            self.copy_to_clipboard(pw);
        }
        if let Some(text) = copy_plain {
            self.copy_plain(&text);
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
            FormAction::Delete => {
                // Deleting a linked-from account is allowed but never silent: instead of
                // deleting, ARM the confirmation (rendered next frame — the warning text
                // + "Delete anyway"/"Cancel" above). The links are NOT cascaded, so the
                // existing delete rollback stays correct — nothing else is touched. An
                // unlinked account deletes immediately, exactly as before.
                if linked_from.is_empty() {
                    self.delete_current(Tab::Accounts);
                } else {
                    self.pending_account_delete = self.edit_account.as_ref().map(|r| r.id.clone());
                }
            }
            _ => {}
        }
        if confirm_delete {
            self.confirm_pending_account_delete();
        }
        if cancel_delete {
            self.pending_account_delete = None;
            self.status = "Delete cancelled.".into();
        }
        if let Some(id) = open_asset {
            self.open_linking_asset(&id);
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
        // The single global "reveal all" toggle for this screen (mirrors Accounts): when
        // on, all four portal passwords are shown. There is no per-record reveal.
        let accent_c = accent(self.theme);
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(egui::RichText::new("View").strong().small().color(accent_c));
                ui.checkbox(&mut self.re_reveal_all, "👁 reveal all portal passwords").on_hover_text(
                    "Unmask the four portal passwords on this screen. Resets when you switch tabs.",
                );
            });
        });
        ui.add_space(6.0);
        let reveal = self.re_reveal_all;
        let writable = self.writable;
        let mut new = false;
        let mut select = None;
        let mut export = false;
        let mut action = FormAction::None;
        let mut copy_pw: Option<Zeroizing<String>> = None;
        let mut docreq = ReDocReq::None;

        ui.columns(2, |c| {
            (new, select, export) = list_panel(&mut c[0], "Real Estate", "➕ New", &labels, cur.as_deref(), writable, None);
            // The form pane scrolls on its OWN axis. Previously the whole tab sat inside
            // one both-axis ScrollArea, so this vertical scroller was nested inside
            // another one and was handed unbounded height — the layout could not settle
            // on a scrollbar, which is what flickered on a small window.
            egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("form_pane_realestate").show(&mut c[1], |ui| {
            if let Some(r) = self.edit_realestate.as_mut() {
                // No inner ScrollArea here: the whole tab is already wrapped in the
                // CentralPanel's both-axis scroll. A nested vertical scroll over this
                // form would capture the wheel and (having no overflow of its own)
                // scroll nothing, while the outer area never saw the event.
                egui::Grid::new("re_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    text_row(ui, "Address", &mut r.address, writable);
                    text_row(ui, "Owner", &mut r.owner, writable);
                    text_row(ui, "Taxes", &mut r.taxes, writable);
                    text_row(ui, "HOA dues / info", &mut r.hoa, writable);
                    text_row(ui, "Income account", &mut r.income_account, writable);
                    text_row(ui, "Financing account", &mut r.financing_account, writable);
                    text_row(ui, "Financing balance", &mut r.financing_balance, writable);
                    text_row(ui, "Payment account", &mut r.payment_account, writable);
                });

                portal_section(ui, "Property Management portal", &mut r.property_mgmt_url, &mut r.property_mgmt_username, &mut r.property_mgmt_password, &mut r.property_mgmt_comment, reveal, writable, &mut copy_pw);
                portal_section(ui, "Insurance portal", &mut r.insurance_url, &mut r.insurance_username, &mut r.insurance_password, &mut r.insurance_comment, reveal, writable, &mut copy_pw);
                portal_section(ui, "HOA portal", &mut r.hoa_url, &mut r.hoa_username, &mut r.hoa_password, &mut r.hoa_comment, reveal, writable, &mut copy_pw);
                portal_section(ui, "Tax portal", &mut r.tax_portal_url, &mut r.tax_portal_username, &mut r.tax_portal_password, &mut r.tax_portal_comment, reveal, writable, &mut copy_pw);

                ui.separator();
                ui.label("Comments");
                field_multiline(ui, &mut r.comments, writable, 3);

                ui.separator();
                ui.label(format!(
                    "Documents ({}) — under <owner>/{}[/subfolder]/<ts>_<file>",
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
                empty_form_hint(ui, "a property");
            }
        });
        });

        if export {
            self.export_current_tab_csv();
        }
        if new {
            self.edit_realestate = RealEstate::new().ok();
            self.clear_doc_inputs();
        }
        if let Some(i) = select {
            self.edit_realestate = self.vault_ref().vault.real_estate.get(i).cloned();
            self.clear_doc_inputs();
        }
        // Pre-size the portal password buffers so per-keystroke typing never grows
        // (and so reallocates) them — a reallocation frees the old buffer WITHOUT
        // zeroizing, stranding cleartext fragments of a portal password in freed
        // heap. RealEstate is ZeroizeOnDrop, but that only wipes the final buffer,
        // not abandoned reallocations. Same mitigation as the Accounts password field.
        if let Some(r) = self.edit_realestate.as_mut() {
            presize_secret(&mut r.property_mgmt_password);
            presize_secret(&mut r.insurance_password);
            presize_secret(&mut r.hoa_password);
            presize_secret(&mut r.tax_portal_password);
        }
        if let Some(pw) = copy_pw {
            self.copy_to_clipboard(pw);
        }
        self.handle_re_doc(docreq);
        match action {
            FormAction::Save => {
                if let Some(r) = self.edit_realestate.as_mut() {
                    r.trim_fields();
                }
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
        let mut export = false;
        let mut action = FormAction::None;
        let mut docreq = TaxDocReq::None;

        ui.columns(2, |c| {
            (new, select, export) = list_panel(&mut c[0], "Taxes", "➕ New", &labels, cur.as_deref(), writable, None);
            // The form pane scrolls on its OWN axis. Previously the whole tab sat inside
            // one both-axis ScrollArea, so this vertical scroller was nested inside
            // another one and was handed unbounded height — the layout could not settle
            // on a scrollbar, which is what flickered on a small window.
            egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("form_pane_taxes").show(&mut c[1], |ui| {
            if let Some(r) = self.edit_taxfiling.as_mut() {
                egui::Grid::new("tax_form").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    text_row(ui, "Owner", &mut r.owner, writable);
                    text_row(ui, "Filing year", &mut r.year, writable);
                });
                ui.label("Notes");
                field_multiline(ui, &mut r.notes, writable, 4);
                ui.separator();

                // Attached documents — all live under <owner>/taxes/<year>/…/<ts>_<file>
                ui.label(format!(
                    "Documents ({}) — under <owner>/{}[/subfolder]/<ts>_<file>",
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
                empty_form_hint(ui, "a tax year");
            }
        });
        });

        if export {
            self.export_current_tab_csv();
        }
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
                if let Some(r) = self.edit_taxfiling.as_mut() {
                    r.trim_fields();
                }
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
                // Accept a path pasted with surrounding double quotes ("Copy as path").
                let src = records::unquote_path(&self.doc_source).to_string();
                if src.is_empty() {
                    self.status = "'Upload from' path is required.".into();
                    return;
                }
                // If no filename is given, default to the source file's own name.
                let name = records::effective_doc_filename(&self.doc_filename, &src);
                if name.trim().is_empty() {
                    self.status = "Filename is required (the source path has no file name).".into();
                    return;
                }
                let address = self.edit_realestate.as_ref().map(|r| r.address.clone()).unwrap_or_default();
                let prefix = records::owner_prefix(
                    self.edit_realestate.as_ref().map(|r| r.owner.as_str()),
                    &records::real_estate_doc_location(&address),
                );
                let ts = records::compact_utc(records::unix_now());
                let name = records::timestamped_filename(&ts, &records::doc_filename(&name));
                let loc = records::doc_upload_dir(&prefix, &self.doc_subfolder);
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
                            self.fail(format!("Upload failed: {e}"));
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
                if let Some(id) = self.edit_realestate.as_ref().and_then(|r| r.documents.get(i).cloned()) {
                    self.export_doc_to_config_dir(&id);
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
                    self.fail(format!("Unlinked, but blob cleanup failed: {e}"));
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
                // Accept a path pasted with surrounding double quotes ("Copy as path").
                let src = records::unquote_path(&self.doc_source).to_string();
                if src.is_empty() {
                    self.status = "'Upload from' path is required.".into();
                    return;
                }
                // If no filename is given, default to the source file's own name.
                let name = records::effective_doc_filename(&self.doc_filename, &src);
                if name.trim().is_empty() {
                    self.status = "Filename is required (the source path has no file name).".into();
                    return;
                }
                // Don't upload+persist an INVALID asset that the Save path rejects (empty owner
                // or non-numeric value → the Summary silently treats it as 0). Validate first,
                // mirroring the Save path's records::asset_validation_error gate.
                if let DocTarget::Asset = target
                    && let Some(r) = self.edit_asset.as_ref()
                    && let Some(msg) = records::asset_validation_error(r)
                {
                    self.fail(msg);
                    return;
                }
                // Owner-first prefix: Assets nest under the owner initials + kind root
                // (/<INITIALS>/assets|liabilities); Trust&Will/General have no owner and keep
                // their slugged group. The timestamp is folded into the filename, so the
                // directory is <prefix>[/<subfolder>].
                let prefix = match target {
                    DocTarget::TrustWill => records::trust_will_doc_location(
                        self.edit_trustwill.as_ref().map(|r| r.document.as_str()).unwrap_or(""),
                    ),
                    DocTarget::Asset => records::owner_prefix(
                        self.edit_asset.as_ref().map(|r| r.owner.as_str()),
                        &records::asset_doc_location(self.edit_asset.as_ref().map(|r| r.kind.as_str()).unwrap_or("")),
                    ),
                    DocTarget::General => records::general_doc_location(
                        self.edit_general.as_ref().map(|r| r.title.as_str()).unwrap_or(""),
                    ),
                };
                let ts = records::compact_utc(records::unix_now());
                let fname = records::timestamped_filename(&ts, &records::doc_filename(&name));
                let loc = records::doc_upload_dir(&prefix, &self.doc_subfolder);
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
                            self.fail(format!("Upload failed: {e}"));
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
                if let Some(id) = file_id {
                    self.export_doc_to_config_dir(&id);
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
                    self.fail(format!("Unlinked, but blob cleanup failed: {e}"));
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
                // Accept a path pasted with surrounding double quotes ("Copy as path").
                let src = records::unquote_path(&self.doc_source).to_string();
                if src.is_empty() {
                    self.status = "'Upload from' path is required.".into();
                    return;
                }
                // If no filename is given, default to the source file's own name.
                let name = records::effective_doc_filename(&self.doc_filename, &src);
                if name.trim().is_empty() {
                    self.status = "Filename is required (the source path has no file name).".into();
                    return;
                }
                // The folder is derived from the filing year, NOT user-entered.
                let year = self.edit_taxfiling.as_ref().map(|r| r.year.clone()).unwrap_or_default();
                let prefix = records::owner_prefix(
                    self.edit_taxfiling.as_ref().map(|r| r.owner.as_str()),
                    &records::tax_doc_location(&year),
                );
                let ts = records::compact_utc(records::unix_now());
                let name = records::timestamped_filename(&ts, &records::doc_filename(&name));
                let loc = records::doc_upload_dir(&prefix, &self.doc_subfolder);
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
                            self.fail(format!("Upload failed: {e}"));
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
                if let Some(id) = self.edit_taxfiling.as_ref().and_then(|r| r.documents.get(i).cloned()) {
                    self.export_doc_to_config_dir(&id);
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
                    self.fail(format!("Unlinked, but blob cleanup failed: {e}"));
                    return;
                }
                self.status = "Removed document from the vault.".into();
            }
        }
    }

    /// Apply a deferred linked-accounts request from the Assets form (see [`LinkReq`]).
    /// Add/Unlink edit the WORKING BUFFER only — the link list persists through the
    /// ordinary Save path with the rest of the form (never a direct vault write, so
    /// abandoning the edit discards it like any other unsaved change). Open navigates.
    /// Execute an armed "Delete anyway" confirmation for a linked-from account.
    /// Confirm-time id re-check: the render-time guard alone is NOT enough — a bare
    /// arrow-key nav event can land in the SAME egui frame as the "Delete anyway"
    /// click, and the select/nav handler runs before this, swapping `edit_account`
    /// to the neighboring record (and disarming `pending_account_delete`) after the
    /// click was captured. Without this check the raced confirm would delete the
    /// NEIGHBOR. Requiring the armed id to still match the loaded record drops such
    /// a stale confirm (the swap set pending to None, so the equality fails).
    fn confirm_pending_account_delete(&mut self) {
        let armed_matches_current = self.pending_account_delete.is_some()
            && self.pending_account_delete.as_deref()
                == self.edit_account.as_ref().map(|r| r.id.as_str());
        self.pending_account_delete = None;
        if armed_matches_current {
            self.delete_current(Tab::Accounts);
        }
    }

    fn handle_link_req(&mut self, req: LinkReq) {
        match req {
            LinkReq::None => {}
            LinkReq::Add(id) => {
                // The dropdown only offers not-yet-linked accounts, but the request is
                // re-checked here (deferred handling) so a duplicate can never slip in.
                if let Some(r) = self.edit_asset.as_mut()
                    && !r.linked_accounts.iter().any(|l| l == &id)
                {
                    r.linked_accounts.push(id);
                }
            }
            LinkReq::Remove(i) => {
                // Bounds-checked: the index was captured a frame ago against the same
                // buffer, but a stale/raced index must drop the request, not panic.
                if let Some(r) = self.edit_asset.as_mut()
                    && i < r.linked_accounts.len()
                {
                    r.linked_accounts.remove(i);
                }
            }
            LinkReq::Open(id) => self.open_linked_account(&id),
        }
    }

    /// Jump from an asset's link row to the linked Account: load it in the Accounts
    /// editor and switch tabs. A dangling link (the account was deleted — links are
    /// never cascaded) surfaces a status message and does NOT navigate.
    fn open_linked_account(&mut self, id: &str) {
        let Some(a) = self.vault_ref().vault.accounts.iter().find(|a| a.id == id).cloned() else {
            self.status = "Linked account not found — it may have been deleted.".into();
            return;
        };
        // A programmatic tab change bypasses ui_top_bar's prev_tab compare, so perform
        // the same switch resets here: re-mask to the saved reveal default and clear
        // the shared document-input buffers (see the reset block in `ui_top_bar`).
        self.tab = Tab::Accounts;
        self.reveal_all = self.reveal_default;
        self.re_reveal_all = self.reveal_default;
        self.clear_doc_inputs();
        // Retarget any ACTIVE Accounts filters/search to the jump target so the list
        // can't hide the record we just navigated to (same rule as the after-save follow).
        self.sync_account_filters_to(&a);
        self.edit_account = Some(a);
    }

    /// Jump from an account's "Linked from" row to the Asset/Liability linking it —
    /// the reverse of [`Self::open_linked_account`], with the same programmatic
    /// tab-switch resets. The row list is rebuilt from the vault each frame, but the
    /// id is still re-resolved here (deferred handling) rather than trusted.
    fn open_linking_asset(&mut self, id: &str) {
        let Some(r) = self.vault_ref().vault.assets.iter().find(|r| r.id == id).cloned() else {
            self.status = "Linked record not found — it may have been deleted.".into();
            return;
        };
        self.tab = Tab::Assets;
        self.reveal_all = self.reveal_default;
        self.re_reveal_all = self.reveal_default;
        self.clear_doc_inputs();
        // The Assets list's only hiding filter is the review-only toggle: clear it when
        // it would hide the jump target (mirrors the Accounts-side filter follow).
        if self.asset_filter_review && !r.review {
            self.asset_filter_review = false;
        }
        self.edit_asset = Some(r);
    }

    fn delete_current(&mut self, tab: Tab) {
        // Collect any attached document ids to reclaim after removing the record.
        let mut doc_ids: Vec<String> = Vec::new();
        // Roll back the IN-MEMORY removal if the save fails. Without this, a failed persist
        // would leave the record gone from memory (the user was told it failed) and a LATER
        // successful save would silently serialize the whole vault and commit the deletion —
        // unrecoverable data loss. The closure re-inserts the removed record, truncates the
        // remove() audit entry, and restores the edit buffer. (Mirrors the merge path's care.)
        let mut rollback: Option<Box<dyn FnOnce(&mut Self)>> = None;
        if let Some(ov) = self.vault.as_mut() {
            // `&mut ov.vault` is an exclusive borrow of the in-memory vault data,
            // reused below as `v` to keep the match arms terse.
            let v = &mut ov.vault;
            let audit_len = v.audit.len(); // snapshot to undo the remove() audit entry on rollback
            match tab {
                Tab::Urgent => {
                    if let Some(r) = self.edit_urgent.take() {
                        // Restore the SAVED record, not the (possibly dirty) edit buffer — see
                        // the Instructions arm.
                        let stored = v.urgent.iter().find(|x| x.id == r.id).cloned();
                        if records::remove(&mut v.urgent, &r.id, &mut v.audit, "Urgent") {
                            rollback = Some(Box::new(move |s: &mut Self| {
                                if let Some(ov) = s.vault.as_mut() {
                                    ov.vault.audit.truncate(audit_len);
                                    if let Some(stored) = stored {
                                        ov.vault.urgent.push(stored); // restore the SAVED state verbatim
                                    }
                                }
                                s.edit_urgent = Some(r); // restore the user's editing session (UI state)
                            }));
                        }
                    }
                }
                Tab::Instructions => {
                    // `.take()` moves the edited record out of the Option, leaving
                    // `None` behind (so the form clears after deletion) and giving
                    // us owned `r` to read its id.
                    if let Some(r) = self.edit_instruction.take() {
                        // Snapshot the STORED record (its last-SAVED state) for the vault
                        // rollback — NOT the edit buffer `r`, which may hold unsaved edits a
                        // failed delete must not silently commit on a later save.
                        let stored = v.instructions.iter().find(|x| x.id == r.id).cloned();
                        // Only arm the rollback when a record was ACTUALLY removed. A New-but-
                        // never-saved record isn't in the list (remove is a no-op), so the rollback
                        // must NOT resurrect it on a persist failure — the user is discarding it.
                        if records::remove(&mut v.instructions, &r.id, &mut v.audit, "Instruction") {
                            rollback = Some(Box::new(move |s: &mut Self| {
                                if let Some(ov) = s.vault.as_mut() {
                                    ov.vault.audit.truncate(audit_len);
                                    if let Some(stored) = stored {
                                        ov.vault.instructions.push(stored); // restore the SAVED state verbatim
                                    }
                                }
                                s.edit_instruction = Some(r); // restore the user's editing session (UI state)
                            }));
                        }
                    }
                }
                Tab::TrustWill => {
                    if let Some(r) = self.edit_trustwill.take() {
                        if let Some(f) = &r.file {
                            doc_ids.push(f.clone());
                        }
                        // Restore the SAVED record, not the (possibly dirty) edit buffer — see
                        // the Instructions arm.
                        let stored = v.trust_wills.iter().find(|x| x.id == r.id).cloned();
                        if records::remove(&mut v.trust_wills, &r.id, &mut v.audit, "Trust/Will") {
                            rollback = Some(Box::new(move |s: &mut Self| {
                                if let Some(ov) = s.vault.as_mut() {
                                    ov.vault.audit.truncate(audit_len);
                                    if let Some(stored) = stored {
                                        ov.vault.trust_wills.push(stored); // restore the SAVED state verbatim
                                    }
                                }
                                s.edit_trustwill = Some(r); // restore the user's editing session (UI state)
                            }));
                        }
                    }
                }
                Tab::Assets => {
                    if let Some(r) = self.edit_asset.take() {
                        if let Some(f) = &r.statement {
                            doc_ids.push(f.clone());
                        }
                        // Restore the SAVED record, not the (possibly dirty) edit buffer — see
                        // the Instructions arm.
                        let stored = v.assets.iter().find(|x| x.id == r.id).cloned();
                        if records::remove(&mut v.assets, &r.id, &mut v.audit, "Asset/Liability") {
                            rollback = Some(Box::new(move |s: &mut Self| {
                                if let Some(ov) = s.vault.as_mut() {
                                    ov.vault.audit.truncate(audit_len);
                                    if let Some(stored) = stored {
                                        ov.vault.assets.push(stored); // restore the SAVED state verbatim
                                    }
                                }
                                s.edit_asset = Some(r); // restore the user's editing session (UI state)
                            }));
                        }
                    }
                }
                Tab::Accounts => {
                    if let Some(r) = self.edit_account.take() {
                        // Restore the SAVED record, not the (possibly dirty) edit buffer — see
                        // the Instructions arm. Especially load-bearing here: the account edit
                        // buffer can hold an unsaved password change that a failed delete must
                        // never resurrect-and-commit.
                        let stored = v.accounts.iter().find(|x| x.id == r.id).cloned();
                        if records::remove(&mut v.accounts, &r.id, &mut v.audit, "Account") {
                            rollback = Some(Box::new(move |s: &mut Self| {
                                if let Some(ov) = s.vault.as_mut() {
                                    ov.vault.audit.truncate(audit_len);
                                    if let Some(stored) = stored {
                                        ov.vault.accounts.push(stored); // restore the SAVED state verbatim
                                    }
                                }
                                s.edit_account = Some(r); // restore the user's editing session (UI state)
                            }));
                        }
                    }
                }
                Tab::RealEstate => {
                    if let Some(r) = self.edit_realestate.take() {
                        // Reclaim every document attached to this property.
                        for f in &r.documents {
                            doc_ids.push(f.clone());
                        }
                        // Restore the SAVED record, not the (possibly dirty) edit buffer — see
                        // the Instructions arm.
                        let stored = v.real_estate.iter().find(|x| x.id == r.id).cloned();
                        if records::remove(&mut v.real_estate, &r.id, &mut v.audit, "Real Estate") {
                            rollback = Some(Box::new(move |s: &mut Self| {
                                if let Some(ov) = s.vault.as_mut() {
                                    ov.vault.audit.truncate(audit_len);
                                    if let Some(stored) = stored {
                                        ov.vault.real_estate.push(stored); // restore the SAVED state verbatim
                                    }
                                }
                                s.edit_realestate = Some(r); // restore the user's editing session (UI state)
                            }));
                        }
                    }
                }
                Tab::Taxes => {
                    if let Some(r) = self.edit_taxfiling.take() {
                        // Reclaim every document attached to this filing year.
                        for f in &r.documents {
                            doc_ids.push(f.clone());
                        }
                        // Restore the SAVED record, not the (possibly dirty) edit buffer — see
                        // the Instructions arm.
                        let stored = v.tax_filings.iter().find(|x| x.id == r.id).cloned();
                        if records::remove(&mut v.tax_filings, &r.id, &mut v.audit, "Tax filing") {
                            rollback = Some(Box::new(move |s: &mut Self| {
                                if let Some(ov) = s.vault.as_mut() {
                                    ov.vault.audit.truncate(audit_len);
                                    if let Some(stored) = stored {
                                        ov.vault.tax_filings.push(stored); // restore the SAVED state verbatim
                                    }
                                }
                                s.edit_taxfiling = Some(r); // restore the user's editing session (UI state)
                            }));
                        }
                    }
                }
                Tab::GeneralDocuments => {
                    if let Some(r) = self.edit_general.take() {
                        if let Some(f) = &r.file {
                            doc_ids.push(f.clone());
                        }
                        // Restore the SAVED record, not the (possibly dirty) edit buffer — see
                        // the Instructions arm.
                        let stored = v.general_documents.iter().find(|x| x.id == r.id).cloned();
                        if records::remove(&mut v.general_documents, &r.id, &mut v.audit, "General document") {
                            rollback = Some(Box::new(move |s: &mut Self| {
                                if let Some(ov) = s.vault.as_mut() {
                                    ov.vault.audit.truncate(audit_len);
                                    if let Some(stored) = stored {
                                        ov.vault.general_documents.push(stored); // restore the SAVED state verbatim
                                    }
                                }
                                s.edit_general = Some(r); // restore the user's editing session (UI state)
                            }));
                        }
                    }
                }
                // The Summary tab is read-only (no records of its own), so it never deletes.
                Tab::Summary => {}
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
        } else if let Some(rb) = rollback {
            // persist() already set the "Save failed: …" status; undo the in-memory removal so
            // a later successful save cannot silently commit the deletion the user was told failed.
            rb(self);
        }
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
            Err(e) => self.fail(format!("Clipboard unavailable: {e}")),
        }
    }

    /// Copy a NON-secret (a URL or username) to the OS clipboard. Unlike
    /// [`Self::copy_to_clipboard`] this schedules NO 15 s auto-clear and uses the plain
    /// (history-kept) clipboard path. The fresh non-secret has just overwritten whatever
    /// was on the clipboard, so any pending secret auto-clear is cancelled and the dirty
    /// flag cleared: there is no longer a copied password to wipe, and leaving the timer
    /// armed would blank the user's freshly copied URL/username 15 s later.
    fn copy_plain(&mut self, text: &str) {
        match crate::copy_plain_to_clipboard(text) {
            Ok(()) => {
                self.clipboard_dirty = false;
                self.clipboard_clear_at = None;
                self.status = "Copied.".into();
            }
            Err(e) => self.fail(format!("Clipboard unavailable: {e}")),
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
        self.render(ui);
    }
}

impl GuiApp {
    /// Draw the whole window. Split out of [`eframe::App::ui`] (which only forwards
    /// to it) because it needs nothing from `eframe::Frame` — so a headless
    /// `egui_kittest` harness can lay out the REAL window, panels and all, rather
    /// than a hand-assembled approximation of it.
    fn render(&mut self, ui: &mut egui::Ui) {
        self.tick_clipboard(ui.ctx());
        // Apply (and persist) the color theme only when the selection changed.
        if self.theme != self.applied_theme {
            // The palette AND the accent-colored parts of the style change together.
            apply_theme(ui.ctx(), self.theme);
            save_theme(self.theme);
            self.applied_theme = self.theme;
        }
        // Clear the error banner once any later status message has replaced the failure
        // text it was showing (a success/info line means the problem is no longer current).
        if error_banner_is_stale(self.error.as_deref(), &self.status) {
            self.error = None;
        }
        // A hard failure (a failed save/export/backup/upload, …) gets a bright, dismissable
        // banner across the TOP of EVERY screen — far more visible than the weak status
        // line, so a failure can never be missed (e.g. a save that failed on a full disk,
        // where the status line alone would leave the user believing the edit was saved).
        // Rendered before the per-screen panels so it sits above all of them.
        show_error_banner(&mut self.error, ui);
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
        if self.screen == Screen::Merge {
            egui::CentralPanel::default().show_inside(ui, |ui| self.ui_merge(ui));
            return;
        }
        if self.screen == Screen::Help {
            egui::CentralPanel::default().show_inside(ui, |ui| self.ui_help(ui));
            return;
        }

        egui::Panel::top("topbar").show_inside(ui, |ui| {
            ui.add_space(4.0);
            self.ui_top_bar(ui);
            ui.add_space(4.0);
        });
        // The status bar is ALWAYS drawn, even when idle. Showing it conditionally
        // made the whole tab jump by a row whenever a message arrived or aged out;
        // a fixed strip keeps the layout still and gives the message a known home.
        egui::Panel::bottom("status").show_inside(ui, |ui| {
            ui.add_space(3.0);
            let accent = accent(self.theme);
            egui::containers::Sides::new().shrink_left().show(
                ui,
                |ui| {
                    if self.status.is_empty() {
                        ui.label(egui::RichText::new("•").color(accent.gamma_multiply(0.5)).small());
                        ui.label(egui::RichText::new("Ready").weak().small());
                    } else {
                        ui.label(egui::RichText::new("•").color(accent).small());
                        // A long failure message truncates here rather than widening the
                        // window; the banner above carries the full text.
                        ui.add(egui::Label::new(egui::RichText::new(&self.status).small()).truncate())
                            .on_hover_text(&self.status);
                    }
                },
                |ui| {
                    // The clipboard's auto-clear state belongs where the eye already looks
                    // for state — otherwise a copied password's lifetime is invisible.
                    if self.clipboard_dirty {
                        ui.label(
                            egui::RichText::new("📋 clipboard clears automatically")
                                .small()
                                .color(egui::Color32::from_rgb(190, 105, 10)),
                        );
                    }
                },
            );
            ui.add_space(3.0);
        });
        // The tab body fills the panel and does NOT scroll as a whole. Scrolling belongs
        // to the frames that actually hold overflowing content — each tab's list pane and
        // its form pane scroll independently (and Summary's wide table scrolls both ways
        // on its own).
        //
        // It used to be one both-axis ScrollArea wrapped around everything, with the list
        // and form scrollers nested inside it. A scroll area gives its contents unbounded
        // space on its scrolling axes, so those inner vertical scrollers were laid out
        // against infinite height and never decided they needed a scrollbar; meanwhile the
        // outer horizontal bar appeared, took width away, forced a re-layout, and
        // disappeared again. On a window too small for the content that oscillation ran
        // every frame — the flicker.
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(egui::Margin::symmetric(10, 8)))
            .show_inside(ui, |ui| {
                match self.tab {
                    Tab::Urgent => self.tab_urgent(ui),
                    Tab::Instructions => self.tab_instructions(ui),
                    Tab::TrustWill => self.tab_trustwill(ui),
                    Tab::Assets => self.tab_assets(ui),
                    Tab::Summary => self.tab_summary(ui),
                    Tab::Accounts => self.tab_accounts(ui),
                    Tab::RealEstate => self.tab_realestate(ui),
                    Tab::Taxes => self.tab_taxes(ui),
                    Tab::GeneralDocuments => self.tab_general(ui),
                }
            });
    }
}

// --- Free helper widgets -----------------------------------------------------

/// Pure lifetime rule for the conspicuous error banner, unit-testable without egui (mirrors
/// the `clipboard_tick_decision` pattern). The banner shows the last hard failure and must
/// disappear as soon as any later status line replaces that text — a success/info message
/// means the failure is no longer current — while staying put as long as the status still
/// equals it. Returns `true` when the stored `error` is stale and should be cleared.
fn error_banner_is_stale(error: Option<&str>, status: &str) -> bool {
    error.is_some_and(|e| e != status)
}

/// Render the CONSPICUOUS error banner for a hard failure: a bright red full-width strip at
/// the top of the window with a ⚠ and the failure message, plus a Dismiss button that clears
/// it (`*error = None`). Does nothing when `error` is `None`. Kept a free function (taking
/// just `&mut Option<String>` and `ui`) so a headless `egui_kittest` harness can drive it
/// without constructing an `eframe::Frame`. Far more visible than the weak status line, so a
/// failed save/upload can't be silently overlooked.
fn show_error_banner(error: &mut Option<String>, ui: &mut egui::Ui) {
    let Some(msg) = error.clone() else { return };
    egui::Panel::top("error_banner")
        .frame(
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(176, 0, 32))
                .inner_margin(egui::Margin::symmetric(12, 10)),
        )
        .show_inside(ui, |ui| {
            // Dismiss is placed first and the MESSAGE yields space, so the button is
            // reachable no matter how long the failure text is.
            egui::containers::Sides::new().shrink_left().show(
                ui,
                |ui| {
                    ui.label(egui::RichText::new("⚠").color(egui::Color32::WHITE).strong().size(18.0));
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new(&msg).color(egui::Color32::WHITE).strong().size(15.0));
                },
                |ui| {
                    if ui.button("Dismiss ×").clicked() {
                        *error = None;
                    }
                },
            );
        });
}

// `current` is borrowed mutably so the click can change it. `*current` is a
// *dereference*: it reads/writes the value behind the `&mut` reference (compare
// `*current == tab`, assign `*current = tab`).
fn tab_button(ui: &mut egui::Ui, current: &mut Tab, tab: Tab, label: &str, accent: egui::Color32) {
    let selected = *current == tab;
    // The active tab is bolded and tinted, then underlined with an accent bar drawn
    // just under its rect — the underline is what makes "which tab am I on" readable
    // at a glance across ten differently-colored themes.
    let text = if selected {
        egui::RichText::new(label).strong().color(accent)
    } else {
        egui::RichText::new(label)
    };
    let resp = ui.selectable_label(selected, text);
    if selected {
        let r = resp.rect;
        ui.painter().hline(
            r.min.x + 2.0..=r.max.x - 2.0,
            r.max.y + 1.0,
            egui::Stroke::new(2.0, accent),
        );
    }
    if resp.clicked() {
        *current = tab;
    }
}

/// Render the left list panel; return `(new_clicked, selected_index)`.
// `labels: &[(String, String)]` is a borrowed *slice* — a read-only view of a
// contiguous run of `(id, label)` tuples (no ownership taken). `Option<&str>`
// is a maybe-present borrowed string. Returning a tuple lets one call report two
// outcomes at once.
/// Recursive render of one grouped-tree node ([`records::AcctNode`]): child groups (each an
/// expandable `CollapsingHeader`) followed by this node's leaves (shown by label only).
/// Returns the index into `labels` of a clicked leaf, if any. `path` is the stack of ancestor
/// labels; it is hashed AS A SLICE for each header's `id_salt`, which is collision-free
/// (unlike a `/`-joined string, where owner "a/b" would collide with owner "a" + type "b" and
/// share expand state). Shared by the grouped Accounts and Assets views.
// `kind` ("acct" / "asset") prefixes the header id_salt so the Accounts and Assets trees get
// DISTINCT persistent collapse state for a same-named group (e.g. owner "Bob" in both). egui's
// ScrollArea id_salt namespaces only the scroll offset, not child widget ids, so without this
// the two trees would share expand/collapse state (the TUI keeps separate expand-sets for the
// same reason).
fn render_acct_node(
    ui: &mut egui::Ui,
    node: &records::AcctNode,
    path: &mut Vec<String>,
    cur: Option<&str>,
    labels: &[(String, String)],
    kind: &str,
) -> Option<usize> {
    let mut select = None;
    for child in &node.children {
        path.push(child.label.clone());
        let resp = egui::CollapsingHeader::new(&child.label)
            .id_salt((kind, "group_node", path.as_slice()))
            .show(ui, |ui| render_acct_node(ui, child, path, cur, labels, kind));
        if let Some(s) = resp.body_returned.flatten() {
            select = Some(s);
        }
        path.pop();
    }
    for leaf in &node.leaves {
        let sel = cur == Some(leaf.id.as_str());
        let title = if leaf.title.is_empty() { "(no title)".to_string() } else { leaf.title.clone() };
        if ui.selectable_label(sel, title).clicked() {
            // An index into `labels` (the same filtered set as the tree), matching the
            // flat-list model used by the form.
            select = labels.iter().position(|(id, _)| *id == leaf.id);
        }
    }
    select
}

/// Keyboard-navigation target for a FLAT (non-grouped) record list. Returns `Some(index)`
/// when the user pressed ↑/↓ this frame and `enabled` is set and neither a widget holds
/// keyboard focus NOR a popup is open. Those guards mean typing in an edit-pane field moves
/// the text cursor, and an open Type/Subtype dropdown navigates its own options, rather than
/// moving the list selection (nav runs at the top of the tab, before the dropdowns render,
/// so without the popup guard it would drain the arrow key the open combo needs). `enabled`
/// is false in grouped mode (the tree has its own layout).
///
/// The arrow key is consumed so a focused widget that also reads arrows (e.g. a slider)
/// won't act on the same press too. Note this does NOT suppress egui's cardinal focus
/// navigation (`focus_direction` is captured from RawInput before any UI runs); egui only
/// moves focus directionally when a widget already holds it, so the `focused()` guard is
/// what keeps arrows driving the list here.
fn list_nav_target(
    ui: &egui::Ui,
    enabled: bool,
    labels: &[(String, String)],
    current_id: Option<&str>,
) -> Option<usize> {
    if !enabled
        || labels.is_empty()
        || ui.memory(|m| m.focused().is_some())
        || egui::Popup::is_any_open(ui.ctx())
    {
        return None;
    }
    let delta = ui.input_mut(|i| {
        if i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
            1isize
        } else if i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
            -1
        } else {
            0
        }
    });
    if delta == 0 {
        return None;
    }
    let here = current_id.and_then(|id| labels.iter().position(|(lid, _)| lid == id));
    Some(stepped_list_index(here, delta, labels.len()))
}

/// Step a flat-list cursor by `delta` (±1), clamped to `[0, len-1]` (the ends don't wrap).
/// With nothing currently selected, ↓ (`delta > 0`) starts at the top and ↑ at the bottom.
/// `len` must be > 0 (callers guard on a non-empty list).
fn stepped_list_index(current: Option<usize>, delta: isize, len: usize) -> usize {
    match current {
        Some(i) => (i as isize + delta).clamp(0, len as isize - 1) as usize,
        None if delta > 0 => 0,
        None => len - 1,
    }
}

fn list_panel(
    ui: &mut egui::Ui,
    title: &str,
    new_label: &str,
    labels: &[(String, String)],
    current_id: Option<&str>,
    writable: bool,
    // When `Some(i)`, scroll so row `i` is visible (set only on the frame the user navigates
    // with the arrow keys, so it never fights manual scrolling).
    scroll_to: Option<usize>,
) -> (bool, Option<usize>, bool) {
    let mut new = false;
    let mut select = None;
    let mut export = false;
    // `apply_style` parks the theme's accent in the selection stroke, so free widgets
    // can pick it up without every call site having to pass it down.
    let accent = ui_accent(ui);
    // Heading, count, then the two actions — all left-to-right and wrapping, so the
    // buttons stay next to the title they belong to. Right-aligning them pushed them
    // against the divider between the panes, where "⬇ CSV" read as part of the form
    // and was easy to miss entirely on a narrow window.
    ui.horizontal_wrapped(|ui| {
        section_heading(ui, title, accent);
        badge(ui, &format!("{}", labels.len()), accent);
        ui.add_space(4.0);
        // "New" is a write; only offered when writable.
        if writable && ui.button(new_label).clicked() {
            new = true;
        }
        // Offered in read-only sessions too. The tooltip carries the warning the old
        // write-mode gate used to enforce: the file is unencrypted and, on Accounts and
        // Real Estate, holds every password in the clear.
        if ui
            .button("⬇ CSV")
            .on_hover_text(
                "Export every row on this tab to a timestamped CSV in the export directory.\n\
                 The file is UNENCRYPTED and includes passwords in plain text.",
            )
            .clicked()
        {
            export = true;
        }
    });
    ui.add_space(4.0);
    ui.separator();
    ui.add_space(2.0);
    if labels.is_empty() {
        // An empty list previously read as a blank panel, which is indistinguishable
        // from a broken one. Say which it is.
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(if writable {
                "Nothing here yet — click New to add the first record."
            } else {
                "Nothing here (or every record is hidden by a filter)."
            })
            .weak()
            .italics(),
        );
    }
    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
        // `.enumerate()` pairs each item with its index `i`; the `(i, (id, label))`
        // pattern destructures the index and the inner tuple together.
        for (i, (id, label)) in labels.iter().enumerate() {
            // `id.as_str()` borrows the `String` as `&str` to compare with the
            // currently-selected id.
            let selected = current_id == Some(id.as_str());
            let resp = ui.selectable_label(selected, label);
            if resp.clicked() {
                select = Some(i);
            }
            if scroll_to == Some(i) {
                resp.scroll_to_me(Some(egui::Align::Center));
            }
        }
    });
    (new, select, export)
}

/// The right-hand pane before anything is selected. A bare one-line label read as
/// a stray sentence; this centers a glyph and the instruction so the empty pane
/// looks deliberate rather than unfinished.
fn empty_form_hint(ui: &mut egui::Ui, noun: &str) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        ui.label(egui::RichText::new("👈").size(28.0).color(ui_accent(ui).gamma_multiply(0.7)));
        ui.add_space(6.0);
        ui.label(egui::RichText::new(format!("Select {noun} from the list")).strong());
        ui.label(egui::RichText::new("…or click New to add one.").weak().small());
    });
}

// The two reserved status colors for money. They are NOT part of the accent
// family and are never reused as decoration: green means "this is what is owned",
// red "this is what is owed". Both are readable on the light and the dark
// surfaces of all ten themes.
const STAT_GOOD: egui::Color32 = egui::Color32::from_rgb(45, 130, 80);
const STAT_BAD: egui::Color32 = egui::Color32::from_rgb(185, 70, 70);

/// A headline figure with its label: the Summary tab's KPI row.
///
/// Label above in secondary ink (never in the value's color — the number carries
/// the meaning), value below at display size. Read-only presentation of numbers
/// the table below already contains.
fn stat_tile(ui: &mut egui::Ui, label: &str, value: &str, color: egui::Color32) {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.35)))
        .corner_radius(8)
        .inner_margin(egui::Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.set_min_width(140.0);
                ui.label(egui::RichText::new(label).weak().small());
                ui.add_space(2.0);
                ui.label(egui::RichText::new(value).size(22.0).strong().color(color));
            });
        });
    ui.add_space(6.0);
}

/// A Config-screen section heading: accent-colored, with the vertical rhythm that
/// separates one settings group from the next. Config used to run every group
/// together in one undifferentiated column.
fn config_heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(8.0);
    ui.label(egui::RichText::new(text).strong().size(16.0).color(ui_accent(ui)));
    ui.add_space(4.0);
}

/// The theme's accent color, recovered from the style. `apply_style` parks it in
/// the selection stroke so free-standing widgets (which have no `GuiApp` to ask)
/// can stay in the palette without threading a color through every call.
fn ui_accent(ui: &egui::Ui) -> egui::Color32 {
    ui.visuals().selection.stroke.color
}

/// Save / Delete buttons; returns the chosen action. Renders nothing (and stays
/// `None`) in read-only mode.
fn form_buttons(ui: &mut egui::Ui, writable: bool) -> FormAction {
    if !writable {
        return FormAction::None;
    }
    let mut action = FormAction::None;
    ui.add_space(10.0);
    ui.separator();
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        // Save is the primary action, so it is the filled one; delete is destructive,
        // so it is tinted red and sits apart from the button you actually want.
        let accent = ui_accent(ui);
        if ui
            .add(egui::Button::new(egui::RichText::new("💾 Save").strong().color(egui::Color32::WHITE)).fill(accent))
            .on_hover_text("Write this record to the vault")
            .clicked()
        {
            action = FormAction::Save;
        }
        ui.add_space(10.0);
        if ui
            .add(egui::Button::new(egui::RichText::new("🗑 Delete").color(egui::Color32::from_rgb(200, 60, 60))))
            .on_hover_text("Remove this record from the vault")
            .clicked()
        {
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

/// The warning shown before deleting an account that assets/liabilities still link to:
/// states the linked-from count and the consequence — the links are KEPT (no cascade,
/// per the additive/no-silent-loss policy) and will render as unresolved raw ids.
/// `None` when nothing links to the account, in which case delete proceeds unwarned
/// exactly as before. Shared by the form's warning banner and its tests.
fn account_delete_link_warning(linked_from: usize) -> Option<String> {
    if linked_from == 0 {
        return None;
    }
    Some(format!(
        "This account is linked from {linked_from} asset/liability record(s). Deleting it will NOT \
         remove those links — they will show as unresolved ids."
    ))
}

/// Give a freshly-cloned secret field 128 bytes of spare capacity so later per-keystroke
/// edits don't reallocate (which frees the old buffer WITHOUT zeroizing, stranding cleartext
/// in freed heap). Calling `String::reserve` directly on the clone would ITSELF reallocate —
/// the clone has capacity == len — committing the very leak it means to prevent. So we move
/// the value into a roomier buffer and zeroize the original. A no-op once headroom exists
/// (e.g. an empty new-record field), so it is cheap to call every frame.
fn presize_secret(s: &mut String) {
    if s.capacity() >= s.len() + 128 {
        return;
    }
    let mut roomy = String::with_capacity(s.len() + 128);
    roomy.push_str(s);
    s.zeroize(); // wipe the cloned buffer before it is freed by the move below
    *s = roomy;
}

/// Break `text` into lines that fit `max_width`, putting a HYPHEN at the break when
/// a single word has to be split.
///
/// egui wraps at word boundaries and, for a word longer than the line, splits it with
/// no visual cue — so a long path or id just stops mid-character and resumes on the
/// next line, reading as two unrelated fragments. A trailing dash is the typographic
/// convention that says "this word continues".
///
/// Pure: `measure` supplies the width of a string, so the line-breaking logic is
/// unit-testable without a font or a UI. Existing newlines in `text` are preserved as
/// hard breaks.
fn wrap_hyphenated(text: &str, max_width: f32, measure: impl Fn(&str) -> f32) -> String {
    // Degenerate width: nothing sensible to compute, so hand the text back untouched
    // rather than emit one character per line.
    if max_width <= 0.0 {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len() + 8);
    for (i, para) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let mut line = String::new();
        for word in para.split_whitespace() {
            // `rest` is what remains of the current word; a word too long for a whole
            // line is consumed a piece at a time by the inner loop.
            let mut rest = word;
            loop {
                let candidate =
                    if line.is_empty() { rest.to_owned() } else { format!("{line} {rest}") };
                if measure(&candidate) <= max_width {
                    line = candidate;
                    break;
                }
                // Doesn't fit. If something is already on the line, flush it and retry
                // this word on a fresh line.
                if !line.is_empty() {
                    out.push_str(&line);
                    out.push('\n');
                    line.clear();
                    continue;
                }
                // The word alone overflows an empty line: split it, reserving room for
                // the hyphen. Walk char boundaries (never byte offsets — that would
                // panic on multi-byte UTF-8) and take the longest prefix that fits.
                let mut cut = 0;
                for (idx, _) in rest.char_indices().skip(1) {
                    if measure(&format!("{}-", &rest[..idx])) > max_width {
                        break;
                    }
                    cut = idx;
                }
                // Guarantee progress even when a single character overflows, so this
                // loop can never spin forever on a very narrow pane.
                if cut == 0 {
                    cut = rest.char_indices().nth(1).map_or(rest.len(), |(i, _)| i);
                }
                out.push_str(&rest[..cut]);
                out.push_str("-\n");
                rest = &rest[cut..];
                if rest.is_empty() {
                    break;
                }
            }
        }
        out.push_str(&line);
    }
    out
}

/// Render a stored value as READ-ONLY text: left-justified, wrapped to the pane with
/// [`wrap_hyphenated`], and still selectable so it can be copied.
///
/// The alternative — a disabled text box — gave every value the same full-pane width
/// whatever its length, so a one-word owner name occupied as much screen as an
/// address. This shows the text and nothing else. It is display-only: the vault value
/// behind it is never touched, so the dashes exist purely on screen.
fn read_only_value(ui: &mut egui::Ui, text: &str) -> egui::Response {
    let avail = fit(ui, f32::INFINITY);
    let font = egui::TextStyle::Body.resolve(ui.style());
    let wrapped = wrap_hyphenated(text, avail, |s| {
        ui.painter().layout_no_wrap(s.to_owned(), font.clone(), egui::Color32::PLACEHOLDER).size().x
    });
    // Already broken to width, so egui must not wrap it a second time.
    ui.add(egui::Label::new(wrapped).wrap_mode(egui::TextWrapMode::Extend).selectable(true))
}

/// Treat a designed field width as a MAXIMUM, shrinking it to whatever the pane
/// actually offers.
///
/// The form pane scrolls vertically only, so a field wider than the pane is clipped
/// rather than scrolled to. Wide windows are unaffected (the designed width already
/// fits); narrow ones shrink the field instead of losing its right-hand end. The
/// floor keeps a field from collapsing to nothing.
fn fit(ui: &egui::Ui, desired: f32) -> f32 {
    desired.min(ui.available_width() - 8.0).max(90.0)
}

/// A single-line text field that is editable when `writable`, and otherwise shown as
/// an **immutable but still selectable/copyable** field. egui edits require a *mutable*
/// `TextBuffer` while selection only needs an interactive widget — so binding a `&str`
/// (an immutable `TextBuffer`) gives a read-only field whose text the user can still
/// highlight and Ctrl+C, exactly what read-only mode wants (vs. `add_enabled(false)`,
/// which greys it out and blocks selection entirely).
fn field_singleline(ui: &mut egui::Ui, value: &mut String, writable: bool, width: f32) -> egui::Response {
    if writable {
        ui.add(egui::TextEdit::singleline(value).desired_width(fit(ui, width)))
    } else {
        read_only_value(ui, value)
    }
}

/// Like [`field_singleline`] but with a placeholder hint (shown only when editable).
fn field_singleline_hint(ui: &mut egui::Ui, value: &mut String, writable: bool, width: f32, hint: &str) -> egui::Response {
    if writable {
        ui.add(egui::TextEdit::singleline(value).hint_text(hint).desired_width(fit(ui, width)))
    } else {
        read_only_value(ui, value)
    }
}

/// A multi-line field: editable when `writable`, else immutable-but-selectable (see
/// [`field_singleline`]).
fn field_multiline(ui: &mut egui::Ui, value: &mut String, writable: bool, rows: usize) -> egui::Response {
    if writable {
        ui.add(egui::TextEdit::multiline(value).desired_rows(rows).desired_width(f32::INFINITY))
    } else {
        read_only_value(ui, value)
    }
}

fn text_row(ui: &mut egui::Ui, label: &str, value: &mut String, writable: bool) {
    ui.label(label);
    field_singleline(ui, value, writable, 420.0);
    ui.end_row();
}

/// Render one portal-login section (URL / username / masked password + copy, plus a
/// free-form comment) into the Real Estate form. The password is masked unless
/// `reveal`; `copy_pw` is set when the copy button is clicked, to be acted on after
/// rendering.
#[allow(clippy::too_many_arguments)]
fn portal_section(
    ui: &mut egui::Ui,
    title: &str,
    url: &mut String,
    username: &mut String,
    password: &mut String,
    comment: &mut String,
    reveal: bool,
    writable: bool,
    copy_pw: &mut Option<Zeroizing<String>>,
) {
    let accent = ui_accent(ui);
    ui.add_space(4.0);
    // Each of the four portals is its own card, so they read as four separate
    // logins rather than one long run of near-identical fields.
    card(ui, |ui| {
        ui.label(egui::RichText::new(format!("🔐 {title}")).strong().color(accent));
        ui.add_space(4.0);
        egui::Grid::new(title).num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            text_row(ui, "URL", url, writable);
            text_row(ui, "Username", username, writable);
            ui.label("Password");
            ui.horizontal(|ui| {
                // `title` is unique per portal (Property Mgmt / Insurance / HOA / Tax), so
                // it is a valid per-field id salt for the secret-field hardening. Copy stays
                // available read-only (it is a read, not an edit).
                secret_text_edit(ui, title, password, reveal, writable, 260.0, copy_pw);
                if ui
                    .button("📋")
                    .on_hover_text("Copy to the clipboard (cleared automatically after 15 seconds)")
                    .clicked()
                {
                    *copy_pw = Some(Zeroizing::new(password.clone()));
                }
            });
            ui.end_row();
        });
        ui.add_space(2.0);
        ui.label(egui::RichText::new("Comment").weak().small());
        // Editable when writable, else immutable-but-selectable (see `field_singleline`).
        // The per-portal `id_salt` keeps the four comment boxes' ids distinct.
        let salt = (title, "comment");
        if writable {
            ui.add(
                egui::TextEdit::multiline(comment)
                    .id_salt(salt)
                    .hint_text("security questions, account numbers, who to ask for…")
                    .desired_rows(2)
                    .desired_width(f32::INFINITY),
            );
        } else {
            let _ = salt; // the id salt only matters for the editable widget
            read_only_value(ui, comment);
        }
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

/// A dropdown over `options`. Non-interactive (display-only) in read-only mode. The
/// record's CURRENT value is always offered as a choice — even when it is off-list (legacy
/// data, or a type later removed from Config) — so opening the dropdown can never drop it.
fn combo(ui: &mut egui::Ui, id: &str, value: &mut String, options: &[String], writable: bool) {
    let current = if value.is_empty() { "(choose)".to_string() } else { value.clone() };
    ui.add_enabled_ui(writable, |ui| {
        egui::ComboBox::from_id_salt(id).selected_text(current).show_ui(ui, |ui| {
            // Keep an off-list current value selectable, listed first. Compare trimmed +
            // case-insensitively (matching the core's category dedup) so a value differing
            // from a configured entry only by case/whitespace isn't shown as a near-duplicate.
            if !value.is_empty() && !options.iter().any(|o| o.trim().eq_ignore_ascii_case(value.trim())) {
                let cur = value.clone();
                ui.selectable_value(value, cur.clone(), cur);
            }
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
    writable: bool,
) -> DocSectionReq {
    let mut req = DocSectionReq::None;
    let accent = ui_accent(ui);
    ui.add_space(4.0);
    // The whole document area is one card, so a form reads as "fields, then the
    // files that belong to them" rather than as an undifferentiated column.
    card(ui, |ui| {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("📎 Documents").strong().color(accent));
        ui.label(egui::RichText::new("stored encrypted inside the vault").weak().small());
    });
    ui.add_space(6.0);
    if attached.is_empty() {
        ui.label(egui::RichText::new("No documents attached.").weak().italics());
    } else {
        for (i, label) in attached.iter().enumerate() {
            // `shrink_left`: the buttons are placed first and the FILENAME gives up
            // space, so a long name truncates instead of shoving Export/Remove out of
            // the pane.
            egui::containers::Sides::new().shrink_left().show(
                ui,
                |ui| {
                    ui.label(egui::RichText::new("📄").color(accent));
                    ui.add(egui::Label::new(label).truncate()).on_hover_text(label);
                },
                |ui| {
                    if writable
                        && ui
                            .button("🗑 Remove")
                            .on_hover_text("Detach this document from the record and reclaim its space")
                            .clicked()
                    {
                        req = DocSectionReq::Remove(i);
                    }
                    // Export is a read (always allowed); Remove mutates the vault. Export
                    // writes into the directory configured in Config, recreating the document's
                    // volume folder structure — there is no per-export path prompt.
                    if ui
                        .button("⬇ Export")
                        .on_hover_text("Write a DECRYPTED copy into the export directory set in Config")
                        .clicked()
                    {
                        req = DocSectionReq::Export(i);
                    }
                },
            );
        }
    }
    if writable {
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
        ui.label(egui::RichText::new("Attach a file").strong().small());
        egui::Grid::new("doc_attach").num_columns(2).spacing([8.0, 6.0]).show(ui, |ui| {
            ui.label("Subfolder (optional)");
            ui.add(egui::TextEdit::singleline(subfolder).hint_text("statements").desired_width(fit(ui, 300.0)));
            ui.end_row();
            ui.label("Filename");
            ui.add(egui::TextEdit::singleline(filename).hint_text("statement.pdf").desired_width(fit(ui, 300.0)));
            ui.end_row();
            ui.label("Upload from");
            ui.add(
                egui::TextEdit::singleline(source)
                    .hint_text("/path/on/disk/file.pdf")
                    .desired_width(fit(ui, 300.0)),
            )
            .on_hover_text("The full path to the file. A double-quoted path is accepted as-is.");
            ui.end_row();
        });
        ui.label(
            egui::RichText::new("Leave Filename blank to keep the source file's own name. The original file is not moved.")
                .weak()
                .small(),
        );
        ui.add_space(4.0);
        // Approximate the virtual path length: the stored path also includes the
        // owner-initials/group levels and the <ts>_ filename prefix (~80 bytes, not
        // visible here), so reserve for them. `handle_doc`/`handle_*_doc` do the
        // authoritative check on write.
        let vpath_len = vault::virtual_path(subfolder, filename).len() + 80;
        let over_limit = vpath_len > crate::storage::MAX_PATH_LEN;
        if over_limit {
            ui.colored_label(
                egui::Color32::from_rgb(0xC0, 0x30, 0x30),
                format!("Path may be too long (~{vpath_len} / {} bytes) — shorten the filename or subfolder.", crate::storage::MAX_PATH_LEN),
            );
        }
        if ui
            .add_enabled(
                !over_limit,
                egui::Button::new(egui::RichText::new("⬆ Attach").strong().color(egui::Color32::WHITE)).fill(accent),
            )
            .on_hover_text("Encrypt a copy of the file into the vault's document archive")
            .clicked()
        {
            req = DocSectionReq::Upload;
        }
    }
    });
    ui.add_space(4.0);
    req
}

/// Deferred linked-accounts action gathered while rendering the Assets form (see
/// [`linked_accounts_section`]). `Add`/`Open` carry an Account id; `Remove` carries the
/// index into the asset's `linked_accounts` list. Applied after the columns closure
/// like every other deferred request, so mutation/navigation stays outside the form
/// borrow. Not `Copy` (unlike [`DocSectionReq`]) — two variants own a `String`.
#[derive(PartialEq, Eq, Clone)]
enum LinkReq {
    None,
    Add(String),
    Remove(usize),
    Open(String),
}

/// Resolve an asset's linked-account ids to display rows `(id, resolved label)`. A
/// dangling id (the account was deleted — links are never cascaded) resolves to the
/// RAW id: tolerant and nothing hidden, per the additive/no-silent-loss policy.
fn linked_account_rows(accounts: &[Account], linked: &[String]) -> Vec<(String, String)> {
    linked
        .iter()
        .map(|id| (id.clone(), records::account_label(accounts, id).unwrap_or_else(|| id.clone())))
        .collect()
}

/// The accounts offered by the Assets form's "add link" dropdown: every account NOT
/// already linked (a second link to the same account would be meaningless).
fn link_candidates(accounts: &[Account], linked: &[String]) -> Vec<(String, String)> {
    accounts
        .iter()
        .filter(|a| !linked.iter().any(|id| id == &a.id))
        .map(|a| (a.id.clone(), a.label()))
        .collect()
}

/// The "Linked accounts" section of the Asset/Liability form (modeled on
/// [`doc_section`]): one row per link — Open always (navigation is a read, kept in
/// read-only mode), Unlink writable-only (it edits the record) — plus, when writable,
/// an "add link" dropdown over `candidates`. `linked` comes from
/// [`linked_account_rows`], `candidates` from [`link_candidates`]. The caller applies
/// the returned request after rendering, keeping `self` borrows disjoint.
fn linked_accounts_section(
    ui: &mut egui::Ui,
    linked: &[(String, String)],
    candidates: &[(String, String)],
    writable: bool,
) -> LinkReq {
    let mut req = LinkReq::None;
    let accent = ui_accent(ui);
    ui.add_space(4.0);
    card(ui, |ui| {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("🔗 Linked accounts").strong().color(accent));
        ui.label(egui::RichText::new("the logins that hold or service this").weak().small());
    });
    ui.add_space(6.0);
    if linked.is_empty() {
        ui.label(egui::RichText::new("No linked accounts.").weak().italics());
    }
    for (i, (id, label)) in linked.iter().enumerate() {
        egui::containers::Sides::new().shrink_left().show(
            ui,
            |ui| {
                ui.label(egui::RichText::new("🔑").color(accent));
                ui.add(egui::Label::new(label).truncate()).on_hover_text(label);
            },
            |ui| {
                if writable && ui.button("Unlink").on_hover_text("Remove this link (the account itself is untouched)").clicked() {
                    req = LinkReq::Remove(i);
                }
                if ui.button("Open").on_hover_text("Jump to this account on the Accounts tab").clicked() {
                    req = LinkReq::Open(id.clone());
                }
            },
        );
    }
    if writable {
        ui.add_space(4.0);
        // Hand-rolled (id, label) dropdown: the shared `combo`/`filter_combo` helpers
        // bind a &mut String VALUE from a String list, but a link stores the account's
        // ID while showing its LABEL — so there is no bound buffer; a click on an entry
        // just emits the Add request (nothing is "currently selected").
        egui::ComboBox::from_id_salt("asset_link_add").selected_text("➕ Link an account…").show_ui(ui, |ui| {
            if candidates.is_empty() {
                ui.label(egui::RichText::new("(no more accounts to link)").weak());
            }
            for (id, label) in candidates {
                if ui.selectable_label(false, label).clicked() {
                    req = LinkReq::Add(id.clone());
                }
            }
        });
    }
    });
    ui.add_space(4.0);
    req
}

/// A collapsing, timestamped history view for a record.
// `&[records::Change]` is a read-only slice of change entries.
fn history_view(ui: &mut egui::Ui, history: &[records::Change]) {
    ui.add_space(10.0);
    // The entry count sits in the header so it is visible without expanding —
    // "has this record ever been touched" is answerable at a glance.
    let title = if history.is_empty() {
        "🕘 History".to_string()
    } else {
        format!("🕘 History  ({} entr{})", history.len(), if history.len() == 1 { "y" } else { "ies" })
    };
    egui::CollapsingHeader::new(egui::RichText::new(title).strong()).default_open(false).show(ui, |ui| {
        if history.is_empty() {
            ui.label(egui::RichText::new("No changes recorded yet.").weak().italics());
        }
        egui::ScrollArea::vertical().max_height(180.0).id_salt("hist").show(ui, |ui| {
            // `.iter().rev()` walks the entries newest-first (reverse order).
            for c in history.iter().rev() {
                // `display_detail` masks password before/after values so the history
                // pane never leaks a cleartext password (it can't be copied from here
                // and the live field's reveal toggle deliberately does not extend here).
                let detail =
                    if c.detail.is_empty() { c.action.clone() } else { records::display_detail(&c.detail) };
                ui.horizontal_top(|ui| {
                    // A fixed-width monospace timestamp column makes the log scannable
                    // instead of a ragged run of prose.
                    ui.label(egui::RichText::new(format_time(c.at)).monospace().weak().small());
                    ui.label(egui::RichText::new(detail).small());
                });
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
fn secret_text_edit(
    ui: &mut egui::Ui,
    id_salt: &str,
    value: &mut String,
    revealed: bool,
    writable: bool,
    width: f32,
    copied_out: &mut Option<Zeroizing<String>>,
) -> egui::Response {
    let width = fit(ui, width);
    let id = ui.make_persistent_id(id_salt);
    // Read-only: bind a `&str` (immutable TextBuffer) so the field stays selectable and
    // copyable (incl. the hardened Ctrl+C reroute below) but cannot be edited; writable
    // binds the real `&mut String`.
    let resp = if writable {
        ui.add(egui::TextEdit::singleline(value).id(id).password(!revealed).desired_width(width))
    } else {
        let mut ro = value.as_str();
        ui.add(egui::TextEdit::singleline(&mut ro).id(id).password(!revealed).desired_width(width))
    };
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
        let mut copied: Vec<String> = ui.ctx().output_mut(|o| {
            // MOVE the secret out of each CopyText command (leaving an empty String) rather
            // than cloning it: a `retain` that cloned then returned false would DROP the
            // command's original String — the cleartext password egui staged for the
            // clipboard — without zeroizing it, stranding it in freed heap. mem::take leaves
            // an empty String behind, which the retain below then drops harmlessly.
            let mut taken = Vec::new();
            for c in o.commands.iter_mut() {
                if let egui::OutputCommand::CopyText(t) = c {
                    taken.push(std::mem::take(t));
                }
            }
            // Remove the (now-emptied) CopyText commands so eframe's plain set_text never runs.
            o.commands.retain(|c| !matches!(c, egui::OutputCommand::CopyText(_)));
            taken
        });
        // Surface the intercepted secret to the caller so it routes through the app's
        // `copy_to_clipboard`, which applies the hardened (history-excluded) copy AND
        // arms the 15s auto-clear + on-exit wipe. Doing the hardened copy directly here
        // (as before) skipped that arming, leaving a Ctrl+C/cut'd password on the
        // clipboard indefinitely (audit B-1). There is at most one focused field, so
        // at most one CopyText; take it and zeroize any stray extras.
        if let Some(t) = copied.pop() {
            *copied_out = Some(Zeroizing::new(t));
        }
        for mut leftover in copied {
            leftover.zeroize();
        }
    }
    resp
}

/// A masked single-line password field; returns true if Enter was pressed. `id_salt`
/// is unique per field (unlock/create/change-password use four distinct fields).
/// True if two `vault.pmv` paths refer to the same vault on disk (canonicalized when both
/// exist, else compared raw). Used to refuse "update from another vault" pointed at itself.
fn same_vault_path(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

fn password_field(
    ui: &mut egui::Ui,
    id_salt: &str,
    value: &mut String,
    copied_out: &mut Option<Zeroizing<String>>,
) -> bool {
    // Always masked (revealed = false); the secret hardening (undo scrub + copy
    // re-route) still applies — a master password is the most sensitive of all.
    // Always editable (`writable = true`): this is the unlock/create field, which
    // exists before any vault is open, so the read-only mode does not apply here.
    // `copied_out` surfaces a built-in Ctrl+C of the master password so the caller
    // arms the auto-clear (otherwise it would linger on the clipboard).
    let resp = secret_text_edit(ui, id_salt, value, false, true, 280.0, copied_out);
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

    #[test]
    fn stepped_list_index_clamps_and_seeds_from_empty_selection() {
        // From a known position, ±1 with clamped ends (no wrap).
        assert_eq!(stepped_list_index(Some(2), 1, 5), 3);
        assert_eq!(stepped_list_index(Some(2), -1, 5), 1);
        assert_eq!(stepped_list_index(Some(4), 1, 5), 4, "down at the bottom stays put");
        assert_eq!(stepped_list_index(Some(0), -1, 5), 0, "up at the top stays put");
        // With nothing selected, down seeds the top and up seeds the bottom.
        assert_eq!(stepped_list_index(None, 1, 5), 0);
        assert_eq!(stepped_list_index(None, -1, 5), 4);
        // Single-item list: both directions stay on the only row.
        assert_eq!(stepped_list_index(Some(0), 1, 1), 0);
        assert_eq!(stepped_list_index(None, -1, 1), 0);
    }

    #[test]
    fn error_banner_clears_when_a_later_status_replaces_the_failure() {
        // Nothing showing → never stale (the banner is hidden anyway).
        assert!(!error_banner_is_stale(None, ""));
        assert!(!error_banner_is_stale(None, "Saved."));
        // The failure is still current (the status line still holds it) → keep the banner.
        assert!(!error_banner_is_stale(Some("Save failed: disk full"), "Save failed: disk full"));
        // A later success/info line replaced the failure text → the banner is stale and the
        // core rule fires: a fixed problem must not leave a scary banner stuck on screen.
        assert!(error_banner_is_stale(Some("Save failed: disk full"), "Saved."));
        assert!(error_banner_is_stale(Some("Upload failed: bad path"), ""));
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

    /// Lay out every tab in a real egui — with and without a record selected — so a
    /// layout fault in the shared chrome (the cards, the right-aligned action rows,
    /// the stat tiles, the empty-state pane) fails here rather than in front of the
    /// user. Nested layouts and duplicate widget ids only misbehave once something
    /// actually measures them.
    /// Lay the real window out across a fine sweep of widths, including sizes well
    /// below the 720 px minimum, and require that it SETTLES and that the per-tab
    /// controls survive the squeeze.
    ///
    /// Two things this pins down:
    /// - **Settling.** `try_run` drives frames until egui stops asking to repaint. A
    ///   layout that cannot decide whether it needs a scrollbar never stops asking.
    ///   (This is a necessary condition, not a sufficient one — a headless harness does
    ///   not reproduce every real-window oscillation — so it is a guard, not a proof.)
    /// - **Reachability.** "⬇ CSV" must still be present at every width on every tab
    ///   that has a CSV form. It once sat in a right-aligned group where a narrow pane
    ///   pushed it against the divider; Summary is the sole tab with no CSV, because it
    ///   is a calculated view with no `csv::CsvTab` of its own.
    #[test]
    fn window_settles_and_keeps_its_controls_at_every_width() {
        use egui_kittest::{kittest::Queryable, Harness};

        let mut w = 480.0f32;
        while w <= 1040.0 {
            for tab in [Tab::Accounts, Tab::Assets, Tab::RealEstate, Tab::Taxes, Tab::Summary] {
                let (mut app, path) = app_unlocked("settle");
                // Enough rows, and long enough labels, that a small window genuinely
                // overflows — the condition under which scroll geometry gets decided.
                {
                    let ov = app.vault.as_mut().unwrap();
                    for i in 0..40 {
                        let mut a = Account::new().unwrap();
                        a.title = format!("A rather long account title number {i}");
                        a.owner = "Jane Q. Longname".into();
                        ov.vault.accounts.push(a);
                    }
                }
                app.tab = tab;
                app.edit_account = Account::new().ok();
                app.edit_asset = AssetLiability::new().ok();
                app.edit_realestate = RealEstate::new().ok();
                app.edit_taxfiling = TaxFiling::new().ok();
                app.status = "Exported 3 record(s) to /a/deliberately/long/export/path/file.csv".into();
                let app = std::cell::RefCell::new(app);

                let mut h = Harness::builder()
                    .with_size(egui::vec2(w, 420.0))
                    .with_max_steps(64)
                    .build_ui(|ui| app.borrow_mut().render(ui));
                h.try_run().unwrap_or_else(|e| panic!("window never settled at {w}x420 on {tab:?}: {e}"));

                if tab != Tab::Summary {
                    assert_eq!(
                        h.query_all_by_label("⬇ CSV").count(),
                        1,
                        "the CSV export button must stay reachable at {w}x420 on {tab:?}"
                    );
                }
                cleanup(&path);
            }
            w += 16.0;
        }
    }

    /// The read-only line-breaker, driven by a fake measurer (1 unit per character) so
    /// the breaking logic is pinned without a font.
    #[test]
    fn wrap_hyphenated_breaks_words_with_a_dash_and_always_progresses() {
        let w = |s: &str| s.chars().count() as f32;

        // Fits: untouched.
        assert_eq!(wrap_hyphenated("hello there", 20.0, w), "hello there");

        // Word boundary preferred over splitting — no dash appears.
        assert_eq!(wrap_hyphenated("hello there", 6.0, w), "hello\nthere");

        // A word too long for the line is split WITH a trailing dash, and every
        // fragment respects the width (the dash is part of the measured line).
        let out = wrap_hyphenated("supercalifragilistic", 8.0, w);
        assert!(out.contains('-'), "an over-long word must break with a dash: {out:?}");
        for line in out.lines() {
            assert!(w(line) <= 8.0, "line {line:?} exceeds the width in {out:?}");
        }
        // Nothing is lost or invented: dropping the added dashes and newlines
        // reconstitutes the original word.
        assert_eq!(out.replace("-\n", ""), "supercalifragilistic");

        // Existing newlines stay hard breaks.
        assert_eq!(wrap_hyphenated("a\nb", 40.0, w), "a\nb");

        // Pathological widths must terminate rather than spin: one character cannot
        // fit alongside a dash at width 1, and the loop still has to make progress.
        let tiny = wrap_hyphenated("abcd", 1.0, w);
        assert_eq!(tiny.replace("-\n", ""), "abcd");
        // A nonsense width is handed back untouched instead of exploding.
        assert_eq!(wrap_hyphenated("abcd", 0.0, w), "abcd");

        // Multi-byte text must split on character boundaries, not bytes (a byte-index
        // split would panic).
        let uni = wrap_hyphenated("ααααααααββββββββ", 5.0, w);
        assert_eq!(uni.replace("-\n", ""), "ααααααααββββββββ");
    }

    /// A read-only value must occupy the width of its TEXT, not the width of the pane.
    /// It used to render as a disabled text box, so a one-word owner name took as much
    /// room as a full address and the form read as a column of empty boxes.
    #[test]
    fn read_only_values_are_not_stretched_to_the_pane_in_real_egui() {
        use egui_kittest::{kittest::NodeT as _, Harness};

        let width_of = |writable: bool| -> f32 {
            let path = tmp("rowidth");
            let ov = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            let mut app = GuiApp::new(path.clone(), writable);
            app.vault = Some(ov);
            app.screen = Screen::Main;
            app.tab = Tab::RealEstate;
            let mut r = RealEstate::new().unwrap();
            r.owner = "Jane".into();
            app.edit_realestate = Some(r);
            let app = std::cell::RefCell::new(app);
            let mut h = Harness::builder()
                .with_size(egui::vec2(1000.0, 680.0))
                .build_ui(|ui| app.borrow_mut().render(ui));
            h.run();
            let w = h
                .root()
                .children_recursive()
                .filter(|n| n.value().as_deref() == Some("Jane"))
                .filter_map(|n| n.accesskit_node().bounding_box().map(|b| b.width() as f32))
                .fold(0.0_f32, f32::max);
            cleanup(&path);
            w
        };

        let ro = width_of(false);
        assert!(ro > 0.0, "the read-only value must render at all");
        assert!(
            ro < 120.0,
            "a four-letter read-only value should take the width of its text, not the pane (got {ro})"
        );
        // Write mode still uses a real edit box, which is meant to be a uniform target.
        assert!(width_of(true) > 200.0, "editable fields keep their designed width");
    }

    #[test]
    fn every_tab_renders_in_real_egui() {
        use egui_kittest::Harness;

        let (app, path) = app_unlocked("tabrender");
        let app = std::cell::RefCell::new(app);
        let tabs = [
            Tab::Urgent,
            Tab::Instructions,
            Tab::TrustWill,
            Tab::Assets,
            Tab::Accounts,
            Tab::RealEstate,
            Tab::Taxes,
            Tab::GeneralDocuments,
            Tab::Summary,
        ];
        // `selected == true` starts a blank record on the tab first, which is what
        // brings the form, its document/link/portal cards, and the history view into
        // the frame; `false` exercises the empty-state pane.
        for selected in [false, true] {
            for tab in tabs {
                {
                    let mut a = app.borrow_mut();
                    a.tab = tab;
                    if selected {
                        // Seed the tab's edit buffer directly (the same thing its "New"
                        // button does) so the form half of the split renders.
                        match tab {
                            Tab::Urgent => a.edit_urgent = Urgent::new().ok(),
                            Tab::Instructions => a.edit_instruction = Instruction::new().ok(),
                            Tab::TrustWill => a.edit_trustwill = TrustWill::new().ok(),
                            Tab::Assets => a.edit_asset = AssetLiability::new().ok(),
                            Tab::Accounts => a.edit_account = Account::new().ok(),
                            Tab::RealEstate => a.edit_realestate = RealEstate::new().ok(),
                            Tab::Taxes => a.edit_taxfiling = TaxFiling::new().ok(),
                            Tab::GeneralDocuments => a.edit_general = GeneralDocument::new().ok(),
                            Tab::Summary => {} // a calculated view — no edit buffer
                        }
                    }
                }
                let mut h = Harness::new_ui(|ui| {
                    let mut a = app.borrow_mut();
                    a.ui_top_bar(ui);
                    let tab = a.tab;
                    match tab {
                        Tab::Urgent => a.tab_urgent(ui),
                        Tab::Instructions => a.tab_instructions(ui),
                        Tab::TrustWill => a.tab_trustwill(ui),
                        Tab::Assets => a.tab_assets(ui),
                        Tab::Accounts => a.tab_accounts(ui),
                        Tab::RealEstate => a.tab_realestate(ui),
                        Tab::Taxes => a.tab_taxes(ui),
                        Tab::GeneralDocuments => a.tab_general(ui),
                        Tab::Summary => a.tab_summary(ui),
                    }
                });
                h.run();
            }
        }
        // The Config and Help screens go through the same treatment.
        let mut h = Harness::new_ui(|ui| app.borrow_mut().ui_config(ui));
        h.run();
        let mut h = Harness::new_ui(|ui| app.borrow_mut().ui_help(ui));
        h.run();
        cleanup(&path);
    }

    #[test]
    fn start_page_prefills_vault_dir_and_switches_mode_with_directory() {
        // The start page pre-fills the vault directory (the default/launch dir) and flips
        // Unlock<->Create as the directory changes; in --write mode an empty dir creates.
        let base = std::env::temp_dir().join(format!("passmgr-gui-startdir-{}", nanos()));
        std::fs::create_dir_all(&base).unwrap();

        // Launched at a non-existent path -> Create, and vault_dir is pre-filled with the dir.
        let start = base.join("fresh").join("vault.pmv");
        let mut app = GuiApp::new(start.clone(), true);
        assert_eq!(app.auth_mode, AuthMode::Create, "no vault yet -> Create");
        assert_eq!(app.vault_dir, base.join("fresh").display().to_string(), "dir pre-filled");

        // Collapsed model: root pre-filled with the launch dir's parent, name = its folder.
        assert_eq!(app.vault_root, base.display().to_string(), "root = parent of launch dir");
        assert_eq!(app.vault_name, "fresh", "name = launch dir's folder");

        // Type a brand-new vault name to create it under the root.
        app.vault_name = "brandnew".into();
        app.recompute_vault_path();
        let fresh = base.join("brandnew");
        assert_eq!(app.vault_dir, fresh.display().to_string(), "dir = root/name");
        assert_eq!(app.auth_mode, AuthMode::Create, "no vault there -> Create");
        app.pw1 = "a".into();
        app.confirm1 = "a".into();
        app.pw2 = "b".into();
        app.confirm2 = "b".into();
        app.submit_auth();
        assert!(app.vault.is_some(), "vault created in the new dir; status: {}", app.status);
        assert!(fresh.join("vault.pmv").exists(), "vault.pmv created on disk");

        // A new app pointed at that now-existing dir resolves to Unlock.
        let app2 = GuiApp::new(fresh.join("vault.pmv"), true);
        assert_eq!(app2.auth_mode, AuthMode::Unlock, "existing vault -> Unlock");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn start_page_read_only_cannot_create_in_empty_dir() {
        // Pointing read-only mode at a directory with no vault: Create mode is shown, but
        // submit refuses (you can't create a vault read-only) — the field stays usable so
        // an heir can still point at a real vault to READ.
        let base = std::env::temp_dir().join(format!("passmgr-gui-rodir-{}", nanos()));
        std::fs::create_dir_all(&base).unwrap();
        let mut app = GuiApp::new(base.join("empty").join("vault.pmv"), false); // read-only
        assert_eq!(app.auth_mode, AuthMode::Create);
        app.pw1 = "a".into();
        app.confirm1 = "a".into();
        app.pw2 = "b".into();
        app.confirm2 = "b".into();
        app.submit_auth();
        assert!(app.vault.is_none(), "read-only must not create a vault");
        assert!(
            app.auth_error.as_deref().unwrap_or("").contains("--write"),
            "error explains --write is needed; got {:?}",
            app.auth_error
        );
        std::fs::remove_dir_all(&base).ok();
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
    fn export_current_tab_csv_writes_accounts_file_in_gui() {
        let (mut app, path) = app_unlocked("guicsv");
        let outdir = path.parent().unwrap().join("guicsv-out");
        {
            let ov = app.vault.as_mut().unwrap();
            let mut a = Account::new().unwrap();
            a.title = "Bank".into();
            a.owner = "Jane".into();
            a.password = "hunter2".into();
            records::upsert(&mut ov.vault.accounts, a);
        }
        app.tab = Tab::Accounts;
        app.export_dir = outdir.to_string_lossy().into();
        app.export_current_tab_csv();
        assert!(app.status.starts_with("Exported 1 record"), "status: {}", app.status);
        let entry = std::fs::read_dir(&outdir).unwrap().next().unwrap().unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(name.starts_with("accounts-") && name.ends_with(".csv"), "timestamped name: {name}");
        let body = std::fs::read_to_string(entry.path()).unwrap();
        assert!(body.contains("hunter2"), "password exported in plaintext (user opted in)");
        assert!(body.contains("Bank"));
        cleanup(&path);
    }

    #[test]
    fn export_current_tab_csv_works_in_read_only_mode_in_gui() {
        // CSV export is deliberately available to a READ-ONLY session (the vault owner
        // asked for it). The file is unencrypted and may hold plaintext passwords, so the
        // status line has to say so rather than report a bare success.
        let (mut app, path) = app_unlocked("guicsvro");
        let outdir = path.parent().unwrap().join("guicsvro-out");
        {
            let ov = app.vault.as_mut().unwrap();
            let mut a = Account::new().unwrap();
            a.title = "Bank".into();
            a.owner = "Jane".into();
            a.password = "hunter2".into();
            records::upsert(&mut ov.vault.accounts, a);
        }
        app.tab = Tab::Accounts;
        app.export_dir = outdir.to_string_lossy().into();
        app.writable = false; // a read-only session
        app.export_current_tab_csv();
        assert!(app.status.starts_with("Exported"), "export ran read-only: {}", app.status);
        assert!(
            app.status.contains("UNENCRYPTED"),
            "the plaintext warning must ride along with the success: {}",
            app.status
        );
        assert!(app.error.is_none(), "a successful export raises no failure banner");
        let written: Vec<_> = std::fs::read_dir(&outdir).unwrap().filter_map(Result::ok).collect();
        assert_eq!(written.len(), 1, "one CSV written");
        let body = std::fs::read_to_string(written[0].path()).unwrap();
        assert!(body.contains("hunter2"), "the CSV carries the plaintext password it warns about");
        cleanup(&path);
    }

    /// The button itself must be present in a read-only session, on both the flat list
    /// and the grouped tree — the export is useless if it cannot be reached.
    #[test]
    fn csv_button_is_offered_in_read_only_mode_in_real_egui() {
        use egui_kittest::{kittest::Queryable, Harness};

        for grouped in [false, true] {
            let path = tmp("rocsvbtn");
            let ov = OpenVault::create(path.clone(), b"a", b"b", fast()).unwrap();
            let mut app = GuiApp::new(path.clone(), false); // read-only
            app.vault = Some(ov);
            app.screen = Screen::Main;
            app.tab = Tab::Accounts;
            app.acct_grouped = grouped;
            let app = std::cell::RefCell::new(app);
            let mut h = Harness::builder()
                .with_size(egui::vec2(1000.0, 680.0))
                .build_ui(|ui| app.borrow_mut().render(ui));
            h.run();
            assert_eq!(
                h.query_all_by_label("⬇ CSV").count(),
                1,
                "CSV must be reachable read-only (grouped={grouped})"
            );
            // "New" stays hidden: creating records is still a write.
            assert_eq!(h.query_all_by_label("➕ New").count(), 0, "New stays write-only");
            cleanup(&path);
        }
    }

    #[test]
    fn trim_all_records_bulk_trims_every_tab_and_reports_in_gui() {
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
            // A dirty record on ANOTHER tab must also be trimmed (whole-vault sweep).
            let mut re = RealEstate::new().unwrap();
            re.address = "  1 Main St  ".into();
            re.property_mgmt_password = "  portalpw  ".into();
            records::upsert(&mut ov.vault.real_estate, re);
            let mut tax = TaxFiling::new().unwrap();
            tax.year = " 2024 ".into();
            records::upsert(&mut ov.vault.tax_filings, tax);
        }
        let n = app.trim_all_records();
        assert_eq!(n, 3, "the dirty account + real-estate + tax records are all counted");
        let a = &app.vault.as_ref().unwrap().vault.accounts[0];
        assert_eq!(a.owner, "Alice");
        assert_eq!(a.title, "Brokerage");
        assert_eq!(a.password, "s3cret", "the password is trimmed too (configured policy)");
        let re = &app.vault.as_ref().unwrap().vault.real_estate[0];
        assert_eq!(re.address, "1 Main St");
        assert_eq!(re.property_mgmt_password, "portalpw", "portal passwords are trimmed too");
        assert_eq!(app.vault.as_ref().unwrap().vault.tax_filings[0].year, "2024");
        assert!(app.status.contains("Trimmed 3"), "status: {}", app.status);
        // Idempotent.
        assert_eq!(app.trim_all_records(), 0);
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
        // Uniform layout: /general-documents/<title>/<subfolder>/<ts>_<filename>.
        let vpath = app.vault.as_ref().unwrap().doc_path(&id).unwrap();
        assert!(vpath.trim_start_matches('/').starts_with("general-documents/passport/ids/"), "got {vpath}");
        assert!(vpath.ends_with("_p.pdf"), "ts-prefixed filename, got {vpath}");

        // Export goes to the configured export dir, recreating the volume folder structure.
        let export_root = dir.join("exports");
        app.export_dir = export_root.to_string_lossy().into();
        app.handle_doc(DocReq::Export, DocTarget::General);
        let exported = export_root.join(vpath.trim_start_matches('/'));
        assert_eq!(
            std::fs::read(&exported).unwrap(),
            b"passport",
            "export recreates the volume structure under the config dir (status: {})",
            app.status
        );

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

        // --- export (into the configured export dir, structure preserved) ---
        let export_root = dir.join("exports");
        app.export_dir = export_root.to_string_lossy().into();
        let re_id = app.edit_realestate.as_ref().unwrap().documents[0].clone();
        let vpath = app.vault.as_ref().unwrap().doc_path(&re_id).unwrap();
        app.handle_re_doc(ReDocReq::Export(0));
        let exported = export_root.join(vpath.trim_start_matches('/'));
        assert_eq!(std::fs::read(&exported).unwrap(), b"the deed", "export recreates structure (status: {})", app.status);

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

        let export_root = dir.join("exports");
        app.export_dir = export_root.to_string_lossy().into();
        let tax_id = app.edit_taxfiling.as_ref().unwrap().documents[0].clone();
        let vpath = app.vault.as_ref().unwrap().doc_path(&tax_id).unwrap();
        app.handle_tax_doc(TaxDocReq::Export(0));
        let exported = export_root.join(vpath.trim_start_matches('/'));
        assert_eq!(std::fs::read(&exported).unwrap(), b"taxable income", "export recreates structure (status: {})", app.status);

        app.handle_tax_doc(TaxDocReq::Remove(0));
        assert!(app.edit_taxfiling.as_ref().unwrap().documents.is_empty(), "removed the doc");
        assert!(app.vault.as_ref().unwrap().vault.tax_filings[0].documents.is_empty(), "unlinked");
        cleanup(&path);
    }

    #[test]
    fn upload_with_empty_filename_uses_source_basename_in_gui() {
        // "If a filename isn't specified, use the same filename as the uploaded file."
        let (mut app, path) = app_unlocked("guinofname");
        let dir = path.parent().unwrap().to_path_buf();
        app.edit_general = Some(GeneralDocument::new().unwrap());
        let src = dir.join("MyDeed.PDF");
        std::fs::write(&src, b"x").unwrap();
        app.doc_filename = String::new(); // no filename given
        app.doc_source = src.to_string_lossy().into();
        app.handle_doc(DocReq::Attach, DocTarget::General);
        let id = app.edit_general.as_ref().unwrap().file.clone().expect("uploaded (status: ");
        let vpath = app.vault.as_ref().unwrap().doc_path(&id).unwrap();
        assert!(vpath.ends_with("_MyDeed.PDF"), "empty filename falls back to the source basename: {vpath}");
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
        std::fs::write(&p, vec![b'{'; (crate::MAX_PREFS_SIZE as usize) + 1]).unwrap();
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
    fn urgent_tab_is_the_default_and_delete_removes_the_note() {
        let (mut app, path) = app_unlocked("urgent");
        // URGENT is the first/default tab.
        assert!(matches!(app.tab, Tab::Urgent));
        // Seed an urgent note, load it into the editor, and delete it via the tab arm.
        let id = {
            let ov = app.vault.as_mut().unwrap();
            let mut u = Urgent::new().unwrap();
            u.title = "Hospital".into();
            u.description = "Contact Dr. Smith".into();
            let id = u.id.clone();
            records::upsert(&mut ov.vault.urgent, u.clone());
            app.edit_urgent = Some(u);
            id
        };
        assert_eq!(app.vault.as_ref().unwrap().vault.urgent.len(), 1);
        app.delete_current(Tab::Urgent);
        assert!(app.vault.as_ref().unwrap().vault.urgent.is_empty(), "note deleted");
        assert!(app.edit_urgent.is_none(), "editor cleared");
        assert!(!id.is_empty());
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

        let mut asset = AssetLiability::new().unwrap();
        asset.owner = "Jane Doe".into(); // owner + numeric value are now required before attach
        asset.approx_value = "1000".into();
        app.edit_asset = Some(asset);
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
    fn attach_accepts_a_double_quoted_upload_from_path() {
        // A path pasted with surrounding double quotes ("Copy as path") uploads the same
        // file as the unquoted path — the quotes are stripped, not treated as part of the name.
        let (mut app, path) = app_unlocked("docq");
        let src = std::env::temp_dir().join(format!("passmgr-guiq-{}.txt", nanos()));
        std::fs::write(&src, b"quoted body").unwrap();

        let mut asset = AssetLiability::new().unwrap();
        asset.owner = "Jane Doe".into();
        asset.approx_value = "1000".into();
        app.edit_asset = Some(asset);
        app.doc_subfolder = "wills".into();
        // No explicit filename → it must default to the (quoted) source's basename.
        app.doc_source = format!("\"{}\"", src.display()); // wrap the path in double quotes
        app.handle_doc(DocReq::Attach, DocTarget::Asset);

        let id = app.edit_asset.as_ref().unwrap().statement.clone();
        assert!(id.is_some(), "quoted upload path was accepted and the doc attached");
        let ov = app.vault.as_ref().unwrap();
        let id = id.unwrap();
        assert_eq!(&ov.read_document(&id).unwrap()[..], b"quoted body");
        // The stored virtual path ends with the real filename, not a quote-mangled one.
        let vpath = ov.doc_path(&id).unwrap_or_default();
        let stem = src.file_stem().unwrap().to_string_lossy();
        assert!(vpath.contains(&*stem) && !vpath.contains('"'), "clean filename in {vpath}");

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
        let mut asset = AssetLiability::new().unwrap();
        asset.owner = "Jane Doe".into(); // owner + numeric value are now required before attach
        asset.approx_value = "1000".into();
        app.edit_asset = Some(asset);
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
    fn handle_link_req_adds_and_removes_links_in_edit_buffer_only() {
        let (mut app, path) = app_unlocked("guilinkreq");
        let acct_id = {
            let ov = app.vault.as_mut().unwrap();
            let mut a = Account::new().unwrap();
            a.title = "Brokerage".into();
            a.owner = "Jane".into();
            let id = a.id.clone();
            records::upsert(&mut ov.vault.accounts, a);
            id
        };
        let mut asset = AssetLiability::new().unwrap();
        asset.owner = "Jane".into();
        asset.approx_value = "10".into();
        app.edit_asset = Some(asset);

        // Add appends to the WORKING BUFFER; a duplicate request is dropped (the
        // dropdown never offers one, but the deferred handler re-checks anyway).
        app.handle_link_req(LinkReq::Add(acct_id.clone()));
        app.handle_link_req(LinkReq::Add(acct_id.clone()));
        assert_eq!(app.edit_asset.as_ref().unwrap().linked_accounts, vec![acct_id.clone()]);
        assert!(
            app.vault.as_ref().unwrap().vault.assets.is_empty(),
            "no direct vault write — the link persists through the ordinary Save path"
        );
        // An out-of-range Remove (stale index) is dropped, not a panic; in-range unlinks.
        app.handle_link_req(LinkReq::Remove(5));
        assert_eq!(app.edit_asset.as_ref().unwrap().linked_accounts.len(), 1);
        app.handle_link_req(LinkReq::Remove(0));
        assert!(app.edit_asset.as_ref().unwrap().linked_accounts.is_empty(), "unlinked");
        cleanup(&path);
    }

    #[test]
    fn confirm_pending_account_delete_only_fires_when_the_armed_id_still_matches() {
        let (mut app, path) = app_unlocked("guiconfirmrace");
        let (x_id, y_id) = {
            let ov = app.vault.as_mut().unwrap();
            let mut x = Account::new().unwrap();
            x.title = "Linked".into();
            let mut y = Account::new().unwrap();
            y.title = "Neighbor".into();
            let ids = (x.id.clone(), y.id.clone());
            records::upsert(&mut ov.vault.accounts, x);
            records::upsert(&mut ov.vault.accounts, y);
            ids
        };

        // The raced-confirm shape: the same-frame select handler swapped the
        // editor to the NEIGHBOR and disarmed pending before the captured click
        // is applied. The stale confirm must delete nothing.
        app.edit_account =
            app.vault.as_ref().unwrap().vault.accounts.iter().find(|a| a.id == y_id).cloned();
        app.pending_account_delete = None;
        app.confirm_pending_account_delete();
        assert_eq!(app.vault.as_ref().unwrap().vault.accounts.len(), 2, "raced confirm dropped");

        // Belt-and-braces: an armed id that no longer matches the loaded record
        // (any other way the two could diverge) is also dropped — and disarmed.
        app.pending_account_delete = Some(x_id.clone());
        app.confirm_pending_account_delete();
        assert_eq!(app.vault.as_ref().unwrap().vault.accounts.len(), 2, "mismatched confirm dropped");
        assert!(app.pending_account_delete.is_none(), "always disarmed");

        // The legitimate path: armed id matches the loaded record -> deletes it.
        app.edit_account =
            app.vault.as_ref().unwrap().vault.accounts.iter().find(|a| a.id == x_id).cloned();
        app.pending_account_delete = Some(x_id.clone());
        app.confirm_pending_account_delete();
        let accounts = &app.vault.as_ref().unwrap().vault.accounts;
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].id, y_id, "exactly the armed record was deleted");
        cleanup(&path);
    }

    #[test]
    fn opening_a_vault_clears_prior_per_vault_ui_state() {
        // Audit 2026-07-03 A-8: a fresh open must not inherit the previous session's edit
        // buffers (which can hold cleartext secrets), armed delete, active filters/search, or
        // reveal toggles — otherwise an error path that drops to the unlock screen without going
        // through the constructor leaks vault A's state into vault B.
        let (mut app, path) = app_unlocked("resetui");
        // Dirty a spread of per-vault state as a prior session would leave it.
        let mut a = Account::new().unwrap();
        a.password = "leaky-secret".into();
        app.edit_account = Some(a);
        app.pending_account_delete = Some("armed-id".into());
        app.acct_filter_owner = "Alice".into();
        app.acct_search_user = "bob".into();
        app.reveal_all = true;
        app.tab = Tab::Accounts;

        app.reset_per_vault_ui_state();

        assert!(app.edit_account.is_none(), "edit buffer cleared (its secret is wiped on drop)");
        assert!(app.pending_account_delete.is_none(), "armed delete disarmed");
        assert!(app.acct_filter_owner.is_empty(), "filters cleared");
        assert!(app.acct_search_user.is_empty(), "search cleared");
        assert_eq!(app.reveal_all, app.reveal_default, "reveal back to the saved default");
        assert!(matches!(app.tab, Tab::Urgent), "tab back to the first (URGENT)");
        cleanup(&path);
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn delete_rollback_restores_the_saved_record_not_the_dirty_edit_buffer() {
        // Audit 2026-07-03 A-6: on a failed-persist rollback the vault must be restored to the
        // record's LAST-SAVED state, never the (possibly edited) edit buffer — otherwise a delete
        // the user was told FAILED would silently commit the buffer's unsaved edits on a later save.
        let (mut app, path) = app_unlocked("delrollback");
        let id = {
            let ov = app.vault.as_mut().unwrap();
            let mut a = Account::new().unwrap();
            a.title = "Bank".into();
            a.password = "saved-pw".into();
            let id = a.id.clone();
            records::upsert(&mut ov.vault.accounts, a);
            ov.save().unwrap();
            id
        };
        // Load into the editor, then make an UNSAVED edit to the buffer.
        app.edit_account = app.vault.as_ref().unwrap().vault.accounts.iter().find(|a| a.id == id).cloned();
        app.edit_account.as_mut().unwrap().password = "unsaved-pw".into();
        // Delete with the vault save forced to fail (full disk).
        crate::fault::fail_at("vault.write", 1);
        app.delete_current(Tab::Accounts);
        crate::fault::clear();
        assert!(app.status.contains("Save failed"), "status: {}", app.status);
        // The record is back (rollback fired) with the SAVED password — the unsaved edit is gone.
        let accounts = &app.vault.as_ref().unwrap().vault.accounts;
        assert_eq!(accounts.len(), 1, "record restored by rollback");
        assert_eq!(accounts[0].password, "saved-pw", "restored the SAVED state, not the dirty buffer");
        cleanup(&path);
    }

    #[test]
    fn open_linked_account_jumps_with_tab_switch_resets_and_filter_follow() {
        let (mut app, path) = app_unlocked("guilinkjump");
        let mut a = Account::new().unwrap();
        a.title = "Brokerage".into();
        a.owner = "Jane".into();
        a.account_type = "Financial".into();
        let acct_id = a.id.clone();
        records::upsert(&mut app.vault.as_mut().unwrap().vault.accounts, a);

        app.tab = Tab::Assets;
        app.reveal_default = false;
        app.reveal_all = true; // momentary reveal left on — must not leak into Accounts
        app.doc_filename = "half-typed.pdf".into(); // shared doc buffer — must not linger
        app.acct_filter_type = "Email".into(); // active filter that would hide the target
        app.acct_filter_review = true; // review-only would hide the (unflagged) target
        app.open_linked_account(&acct_id);
        assert!(app.tab == Tab::Accounts, "navigated to the Accounts tab");
        assert_eq!(app.edit_account.as_ref().unwrap().id, acct_id, "target loaded in the editor");
        assert!(!app.reveal_all, "programmatic switch performs ui_top_bar's reveal reset");
        assert!(app.doc_filename.is_empty(), "doc inputs cleared like a real tab switch");
        assert_eq!(app.acct_filter_type, "Financial", "active filter retargeted to the record");
        assert!(!app.acct_filter_review, "review-only relaxed so the target is visible");

        // A dangling link: a status message, and NO navigation.
        app.tab = Tab::Assets;
        app.open_linked_account("gone");
        assert!(app.tab == Tab::Assets, "no navigation for a dangling link");
        assert!(app.status.contains("not found"), "status: {}", app.status);
        cleanup(&path);
    }

    #[test]
    fn open_linking_asset_jumps_back_and_clears_hiding_review_filter() {
        let (mut app, path) = app_unlocked("guilinkback");
        let mut asset = AssetLiability::new().unwrap();
        asset.owner = "Jane".into();
        asset.approx_value = "10".into();
        let asset_id = asset.id.clone();
        records::upsert(&mut app.vault.as_mut().unwrap().vault.assets, asset);

        app.tab = Tab::Accounts;
        app.reveal_default = false;
        app.reveal_all = true;
        app.asset_filter_review = true; // would hide the (unflagged) jump target
        app.open_linking_asset(&asset_id);
        assert!(app.tab == Tab::Assets, "navigated back to the Assets tab");
        assert_eq!(app.edit_asset.as_ref().unwrap().id, asset_id, "target loaded in the editor");
        assert!(!app.reveal_all, "programmatic switch re-masks to the saved default");
        assert!(!app.asset_filter_review, "review-only cleared so the target is visible");
        cleanup(&path);
    }

    #[test]
    fn account_delete_link_warning_states_count_and_consequence() {
        assert_eq!(account_delete_link_warning(0), None, "unlinked accounts delete unwarned, as before");
        let msg = account_delete_link_warning(3).unwrap();
        assert!(msg.contains("linked from 3 asset/liability record(s)"), "count stated: {msg}");
        assert!(msg.contains("unresolved ids"), "consequence stated (links kept, no cascade): {msg}");
    }

    #[test]
    fn linked_account_rows_resolve_labels_and_render_dangling_raw_ids() {
        let mut a = Account::new().unwrap();
        a.title = "Brokerage".into();
        a.account_type = "Financial".into();
        a.username = "jane".into();
        let accounts = vec![a.clone()];
        let rows = linked_account_rows(&accounts, &[a.id.clone(), "gone".into()]);
        assert_eq!(rows[0], (a.id.clone(), a.label()), "live link resolves to the display label");
        assert_eq!(
            rows[1],
            ("gone".to_string(), "gone".to_string()),
            "dangling link renders the RAW id — tolerant, nothing hidden"
        );
        // The add-dropdown offers only the not-yet-linked accounts.
        assert!(link_candidates(&accounts, &[a.id.clone()]).is_empty(), "already linked → not offered");
        assert_eq!(link_candidates(&accounts, &[]).len(), 1, "unlinked account is offered");
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

    #[test]
    fn merge_preview_then_apply_updates_vault_and_copies_blob() {
        use crate::records;
        // SOURCE vault in its own dir, with a newer shared account + a doc-bearing record.
        let s_path = tmp("merge-gui-src");
        let s_dir = s_path.parent().unwrap().to_path_buf();
        let blob_id;
        {
            let mut s = OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
            let mut a = records::Account::new().unwrap();
            a.id = "shared".into();
            a.title = "Shared".into();
            a.owner = "o".into();
            a.account_type = "Checking".into();
            a.username = "alice".into();
            a.password = "NEWPW".into();
            a.updated_at = 2_000;
            s.vault.accounts.push(a);
            let f = std::env::temp_dir().join(format!("pmgui-doc-{}.txt", nanos()));
            std::fs::write(&f, b"deed-bytes").unwrap();
            blob_id = s.add_document("general-documents/deed", "deed.pdf", &f).unwrap();
            let mut gd = records::GeneralDocument::new().unwrap();
            gd.id = "gd-1".into();
            gd.title = "Deed".into();
            gd.file = Some(blob_id.clone());
            gd.updated_at = 3_000;
            s.vault.general_documents.push(gd);
            s.save().unwrap();
        }

        // CURRENT vault (writable, open) with an OLDER version of the shared account.
        let (mut app, c_path) = app_unlocked("merge-gui-cur");
        {
            let cur = app.vault.as_mut().unwrap();
            let mut a = records::Account::new().unwrap();
            a.id = "shared".into();
            a.title = "Shared".into();
            a.owner = "o".into();
            a.account_type = "Checking".into();
            a.username = "alice".into();
            a.password = "OLDPW".into();
            a.updated_at = 1_000;
            cur.vault.accounts.push(a);
            cur.save().unwrap();
        }

        // PREVIEW: enter the source folder + its passwords.
        app.merge_src_dir = s_dir.display().to_string();
        app.merge_pw1 = "s1".into();
        app.merge_pw2 = "s2".into();
        app.merge_preview();
        assert!(app.merge_error.is_none(), "preview error: {:?}", app.merge_error);
        let plan = app.merge_plan.as_ref().expect("a plan was built");
        assert_eq!(plan.updated_count(), 1, "shared account is newer in source");
        assert_eq!(plan.new_count(), 1, "the general document is new");
        assert_eq!(plan.blobs_to_copy(), 1);
        // Passwords were wiped after a successful preview.
        assert!(app.merge_pw1.is_empty() && app.merge_pw2.is_empty());

        // APPLY.
        app.merge_apply();
        assert!(app.merge_plan.is_none(), "merge state cleared after apply");
        assert_eq!(app.screen, Screen::Config);
        assert!(app.status.contains("Updated from another vault"), "status: {}", app.status);
        let cur = app.vault.as_ref().unwrap();
        assert_eq!(cur.vault.accounts.iter().find(|a| a.id == "shared").unwrap().password, "NEWPW");
        assert_eq!(&**cur.read_document(&blob_id).unwrap(), b"deed-bytes");

        cleanup(&s_path);
        cleanup(&c_path);
    }

    #[test]
    fn merge_preview_wrong_password_gives_generic_error() {
        let s_path = tmp("merge-gui-badpw-src");
        let s_dir = s_path.parent().unwrap().to_path_buf();
        {
            OpenVault::create(s_path.clone(), b"s1", b"s2", fast()).unwrap();
        }
        let (mut app, c_path) = app_unlocked("merge-gui-badpw-cur");
        app.merge_src_dir = s_dir.display().to_string();
        app.merge_pw1 = "wrong".into();
        app.merge_pw2 = "wrong".into();
        app.merge_preview();
        assert!(app.merge_plan.is_none());
        // One generic message — never confirms whether the password was right (oracle-safe).
        let err = app.merge_error.as_deref().unwrap_or("");
        assert!(err.contains("wrong password(s) or unreadable"), "got: {err:?}");
        cleanup(&s_path);
        cleanup(&c_path);
    }
}

// Headless egui-driven verification (egui_kittest): runs the REAL `render_acct_node`
// through a real egui Context + accesskit, simulates a real click, and observes widget
// visibility — i.e. drives the actual GUI surface without a window.
#[cfg(test)]
mod kittest_tests {
    use super::render_acct_node;
    use crate::records::{AccountLeaf, AcctNode};
    use eframe::egui;
    use egui_kittest::{kittest::Queryable, Harness};

    /// Every article in the manual must actually render. The help browser nests
    /// panels (top + left + central) inside the screen's own CentralPanel and builds
    /// per-table grid ids from content pointers, so a layout or duplicate-id fault
    /// would only ever show up when a real egui lays it out — not in a data test.
    #[test]
    fn every_help_topic_renders_in_real_egui() {
        use crate::gui_help::{HelpContext, HelpState, TOPICS};

        for (i, topic) in TOPICS.iter().enumerate() {
            let state = std::cell::RefCell::new(HelpState { query: String::new(), topic: i });
            let ctx = HelpContext {
                vault: "/tmp/vault/vault.pmv".into(),
                prefs: "/tmp/prefs.json".into(),
                writable: true,
            };
            let mut h = Harness::new_ui(|ui| {
                let mut s = state.borrow_mut();
                crate::gui_help::ui(ui, &mut s, &ctx, egui::Color32::from_rgb(21, 92, 170));
            });
            h.run();
            // The title renders twice — once in the index, once as the article's
            // heading — so this counts matches rather than expecting exactly one.
            assert!(
                h.query_all_by_label(topic.title).count() >= 2,
                "help topic {:?} did not render in both the index and the body",
                topic.id
            );
        }
    }

    /// Searching must narrow the visible index and leave the browser on a topic the
    /// index still lists — the case where the previously-selected article is filtered
    /// away is exactly where a stale index would render an unreachable page.
    #[test]
    fn help_search_narrows_the_index_and_follows_the_selection_in_real_egui() {
        use crate::gui_help::{HelpContext, HelpState};

        // Start on the LAST topic, then search for something only an early topic
        // matches: the selection must move to a topic that is still listed.
        let last = crate::gui_help::TOPICS.len() - 1;
        let state = std::cell::RefCell::new(HelpState { query: "argon2id".into(), topic: last });
        let ctx =
            HelpContext { vault: "/v".into(), prefs: "/p".into(), writable: false };
        let mut h = Harness::new_ui(|ui| {
            let mut s = state.borrow_mut();
            crate::gui_help::ui(ui, &mut s, &ctx, egui::Color32::from_rgb(21, 92, 170));
        });
        h.run();
        let landed = state.borrow().topic;
        let hits = crate::gui_help::search("argon2id");
        assert!(hits.contains(&landed), "the browser must land on a topic the filtered index lists");
        assert!(
            h.query_all_by_label(crate::gui_help::TOPICS[landed].title).count() >= 2,
            "the followed-to article renders, in the index and as the article heading"
        );
    }

    fn one_group_tree(group: &str, leaf_id: &str, leaf_title: &str) -> AcctNode {
        AcctNode {
            label: String::new(),
            children: vec![AcctNode {
                label: group.into(),
                children: vec![],
                leaves: vec![AccountLeaf { id: leaf_id.into(), title: leaf_title.into() }],
            }],
            leaves: vec![],
        }
    }

    // The PRE-FIX render: id_salt WITHOUT the per-tree `kind` discriminant (used as a negative
    // control to prove the test actually detects the shared-state bug).
    fn render_buggy(ui: &mut egui::Ui, node: &AcctNode, path: &mut Vec<String>) {
        for child in &node.children {
            path.push(child.label.clone());
            egui::CollapsingHeader::new(&child.label)
                .id_salt(("group_node", path.as_slice()))
                .show(ui, |ui| render_buggy(ui, child, path));
            path.pop();
        }
        for leaf in &node.leaves {
            let _ = ui.selectable_label(false, &leaf.title);
        }
    }

    #[test]
    fn error_banner_renders_and_dismiss_clears_it_in_real_egui() {
        use super::show_error_banner;
        use std::cell::RefCell;

        // A live failure message: the conspicuous banner must render with a Dismiss control.
        let error = RefCell::new(Some("Save failed: disk full".to_string()));
        let mut h = Harness::new_ui(|ui| {
            let mut e = error.borrow_mut();
            show_error_banner(&mut e, ui);
        });
        h.run();
        // The banner is on-screen (its Dismiss button is the deterministic, queryable marker).
        assert!(
            h.query_by_label("Dismiss ×").is_some(),
            "the conspicuous error banner renders while an error is set"
        );

        // Clicking Dismiss clears the error and removes the banner entirely.
        h.get_by_label("Dismiss ×").click();
        h.run();
        assert!(error.borrow().is_none(), "Dismiss clears the stored error");
        assert!(
            h.query_by_label("Dismiss ×").is_none(),
            "the banner is gone after dismissal (nothing rendered when error is None)"
        );
    }

    #[test]
    fn grouped_account_and_asset_trees_expand_independently_in_real_egui() {
        // Both trees share the group label "Bob" but have uniquely-labelled leaves, so a leaf
        // being visible tells us exactly which tree's "Bob" is expanded.
        use std::cell::Cell;
        let acct = one_group_tree("Bob", "a1", "acct-leaf");
        let asset = one_group_tree("Bob", "s1", "asset-leaf");
        let labels: Vec<(String, String)> = vec![];

        // Faithfully model the real bug, which is CROSS-TAB: only one tab renders per frame, but
        // both share the same egui Context (hence the persistent collapse state). `tab` selects
        // which tree the harness renders this frame (0 = Accounts, 1 = Assets); `fixed` picks the
        // real render_acct_node (per-tree id) vs the pre-fix shared-id render. Returns whether the
        // Assets "Bob" leaked OPEN after we expanded the Accounts "Bob" and switched tabs.
        let asset_leaks_after_expanding_accounts = |fixed: bool| -> bool {
            let tab = Cell::new(0u8);
            let mut h = Harness::new_ui(|ui| {
                let mut p = Vec::new();
                let (tree, kind) = if tab.get() == 0 { (&acct, "acct") } else { (&asset, "asset") };
                if fixed {
                    render_acct_node(ui, tree, &mut p, None, &labels, kind);
                } else {
                    render_buggy(ui, tree, &mut p);
                }
            });
            // Accounts tab: expand "Bob".
            tab.set(0);
            h.run();
            assert!(h.query_by_label("acct-leaf").is_none(), "accounts/Bob collapsed before the click");
            h.get_by_label("Bob").click();
            h.run();
            assert!(h.query_by_label("acct-leaf").is_some(), "accounts/Bob expanded after the click");
            // Switch to the Assets tab (same Context → shared persistent state) and observe.
            tab.set(1);
            h.run();
            h.query_by_label("asset-leaf").is_some()
        };

        // FIX: expanding Accounts/Bob then switching to Assets leaves Assets/Bob COLLAPSED.
        assert!(
            !asset_leaks_after_expanding_accounts(true),
            "FIX: Assets/Bob must stay collapsed after expanding Accounts/Bob (independent state)"
        );
        // NEGATIVE CONTROL: the pre-fix shared id DOES leak the expand across tabs — proving the
        // test detects the real bug, and that the discriminant is what prevents it.
        assert!(
            asset_leaks_after_expanding_accounts(false),
            "control: the pre-fix shared id leaks the expand to the Assets tab (reproduces the bug)"
        );
    }
}

#[cfg(test)]
mod glyph_tests {
    use eframe::egui;
    use egui_kittest::Harness;

    /// Every non-ASCII character in the GUI's source must exist in the fonts egui
    /// BUNDLES — the app ships as a single self-contained binary with no asset files,
    /// so it cannot rely on what fonts the target machine happens to have. A character
    /// outside the bundled set renders as a tofu box (□) on the user's screen, which no
    /// test that merely queries labels would ever notice.
    ///
    /// The character set is taken from the source with `include_str!` rather than
    /// hand-listed, so introducing a new glyph automatically brings it under this check
    /// instead of quietly shipping. It over-approximates (comments are scanned too),
    /// which is the safe direction: a comment-only character that the fonts lack costs
    /// one line in the allow-list below, whereas a missed rendered one costs a tofu box.
    #[test]
    fn every_glyph_in_the_gui_source_exists_in_the_bundled_fonts() {
        const SOURCES: [&str; 2] = [include_str!("gui.rs"), include_str!("gui_help.rs")];

        // Characters that appear only in prose/comments and are never drawn as UI
        // chrome. Listed explicitly so the exemption is a decision, not an accident;
        // each was checked against the source when it was added here.
        const COMMENT_ONLY: &str = "→↑↓⇄□";

        let mut chars: Vec<char> = SOURCES
            .iter()
            .flat_map(|s| s.chars())
            .filter(|c| !c.is_ascii() && !COMMENT_ONLY.contains(*c))
            .collect();
        chars.sort_unstable();
        chars.dedup();

        let mut h = Harness::new_ui(|_ui| {});
        h.run();
        let (missing, control_present, control_absent): (Vec<char>, bool, bool) = h.ctx.fonts_mut(|f| {
            let id = egui::FontId::proportional(14.0);
            (
                chars.iter().copied().filter(|c| !f.has_glyph(&id, *c)).collect(),
                // Controls, so a broken probe cannot pass silently: a plain letter must
                // be present and a Gothic codepoint must not.
                f.has_glyph(&id, 'A'),
                !f.has_glyph(&id, '\u{10348}'),
            )
        });
        assert!(control_present && control_absent, "the glyph probe itself is broken");
        assert!(
            missing.is_empty(),
            "these characters are NOT in egui's bundled fonts and render as tofu boxes: {missing:?}"
        );
    }
}
