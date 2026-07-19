//! The graphical app's built-in manual.
//!
//! This module holds the *content* of the in-app help (a table of topics, each a
//! list of typed blocks) plus the code that renders it as a two-pane browser:
//! a searchable topic index on the left, the selected article on the right.
//!
//! The content is deliberately kept as plain data (`TOPICS`) rather than inline
//! `ui.label(...)` calls so that:
//! - the search box can match against every word of every article without the
//!   article having to be rendered first ([`search`] is a pure function),
//! - a test can assert structural invariants (unique ids, no empty articles),
//! - re-ordering or re-wording the manual never touches rendering code.
//!
//! Nothing here reads or writes the vault: the manual is static text plus the
//! three on-disk paths handed in via [`HelpContext`].

use eframe::egui;

// --- Content model -----------------------------------------------------------

/// One renderable piece of an article. Keeping these as an `enum` (a closed set
/// of alternatives) means the renderer decides what each kind *looks* like in
/// exactly one place, so the whole manual restyles at once.
pub(crate) enum Block {
    /// A paragraph of prose.
    P(&'static str),
    /// A sub-heading inside an article.
    Sub(&'static str),
    /// An unordered list.
    Bullets(&'static [&'static str]),
    /// A numbered list — used for "do this, then this" procedures.
    Steps(&'static [&'static str]),
    /// A two-column reference table (`what` → `what it does`).
    Rows(&'static [(&'static str, &'static str)]),
    /// An aside worth noticing but not alarming.
    Note(&'static str),
    /// A consequence the user cannot undo — rendered in the warning color.
    Warn(&'static str),
}

/// One article in the manual.
pub(crate) struct Topic {
    /// Stable identifier (used by tests and by cross-references; never shown).
    pub(crate) id: &'static str,
    /// The index group this topic is listed under.
    pub(crate) section: &'static str,
    /// The article's title (shown in the index and as its heading).
    pub(crate) title: &'static str,
    /// One line shown under the heading, and matched by the search box.
    pub(crate) blurb: &'static str,
    pub(crate) body: &'static [Block],
}

/// The index groups, in the order they appear in the navigation pane.
pub(crate) const SECTIONS: &[&str] =
    &["Getting started", "The tabs", "Working with records", "Settings & maintenance", "Reference"];

// The manual itself. Written to be read by someone who has never seen the app —
// including an heir opening it read-only for the first time — so each article
// says what the thing is, what it does, and what it cannot do.
pub(crate) const TOPICS: &[Topic] = &[
    // --- Getting started -----------------------------------------------------
    Topic {
        id: "overview",
        section: "Getting started",
        title: "What pass-mgr is",
        blurb: "An offline, two-password encrypted vault for everything an executor or heir will need.",
        body: &[
            Block::P(
                "pass-mgr keeps the records an estate's executor or heirs need in a single \
                 encrypted vault: account logins, written instructions, trust and will documents, \
                 assets and liabilities, real estate, tax filings, and any other document you want \
                 to leave behind.",
            ),
            Block::P(
                "It is completely offline. There is no network code anywhere in the program: \
                 nothing is uploaded, nothing is synced, and no part of your data leaves this \
                 machine unless you explicitly export it.",
            ),
            Block::Sub("What a vault is on disk"),
            Block::P(
                "A vault is a folder, not a single file. It holds the encrypted record file \
                 (vault.pmv), an encrypted index of your documents (manifest/), and the encrypted \
                 document archive itself (volume/). Back up the whole folder — the parts are of no \
                 use to each other separately.",
            ),
            Block::Sub("The two front-ends"),
            Block::P(
                "This window is the graphical app (pass-mgr-gui). The same vault can be opened \
                 with a terminal interface (pass-mgr --tui) and with command-line tools for \
                 backup, export, and maintenance. See “Command line” in the Reference section.",
            ),
        ],
    },
    Topic {
        id: "opening",
        section: "Getting started",
        title: "Opening or creating a vault",
        blurb: "The start page: pick a folder, pick a vault, enter both passwords.",
        body: &[
            Block::P(
                "The start page is where you choose which vault to open. It has two parts: the \
                 folder that holds your vaults, and the vault inside it.",
            ),
            Block::Rows(&[
                (
                    "Vaults folder",
                    "The directory that is scanned (one level deep) for vaults. Every subfolder \
                     containing a vault.pmv is offered in the dropdown below. This is remembered \
                     for next time.",
                ),
                (
                    "Vault",
                    "The vault's own folder name inside that directory. Choose one from the \
                     dropdown, or type a name that does not exist yet to create a new vault there.",
                ),
                ("Password 1 / Password 2", "Both are required, and the order matters. See “The two passwords”."),
            ]),
            Block::Sub("Unlock vs. Create"),
            Block::P(
                "The button changes to match what is on disk. If the chosen folder already holds a \
                 vault, it reads Unlock and asks for the two passwords once. If the folder is empty \
                 or new, it reads Create and asks for each password twice, to catch typos — a typo \
                 in a password you then forget is unrecoverable.",
            ),
            Block::Note(
                "Creating is only offered in write mode. A read-only session can open existing \
                 vaults but never make one.",
            ),
            Block::Sub("One window per vault"),
            Block::P(
                "Launching the app again for a vault that is already open raises the existing \
                 window instead of opening a second one. In write mode the vault also takes a \
                 single-writer lock, so a second writable session fails fast rather than letting \
                 two windows overwrite each other.",
            ),
        ],
    },
    Topic {
        id: "passwords",
        section: "Getting started",
        title: "The two passwords",
        blurb: "Both are needed, the order matters, and there is no recovery.",
        body: &[
            Block::P(
                "The vault is locked with two passwords entered in sequence. They are chained \
                 through Argon2id key derivation into a single encryption key: the first password's \
                 derived key is an input to deriving the second. Neither password alone reveals \
                 anything, and swapping their order is simply a wrong pair.",
            ),
            Block::P(
                "The intent is that the two can be held separately — for example one with you and \
                 one with a lawyer or in a safe — so that no single place holds everything.",
            ),
            Block::Warn(
                "There is NO recovery, no reset, no backdoor, and no hint. If either password is \
                 lost the data is unrecoverable — by design, not by omission. Write them down and \
                 store them where your executor will actually find them.",
            ),
            Block::Sub("Changing them"),
            Block::Steps(&[
                "Click 🔑 Passwords in the top bar (write mode only).",
                "Enter the current pair, then the new pair twice each.",
                "The vault is re-encrypted with a fresh key. The old passwords stop working immediately.",
            ]),
            Block::Note(
                "Changing passwords rewrites the vault file, not the document archive: your \
                 existing documents stay attached and readable under the new pair.",
            ),
            Block::Sub("Why a wrong password looks like corruption"),
            Block::P(
                "A wrong password and a damaged or tampered-with vault produce the same failure \
                 message. That is intentional: distinguishing them would tell an attacker holding \
                 a copy of your vault whether a guessed password was “close”, turning the file into \
                 a password oracle they could grind against offline.",
            ),
        ],
    },
    Topic {
        id: "readonly",
        section: "Getting started",
        title: "Read-only vs. write mode",
        blurb: "Why the app opens read-only, and exactly what each mode allows.",
        body: &[
            Block::P(
                "The app opens READ-ONLY unless it was launched with --write. A read-only session \
                 writes nothing to the vault at all, so it cannot damage anything — it is the safe \
                 default, and the mode an heir should use.",
            ),
            Block::P("When read-only, an orange 🔒 READ-ONLY badge sits in the top bar and every write control is hidden."),
            Block::Sub("What still works read-only"),
            Block::Bullets(&[
                "Reading every record on every tab. The forms become a view: the text cannot be \
                 edited, but it can still be selected and copied.",
                "Revealing and copying passwords.",
                "Exporting documents to the export directory.",
                "Running a backup of the encrypted vault.",
                "Changing the color theme, the view defaults, and the export directory — these are \
                 local preferences on this machine, not vault content.",
            ]),
            Block::Sub("What needs write mode"),
            Block::Bullets(&[
                "Creating, editing, and deleting records.",
                "Attaching and detaching documents.",
                "Changing the passwords.",
                "Editing the type and subtype lists, the volume size, and the redundancy setting.",
                "Updating from another vault.",
                "Exporting a tab to CSV — a CSV of Accounts or Real Estate holds every password in \
                 plain text, so a read-only heir is deliberately not able to bulk-dump secrets.",
            ]),
            Block::Note("To switch modes, close the window and relaunch with the --write flag."),
        ],
    },
    Topic {
        id: "window",
        section: "Getting started",
        title: "Finding your way around",
        blurb: "The top bar, the two-pane tabs, the status line, and the error banner.",
        body: &[
            Block::Sub("The top bar"),
            Block::P(
                "The first row is the tab strip — one tab per kind of record. The second row holds \
                 the actions that apply everywhere:",
            ),
            Block::Rows(&[
                ("🔑 Passwords", "Change the vault's two passwords (write mode)."),
                ("⚙ Config", "Settings: appearance, view defaults, type lists, export directory, backup, storage."),
                ("❓ Help", "This manual."),
                ("Quit", "Close the window. In-memory secrets are wiped and the clipboard is cleared on exit."),
                ("🔒 READ-ONLY", "Shown when the session cannot make changes."),
            ]),
            Block::Sub("Inside a tab"),
            Block::P(
                "Every record tab is split down the middle: the list of records on the left, the \
                 form for the selected record on the right. Clicking a row in the list opens it in \
                 the form; ➕ New starts a blank one. Nothing is stored until you click 💾 Save.",
            ),
            Block::Warn(
                "Selecting a different record discards unsaved edits to the one you were on. Save \
                 before you click away.",
            ),
            Block::Sub("Status line and error banner"),
            Block::P(
                "The thin line along the bottom reports the result of the last action (“Saved.”, \
                 “Exported to …”). A genuine failure — a save that did not land, an upload that \
                 failed — additionally raises a red banner across the top of the window, so a \
                 failure can never be missed by looking away from the status line. Dismiss it with \
                 the button, or simply do something that succeeds.",
            ),
        ],
    },
    // --- The tabs ------------------------------------------------------------
    Topic {
        id: "tab-urgent",
        section: "The tabs",
        title: "URGENT",
        blurb: "Free-text notes that must be read first. Deliberately the leftmost tab.",
        body: &[
            Block::P(
                "The URGENT tab is for the handful of things someone must know within hours: where \
                 the will is, who to phone, which bill is on auto-pay and must be stopped, the \
                 safe's combination.",
            ),
            Block::P(
                "Each entry is a title and a free-form body — no categories, no required structure. \
                 It sits first so that whoever opens this vault under stress reads it before \
                 anything else.",
            ),
            Block::Note("Keep it short. Anything that is not genuinely urgent belongs on the Instructions tab."),
        ],
    },
    Topic {
        id: "tab-instructions",
        section: "The tabs",
        title: "Instructions",
        blurb: "Longer written guidance: what to do, in what order, and who to contact.",
        body: &[
            Block::P(
                "Instructions hold your written wishes and procedures — funeral arrangements, how to \
                 close accounts, which professionals to contact, what to do with the house, notes \
                 for specific people.",
            ),
            Block::P("Each instruction is a title plus a body of text, and can have documents attached."),
            Block::Note(
                "Instructions are prose, not legal instruments. Nothing here substitutes for a will \
                 or trust — use it to explain and point at those, and store copies on the Trust & \
                 Will tab.",
            ),
        ],
    },
    Topic {
        id: "tab-trustwill",
        section: "The tabs",
        title: "Trust and Will",
        blurb: "The estate instruments themselves, plus scans of the signed originals.",
        body: &[
            Block::P(
                "This tab holds your estate instruments: the will, trusts, powers of attorney, \
                 healthcare directives, and the details of who drafted them and where the signed \
                 originals physically live.",
            ),
            Block::P(
                "Attach scans with the Documents section of the form. The scan in the vault is a \
                 convenience copy — record where the signed original is kept, because that is \
                 usually the document that has legal force.",
            ),
        ],
    },
    Topic {
        id: "tab-assets",
        section: "The tabs",
        title: "Assets and Liabilities",
        blurb: "What is owned and what is owed, optionally linked to the account that holds it.",
        body: &[
            Block::P(
                "One record per asset or liability: property, brokerage and retirement holdings, \
                 vehicles, valuables, loans, mortgages, and credit lines. Each carries its owner, \
                 its type, a value, and free-form detail.",
            ),
            Block::Sub("Grouped view"),
            Block::P(
                "The grouped checkbox switches the list from a flat list to a tree of \
                 owner > asset or liability > type, so a large estate stays navigable. Groups \
                 expand and collapse independently and remember their state.",
            ),
            Block::Sub("Linking to accounts"),
            Block::P(
                "An asset can be linked to the accounts that hold or service it — the brokerage \
                 login for a portfolio, the servicer login for a mortgage. Links are managed from \
                 the asset side; the Accounts form shows the reverse (“linked from”) and offers a \
                 jump back. See “Linking assets and accounts”.",
            ),
            Block::Sub("Review filter"),
            Block::P(
                "“review only” narrows the list to records flagged as needing another look — useful \
                 for working through a backlog of half-finished entries.",
            ),
        ],
    },
    Topic {
        id: "tab-accounts",
        section: "The tabs",
        title: "Accounts",
        blurb: "Logins and credentials, with faceted filters, search, and a grouped tree.",
        body: &[
            Block::P(
                "The Accounts tab holds logins: bank and brokerage, utilities, insurance, email, \
                 subscriptions, and anything else with a username and password. Title and Owner are \
                 required on every account; everything else is optional.",
            ),
            Block::Sub("Filters"),
            Block::P(
                "The filter row narrows the list by type, subtype, owner, and title. The filters are \
                 faceted and cross-narrowing: each dropdown offers only values that actually occur \
                 among the accounts matching the other active filters, so you can never reach an \
                 inexplicably empty list. If a filter you had chosen stops being a valid option, it \
                 clears itself.",
            ),
            Block::Rows(&[
                ("type / subtype / owner / title", "Faceted dropdowns; blank means no filter."),
                ("review only", "Show only accounts flagged for review."),
                ("reveal all", "Unmask every password on this screen. See “Passwords”."),
                ("grouped", "Switch between a flat list and an owner > type > subtype > title tree."),
                ("search", "Case-insensitive substring match on the username OR the title."),
                ("Clear", "Reset every filter, the review flag, and the search box at once."),
                ("Trim all fields", "One-off maintenance: strip leading/trailing whitespace from every field of every record in the whole vault (write mode; recorded in history)."),
            ]),
            Block::Note(
                "Starting a new account while filters are active pre-fills the new record with \
                 those filter values — filter to a type and owner first, and the new record starts \
                 half-written.",
            ),
        ],
    },
    Topic {
        id: "tab-realestate",
        section: "The tabs",
        title: "Real Estate",
        blurb: "Property records with four portal logins each.",
        body: &[
            Block::P(
                "One record per property: address, ownership, purchase and valuation details, and \
                 whatever notes matter. Documents — deeds, surveys, policies, closing statements — \
                 attach to the property.",
            ),
            Block::Sub("The four portals"),
            Block::P(
                "A property carries four separate logins, because these are the four accounts \
                 someone settling an estate always ends up needing:",
            ),
            Block::Bullets(&[
                "Property management",
                "Insurance",
                "HOA",
                "Tax",
            ]),
            Block::P(
                "Each portal has a URL, a username, a password, and a free-form comment for the \
                 things that never fit a field — the security question, the account number, who to \
                 ask for.",
            ),
            Block::Note(
                "This tab has its own “reveal all” toggle, separate from the one on Accounts, so \
                 revealing on one screen never unmasks the other.",
            ),
        ],
    },
    Topic {
        id: "tab-taxes",
        section: "The tabs",
        title: "Taxes",
        blurb: "Filings by year, each with its own set of attached documents.",
        body: &[
            Block::P(
                "One record per filing: the year, the jurisdiction, the preparer, and the details of \
                 what was filed. Returns, schedules, K-1s, and correspondence attach to the filing \
                 they belong to.",
            ),
            Block::P(
                "Unlike most tabs, a tax filing holds a numbered LIST of documents, and the export \
                 and remove buttons act on the entry you pick from that list.",
            ),
            Block::Note("A few prior years of returns are usually the first thing an estate's accountant asks for."),
        ],
    },
    Topic {
        id: "tab-general",
        section: "The tabs",
        title: "General Documents",
        blurb: "The catch-all: anything worth keeping that fits no other tab.",
        body: &[
            Block::P(
                "Passports, birth and marriage certificates, military records, diplomas, warranties, \
                 vehicle titles, membership records — anything that should survive with the estate \
                 but does not belong to an account, a property, or a filing.",
            ),
            Block::P("Each record is a title, a description, and its attached files."),
        ],
    },
    Topic {
        id: "tab-summary",
        section: "The tabs",
        title: "Summary",
        blurb: "A read-only overview of assets and liabilities per owner.",
        body: &[
            Block::P(
                "Summary is a calculated view, not a record type: nothing on it can be edited. It \
                 totals the Assets and Liabilities tab per owner, splitting assets into buckets \
                 (real estate, cash, before-tax, after-tax) against a single liability column.",
            ),
            Block::P("Its numbers are only as good as the values on the individual records — it adds up what is there, nothing more."),
        ],
    },
    // --- Working with records ------------------------------------------------
    Topic {
        id: "editing",
        section: "Working with records",
        title: "Creating, editing, and deleting",
        blurb: "The save/delete cycle shared by every tab.",
        body: &[
            Block::Steps(&[
                "Click ➕ New for a blank record, or click an existing row to load it into the form.",
                "Fill in the fields. Dropdowns come from the type lists in Config; a record's existing value stays selectable even if it is no longer on the list.",
                "Click 💾 Save. The vault file is rewritten and the change is logged to the record's history.",
            ]),
            Block::Warn(
                "Edits live only in the form until you save. Selecting another record, switching \
                 tabs, or quitting discards them without a prompt.",
            ),
            Block::Sub("Deleting"),
            Block::P(
                "🗑 Delete removes the selected record and reclaims the space used by any documents \
                 attached to it. Deleting an account that assets still link to asks for \
                 confirmation first, and tells you how many records link to it.",
            ),
            Block::Note(
                "Those links are deliberately NOT cascaded — deleting the account leaves the asset's \
                 link showing as an unresolved id rather than silently editing a record you did not \
                 open. Nothing in this app deletes data you did not ask it to delete.",
            ),
            Block::Sub("Saves are crash-safe"),
            Block::P(
                "A save writes a new copy and swaps it into place atomically. Losing power in the \
                 middle leaves either the old vault or the new one, never a half-written mixture.",
            ),
        ],
    },
    Topic {
        id: "secrets",
        section: "Working with records",
        title: "Passwords: reveal, generate, copy",
        blurb: "How secrets are shown, made, and put on the clipboard.",
        body: &[
            Block::Sub("Reveal"),
            Block::P(
                "Reveal is a single screen-wide toggle — “reveal all” — on Accounts and on Real \
                 Estate. There is no per-record reveal, so there is no ambiguity about what is \
                 currently visible on screen.",
            ),
            Block::P(
                "Switching tabs resets reveal to whatever “Reveal all passwords by default” is set \
                 to in Config. With that preference off (the default) every tab re-masks when you \
                 leave it, so a revealed password cannot linger on screen for a bystander.",
            ),
            Block::Sub("Generate"),
            Block::P(
                "🎲 fills the field with a strong random password and turns reveal on so you can \
                 see and record what was generated. It replaces whatever was in the field — copy \
                 the old value first if you still need it.",
            ),
            Block::Sub("Copy"),
            Block::P(
                "📋 copies the password to the clipboard through a path flagged to keep it out of \
                 clipboard-manager history.",
            ),
            Block::Bullets(&[
                "The clipboard is cleared automatically 15 seconds after a copy.",
                "It is cleared again when the app exits.",
                "A clipboard manager that ignores the exclusion flag may still keep a copy — the \
                 15-second clear only overwrites the live clipboard, not somebody else's log of it.",
            ]),
        ],
    },
    Topic {
        id: "documents",
        section: "Working with records",
        title: "Documents: attaching and exporting",
        blurb: "Getting files into the encrypted archive, and decrypted copies back out.",
        body: &[
            Block::Sub("Attaching"),
            Block::Steps(&[
                "Put the file's path in “Upload from”. A path in double quotes (as Windows Explorer's “Copy as path” produces) is accepted as-is.",
                "Optionally add a subfolder to organise it inside the vault.",
                "Optionally set a filename. Leave it blank to keep the source file's own name.",
                "Click the upload button. The file is encrypted into the vault's document archive.",
            ]),
            Block::P(
                "The original file is not moved or deleted — the vault takes an encrypted copy. If \
                 the original was the only copy of something sensitive, delete it yourself \
                 afterwards.",
            ),
            Block::Sub("Where documents are stored"),
            Block::P(
                "Storage paths are derived automatically, owner-first, with the upload time folded \
                 into the filename:",
            ),
            Block::Rows(&[(
                "Layout",
                "[<owner initials>/]<record type>[/<group>][/<your subfolder>]/<timestamp>_<filename>",
            )]),
            Block::P(
                "You control only the optional subfolder and the filename; the rest keeps documents \
                 from different owners and record types from colliding.",
            ),
            Block::Sub("Exporting"),
            Block::P(
                "Export writes a DECRYPTED copy of the document to the export directory set in \
                 Config, recreating its folder structure underneath. You are not asked for a path \
                 each time — set it once in Config.",
            ),
            Block::Bullets(&[
                "An export never overwrites an existing file; it adds a _2, _3, … suffix instead.",
                "Export works in read-only mode, which is how an heir gets documents out.",
            ]),
            Block::Warn(
                "Exported files are plain, unencrypted copies sitting in an ordinary folder. Put \
                 them somewhere you trust and delete them when you are done.",
            ),
        ],
    },
    Topic {
        id: "links",
        section: "Working with records",
        title: "Linking assets and accounts",
        blurb: "Tying an asset to the login that manages it, and navigating between them.",
        body: &[
            Block::P(
                "An asset or liability can name the accounts that hold or service it: the brokerage \
                 login behind a portfolio, the servicer login behind a mortgage, the bank login \
                 behind a cash balance.",
            ),
            Block::Steps(&[
                "Open the asset on the Assets and Liabilities tab.",
                "In its linked-accounts section, choose an account and add the link.",
                "Save the asset. Links live on the asset record, so they are stored when it is saved.",
            ]),
            Block::P(
                "The Accounts form shows the other direction — every asset that links to the account \
                 you are looking at — with a button to jump straight to it. Jumping switches tabs \
                 and clears any filter that would have hidden the target, so the record you asked \
                 for is always the one you land on.",
            ),
            Block::Note(
                "Links are stored by record id, so renaming either side keeps the link intact. \
                 Deleting a linked account leaves the link showing as a raw id rather than editing \
                 the asset behind your back.",
            ),
        ],
    },
    Topic {
        id: "history",
        section: "Working with records",
        title: "Record history",
        blurb: "Every record keeps a log of what changed and when.",
        body: &[
            Block::P(
                "Each record carries its own change history, shown at the bottom of its form: what \
                 was created, what fields were edited, and when. It is written automatically on \
                 every save.",
            ),
            Block::P(
                "History is what tells you whether the login you are looking at was checked last \
                 month or last decade — worth a glance before trusting an old credential.",
            ),
            Block::Note(
                "History accumulates and makes the vault file grow. The `compact` command-line tool \
                 can trim it (all of it, or everything before a date) when that matters; the \
                 vault-level audit log is always kept.",
            ),
        ],
    },
    // --- Settings & maintenance ---------------------------------------------
    Topic {
        id: "config",
        section: "Settings & maintenance",
        title: "Config: every setting explained",
        blurb: "Appearance, view defaults, type lists, export directory, storage, redundancy.",
        body: &[
            Block::Sub("Appearance"),
            Block::P(
                "Ten color themes: Light, Dark, High contrast, Solarized, Sepia, Nord, Dracula, \
                 Gruvbox Dark, Gruvbox Light, and Rosé Pine. The choice applies instantly and is \
                 remembered for the next launch.",
            ),
            Block::Sub("View defaults"),
            Block::P("Three preferences that decide how each tab looks when you arrive on it:"),
            Block::Rows(&[
                ("Reveal all passwords by default", "Whether password fields start revealed rather than masked."),
                ("Group assets by default", "Whether the Assets tab opens as a tree."),
                ("Group accounts by default", "Whether the Accounts tab opens as a tree."),
            ]),
            Block::Sub("Asset / Liability types · Account types & subtypes"),
            Block::P(
                "The dropdown lists used by the record forms. Add a type or subtype with the boxes \
                 provided; delete one with its × button. A type in use cannot be deleted, and an \
                 account type with subtypes must have its subtypes removed first — the entries that \
                 are safe to remove are marked “unused”.",
            ),
            Block::Note("These lists live inside the encrypted vault. There are no external configuration files to lose."),
            Block::Sub("Export directory"),
            Block::P(
                "Where every Export button writes its decrypted copy. Stored as a local preference \
                 rather than in the vault, so it can be set even in a read-only session.",
            ),
            Block::Sub("Backup"),
            Block::P(
                "Copies the encrypted vault and its document archive into a timestamped folder \
                 under the destination you give. Nothing is decrypted. See “Backups and recovery”.",
            ),
            Block::Sub("Storage — volume size"),
            Block::P(
                "Documents are packed into fixed-size encrypted volumes; a new one starts once the \
                 current one passes this size. Changing it affects only where future documents \
                 land, never what is already stored.",
            ),
            Block::Sub("Vault file redundancy (advanced)"),
            Block::P(
                "Keeps extra encrypted copies of the small vault file in place: a same-generation \
                 mirror plus N previous generations — which doubles as an undo of the last save if \
                 a save goes wrong. 0 turns it off.",
            ),
            Block::Warn(
                "Redundancy protects against a damaged file, not against a lost, stolen, or burned \
                 disk. It is not a substitute for backups kept somewhere else.",
            ),
            Block::Sub("Sync types from records"),
            Block::P(
                "Scans every record and adds any type or subtype it uses that is missing from the \
                 lists above. Useful after pulling records in from another vault whose type lists \
                 differ from this one's.",
            ),
        ],
    },
    Topic {
        id: "merge",
        section: "Settings & maintenance",
        title: "Updating from another vault",
        blurb: "Pull newer records — and their documents — from a second vault. One-way and additive.",
        body: &[
            Block::P(
                "If you keep a vault on more than one machine, this brings changes from another \
                 copy into this one. It pulls records that are newer (or entirely new) in the other \
                 vault, together with the documents those records reference.",
            ),
            Block::Bullets(&[
                "One-way: the other vault is opened read-only and is never modified.",
                "Additive: nothing in this vault is ever deleted by a merge.",
                "Previewed: the exact list of changes is shown before anything is applied.",
            ]),
            Block::Steps(&[
                "In Config, click “Update from another vault…” (write mode only).",
                "Choose the other vault's folder and enter ITS two passwords.",
                "Read the preview: every record to be added or updated, plus the documents that come with them.",
                "Apply, or go back and change nothing.",
            ]),
            Block::Note(
                "Back this vault up before applying a merge. The command-line equivalent is \
                 `pass-mgr update-from OTHER [DIR] --dry-run`, which prints the same preview without \
                 changing anything.",
            ),
            Block::P(
                "After a merge, run “Sync types from records” in Config if the incoming records use \
                 types this vault's lists do not have yet.",
            ),
        ],
    },
    Topic {
        id: "backups",
        section: "Settings & maintenance",
        title: "Backups and recovery",
        blurb: "What to copy, how often, and what will not save you.",
        body: &[
            Block::P(
                "The Backup button in Config copies the whole encrypted vault — record file, \
                 manifest, and document archive — into a timestamped folder. Nothing is decrypted, \
                 so a backup is exactly as safe to store as the vault itself.",
            ),
            Block::Sub("What to do"),
            Block::Bullets(&[
                "Back up after any session where you changed something.",
                "Keep at least one copy on different physical media, and ideally one off-site.",
                "Back up the whole vault FOLDER. A vault.pmv without its volume/ folder has records but no documents.",
                "Test a backup occasionally by opening it read-only. An untested backup is a hope, not a backup.",
            ]),
            Block::Warn(
                "Your two passwords are not in the backup. A perfect backup plus a forgotten \
                 password is unrecoverable — store the passwords with the same care as the data, \
                 and somewhere your executor will find them.",
            ),
            Block::Sub("Recovering"),
            Block::P(
                "To restore, copy a backup folder back and open it like any other vault. If \
                 redundancy is enabled, a damaged vault.pmv can also be recovered in place from the \
                 mirrored copies without going to a backup at all.",
            ),
        ],
    },
    Topic {
        id: "maintenance",
        section: "Settings & maintenance",
        title: "Keeping the vault small",
        blurb: "Why it grows, and the command-line tools that shrink it.",
        body: &[
            Block::P("Two things make a vault grow beyond the size of what it holds:"),
            Block::Bullets(&[
                "Edit history — every save appends to the edited record's log.",
                "Dead document blocks — replacing or detaching a document leaves its old encrypted \
                 blocks in the archive rather than rewriting the whole volume on the spot.",
            ]),
            Block::P("The `compact` command reclaims both. It is a command-line operation because it rewrites the whole vault:"),
            Block::Rows(&[
                ("pass-mgr compact [DIR] --volume", "Re-pack the document archive, dropping dead blocks."),
                ("pass-mgr compact [DIR] --json --history-all", "Drop all record edit history."),
                ("pass-mgr compact [DIR] --json --history-before YYYY-MM-DD", "Keep history from that date onward."),
                ("--dry-run", "Report what would be reclaimed, change nothing."),
            ]),
            Block::Note(
                "Compaction backs up first by default and is crash-safe: an interruption leaves \
                 either the old vault or the compacted one. The vault-level audit log is always \
                 preserved.",
            ),
        ],
    },
    // --- Reference -----------------------------------------------------------
    Topic {
        id: "security",
        section: "Reference",
        title: "How your data is protected",
        blurb: "The cryptography, the memory handling, and the limits of both.",
        body: &[
            Block::Sub("Encryption"),
            Block::Bullets(&[
                "Two passwords chained through Argon2id (a memory-hard key derivation function, \
                 chosen to make brute-force guessing expensive) into one key.",
                "XChaCha20-Poly1305 authenticated encryption for the vault, the manifest, and the \
                 document volumes.",
                "The file header is authenticated too, so tampering with the parameters is detected \
                 rather than obeyed.",
                "Decryption of tampered data fails outright — the app never shows you data it could \
                 not verify.",
            ]),
            Block::Sub("In memory"),
            Block::Bullets(&[
                "Passwords and decrypted secrets are overwritten with zeros as soon as they are no longer needed.",
                "On desktop, secret memory is locked so the operating system will not page it out to disk.",
                "The clipboard is cleared 15 seconds after a copy and again on exit.",
            ]),
            Block::Sub("What it does not protect against"),
            Block::P(
                "Encryption protects the vault at rest. It cannot protect a machine that is already \
                 compromised: malware running as you, with the vault unlocked on screen, sees what \
                 you see. Nor does it protect plaintext you have chosen to export.",
            ),
            Block::Warn(
                "The weakest link is almost never the cryptography. It is a password written \
                 somewhere careless, or an exported folder of decrypted documents left behind.",
            ),
        ],
    },
    Topic {
        id: "keys",
        section: "Reference",
        title: "Keyboard and mouse",
        blurb: "The shortcuts this window understands.",
        body: &[
            Block::Rows(&[
                ("Up / Down arrow", "Move to the previous/next record in a flat list, scrolling it into view."),
                ("Click a row", "Open that record in the form."),
                ("Click a group header", "Expand or collapse it in a grouped tree."),
                ("Tab / Shift+Tab", "Move between fields."),
                ("Enter", "Submit on the unlock screen."),
                ("Ctrl+C", "Copy selected text — including from read-only fields."),
                ("Hover a button", "Show a tooltip explaining what it does."),
            ]),
            Block::Note(
                "The graphical app is mouse-first by design. The terminal interface \
                 (`pass-mgr --tui`) is the keyboard-driven one: there, digits 1–9 jump between \
                 tabs, n/d create and delete, g toggles grouping, r reveals, / searches, and Ctrl+S \
                 saves.",
            ),
        ],
    },
    Topic {
        id: "cli",
        section: "Reference",
        title: "Command line",
        blurb: "Everything the console binary can do that this window cannot.",
        body: &[
            Block::P(
                "The console binary (`pass-mgr`) opens the same vaults and adds the bulk operations. \
                 DIR is the vault folder; leaving it out uses the default one. Every command prompts \
                 for the two passwords.",
            ),
            Block::Rows(&[
                ("pass-mgr [DIR]", "Launch this graphical app (read-only)."),
                ("pass-mgr --write [DIR]", "Launch it able to make changes."),
                ("pass-mgr --tui [DIR]", "Launch the terminal interface instead."),
                ("pass-mgr decrypt [DIR]", "Print the whole decrypted vault as JSON — every secret in plain text."),
                ("pass-mgr manifest [DIR]", "Print the decrypted document index."),
                ("pass-mgr extract [DIR] OUT", "Decrypt every stored document into OUT."),
                ("pass-mgr backup [DIR] DEST", "Copy the encrypted vault into a timestamped folder under DEST."),
                ("pass-mgr export-tree [DIR] OUT", "Write a fully decrypted mirror of the vault."),
                ("pass-mgr import-tree SRC [DIR]", "Build a NEW encrypted vault, with new passwords, from such a mirror."),
                ("pass-mgr update-from OTHER [DIR]", "Pull newer records from another vault; add --dry-run to preview."),
                ("pass-mgr compact [DIR] …", "Reclaim space. See “Keeping the vault small”."),
                ("pass-mgr --help", "The full, authoritative list of options."),
            ]),
            Block::Warn(
                "decrypt, extract, and export-tree write or print your data with no encryption at \
                 all. Redirecting decrypt into a file puts every password on disk in the clear.",
            ),
            Block::Note(
                "export-tree and import-tree round-trip, which makes them the escape hatch: your \
                 data can always be taken out of this program's format entirely.",
            ),
        ],
    },
    Topic {
        id: "troubleshooting",
        section: "Reference",
        title: "Troubleshooting",
        blurb: "Common messages and what they actually mean.",
        body: &[
            Block::Rows(&[
                (
                    "The passwords are rejected but you are sure they are right",
                    "Check the order — they are not interchangeable. Check the keyboard layout and \
                     Caps Lock. Confirm you are opening the vault folder you think you are. The same \
                     message also appears for a damaged file, deliberately.",
                ),
                (
                    "“already open” on launch",
                    "A window for this vault is open; it has been raised instead. Look for it on \
                     another workspace or minimised.",
                ),
                (
                    "A writable session refuses to start",
                    "Another writable session holds the single-writer lock. Close it. If none is \
                     running, the vault was left locked by a crash — the lock clears on its own once \
                     the stale process is gone.",
                ),
                (
                    "Nothing is editable",
                    "The session is read-only. Look for the 🔒 badge; relaunch with --write.",
                ),
                (
                    "A save or upload failed",
                    "Read the red banner. Usually a full disk or a permissions problem on the vault \
                     folder. The vault is intact — saves are atomic, so a failed save changed nothing.",
                ),
                (
                    "Export did nothing visible",
                    "Check the export directory in Config; that is where the file went. An existing \
                     file is never overwritten, so look for a _2 suffix.",
                ),
                (
                    "An upload cannot find the file",
                    "The whole path is needed, not just the filename. Quoted paths are accepted.",
                ),
                (
                    "The list is unexpectedly empty",
                    "A filter or the search box is still active. Click Clear.",
                ),
                (
                    "A link shows a raw id",
                    "The account it pointed at was deleted. Edit the asset to remove or re-point the link.",
                ),
            ]),
        ],
    },
    Topic {
        id: "faq",
        section: "Reference",
        title: "Questions people ask",
        blurb: "Short answers about recovery, sharing, trust, and what happens next.",
        body: &[
            Block::Sub("Can a lost password be recovered?"),
            Block::P("No. Not by you, not by anyone. There is no reset, no backdoor, and no support channel that can help."),
            Block::Sub("Does anything leave this machine?"),
            Block::P(
                "Only what you export yourself. The program contains no network code — it cannot \
                 phone home, sync, or update itself.",
            ),
            Block::Sub("Is it safe to put the vault in cloud storage?"),
            Block::P(
                "The files are encrypted, so a cloud copy is a reasonable off-site backup. Do not \
                 let two machines write to the same synced copy at once, and never put the passwords \
                 in the same place.",
            ),
            Block::Sub("How should this be handed over?"),
            Block::P(
                "Tell your executor that the vault exists, where the folder is, where each password \
                 is kept, and that they should open it read-only. The URGENT tab is the first thing \
                 they should read.",
            ),
            Block::Sub("What if this program is gone by then?"),
            Block::P(
                "Keep a copy of the program with the backup. Failing that, `export-tree` turns a \
                 vault into an ordinary folder of files and JSON that any future tool can read — the \
                 data is never trapped in this format.",
            ),
            Block::Sub("What is the recommended routine?"),
            Block::Bullets(&[
                "Open read-only unless you intend to change something.",
                "Review the URGENT and Instructions tabs once a year.",
                "Back up after any session that changed anything, and keep a copy off-site.",
                "Check that your executor still knows where the passwords are.",
            ]),
        ],
    },
];

// --- Search ------------------------------------------------------------------

/// The searchable text of a topic: its title, blurb, section, and every word of
/// its body. Built on demand so the content table stays plain data.
fn haystack(t: &Topic) -> String {
    let mut s = String::with_capacity(512);
    s.push_str(t.title);
    s.push(' ');
    s.push_str(t.blurb);
    s.push(' ');
    s.push_str(t.section);
    for b in t.body {
        s.push(' ');
        match b {
            Block::P(p) | Block::Sub(p) | Block::Note(p) | Block::Warn(p) => s.push_str(p),
            Block::Bullets(items) | Block::Steps(items) => {
                for i in *items {
                    s.push_str(i);
                    s.push(' ');
                }
            }
            Block::Rows(rows) => {
                for (k, v) in *rows {
                    s.push_str(k);
                    s.push(' ');
                    s.push_str(v);
                    s.push(' ');
                }
            }
        }
    }
    s.to_lowercase()
}

/// Indices of the topics matching `query`, in manual order. Every whitespace-separated
/// word of the query must appear somewhere in the topic (AND semantics), which is what
/// makes a two-word query like "export documents" narrow rather than widen the result.
/// An empty/whitespace query matches everything.
///
/// A pure function of its input — unit-tested without a UI.
pub(crate) fn search(query: &str) -> Vec<usize> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return (0..TOPICS.len()).collect();
    }
    let words: Vec<&str> = q.split_whitespace().collect();
    TOPICS
        .iter()
        .enumerate()
        .filter(|(_, t)| {
            let hay = haystack(t);
            words.iter().all(|w| hay.contains(w))
        })
        .map(|(i, _)| i)
        .collect()
}

// --- Rendering ---------------------------------------------------------------

/// The mutable state the help browser keeps between frames. Lives in the app so
/// the user's place in the manual survives leaving and re-opening Help.
/// The default lands on the first topic with an empty search box — i.e. the
/// overview, which is what Help should open on.
#[derive(Default)]
pub(crate) struct HelpState {
    /// The search box's contents.
    pub(crate) query: String,
    /// Index into [`TOPICS`] of the article being shown.
    pub(crate) topic: usize,
}

/// The few live facts the manual shows alongside its static text.
pub(crate) struct HelpContext {
    /// This vault's path on disk.
    pub(crate) vault: String,
    /// The non-secret preferences file's path.
    pub(crate) prefs: String,
    /// Whether this session can make changes (shown as the mode badge).
    pub(crate) writable: bool,
}

/// Draw the help browser. Returns `true` when the user asked to go back.
///
/// Takes the accent color rather than reaching for the theme, so this module
/// stays independent of the theme enum in `gui`.
pub(crate) fn ui(ui: &mut egui::Ui, state: &mut HelpState, ctx: &HelpContext, accent: egui::Color32) -> bool {
    let mut back = false;

    // Header: title, mode badge, search, and the way out.
    egui::Panel::top("help_header").show_inside(ui, |ui| {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("⬅ Back").clicked() {
                back = true;
            }
            ui.add_space(4.0);
            ui.heading(egui::RichText::new("Help").color(accent));
            ui.label(
                egui::RichText::new(if ctx.writable { "write mode" } else { "read-only mode" })
                    .weak()
                    .small(),
            );
            // Right-align the search box so it keeps its place as the window resizes.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if !state.query.is_empty() && ui.button("×").on_hover_text("Clear the search").clicked() {
                    state.query.clear();
                }
                ui.add(
                    egui::TextEdit::singleline(&mut state.query)
                        .hint_text("🔍  Search the manual…")
                        .desired_width(260.0),
                );
            });
        });
        ui.add_space(6.0);
    });

    // Left: the index, grouped by section and filtered by the search box.
    let hits = search(&state.query);
    egui::Panel::left("help_nav").resizable(true).default_size(238.0).show_inside(ui, |ui| {
        ui.add_space(6.0);
        if hits.is_empty() {
            ui.label(egui::RichText::new("No topic matches that search.").weak().italics());
            return;
        }
        if !state.query.trim().is_empty() {
            ui.label(egui::RichText::new(format!("{} matching topic(s)", hits.len())).weak().small());
            ui.add_space(4.0);
        }
        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("help_nav_scroll").show(ui, |ui| {
            for section in SECTIONS {
                // Only draw a section header when the filter left something under it.
                let in_section: Vec<usize> =
                    hits.iter().copied().filter(|i| TOPICS[*i].section == *section).collect();
                if in_section.is_empty() {
                    continue;
                }
                ui.add_space(6.0);
                ui.label(egui::RichText::new(*section).strong().color(accent).small());
                for i in in_section {
                    if ui.selectable_label(state.topic == i, TOPICS[i].title).clicked() {
                        state.topic = i;
                    }
                }
            }
            ui.add_space(8.0);
        });
    });

    // Right: the selected article. If a search hid the current topic, show the
    // first hit instead of an article the index no longer lists.
    if !hits.is_empty() && !hits.contains(&state.topic) {
        state.topic = hits[0];
    }
    egui::CentralPanel::default().show_inside(ui, |ui| {
        let Some(topic) = TOPICS.get(state.topic) else { return };
        egui::ScrollArea::vertical().auto_shrink([false, false]).id_salt("help_body_scroll").show(ui, |ui| {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(topic.section).weak().small());
            ui.heading(topic.title);
            ui.label(egui::RichText::new(topic.blurb).italics().weak());
            ui.add_space(8.0);
            ui.separator();
            ui.add_space(6.0);
            for block in topic.body {
                render_block(ui, block, accent);
            }
            // The live paths belong with the article about files, not on every page.
            if topic.id == "overview" {
                ui.add_space(10.0);
                paths_card(ui, ctx);
            }
            ui.add_space(24.0);
        });
    });

    back
}

/// Render one content block. All of the manual's typography lives here.
fn render_block(ui: &mut egui::Ui, block: &Block, accent: egui::Color32) {
    match block {
        Block::P(text) => {
            ui.label(*text);
            ui.add_space(8.0);
        }
        Block::Sub(text) => {
            ui.add_space(6.0);
            ui.label(egui::RichText::new(*text).strong().size(15.5).color(accent));
            ui.add_space(4.0);
        }
        Block::Bullets(items) => {
            for item in *items {
                ui.horizontal_top(|ui| {
                    ui.label(egui::RichText::new("•").color(accent).strong());
                    ui.label(*item);
                });
                ui.add_space(3.0);
            }
            ui.add_space(6.0);
        }
        Block::Steps(items) => {
            for (n, item) in items.iter().enumerate() {
                ui.horizontal_top(|ui| {
                    ui.label(egui::RichText::new(format!("{}.", n + 1)).color(accent).strong());
                    ui.label(*item);
                });
                ui.add_space(3.0);
            }
            ui.add_space(6.0);
        }
        Block::Rows(rows) => {
            // A striped two-column grid; the left column is the thing being named
            // (a button, a command, a symptom), the right column what it means.
            egui::Grid::new(rows.as_ptr() as usize) // stable per-table id
                .num_columns(2)
                .striped(true)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    for (k, v) in *rows {
                        ui.label(egui::RichText::new(*k).strong());
                        ui.label(*v);
                        ui.end_row();
                    }
                });
            ui.add_space(10.0);
        }
        Block::Note(text) => {
            callout(ui, "ℹ", text, accent);
        }
        Block::Warn(text) => {
            callout(ui, "⚠", text, egui::Color32::from_rgb(200, 90, 20));
        }
    }
}

/// A tinted, left-barred aside used for both notes and warnings.
fn callout(ui: &mut egui::Ui, glyph: &str, text: &str, color: egui::Color32) {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.55)))
        .corner_radius(6)
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.horizontal_top(|ui| {
                ui.label(egui::RichText::new(glyph).color(color).strong());
                ui.label(text);
            });
        });
    ui.add_space(10.0);
}

/// The "where things are on this machine" card shown at the end of the overview.
fn paths_card(ui: &mut egui::Ui, ctx: &HelpContext) {
    egui::Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(6)
        .inner_margin(egui::Margin::same(10))
        .show(ui, |ui| {
            ui.label(egui::RichText::new("Files on this machine").strong());
            ui.add_space(6.0);
            egui::Grid::new("help_paths").num_columns(2).spacing([14.0, 6.0]).show(ui, |ui| {
                ui.label("This vault");
                ui.label(egui::RichText::new(&ctx.vault).monospace());
                ui.end_row();
                ui.label("Preferences");
                ui.label(egui::RichText::new(&ctx.prefs).monospace());
                ui.end_row();
            });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "The preferences file holds the theme, the view defaults, and the export \
                     directory. It contains no vault data and no secrets.",
                )
                .weak()
                .small(),
            );
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_topic_is_well_formed_and_uniquely_identified() {
        let mut ids: Vec<&str> = Vec::new();
        for t in TOPICS {
            assert!(!t.title.is_empty(), "topic {} has no title", t.id);
            assert!(!t.blurb.is_empty(), "topic {} has no blurb", t.id);
            assert!(!t.body.is_empty(), "topic {} has an empty body", t.id);
            assert!(
                SECTIONS.contains(&t.section),
                "topic {} is filed under unknown section {:?}",
                t.id,
                t.section
            );
            assert!(!ids.contains(&t.id), "duplicate topic id {}", t.id);
            ids.push(t.id);
        }
        // Every declared section must actually have topics, or the index would
        // render a heading with nothing under it.
        for s in SECTIONS {
            assert!(TOPICS.iter().any(|t| t.section == *s), "section {s:?} has no topics");
        }
    }

    #[test]
    fn search_matches_title_body_and_requires_every_word() {
        // Empty query = the whole manual.
        assert_eq!(search("").len(), TOPICS.len());
        assert_eq!(search("   ").len(), TOPICS.len());

        // Matches on the title, case-insensitively.
        let hits = search("URGENT");
        assert!(hits.iter().any(|i| TOPICS[*i].id == "tab-urgent"));

        // Matches on body text, not just titles: "Argon2id" appears only in prose.
        let hits = search("argon2id");
        assert!(!hits.is_empty(), "a word that appears only in body text must be findable");
        assert!(hits.iter().any(|i| TOPICS[*i].id == "passwords" || TOPICS[*i].id == "security"));

        // AND semantics: adding a word narrows the result rather than widening it.
        let one = search("export").len();
        let two = search("export clipboard").len();
        assert!(two <= one, "a second word must not widen the result set ({two} > {one})");

        // A word in no article matches nothing.
        assert!(search("zzzznotaword").is_empty());
    }

    #[test]
    fn troubleshooting_covers_the_failure_users_actually_hit() {
        // The read-only surprise is the single most common confusion, so the manual
        // must always answer it somewhere findable.
        let hits = search("read-only");
        assert!(hits.len() >= 2, "read-only must be documented in more than one place");
        assert!(!search("password rejected").is_empty() || !search("passwords are rejected").is_empty());
    }
}
