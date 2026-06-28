//! Plain-text CSV export of the vault's record tabs (RFC 4180 quoting).
//!
//! Each `*_csv` function turns one tab's records into a CSV string: a header row
//! followed by one row per record, in the same field order as the struct. The text
//! is meant to be written to disk by the front-ends (see `vault::write_export_bytes`)
//! into the user's configured export directory.
//!
//! Design notes:
//! * Document/file columns hold the file **names**, not the internal volume blob ids.
//!   The caller passes a `name_of` resolver (typically `OpenVault::doc_path` reduced to
//!   its basename via [`basename`]); a record with several documents gets them joined
//!   with `"; "`, and a missing/tombstoned id resolves to an empty cell.
//! * Every cell is first run through [`records::display_safe`], which replaces control
//!   characters and Unicode bidi/zero-width spoof characters with `_`. That keeps the
//!   export strictly one physical line per record (embedded newlines become `_`) and
//!   prevents a crafted field from spoofing a spreadsheet/terminal. It does NOT alter
//!   ordinary printable text, so realistic data — including generated passwords — round
//!   trips unchanged. Values are NOT otherwise mangled (no anti-formula prefixing), so a
//!   plaintext-password export stays faithful for migrating into another manager.
//! * Line endings are CRLF, per RFC 4180.
//!
//! Secret handling: the Accounts / Real-Estate CSVs contain plaintext passwords by the
//! user's explicit opt-in, and the front-ends move the FINAL assembled string into a
//! `Zeroizing` buffer (and write the file 0600). The transient intermediates here — the
//! growing `out` buffer's pre-reallocation copies, plus the small per-cell strings from
//! `display_safe`/`esc` — are plain `String`s and are NOT zeroized, so password fragments
//! can briefly linger in freed heap (cf. `vault::serialize_secret_json`, which pre-sizes to
//! avoid this for the on-disk vault). That residue is deliberately tolerated here: the whole
//! point of this export is to put those same secrets on disk in cleartext, so the marginal
//! in-memory exposure is not worth a counting-pass rewrite.

use crate::records::{
    self, Account, AssetLiability, GeneralDocument, Instruction, RealEstate, TaxFiling, TrustWill, Vault,
};

/// The basename of a volume virtual path (`taxes/2024/<ts>/w2.pdf` -> `w2.pdf`).
/// Used by the front-ends to turn a resolved `doc_path` into a bare file name.
pub fn basename(virtual_path: &str) -> String {
    virtual_path.rsplit('/').next().unwrap_or(virtual_path).to_string()
}

/// RFC 4180-escape one cell: neutralize control/bidi/zero-width chars, then wrap in
/// double quotes (doubling any internal quote) when the value contains a comma or a
/// quote, or has leading/trailing whitespace. After `display_safe` no CR/LF remains,
/// so quoting is only ever needed for commas, quotes, and edge spaces.
fn esc(s: &str) -> String {
    let safe = records::display_safe(s);
    let needs_quote =
        safe.contains(',') || safe.contains('"') || safe.starts_with(' ') || safe.ends_with(' ');
    if needs_quote {
        let mut out = String::with_capacity(safe.len() + 2);
        out.push('"');
        out.push_str(&safe.replace('"', "\"\""));
        out.push('"');
        out
    } else {
        safe
    }
}

/// Append one CSV record line (escaped cells, comma-separated, CRLF-terminated).
fn row(out: &mut String, cells: &[&str]) {
    for (i, c) in cells.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&esc(c));
    }
    out.push_str("\r\n");
}

/// A human-readable UTC timestamp `YYYY-MM-DD HH:MM:SSZ` for the created/updated cells.
fn iso_utc(unix: i64) -> String {
    let (y, mo, d, h, mi, s) = records::civil_from_unix(unix);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}Z")
}

fn yn(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// Resolve a list of document ids to a `"; "`-joined list of file names (empties dropped).
fn join_names(ids: &[String], name_of: &impl Fn(&str) -> String) -> String {
    ids.iter().map(|id| name_of(id)).filter(|n| !n.is_empty()).collect::<Vec<_>>().join("; ")
}

/// Resolve an optional single document id to its file name (empty when `None`/unresolved).
fn opt_name(opt: &Option<String>, name_of: &impl Fn(&str) -> String) -> String {
    opt.as_deref().map(name_of).unwrap_or_default()
}

// --- Per-tab exporters -------------------------------------------------------

pub fn instructions_csv(rows: &[Instruction]) -> String {
    let mut out = String::new();
    row(&mut out, &["id", "title", "description", "created", "updated"]);
    for r in rows {
        let created = iso_utc(r.created_at);
        let updated = iso_utc(r.updated_at);
        row(&mut out, &[&r.id, &r.title, &r.description, &created, &updated]);
    }
    out
}

pub fn trust_wills_csv(rows: &[TrustWill], name_of: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    row(&mut out, &["id", "document", "usage", "file", "created", "updated"]);
    for r in rows {
        let file = opt_name(&r.file, &name_of);
        let created = iso_utc(r.created_at);
        let updated = iso_utc(r.updated_at);
        row(&mut out, &[&r.id, &r.document, &r.usage, &file, &created, &updated]);
    }
    out
}

pub fn assets_csv(rows: &[AssetLiability], name_of: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    row(
        &mut out,
        &[
            "id", "kind", "description", "owner", "title", "approx_value", "as_of_date",
            "institution", "asset_type", "url", "beneficiary", "review", "statement", "created",
            "updated",
        ],
    );
    for r in rows {
        let review = yn(r.review);
        let statement = opt_name(&r.statement, &name_of);
        let created = iso_utc(r.created_at);
        let updated = iso_utc(r.updated_at);
        row(
            &mut out,
            &[
                &r.id, &r.kind, &r.description, &r.owner, &r.title, &r.approx_value, &r.as_of_date,
                &r.institution, &r.asset_type, &r.url, &r.beneficiary, review, &statement, &created,
                &updated,
            ],
        );
    }
    out
}

pub fn accounts_csv(rows: &[Account]) -> String {
    let mut out = String::new();
    row(
        &mut out,
        &[
            "id", "title", "account_type", "account_subtype", "owner", "username", "password",
            "description", "url", "closed_as_of", "review", "created", "updated",
        ],
    );
    for r in rows {
        let review = yn(r.review);
        let created = iso_utc(r.created_at);
        let updated = iso_utc(r.updated_at);
        row(
            &mut out,
            &[
                &r.id, &r.title, &r.account_type, &r.account_subtype, &r.owner, &r.username,
                &r.password, &r.description, &r.url, &r.closed_as_of, review, &created, &updated,
            ],
        );
    }
    out
}

pub fn real_estate_csv(rows: &[RealEstate], name_of: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    row(
        &mut out,
        &[
            "id", "address", "ownership", "taxes", "hoa", "income_account", "financing_account",
            "payment_account", "financing_balance", "property_mgmt_url", "property_mgmt_username",
            "property_mgmt_password", "property_mgmt_comment", "insurance_url", "insurance_username",
            "insurance_password", "insurance_comment", "hoa_url", "hoa_username", "hoa_password",
            "hoa_comment", "tax_portal_url", "tax_portal_username", "tax_portal_password",
            "tax_portal_comment", "comments", "documents", "created", "updated",
        ],
    );
    for r in rows {
        let docs = join_names(&r.documents, &name_of);
        let created = iso_utc(r.created_at);
        let updated = iso_utc(r.updated_at);
        row(
            &mut out,
            &[
                &r.id, &r.address, &r.ownership, &r.taxes, &r.hoa, &r.income_account,
                &r.financing_account, &r.payment_account, &r.financing_balance, &r.property_mgmt_url,
                &r.property_mgmt_username, &r.property_mgmt_password, &r.property_mgmt_comment,
                &r.insurance_url, &r.insurance_username, &r.insurance_password, &r.insurance_comment,
                &r.hoa_url, &r.hoa_username, &r.hoa_password, &r.hoa_comment, &r.tax_portal_url,
                &r.tax_portal_username, &r.tax_portal_password, &r.tax_portal_comment, &r.comments,
                &docs, &created, &updated,
            ],
        );
    }
    out
}

pub fn tax_filings_csv(rows: &[TaxFiling], name_of: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    row(&mut out, &["id", "owner", "year", "notes", "documents", "created", "updated"]);
    for r in rows {
        let docs = join_names(&r.documents, &name_of);
        let created = iso_utc(r.created_at);
        let updated = iso_utc(r.updated_at);
        row(&mut out, &[&r.id, &r.owner, &r.year, &r.notes, &docs, &created, &updated]);
    }
    out
}

pub fn general_documents_csv(rows: &[GeneralDocument], name_of: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    row(&mut out, &["id", "title", "description", "file", "created", "updated"]);
    for r in rows {
        let file = opt_name(&r.file, &name_of);
        let created = iso_utc(r.created_at);
        let updated = iso_utc(r.updated_at);
        row(&mut out, &[&r.id, &r.title, &r.description, &file, &created, &updated]);
    }
    out
}

// --- Tab dispatch (shared by both front-ends) --------------------------------

/// Which record tab to export. Lets the GUI and TUI share ONE tab -> collection
/// mapping (each front-end has its own `Tab` enum but maps it to this), so adding a
/// record type or changing a base filename is a single-site change here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CsvTab {
    Instructions,
    TrustWill,
    Assets,
    Accounts,
    RealEstate,
    Taxes,
    GeneralDocuments,
}

/// Build the CSV for one tab's records: returns the base filename (the front-ends append
/// `-<timestamp>.csv`), the CSV text, and the record count. `name_of` resolves a document
/// blob id to its file name. The text may contain plaintext passwords (Accounts / Real
/// Estate) by the user's explicit opt-in; the front-ends hold it in `Zeroizing`.
pub fn build_tab_csv(v: &Vault, tab: CsvTab, name_of: impl Fn(&str) -> String) -> (&'static str, String, usize) {
    match tab {
        CsvTab::Instructions => ("instructions", instructions_csv(&v.instructions), v.instructions.len()),
        CsvTab::TrustWill => ("trust-will", trust_wills_csv(&v.trust_wills, name_of), v.trust_wills.len()),
        CsvTab::Assets => ("assets-liabilities", assets_csv(&v.assets, name_of), v.assets.len()),
        CsvTab::Accounts => ("accounts", accounts_csv(&v.accounts), v.accounts.len()),
        CsvTab::RealEstate => ("real-estate", real_estate_csv(&v.real_estate, name_of), v.real_estate.len()),
        CsvTab::Taxes => ("taxes", tax_filings_csv(&v.tax_filings, name_of), v.tax_filings.len()),
        CsvTab::GeneralDocuments => {
            ("general-documents", general_documents_csv(&v.general_documents, name_of), v.general_documents.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A resolver that just echoes the id as a "name", to exercise document columns.
    fn echo(id: &str) -> String {
        id.to_string()
    }

    #[test]
    fn basename_takes_last_path_component() {
        assert_eq!(basename("taxes/2024/20240101-000000/w2.pdf"), "w2.pdf");
        assert_eq!(basename("flat.txt"), "flat.txt");
        assert_eq!(basename(""), "");
    }

    #[test]
    fn esc_quotes_only_when_needed() {
        assert_eq!(esc("plain"), "plain");
        assert_eq!(esc("a,b"), "\"a,b\"");
        assert_eq!(esc("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(esc(" leading"), "\" leading\"");
        assert_eq!(esc("trailing "), "\"trailing \"");
        // Control chars (here a newline) are neutralized to '_', not quoted.
        assert_eq!(esc("line1\nline2"), "line1_line2");
    }

    #[test]
    fn accounts_csv_has_header_and_one_row_per_record_with_password() {
        let mut a = Account::new().unwrap();
        a.id = "id1".into();
        a.title = "My, Bank".into(); // comma forces quoting
        a.owner = "Jane".into();
        a.username = "jane".into();
        a.password = "p@ss=w0rd".into(); // included verbatim (no anti-formula mangling)
        a.review = true;
        let out = accounts_csv(&[a]);
        let lines: Vec<&str> = out.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2, "header + one record");
        assert!(lines[0].starts_with("id,title,account_type"));
        assert!(lines[0].contains(",password,"));
        assert!(lines[1].contains("\"My, Bank\""), "comma field is quoted");
        assert!(lines[1].contains("p@ss=w0rd"), "password exported in plaintext");
        assert!(lines[1].contains(",yes,"), "review bool rendered yes/no");
    }

    #[test]
    fn tax_filings_csv_owner_year_and_doc_names() {
        let mut t = TaxFiling::new().unwrap();
        t.id = "t1".into();
        t.owner = "Joint".into();
        t.year = "2024".into();
        t.documents = vec!["docA".into(), "docB".into()];
        let out = tax_filings_csv(&[t], echo);
        let line = out.split("\r\n").nth(1).unwrap();
        assert!(line.contains("Joint"));
        assert!(line.contains("2024"));
        assert!(line.contains("docA; docB"), "multiple doc names joined with '; '");
    }

    #[test]
    fn empty_list_still_emits_header_only() {
        let out = instructions_csv(&[]);
        assert_eq!(out, "id,title,description,created,updated\r\n");
    }

    #[test]
    fn realestate_csv_resolves_document_names_and_keeps_portal_passwords() {
        let mut r = RealEstate::new().unwrap();
        r.id = "re1".into();
        r.address = "1 Main St".into();
        r.tax_portal_password = "secret".into();
        r.documents = vec!["deed".into()];
        let out = real_estate_csv(&[r], echo);
        let line = out.split("\r\n").nth(1).unwrap();
        assert!(line.contains("1 Main St"));
        assert!(line.contains("secret"), "portal password kept in plaintext");
        assert!(line.contains("deed"), "document name resolved");
    }

    #[test]
    fn assets_csv_header_columns_review_and_statement() {
        let mut a = AssetLiability::new().unwrap();
        a.id = "a1".into();
        a.kind = "Asset".into();
        a.description = "Brokerage".into();
        a.owner = "Jane".into();
        a.review = true;
        a.statement = Some("stmt".into());
        let out = assets_csv(&[a], echo);
        let lines: Vec<&str> = out.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("id,kind,description,owner,title,approx_value"), "header field order: {}", lines[0]);
        assert!(lines[0].ends_with(",statement,created,updated"));
        assert!(lines[1].contains(",yes,"), "review=true -> yes");
        assert!(lines[1].contains("stmt"), "statement doc id resolved to a name");
    }

    #[test]
    fn trust_wills_and_general_documents_resolve_optional_file_or_empty() {
        let mut tw = TrustWill::new().unwrap();
        tw.id = "tw1".into();
        tw.document = "Living Trust".into();
        tw.file = Some("trust.pdf".into());
        let twl = trust_wills_csv(&[tw], echo);
        assert!(twl.split("\r\n").next().unwrap().starts_with("id,document,usage,file,"));
        assert!(twl.split("\r\n").nth(1).unwrap().contains("trust.pdf"));

        let mut g = GeneralDocument::new().unwrap();
        g.id = "g1".into();
        g.title = "Passport".into();
        g.file = None; // no attachment -> empty file cell, no panic
        let gl = general_documents_csv(&[g], echo);
        let row = gl.split("\r\n").nth(1).unwrap();
        // The penultimate column group is `file,created,updated`; file must be empty.
        assert!(row.starts_with("g1,Passport,"), "row: {row}");
    }

    #[test]
    fn join_names_drops_unresolved_ids_without_trailing_separator() {
        // A resolver that fails to resolve "gone" (tombstoned/missing doc) -> empty name.
        let resolve = |id: &str| if id == "gone" { String::new() } else { id.to_string() };
        let mut t = TaxFiling::new().unwrap();
        t.id = "t".into();
        t.documents = vec!["deed".into(), "gone".into()];
        let line = tax_filings_csv(&[t], resolve).split("\r\n").nth(1).unwrap().to_string();
        assert!(line.contains("deed"), "live doc name present");
        assert!(!line.contains("deed;"), "no dangling '; ' for the dropped unresolved id: {line}");
        assert!(!line.contains("; "), "the only doc cell holds a single resolved name");
    }

    #[test]
    fn iso_utc_is_fixed_width_for_extreme_timestamps() {
        // civil_from_unix clamps the domain, so the CSV created/updated columns stay fixed-width
        // even for a crafted i64::MAX/MIN timestamp (no widened year breaking the column).
        assert_eq!(iso_utc(0), "1970-01-01 00:00:00Z");
        assert!(iso_utc(i64::MAX).starts_with("9999-12-31"));
        assert_eq!(iso_utc(i64::MAX).len(), iso_utc(0).len(), "fixed width regardless of value");
        assert_eq!(iso_utc(i64::MIN), "1970-01-01 00:00:00Z");
    }

    #[test]
    fn u2028_line_separator_is_neutralized_in_a_cell() {
        // U+2028 must not survive into a CSV cell as a real line break (regression guard
        // for the display_safe gap). The whole record stays one physical line.
        let mut a = Account::new().unwrap();
        a.id = "x".into();
        a.title = "a\u{2028}b".into();
        let out = accounts_csv(&[a]);
        assert_eq!(out.matches("\r\n").count(), 2, "header + exactly one record line");
        assert!(out.contains("a_b"), "U+2028 replaced with '_'");
    }

    #[test]
    fn build_tab_csv_maps_each_tab_to_its_collection() {
        let mut v = Vault::default();
        let mut acc = Account::new().unwrap();
        acc.title = "Bank".into();
        v.accounts.push(acc);
        let mut tax = TaxFiling::new().unwrap();
        tax.owner = "Joint".into();
        v.tax_filings.push(tax);

        let (base, text, n) = build_tab_csv(&v, CsvTab::Accounts, echo);
        assert_eq!(base, "accounts");
        assert_eq!(n, 1);
        assert!(text.contains("Bank"));

        let (base, text, n) = build_tab_csv(&v, CsvTab::Taxes, echo);
        assert_eq!(base, "taxes");
        assert_eq!(n, 1);
        assert!(text.contains("Joint"));

        // A tab with no records yields a header-only CSV and count 0.
        let (base, _t, n) = build_tab_csv(&v, CsvTab::Instructions, echo);
        assert_eq!((base, n), ("instructions", 0));
    }
}
