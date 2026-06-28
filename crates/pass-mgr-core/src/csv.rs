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
    self, Account, AssetLiability, GeneralDocument, Instruction, RealEstate, TaxFiling, TrustWill,
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
}
