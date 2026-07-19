//! Build a throwaway demo vault full of obviously-fake data.
//!
//! Usage:
//!   cargo run -p pass-mgr --example seed_sample_vault -- <DIR> <PASSWORD1> <PASSWORD2>
//!
//! Creates `<DIR>/vault.pmv` plus its `manifest/` and `volume/`, populated across every
//! tab: URGENT notes, instructions, trust & will, assets and liabilities (with links to
//! accounts), accounts, real estate (with all four portal logins), tax filings, and
//! general documents — plus a few attached documents so the encrypted volume is real.
//!
//! Everything in here is fiction. The "passwords" are visibly fake placeholders so a
//! demo vault can never be mistaken for a real one, and nothing resembles a working
//! credential for any real service.
//!
//! This is an example, not part of the shipped binaries — `cargo build` does not
//! compile it, and it is never reachable from the app.

use pass_mgr::crypto::KdfParams;
use pass_mgr::records::{
    self, Account, AssetLiability, GeneralDocument, Instruction, RealEstate, TaxFiling, TrustWill, Urgent,
};
use pass_mgr::vault::OpenVault;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir, pw1, pw2] = args.as_slice() else {
        anyhow::bail!("usage: seed_sample_vault <DIR> <PASSWORD1> <PASSWORD2>");
    };
    let dir = PathBuf::from(dir);
    let path = dir.join("vault.pmv");
    if path.exists() {
        anyhow::bail!("{} already exists — refusing to overwrite it", path.display());
    }
    std::fs::create_dir_all(&dir)?;

    // Default KDF params: the demo vault should open exactly as slowly as a real one,
    // so it is a faithful thing to click around in.
    let mut v = OpenVault::create(path.clone(), pw1.as_bytes(), pw2.as_bytes(), KdfParams::default())?;

    // --- Category lists (these drive the dropdowns) --------------------------
    for t in ["Real Estate", "Brokerage", "Retirement", "Cash", "Vehicle", "Mortgage", "Credit Line"] {
        v.add_asset_type(t)?;
    }
    for (t, subs) in [
        ("Banking", &["Checking", "Savings"][..]),
        ("Brokerage", &["Taxable", "IRA", "401k"][..]),
        ("Utilities", &["Electric", "Water", "Internet"][..]),
        ("Insurance", &["Home", "Auto", "Life"][..]),
        ("Email", &[][..]),
    ] {
        v.add_account_type(t)?;
        for s in subs {
            v.add_account_subtype(t, s)?;
        }
    }

    // --- A scratch file to attach as a "document" ---------------------------
    let scratch = dir.join("_sample_source.txt");

    // --- URGENT (the first thing an executor should read) -------------------
    for (title, body) in [
        (
            "Read this first",
            "1. Call Dana Okafor (attorney) — 555-0142.\n2. The original signed will is in the \
             fire safe in the study; the combination is in the Trust & Will tab.\n3. Do NOT cancel \
             the homeowner's policy until the house sale closes.",
        ),
        (
            "Auto-payments to stop",
            "The lawn service and the gym membership both auto-charge the Everyday Checking \
             account on the 3rd. Cancel them before then or the account will overdraw.",
        ),
    ] {
        let mut r = Urgent::new()?;
        r.title = title.into();
        r.description = body.into();
        records::upsert(&mut v.vault.urgent, r);
    }

    // --- Instructions -------------------------------------------------------
    for (title, body) in [
        (
            "Funeral wishes",
            "Cremation, no formal service. Scatter at Cape Perpetua. There is a prepaid \
             arrangement with Harbor Memorial (contract number in General Documents).",
        ),
        (
            "Who to contact, in order",
            "Dana Okafor (attorney) → Priya Raman (accountant) → the bank's estate desk. \
             Do not contact the brokerage before the attorney has the death certificate.",
        ),
        (
            "The house",
            "Sell rather than rent. Marek next door has a key and has agreed to check on it \
             weekly until it is listed.",
        ),
    ] {
        let mut r = Instruction::new()?;
        r.title = title.into();
        r.description = body.into();
        records::upsert(&mut v.vault.instructions, r);
    }

    // --- Trust & Will (with an attached "scan") -----------------------------
    std::fs::write(&scratch, b"SAMPLE SCAN - Last Will and Testament (fictional).\n")?;
    let will_doc = v.add_document("trust-will", "will-2024-signed.txt", &scratch)?;
    let mut tw = TrustWill::new()?;
    tw.document = "Last Will and Testament (2024)".into();
    tw.usage = "Signed original is in the study fire safe, combination 24-11-06. This scan is \
                a convenience copy — the signed paper is the one with legal force. Drafted by \
                Dana Okafor, Okafor & Lund."
        .into();
    tw.file = Some(will_doc);
    records::upsert(&mut v.vault.trust_wills, tw);

    let mut tw2 = TrustWill::new()?;
    tw2.document = "Durable Power of Attorney".into();
    tw2.usage = "Names Sam Okonkwo as agent. Revoked on death — included so the executor knows \
                 it exists and is no longer operative."
        .into();
    records::upsert(&mut v.vault.trust_wills, tw2);

    // --- Accounts -----------------------------------------------------------
    // Kept first so assets can link to their ids.
    let accounts: Vec<(&str, &str, &str, &str, &str, &str)> = vec![
        ("Everyday Checking", "Banking", "Checking", "Jordan Vale", "jvale", "sample-not-a-real-password-1"),
        ("Rainy Day Savings", "Banking", "Savings", "Jordan Vale", "jvale", "sample-not-a-real-password-2"),
        ("Brokerage — taxable", "Brokerage", "Taxable", "Jordan Vale", "jordan.vale", "sample-not-a-real-password-3"),
        ("Rollover IRA", "Brokerage", "IRA", "Jordan Vale", "jordan.vale", "sample-not-a-real-password-4"),
        ("City Power", "Utilities", "Electric", "Jordan Vale", "jvale@example.invalid", "sample-not-a-real-password-5"),
        ("Home policy", "Insurance", "Home", "Jordan Vale", "jvale@example.invalid", "sample-not-a-real-password-6"),
        ("Primary email", "Email", "", "Jordan Vale", "jordan.vale@example.invalid", "sample-not-a-real-password-7"),
        ("Joint Checking", "Banking", "Checking", "Alex Vale", "avale", "sample-not-a-real-password-8"),
    ];
    let mut acct_ids = std::collections::HashMap::new();
    for (title, ty, sub, owner, user, pw) in accounts {
        let mut a = Account::new()?;
        a.title = title.into();
        a.account_type = ty.into();
        a.account_subtype = sub.into();
        a.owner = owner.into();
        a.username = user.into();
        a.password = pw.into();
        a.url = format!("https://{}.example.invalid/login", title.to_lowercase().replace(' ', "-"));
        a.description = "Demo record — not a real account.".into();
        acct_ids.insert(title.to_string(), a.id.clone());
        records::upsert(&mut v.vault.accounts, a);
    }
    // One flagged for review, to exercise that filter.
    if let Some(a) = v.vault.accounts.iter_mut().find(|a| a.title == "City Power") {
        a.review = true;
    }

    // --- Assets & liabilities (some linked to the accounts above) -----------
    std::fs::write(&scratch, b"SAMPLE STATEMENT - brokerage, Q4 (fictional).\n")?;
    let stmt_doc = v.add_document("assets", "brokerage-q4.txt", &scratch)?;

    let assets: Vec<(&str, &str, &str, &str, &str, &str, Vec<&str>)> = vec![
        ("Asset", "412 Alder Street", "Jordan Vale", "540000", "Real Estate", "", vec![]),
        ("Asset", "Brokerage — taxable", "Jordan Vale", "128400.55", "Brokerage", "Meridian Brokerage", vec!["Brokerage — taxable"]),
        ("Asset", "Rollover IRA", "Jordan Vale", "233900", "Retirement", "Meridian Brokerage", vec!["Rollover IRA"]),
        ("Asset", "Everyday Checking", "Jordan Vale", "8420.12", "Cash", "First Harbor Bank", vec!["Everyday Checking"]),
        ("Asset", "Rainy Day Savings", "Jordan Vale", "31000", "Cash", "First Harbor Bank", vec!["Rainy Day Savings"]),
        ("Asset", "2019 estate wagon", "Alex Vale", "14500", "Vehicle", "", vec![]),
        ("Asset", "Joint Checking", "Alex Vale", "6100", "Cash", "First Harbor Bank", vec!["Joint Checking"]),
        ("Liability", "Mortgage — 412 Alder Street", "Jordan Vale", "268300", "Mortgage", "First Harbor Bank", vec![]),
        ("Liability", "Credit card", "Jordan Vale", "2140.88", "Credit Line", "First Harbor Bank", vec![]),
    ];
    for (kind, title, owner, value, ty, inst, links) in assets {
        let mut a = AssetLiability::new()?;
        a.kind = kind.into();
        a.title = title.into();
        a.owner = owner.into();
        a.approx_value = value.into();
        a.asset_type = ty.into();
        a.institution = inst.into();
        a.as_of_date = "2026-01-31".into();
        a.description = "Demo record — figures are invented.".into();
        a.linked_accounts = links.iter().filter_map(|t| acct_ids.get(*t).cloned()).collect();
        if title == "Brokerage — taxable" {
            a.statement = Some(stmt_doc.clone());
        }
        records::upsert(&mut v.vault.assets, a);
    }

    // --- Real estate (all four portals) -------------------------------------
    std::fs::write(&scratch, b"SAMPLE DEED (fictional).\n")?;
    let deed = v.add_document("real-estate", "deed-412-alder.txt", &scratch)?;
    let mut re = RealEstate::new()?;
    re.address = "412 Alder Street, Corvallis OR 97330".into();
    re.owner = "Jordan Vale".into();
    re.taxes = "≈ $6,200/yr, Benton County".into();
    re.hoa = "None".into();
    re.income_account = "n/a — owner occupied".into();
    re.financing_account = "First Harbor Bank mortgage #SAMPLE-0000".into();
    re.payment_account = "Everyday Checking (auto-pay, 1st of month)".into();
    re.financing_balance = "268300".into();
    re.property_mgmt_url = "https://propmgmt.example.invalid".into();
    re.property_mgmt_username = "jvale".into();
    re.property_mgmt_password = "sample-not-a-real-password-9".into();
    re.property_mgmt_comment = "Only used while the house was rented in 2021.".into();
    re.insurance_url = "https://homeins.example.invalid".into();
    re.insurance_username = "jvale@example.invalid".into();
    re.insurance_password = "sample-not-a-real-password-10".into();
    re.insurance_comment = "Policy SAMPLE-HO-000. Do not cancel until the sale closes.".into();
    re.hoa_url = String::new();
    re.hoa_username = String::new();
    re.hoa_password = String::new();
    re.hoa_comment = "No HOA for this property.".into();
    re.tax_portal_url = "https://taxes.example.invalid".into();
    re.tax_portal_username = "jvale".into();
    re.tax_portal_password = "sample-not-a-real-password-11".into();
    re.tax_portal_comment = "County portal. Security question answer is the street you grew up on.".into();
    re.comments = "Roof replaced 2022; receipts in General Documents.".into();
    re.documents = vec![deed];
    records::upsert(&mut v.vault.real_estate, re);

    // --- Taxes --------------------------------------------------------------
    std::fs::write(&scratch, b"SAMPLE 1040 (fictional).\n")?;
    let ret_2025 = v.add_document("taxes", "return-2025.txt", &scratch)?;
    let mut tf = TaxFiling::new()?;
    tf.year = "2025".into();
    tf.owner = "Jordan Vale".into();
    tf.notes = "Filed jointly. Prepared by Priya Raman CPA, 555-0188. Refund applied to 2026 \
                estimated tax."
        .into();
    tf.documents = vec![ret_2025];
    records::upsert(&mut v.vault.tax_filings, tf);

    let mut tf2 = TaxFiling::new()?;
    tf2.year = "2024".into();
    tf2.owner = "Jordan Vale".into();
    tf2.notes = "Filed jointly. Paper copy in the study filing cabinet.".into();
    records::upsert(&mut v.vault.tax_filings, tf2);

    // --- General documents --------------------------------------------------
    std::fs::write(&scratch, b"SAMPLE PASSPORT SCAN (fictional).\n")?;
    let passport = v.add_document("general", "passport.txt", &scratch)?;
    let mut g = GeneralDocument::new()?;
    g.title = "Passport — Jordan Vale".into();
    g.description = "Expires 2029. Original in the fire safe.".into();
    g.file = Some(passport);
    records::upsert(&mut v.vault.general_documents, g);

    let mut g2 = GeneralDocument::new()?;
    g2.title = "Prepaid funeral contract".into();
    g2.description = "Harbor Memorial, contract SAMPLE-4417. Paid in full 2023.".into();
    records::upsert(&mut v.vault.general_documents, g2);

    v.save()?;
    let _ = std::fs::remove_file(&scratch);

    println!("Sample vault created at {}", dir.display());
    println!(
        "  {} urgent · {} instructions · {} trust&will · {} assets/liabilities · {} accounts · \
         {} real estate · {} tax filings · {} general documents",
        v.vault.urgent.len(),
        v.vault.instructions.len(),
        v.vault.trust_wills.len(),
        v.vault.assets.len(),
        v.vault.accounts.len(),
        v.vault.real_estate.len(),
        v.vault.tax_filings.len(),
        v.vault.general_documents.len(),
    );
    Ok(())
}
