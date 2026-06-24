//! Backward-compatibility GOLDEN fixture.
//!
//! Every other on-disk-format test constructs the vault at runtime with the CURRENT
//! code, so the reader and writer drift together: a silent change to the binary layout
//! (field order, endianness, header offsets, an AAD prefix string) still self-round-trips
//! and passes them all — while making every PREVIOUSLY-saved vault permanently unreadable.
//!
//! This test instead opens a real v4 vault committed as FROZEN BYTES under
//! `tests/fixtures/golden_v4/` (built once by an earlier build), proving today's reader
//! still opens vaults written by older code, and pins the deterministic header prefix.
//! If this test ever fails, the on-disk format changed in a vault-bricking way: it must
//! be paired with a `FORMAT_VERSION` bump + migration and a regenerated fixture — never a
//! silent edit to "make the test pass".

use std::path::{Path, PathBuf};

use pass_mgr_core::vault::OpenVault;

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "pmgold-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn committed_v4_vault_still_opens_and_header_prefix_is_pinned() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden_v4");

    // (1) Pin the DETERMINISTIC header prefix: MAGIC | version=4 | m/t/p_cost (LE u32).
    // Bytes 21..61 (salt + nonce) are random per write and intentionally excluded.
    let raw = std::fs::read(fixture.join("vault.pmv")).expect("golden fixture present");
    let prefix: String = raw[0..21].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        prefix, "504d5641554c540004000100000100000001000000",
        "on-disk header layout (magic/version/Argon2 params) changed — existing vaults may not open"
    );

    // (2) Open the FROZEN bytes (read-only writes nothing) from a temp copy, so the
    // committed fixture is never mutated, and verify the decrypted contents + a blob.
    let work = tmp("open");
    copy_dir(&fixture, &work);
    let ov = OpenVault::open_read_only(work.join("vault.pmv"), b"golden-pw-one", b"golden-pw-two")
        .expect("a v4 vault written by an earlier build must still open with today's reader");

    let acc = ov
        .vault
        .accounts
        .iter()
        .find(|a| a.id == "golden-account-id")
        .expect("the golden account survives the format");
    assert_eq!(acc.username, "golden-user");
    assert_eq!(acc.password, "golden-secret", "the encrypted account password still decrypts verbatim");

    let tw = ov
        .vault
        .trust_wills
        .iter()
        .find(|t| t.id == "golden-tw-id")
        .expect("the golden trust-will survives the format");
    let blob = tw.file.clone().expect("the trust-will's attached blob id");
    assert_eq!(
        &**ov.read_document(&blob).unwrap(),
        &b"golden-document-bytes"[..],
        "the committed volume frame still decrypts to the original document bytes"
    );

    drop(ov);
    std::fs::remove_dir_all(&work).ok();
}
