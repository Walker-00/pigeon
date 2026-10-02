use std::collections::BTreeSet;

use chrono::Utc;
use pigeon::crypto::{MasterKey, Vault, VaultError};
use pigeon::store::Store;
use pigeon::store::model::{Addr, Envelope, Flags};

const SECRET_SUBJECT: &str = "Quarterly figures for Northwind Traders";
const SECRET_BODY: &str = "the merger closes on the fourteenth of March";
const SECRET_SENDER: &str = "ada.lovelace@analytical-engine.example";

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pigeon-test-{tag}-{}-{}",
        std::process::id(),
        uuid_like()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn uuid_like() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn sample(uid: u32) -> Envelope {
    Envelope {
        account: "personal".into(),
        folder: "INBOX".into(),
        uid,
        modseq: 0,
        message_id: Some(format!("msg-{uid}@example.org")),
        in_reply_to: None,
        references: Vec::new(),
        thread_id: None,
        subject: SECRET_SUBJECT.into(),
        from: vec![Addr::named("Ada Lovelace", SECRET_SENDER)],
        sender: Vec::new(),
        reply_to: Vec::new(),
        to: vec![Addr::new("bob@example.org")],
        cc: Vec::new(),
        bcc: Vec::new(),
        list_id: None,
        date: Utc::now(),
        received: None,
        size: 4096,
        flags: Flags::EMPTY,
        keywords: BTreeSet::new(),
        tags: BTreeSet::new(),
        preview: SECRET_BODY.into(),
        attachments: Vec::new(),
        crypto: Default::default(),
        body_blob: None,
        has_html: false,
    }
}

#[test]
fn database_file_contains_no_plaintext() {
    let dir = temp_dir("at-rest");
    let vault_path = dir.join("vault.key");
    let db_path = dir.join("mail.redb");

    let vault = Vault::create(&vault_path, b"correct horse battery staple").expect("create vault");
    let store = Store::open(&db_path, vault.key()).expect("open store");

    store.put_envelopes(&[sample(1), sample(2)]).expect("store envelopes");
    store
        .put_blob("body:personal:INBOX:1", SECRET_BODY.as_bytes())
        .expect("store blob");
    drop(store);

    let raw = std::fs::read(&db_path).expect("read database");

    for needle in [SECRET_SUBJECT, SECRET_BODY, SECRET_SENDER, "INBOX"] {
        assert!(
            !contains(&raw, needle.as_bytes()),
            "`{needle}` was found in plaintext inside the database file"
        );
    }

    let vault_raw = std::fs::read(&vault_path).expect("read vault");
    assert!(
        !contains(&vault_raw, b"correct horse battery staple"),
        "the passphrase leaked into the vault header"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn round_trips_through_the_vault() {
    let dir = temp_dir("round-trip");
    let vault_path = dir.join("vault.key");
    let db_path = dir.join("mail.redb");

    {
        let vault = Vault::create(&vault_path, b"hunter2").expect("create vault");
        let store = Store::open(&db_path, vault.key()).expect("open store");
        store.put_envelopes(&[sample(7)]).expect("store envelope");
    }

    let vault = Vault::unlock(&vault_path, b"hunter2").expect("unlock vault");
    let store = Store::open(&db_path, vault.key()).expect("reopen store");

    let got = store
        .envelope("personal", "INBOX", 7)
        .expect("query")
        .expect("envelope should still be there");
    assert_eq!(got.subject, SECRET_SUBJECT);
    assert_eq!(got.from[0].email, SECRET_SENDER);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrong_passphrase_is_rejected() {
    let dir = temp_dir("wrong-pass");
    let vault_path = dir.join("vault.key");

    Vault::create(&vault_path, b"right").expect("create vault");
    let err = Vault::unlock(&vault_path, b"wrong").expect_err("must not unlock");
    assert!(matches!(err, VaultError::WrongPassphrase));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_different_key_cannot_read_the_database() {
    let dir = temp_dir("wrong-key");
    let db_path = dir.join("mail.redb");

    {
        let store = Store::open(&db_path, &MasterKey::from_bytes([1u8; 32])).expect("open");
        store.put_envelopes(&[sample(3)]).expect("store");
    }

    let store = Store::open(&db_path, &MasterKey::from_bytes([2u8; 32])).expect("open");
    assert!(
        store.envelope("personal", "INBOX", 3).is_err()
            || store.envelope("personal", "INBOX", 3).unwrap().is_none(),
        "a foreign key must not decrypt the record"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn blind_index_finds_messages_without_storing_terms() {
    let dir = temp_dir("blind-index");
    let db_path = dir.join("mail.redb");

    let store = Store::open(&db_path, &MasterKey::from_bytes([9u8; 32])).expect("open");
    store.put_envelopes(&[sample(11)]).expect("store");

    let hits = store.search_token("subject", "northwind").expect("search");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].uid, 11);
    assert_eq!(hits[0].folder, "INBOX");

    assert!(store.search_token("subject", "nothing-like-this").unwrap().is_empty());

    let raw = std::fs::read(&db_path).expect("read database");
    assert!(
        !contains(&raw, b"northwind"),
        "the search index stored a plaintext term"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let lower: Vec<u8> = haystack.iter().map(|b| b.to_ascii_lowercase()).collect();
    let n: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
    lower.windows(n.len()).any(|w| w == n.as_slice())
}
