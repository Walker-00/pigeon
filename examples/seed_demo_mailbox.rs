use std::collections::BTreeSet;

use chrono::{Duration, Utc};
use pigeon::crypto::Vault;
use pigeon::store::Store;
use pigeon::store::model::{Addr, AttachmentMeta, Envelope, Flags, FolderRole, FolderState};
use pigeon::sync::engine::blob_id;

/// Fills a pigeon data directory with a few messages so a front end — the
/// Quickshell mail widget, say — can be developed and reviewed before a real
/// account exists.
///
///     cargo run --example seed_demo_mailbox -- ~/.local/share/pigeon-demo hunter2 test
fn main() {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: seed_demo_mailbox DATA_DIR [PASSPHRASE] [ACCOUNT]");
        std::process::exit(2);
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).expect("create the data directory");
    let pass = args.next().unwrap_or_else(|| "hunter2".into());
    let account = args.next().unwrap_or_else(|| "test".into());

    let vault_path = dir.join("vault.key");
    let vault = if Vault::exists(&vault_path) {
        Vault::unlock(&vault_path, pass.as_bytes()).unwrap()
    } else {
        Vault::create(&vault_path, pass.as_bytes()).unwrap()
    };
    let store = Store::open(&dir.join("mail.redb"), vault.key()).unwrap();

    for (name, role, unseen) in [
        ("INBOX", FolderRole::Inbox, 2u32),
        ("Archive", FolderRole::Archive, 0),
        ("Sent", FolderRole::Sent, 0),
        ("Trash", FolderRole::Trash, 0),
    ] {
        store
            .put_folder(&FolderState {
                account: account.clone(),
                name: name.into(),
                delimiter: Some("/".into()),
                attributes: vec![],
                uid_validity: 1,
                uid_next: 10,
                highest_modseq: 1,
                exists: if name == "INBOX" { 3 } else { 0 },
                unseen,
                last_sync: Some(Utc::now()),
                subscribed: true,
                role: Some(role),
            })
            .unwrap();
    }

    let samples = [
        (1u32, "Review the deployment plan", "ada@example.org", "Ada Lovelace", false, true),
        (2, "Lunch on Thursday?", "grace@example.org", "Grace Hopper", false, false),
        (3, "Re: Review the deployment plan", "alan@example.org", "Alan Turing", true, false),
    ];

    let mut envelopes = Vec::new();
    for (uid, subject, email, name, seen, attach) in samples {
        let raw = format!(
            "From: {name} <{email}>\r\nTo: Me <me@example.org>\r\nSubject: {subject}\r\n\
             Date: Thu, 25 Sep 2025 10:00:00 +0000\r\nMIME-Version: 1.0\r\n\
             Content-Type: text/plain; charset=utf-8\r\n\r\n\
             Hello,\r\n\r\nThis is the body of message {uid}. It has a few lines so the\r\n\
             reader has something to wrap.\r\n\r\n> and a quoted line from earlier\r\n\r\n-- \r\n{name}\r\n"
        );
        store.put_blob(&blob_id(&pigeon::store::model::MsgKey {
            account: account.clone(),
            folder: "INBOX".into(),
            uid,
        }), raw.as_bytes()).unwrap();

        envelopes.push(Envelope {
            account: account.clone(),
            folder: "INBOX".into(),
            uid,
            modseq: uid as u64,
            message_id: Some(format!("<msg-{uid}@example.org>")),
            in_reply_to: None,
            references: Vec::new(),
            thread_id: None,
            subject: subject.into(),
            from: vec![Addr::named(name, email)],
            sender: Vec::new(),
            reply_to: Vec::new(),
            to: vec![Addr::named("Me", "me@example.org")],
            cc: Vec::new(),
            bcc: Vec::new(),
            list_id: None,
            date: Utc::now() - Duration::hours(uid as i64),
            received: None,
            size: raw.len() as u64,
            flags: if seen { Flags::SEEN } else { Flags::EMPTY },
            keywords: BTreeSet::new(),
            tags: BTreeSet::new(),
            preview: "Hello, this is the body of the message.".into(),
            attachments: if attach {
                vec![AttachmentMeta {
                    name: "plan.pdf".into(),
                    mime: "application/pdf".into(),
                    size: 34567,
                    part_id: "2".into(),
                    inline: false,
                    content_id: None,
                    blob: None,
                }]
            } else {
                Vec::new()
            },
            crypto: Default::default(),
            body_blob: None,
            has_html: false,
        });
    }

    store.put_envelopes(&envelopes).unwrap();
    println!("seeded {} messages into {}", envelopes.len(), dir.display());
}
