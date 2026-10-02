use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::Utc;
use pigeon::cli::{Args, Cmd};
use pigeon::crypto::Vault;
use pigeon::store::Store;
use pigeon::store::model::{Addr, Envelope, Flags};
use serde_json::{Value, json};

const PASSPHRASE: &str = "correct horse battery staple";

fn temp_dir(tag: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("pigeon-{tag}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn envelope(uid: u32, subject: &str, from: &str, seen: bool) -> Envelope {
    Envelope {
        account: "work".into(),
        folder: "INBOX".into(),
        uid,
        modseq: 0,
        message_id: Some(format!("msg-{uid}@example.org")),
        in_reply_to: None,
        references: Vec::new(),
        thread_id: None,
        subject: subject.into(),
        from: vec![Addr::named(from.split('@').next().unwrap_or(from), from)],
        sender: Vec::new(),
        reply_to: Vec::new(),
        to: vec![Addr::new("me@example.org")],
        cc: Vec::new(),
        bcc: Vec::new(),
        list_id: None,
        date: Utc::now(),
        received: None,
        size: 2048,
        flags: if seen { Flags::SEEN } else { Flags::EMPTY },
        keywords: BTreeSet::new(),
        tags: BTreeSet::new(),
        preview: "body text".into(),
        attachments: Vec::new(),
        crypto: Default::default(),
        body_blob: None,
        has_html: false,
    }
}

fn write_config(path: &Path) {
    // `unlock = "command"` is what lets a daemon start without a terminal, and
    // it is the mode a session service would use.
    std::fs::write(
        path,
        format!(
            r#"
[general]
encrypt_at_rest = true
unlock = "command"
unlock_command = "printf '{PASSPHRASE}'"
notify = false
idle = false
poll_interval_secs = 3600

[[account]]
name = "work"
address = "me@example.org"
display_name = "Me"

[account.imap]
host = "127.0.0.1"
port = 1
security = "none"
user = "me@example.org"
auth = "none"

[account.smtp]
host = "127.0.0.1"
port = 1
security = "none"
auth = "none"

[account.folders]
inbox = "INBOX"
"#
        ),
    )
    .expect("write config");
}

struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl Client {
    fn connect(socket: &Path) -> Self {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match UnixStream::connect(socket) {
                Ok(stream) => {
                    let writer = stream.try_clone().expect("clone socket");
                    return Self {
                        reader: BufReader::new(stream),
                        writer,
                        next_id: 1,
                    };
                }
                Err(e) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                    let _ = e;
                }
                Err(e) => panic!("could not connect to {}: {e}", socket.display()),
            }
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;

        let line = serde_json::to_string(&json!({"id": id, "method": method, "params": params}))
            .expect("encode request");
        self.writer.write_all(line.as_bytes()).expect("write request");
        self.writer.write_all(b"\n").expect("write newline");
        self.writer.flush().expect("flush");

        loop {
            let mut line = String::new();
            let read = self.reader.read_line(&mut line).expect("read response");
            assert!(read > 0, "the daemon closed the connection");
            let value: Value = serde_json::from_str(&line).expect("decode response");
            // Pushes share the socket with replies, so skip anything unsolicited.
            if value.get("event").is_some() {
                continue;
            }
            return value;
        }
    }

    fn ok(&mut self, method: &str, params: Value) -> Value {
        let response = self.call(method, params);
        assert_eq!(
            response["ok"], json!(true),
            "`{method}` failed: {}", response["error"]
        );
        response["result"].clone()
    }
}

/// Everything the shell integration depends on, over a real socket: the reply
/// framing, the locked-state guard, reads out of the encrypted store, and the
/// search query language.
#[test]
fn serves_mail_over_a_unix_socket() {
    let dir = temp_dir("daemon");
    let config = dir.join("config.toml");
    let socket = dir.join("daemon.sock");
    write_config(&config);

    let vault = Vault::create(&dir.join("vault.key"), PASSPHRASE.as_bytes()).expect("vault");
    let store = Store::open(&dir.join("mail.redb"), vault.key()).expect("store");
    store
        .put_envelopes(&[
            envelope(1, "Quarterly figures", "ada@example.org", false),
            envelope(2, "Lunch on Thursday", "bob@example.org", true),
        ])
        .expect("seed envelopes");
    drop(store);

    let args = Args {
        cmd: Cmd::Daemon,
        config: Some(config.clone()),
        data_dir: Some(dir.clone()),
        account: None,
        socket: Some(socket.clone()),
        no_encrypt: false,
        verbose: false,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let server = {
        let socket = socket.clone();
        runtime.spawn(async move { pigeon::daemon::serve(&args, Some(&socket)).await })
    };

    let mut client = Client::connect(&socket);

    let hello = client.ok("hello", json!({}));
    assert_eq!(hello["locked"], json!(false), "the config says how to unlock");
    assert_eq!(hello["protocol"], json!(1));

    let accounts = client.ok("accounts", json!({}));
    assert_eq!(accounts[0]["name"], json!("work"));
    assert_eq!(accounts[0]["email"], json!("me@example.org"));

    let listing = client.ok("messages", json!({ "folder": "INBOX" }));
    assert_eq!(listing["total"], json!(2));
    let messages = listing["messages"].as_array().expect("array");
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().any(|m| m["subject"] == json!("Quarterly figures")));
    assert!(messages.iter().any(|m| m["seen"] == json!(true)));
    assert!(messages.iter().any(|m| m["seen"] == json!(false)));

    let unread = client.ok("messages", json!({ "folder": "INBOX", "unread": true }));
    assert_eq!(unread["messages"].as_array().map(Vec::len), Some(1));

    let hits = client.ok("search", json!({ "query": "from:ada" }));
    let found = hits["messages"].as_array().expect("array");
    assert_eq!(found.len(), 1, "search should find exactly Ada's message");
    assert_eq!(found[0]["subject"], json!("Quarterly figures"));

    assert_eq!(
        client.ok("subscribe", json!({ "events": true }))["subscribed"],
        json!(true)
    );

    let bad = client.call("mark", json!({ "account": "work", "folder": "INBOX", "uid": 1 }));
    assert_eq!(bad["ok"], json!(false), "a mark with no flags is rejected");

    let marked = client.ok(
        "mark",
        json!({ "account": "work", "folder": "INBOX", "uid": 1, "seen": true }),
    );
    assert_eq!(marked["queued"], json!(true));

    let unknown = client.call("frobnicate", json!({}));
    assert_eq!(unknown["ok"], json!(false));
    assert!(
        unknown["error"].as_str().unwrap_or_default().contains("unknown method"),
        "unexpected error: {}", unknown["error"]
    );

    client.ok("lock", json!({}));
    let after_lock = client.call("messages", json!({}));
    assert_eq!(after_lock["ok"], json!(false), "a locked daemon serves no mail");

    client.ok("shutdown", json!({}));
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A desktop shell has to be able to set pigeon up from nothing: create the
/// vault, unlock it and add the first account, without a config file existing
/// first.
#[test]
fn sets_up_a_first_account_from_an_empty_machine() {
    let dir = temp_dir("daemon-firstrun");
    let config = dir.join("config.toml");
    let socket = dir.join("daemon.sock");

    let args = Args {
        cmd: Cmd::Daemon,
        config: Some(config.clone()),
        data_dir: Some(dir.clone()),
        account: None,
        socket: Some(socket.clone()),
        no_encrypt: false,
        verbose: false,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let server = {
        let socket = socket.clone();
        runtime.spawn(async move { pigeon::daemon::serve(&args, Some(&socket)).await })
    };

    let mut client = Client::connect(&socket);

    let hello = client.ok("hello", json!({}));
    assert_eq!(hello["locked"], json!(true));
    assert_eq!(hello["configured"], json!(false), "nothing is set up yet");

    let vault = client.ok("vault-status", json!({}));
    assert_eq!(vault["exists"], json!(false));

    assert_eq!(
        client.call("vault-create", json!({ "passphrase": "short" }))["ok"],
        json!(false),
        "a short passphrase is refused"
    );

    client.ok("vault-create", json!({ "passphrase": PASSPHRASE }));
    client.ok("unlock", json!({ "passphrase": PASSPHRASE }));

    let added = client.ok(
        "account-add",
        json!({
            "email": "me@example.org",
            "displayName": "Me",
            "password": "hunter2",
            "imap": { "host": "127.0.0.1", "port": 993, "security": "tls", "user": "me@example.org" },
            "smtp": { "host": "127.0.0.1", "port": 587, "security": "starttls" },
        }),
    );
    assert_eq!(added["added"], json!("me"));

    let accounts = client.ok("accounts", json!({}));
    assert_eq!(accounts.as_array().map(Vec::len), Some(1));
    assert_eq!(accounts[0]["email"], json!("me@example.org"));

    assert!(config.exists(), "the account should have been written to the config");
    let written = std::fs::read_to_string(&config).expect("read config");
    assert!(written.contains("me@example.org"));
    assert!(
        !written.contains("hunter2"),
        "the password must not be written into the config"
    );

    client.ok("shutdown", json!({}));
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The socket carries a vault passphrase, so its permissions are part of the
/// security boundary, not a detail.
#[test]
fn the_socket_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let dir = temp_dir("daemon-perms");
    let config = dir.join("config.toml");
    let socket = dir.join("daemon.sock");
    write_config(&config);
    Vault::create(&dir.join("vault.key"), PASSPHRASE.as_bytes()).expect("vault");

    let args = Args {
        cmd: Cmd::Daemon,
        config: Some(config),
        data_dir: Some(dir.clone()),
        account: None,
        socket: Some(socket.clone()),
        no_encrypt: false,
        verbose: false,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let server = {
        let socket = socket.clone();
        runtime.spawn(async move { pigeon::daemon::serve(&args, Some(&socket)).await })
    };

    let mut client = Client::connect(&socket);
    client.ok("hello", json!({}));

    let mode = std::fs::metadata(&socket).expect("stat socket").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the socket must not be readable by other users");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

const HTML_MESSAGE: &[u8] = b"From: ada@example.org\r\n\
Subject: Quarterly figures\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"b1\"\r\n\
\r\n\
--b1\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
The figures are in.\r\n\
--b1\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<html><body><script>fetch('https://tracker.example/x')</script>\
<p onclick=\"steal()\">The <b>figures</b> are in.</p>\
<img src=\"https://tracker.example/pixel.gif\">\
</body></html>\r\n\
--b1--\r\n";

/// The reader asks for html when the user has turned it on, and what comes back
/// has to be both present and safe: no script, no handlers, no remote fetches.
#[test]
fn serves_html_with_the_remote_content_stripped() {
    let dir = temp_dir("html");
    let config = dir.join("config.toml");
    let socket = dir.join("daemon.sock");
    write_config(&config);

    let vault = Vault::create(&dir.join("vault.key"), PASSPHRASE.as_bytes()).expect("vault");
    let store = Store::open(&dir.join("mail.redb"), vault.key()).expect("store");

    let key = pigeon::store::model::MsgKey {
        account: "work".into(),
        folder: "INBOX".into(),
        uid: 1,
    };
    store
        .put_blob(&pigeon::sync::engine::blob_id(&key), HTML_MESSAGE)
        .expect("seed body");
    store
        .put_envelopes(&[envelope(1, "Quarterly figures", "ada@example.org", false)])
        .expect("seed envelope");
    drop(store);

    let args = Args {
        cmd: Cmd::Daemon,
        config: Some(config.clone()),
        data_dir: Some(dir.clone()),
        account: None,
        socket: Some(socket.clone()),
        no_encrypt: false,
        verbose: false,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let server = {
        let socket = socket.clone();
        runtime.spawn(async move { pigeon::daemon::serve(&args, Some(&socket)).await })
    };

    let mut client = Client::connect(&socket);
    let body = client.ok(
        "message",
        json!({ "account": "work", "folder": "INBOX", "uid": 1, "html": true }),
    );

    assert_eq!(
        body["rawBytes"].as_u64(),
        Some(HTML_MESSAGE.len() as u64),
        "the whole message has to reach the renderer or its html part is lost"
    );

    let html = body["html"].as_str().unwrap_or_default();
    assert!(html.contains("<b>figures</b>"), "no html was rendered: {html:?}");
    assert!(!html.contains("script"), "script survived: {html}");
    assert!(!html.contains("onclick"), "an event handler survived: {html}");
    assert!(!html.contains("tracker.example"), "a remote fetch survived: {html}");

    assert_eq!(body["text"].as_str().map(str::trim), Some("The figures are in."));

    client.ok("shutdown", json!({}));
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}
