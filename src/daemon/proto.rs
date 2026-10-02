use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::store::model::{AttachmentMeta, Envelope, FolderRole, FolderState, MsgKey, OutboxItem};
use crate::sync::event::SyncStatus;

/// One line of JSON per message in both directions. A line protocol keeps the
/// client side trivial: Quickshell's `Socket` already splits on a marker, so no
/// framing code is needed in QML.
pub const NEWLINE: u8 = b'\n';

#[derive(Debug, Deserialize)]
pub struct Request {
    #[serde(default)]
    pub id: Option<u64>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    pub fn ok(id: Option<u64>, result: serde_json::Value) -> Self {
        Self { id, ok: true, result: Some(result), error: None }
    }

    pub fn err(id: Option<u64>, error: impl std::fmt::Display) -> Self {
        Self { id, ok: false, result: None, error: Some(error.to_string()) }
    }
}

/// Unsolicited messages. `event` doubles as the discriminator so a QML client
/// can dispatch on one field without inspecting the shape.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Push {
    Unlocked {
        accounts: Vec<AccountView>,
    },
    Locked,
    Status {
        account: String,
        status: &'static str,
    },
    Folders {
        account: String,
        folders: Vec<FolderView>,
    },
    NewMail {
        account: String,
        folder: String,
        messages: Vec<MessageView>,
    },
    Messages {
        account: String,
        folder: String,
        messages: Vec<MessageView>,
        replaced: bool,
    },
    Removed {
        account: String,
        folder: String,
        uids: Vec<u32>,
    },
    Flags {
        account: String,
        folder: String,
        uid: u32,
        seen: bool,
        flagged: bool,
        answered: bool,
        draft: bool,
        flags: Vec<String>,
    },
    Outbox {
        items: Vec<OutboxView>,
    },
    Sent {
        id: String,
    },
    SendFailed {
        id: String,
        message: String,
    },
    Unread {
        total: u32,
        by_account: BTreeMap<String, u32>,
    },
    Notice {
        message: String,
    },
    Error {
        #[serde(skip_serializing_if = "Option::is_none")]
        account: Option<String>,
        message: String,
    },
    Shutdown,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountView {
    pub name: String,
    pub email: String,
    pub display_name: String,
    pub enabled: bool,
    pub aliases: Vec<String>,
    pub status: &'static str,
    pub imap_host: String,
    pub smtp_host: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FolderView {
    pub account: String,
    pub name: String,
    pub display: String,
    pub role: Option<FolderRole>,
    pub icon: &'static str,
    pub depth: usize,
    pub total: u32,
    pub unread: u32,
    pub selectable: bool,
    pub subscribed: bool,
}

impl FolderView {
    pub fn of(f: &FolderState) -> Self {
        Self {
            account: f.account.clone(),
            name: f.name.clone(),
            display: f.leaf().to_string(),
            role: f.role,
            icon: role_icon(f.role, &f.name),
            depth: f.depth(),
            total: f.exists,
            unread: f.unseen,
            selectable: f.is_selectable(),
            subscribed: f.subscribed,
        }
    }
}

/// Material Symbols names, because that is the icon set the shell already
/// bundles; a role with no obvious symbol falls back to a plain folder.
fn role_icon(role: Option<FolderRole>, name: &str) -> &'static str {
    match role {
        Some(FolderRole::Inbox) => "inbox",
        Some(FolderRole::Sent) => "send",
        Some(FolderRole::Drafts) => "draft",
        Some(FolderRole::Trash) => "delete",
        Some(FolderRole::Archive) => "archive",
        Some(FolderRole::Spam) => "report",
        Some(FolderRole::All) => "all_inbox",
        None if name.eq_ignore_ascii_case("inbox") => "inbox",
        None => "folder",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AddrView {
    pub name: String,
    pub email: String,
    pub display: String,
}

/// The wire form of an envelope. The stored `Flags` bitfield is expanded into
/// booleans so QML can bind to them directly instead of doing bit arithmetic.
#[derive(Debug, Clone, Serialize)]
pub struct MessageView {
    pub account: String,
    pub folder: String,
    pub uid: u32,
    pub subject: String,
    pub from: Vec<AddrView>,
    pub to: Vec<AddrView>,
    pub cc: Vec<AddrView>,
    pub sender: String,
    pub sender_email: String,
    pub date: String,
    pub timestamp: i64,
    pub size: u64,
    pub preview: String,
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
    pub deleted: bool,
    pub flags: Vec<String>,
    pub tags: Vec<String>,
    pub attachments: Vec<AttachmentView>,
    pub has_attachments: bool,
    pub crypto: &'static str,
    pub has_html: bool,
    pub cached: bool,
    pub thread_id: Option<String>,
    pub message_id: Option<String>,
    pub list_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentView {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub part_id: String,
    pub inline: bool,
}

impl AttachmentView {
    fn of(a: &AttachmentMeta) -> Self {
        Self {
            name: a.name.clone(),
            mime: a.mime.clone(),
            size: a.size,
            part_id: a.part_id.clone(),
            inline: a.inline,
        }
    }
}

fn addrs(list: &[crate::store::model::Addr]) -> Vec<AddrView> {
    list.iter()
        .map(|a| AddrView {
            name: a.name.clone().unwrap_or_default(),
            email: a.email.clone(),
            display: a.display().to_string(),
        })
        .collect()
}

impl MessageView {
    pub fn of(e: &Envelope, cached: bool) -> Self {
        use crate::store::model::Flags;

        Self {
            account: e.account.clone(),
            folder: e.folder.clone(),
            uid: e.uid,
            subject: e.subject_or_placeholder().to_string(),
            from: addrs(&e.from),
            to: addrs(&e.to),
            cc: addrs(&e.cc),
            sender: e.display_from(),
            sender_email: e.from.first().map(|a| a.email.clone()).unwrap_or_default(),
            date: e.date.to_rfc3339(),
            timestamp: e.date.timestamp(),
            size: e.size,
            preview: e.preview.clone(),
            seen: e.flags.contains(Flags::SEEN),
            flagged: e.flags.contains(Flags::FLAGGED),
            answered: e.flags.contains(Flags::ANSWERED),
            draft: e.flags.contains(Flags::DRAFT),
            deleted: e.flags.contains(Flags::DELETED),
            flags: e.flags.wire_names().into_iter().map(str::to_string).collect(),
            tags: e.tags.iter().cloned().collect(),
            attachments: e.attachments.iter().map(AttachmentView::of).collect(),
            has_attachments: e.attachments.iter().any(|a| !a.inline),
            crypto: crypto_name(e.crypto),
            has_html: e.has_html,
            cached,
            thread_id: e.thread_id.clone(),
            message_id: e.message_id.clone(),
            list_id: e.list_id.clone(),
        }
    }
}

fn crypto_name(state: crate::store::model::CryptoState) -> &'static str {
    use crate::store::model::CryptoState as C;
    match state {
        C::None => "none",
        C::SignedValid => "signed-valid",
        C::SignedInvalid => "signed-invalid",
        C::SignedUnknownKey => "signed-unknown",
        C::Encrypted => "encrypted",
        C::EncryptedAndSigned => "encrypted-signed",
        C::DecryptFailed => "decrypt-failed",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OutboxView {
    pub id: String,
    pub account: String,
    pub subject: String,
    pub to: Vec<AddrView>,
    pub queued_at: String,
    pub attempts: u32,
    pub last_error: Option<String>,
}

impl OutboxView {
    pub fn of(i: &OutboxItem) -> Self {
        Self {
            id: i.id.clone(),
            account: i.account.clone(),
            subject: i.subject.clone(),
            to: addrs(&i.to),
            queued_at: i.queued_at.to_rfc3339(),
            attempts: i.attempts,
            last_error: i.last_error.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct KeyRef {
    pub account: String,
    pub folder: String,
    pub uid: u32,
}

impl From<KeyRef> for MsgKey {
    fn from(k: KeyRef) -> Self {
        MsgKey { account: k.account, folder: k.folder, uid: k.uid }
    }
}

pub fn status_name(s: SyncStatus) -> &'static str {
    s.label()
}
