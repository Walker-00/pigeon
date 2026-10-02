use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Addr {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub email: String,
}

impl Addr {
    pub fn new(email: impl Into<String>) -> Self {
        Self { name: None, email: email.into() }
    }

    pub fn named(name: impl Into<String>, email: impl Into<String>) -> Self {
        Self { name: Some(name.into()), email: email.into() }
    }

    pub fn display(&self) -> &str {
        self.name.as_deref().filter(|n| !n.is_empty()).unwrap_or(&self.email)
    }

    pub fn domain(&self) -> &str {
        self.email.rsplit('@').next().unwrap_or("")
    }

    pub fn encoded(&self) -> String {
        match &self.name {
            Some(n) if !n.is_empty() => format!("{n} <{}>", self.email),
            _ => self.email.clone(),
        }
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encoded())
    }
}

bitflags_like! {
    Flags {
        SEEN      = 1 << 0, "\\Seen";
        ANSWERED  = 1 << 1, "\\Answered";
        FLAGGED   = 1 << 2, "\\Flagged";
        DELETED   = 1 << 3, "\\Deleted";
        DRAFT     = 1 << 4, "\\Draft";
        RECENT    = 1 << 5, "\\Recent";
        FORWARDED = 1 << 6, "$Forwarded";
        JUNK      = 1 << 7, "$Junk";
        NOTJUNK   = 1 << 8, "$NotJunk";
        PHISHING  = 1 << 9, "$Phishing";
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoState {
    None,
    SignedValid,
    SignedInvalid,
    SignedUnknownKey,
    Encrypted,
    EncryptedAndSigned,
    DecryptFailed,
}

impl CryptoState {
    pub fn badge(self) -> &'static str {
        match self {
            CryptoState::None => "",
            CryptoState::SignedValid => "signed",
            CryptoState::SignedInvalid => "BAD SIG",
            CryptoState::SignedUnknownKey => "sig?",
            CryptoState::Encrypted => "enc",
            CryptoState::EncryptedAndSigned => "enc+sig",
            CryptoState::DecryptFailed => "locked",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub part_id: String,
    #[serde(default)]
    pub inline: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub account: String,
    pub folder: String,
    pub uid: u32,
    #[serde(default)]
    pub modseq: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,

    pub subject: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub from: Vec<Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sender: Vec<Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reply_to: Vec<Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to: Vec<Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cc: Vec<Addr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bcc: Vec<Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_id: Option<String>,

    pub date: DateTime<Utc>,
    #[serde(default)]
    pub received: Option<DateTime<Utc>>,
    pub size: u64,
    pub flags: Flags,
    #[serde(default)]
    pub keywords: BTreeSet<String>,
    #[serde(default)]
    pub tags: BTreeSet<String>,

    #[serde(default)]
    pub preview: String,
    #[serde(default)]
    pub attachments: Vec<AttachmentMeta>,
    #[serde(default)]
    pub crypto: CryptoState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_blob: Option<String>,
    #[serde(default)]
    pub has_html: bool,
}

impl Default for CryptoState {
    fn default() -> Self {
        CryptoState::None
    }
}

impl Envelope {
    pub fn key(&self) -> MsgKey {
        MsgKey {
            account: self.account.clone(),
            folder: self.folder.clone(),
            uid: self.uid,
        }
    }

    pub fn is_unread(&self) -> bool {
        !self.flags.contains(Flags::SEEN)
    }

    pub fn display_from(&self) -> String {
        match self.from.first() {
            Some(a) => a.display().to_string(),
            None => "(unknown sender)".into(),
        }
    }

    pub fn subject_or_placeholder(&self) -> &str {
        if self.subject.trim().is_empty() {
            "(no subject)"
        } else {
            &self.subject
        }
    }

    /// Normalised subject used to group a thread when `References` are missing,
    /// as mail from some clients drops those headers on reply.
    pub fn base_subject(&self) -> &str {
        let mut s = self.subject.trim();
        loop {
            let lower = s.to_ascii_lowercase();
            let cut = ["re:", "fwd:", "fw:", "aw:", "sv:", "vs:", "antw:"]
                .iter()
                .find_map(|p| lower.starts_with(p).then_some(p.len()));
            match cut {
                Some(n) => s = s[n..].trim_start(),
                None => break,
            }
        }
        s
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MsgKey {
    pub account: String,
    pub folder: String,
    pub uid: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FolderState {
    pub account: String,
    pub name: String,
    pub delimiter: Option<String>,
    #[serde(default)]
    pub attributes: Vec<String>,
    #[serde(default)]
    pub uid_validity: u32,
    #[serde(default)]
    pub uid_next: u32,
    #[serde(default)]
    pub highest_modseq: u64,
    #[serde(default)]
    pub exists: u32,
    #[serde(default)]
    pub unseen: u32,
    #[serde(default)]
    pub last_sync: Option<DateTime<Utc>>,
    #[serde(default)]
    pub subscribed: bool,
    #[serde(default)]
    pub role: Option<FolderRole>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FolderRole {
    Inbox,
    Sent,
    Drafts,
    Trash,
    Archive,
    Spam,
    All,
}

impl FolderState {
    pub fn depth(&self) -> usize {
        match &self.delimiter {
            Some(d) if !d.is_empty() => self.name.matches(d.as_str()).count(),
            _ => 0,
        }
    }

    pub fn leaf(&self) -> &str {
        match &self.delimiter {
            Some(d) if !d.is_empty() => self.name.rsplit(d.as_str()).next().unwrap_or(&self.name),
            _ => &self.name,
        }
    }

    pub fn is_selectable(&self) -> bool {
        !self
            .attributes
            .iter()
            .any(|a| a.eq_ignore_ascii_case("\\Noselect") || a.eq_ignore_ascii_case("\\NonExistent"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxItem {
    pub id: String,
    pub account: String,
    pub from: Addr,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub bcc: Vec<Addr>,
    pub subject: String,
    pub queued_at: DateTime<Utc>,
    #[serde(default)]
    pub send_after: Option<DateTime<Utc>>,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub last_error: Option<String>,
    pub raw_blob: String,
    #[serde(default = "yes")]
    pub save_to_sent: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendingOp {
    AddFlags { key: MsgKey, flags: Flags },
    RemoveFlags { key: MsgKey, flags: Flags },
    Move { key: MsgKey, to: String },
    Copy { key: MsgKey, to: String },
    Delete { key: MsgKey },
    Expunge { account: String, folder: String },
    CreateFolder { account: String, name: String },
    DeleteFolder { account: String, name: String },
    RenameFolder { account: String, from: String, to: String },
}
