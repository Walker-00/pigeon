use std::sync::Arc;

use crate::mail::compose::Draft;
use crate::store::model::{Envelope, Flags, FolderState, MsgKey, OutboxItem};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    Idle,
    Connecting,
    Syncing,
    Watching,
    Offline,
}

impl SyncStatus {
    pub fn label(self) -> &'static str {
        match self {
            SyncStatus::Idle => "idle",
            SyncStatus::Connecting => "connecting",
            SyncStatus::Syncing => "syncing",
            SyncStatus::Watching => "watching",
            SyncStatus::Offline => "offline",
        }
    }
}

#[derive(Debug)]
pub enum Event {
    Status { account: String, status: SyncStatus },
    Folders { account: String, folders: Vec<FolderState> },
    Envelopes { account: String, folder: String, envelopes: Vec<Envelope>, replaced: bool },
    Removed { account: String, folder: String, uids: Vec<u32> },
    FlagsChanged { key: MsgKey, flags: Flags },
    Body { key: MsgKey, raw: Arc<Vec<u8>> },
    NewMail { account: String, folder: String, envelopes: Vec<Envelope> },
    OutboxChanged { pending: Vec<OutboxItem> },
    Sent { id: String },
    SendFailed { id: String, message: String },
    Notice(String),
    Error { account: Option<String>, message: String },
}

#[derive(Debug)]
pub enum Command {
    SyncAll,
    SyncAccount(String),
    SyncFolder { account: String, folder: String },
    FetchBody(MsgKey),
    PrefetchBodies { account: String, folder: String, uids: Vec<u32> },
    SetFlags { keys: Vec<MsgKey>, add: Flags, remove: Flags },
    Move { keys: Vec<MsgKey>, to: String },
    Copy { keys: Vec<MsgKey>, to: String },
    Delete { keys: Vec<MsgKey>, permanent: bool },
    Send(Box<Draft>),
    SaveDraft(Box<Draft>),
    CreateFolder { account: String, name: String },
    DeleteFolder { account: String, name: String },
    RenameFolder { account: String, from: String, to: String },
    ServerSearch { account: String, folder: String, query: String },
    FlushOutbox,
    Reconnect,
    Shutdown,
}
