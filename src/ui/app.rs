use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::UnboundedSender;

use crate::config::Config;
use crate::mail::body::{RenderOptions, RenderedBody};
use crate::mail::query::{self, Node};
use crate::mail::thread::{self, Thread};
use crate::secrets::SecretProvider;
use crate::store::Store;
use crate::store::model::{AttachmentMeta, Envelope, Flags, FolderRole, FolderState, MsgKey};
use crate::sync::{Command, SyncStatus};

use super::keys::Keymap;
use super::theme::Theme;

pub const NOTICE_TTL: Duration = Duration::from_secs(6);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Folders,
    List,
    Preview,
}

impl Pane {
    pub fn next(self) -> Self {
        match self {
            Pane::Folders => Pane::List,
            Pane::List => Pane::Preview,
            Pane::Preview => Pane::Folders,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Pane::Folders => Pane::Preview,
            Pane::List => Pane::Folders,
            Pane::Preview => Pane::List,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Overlay {
    None,
    Help,
    Palette,
    Attachments,
    Links,
    Outbox,
    Source,
    FolderPicker { copy: bool },
    Confirm { prompt: String, action: ConfirmAction },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfirmAction {
    Quit,
    DeletePermanent(Vec<MsgKey>),
    MarkAllRead,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    None,
    Search,
    ExCommand,
    Filter,
    /// Password entry: echoed as dots and never written to the notice line.
    Secret,
}

#[derive(Debug, Clone)]
pub struct FolderRow {
    pub account: String,
    pub name: String,
    pub label: String,
    pub depth: usize,
    pub unread: u32,
    pub total: u32,
    pub role: Option<FolderRole>,
    pub is_account_header: bool,
}

#[derive(Debug, Clone)]
pub enum ListRow {
    Thread { index: usize, collapsed: bool },
    Message { msg: usize, depth: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    DateDesc,
    DateAsc,
    SubjectAsc,
    SenderAsc,
    SizeDesc,
    UnreadFirst,
}

impl Sort {
    pub fn label(self) -> &'static str {
        match self {
            Sort::DateDesc => "date ↓",
            Sort::DateAsc => "date ↑",
            Sort::SubjectAsc => "subject",
            Sort::SenderAsc => "sender",
            Sort::SizeDesc => "size",
            Sort::UnreadFirst => "unread",
        }
    }

    pub fn cycle(self) -> Self {
        match self {
            Sort::DateDesc => Sort::DateAsc,
            Sort::DateAsc => Sort::SubjectAsc,
            Sort::SubjectAsc => Sort::SenderAsc,
            Sort::SenderAsc => Sort::SizeDesc,
            Sort::SizeDesc => Sort::UnreadFirst,
            Sort::UnreadFirst => Sort::DateDesc,
        }
    }
}

pub struct App {
    pub store: Arc<Store>,
    pub secrets: Arc<SecretProvider>,
    pub config: Arc<Config>,
    pub commands: UnboundedSender<Command>,
    pub theme: Theme,
    pub keymap: Keymap,

    pub pane: Pane,
    pub overlay: Overlay,
    pub input_mode: InputMode,
    pub input: String,
    pub input_cursor: usize,
    pub overlay_sel: usize,

    pub folders: Vec<FolderRow>,
    pub folder_sel: usize,
    pub sidebar: bool,

    pub messages: Vec<Envelope>,
    pub threads: Vec<Thread>,
    pub rows: Vec<ListRow>,
    pub list_sel: usize,
    pub list_offset: usize,
    pub collapsed: HashSet<String>,
    pub marked: BTreeSet<MsgKey>,

    pub body: Option<RenderedBody>,
    pub body_raw: Option<Arc<Vec<u8>>>,
    pub body_scroll: u16,
    pub body_key: Option<MsgKey>,
    pub render: RenderOptions,

    pub query: Option<Node>,
    pub query_text: String,
    pub sort: Sort,
    pub threading: bool,

    pub status: HashMap<String, SyncStatus>,
    pub notice: Option<(String, Instant, bool)>,
    pub outbox_len: usize,
    pub should_quit: bool,
    pub redraw: bool,
    pub last_body_request: Option<Instant>,
    /// Account and purpose awaiting a password typed into the input line.
    pub pending_secret: Option<(String, String)>,
}

impl App {
    pub fn new(
        store: Arc<Store>,
        secrets: Arc<SecretProvider>,
        config: Arc<Config>,
        commands: UnboundedSender<Command>,
    ) -> Self {
        let theme = Theme::by_name(&config.ui.theme);
        let keymap = Keymap::build(config.ui.vim_keys, &config.bindings);
        let threading = config.ui.threading;

        let mut app = Self {
            store,
            secrets,
            theme,
            keymap,
            commands,
            pane: Pane::List,
            overlay: Overlay::None,
            input_mode: InputMode::None,
            input: String::new(),
            input_cursor: 0,
            overlay_sel: 0,
            folders: Vec::new(),
            folder_sel: 0,
            sidebar: config.ui.layout != crate::config::Layout::ListOnly,
            messages: Vec::new(),
            threads: Vec::new(),
            rows: Vec::new(),
            list_sel: 0,
            list_offset: 0,
            collapsed: HashSet::new(),
            marked: BTreeSet::new(),
            body: None,
            body_raw: None,
            body_scroll: 0,
            body_key: None,
            render: RenderOptions {
                width: config.ui.wrap_width as usize,
                ..Default::default()
            },
            query: None,
            query_text: String::new(),
            sort: Sort::DateDesc,
            threading,
            status: HashMap::new(),
            notice: None,
            outbox_len: 0,
            should_quit: false,
            redraw: true,
            last_body_request: None,
            pending_secret: None,
            config,
        };
        app.reload_folders();
        app.reload_messages();
        app
    }

    pub fn notify(&mut self, message: impl Into<String>) {
        self.notice = Some((message.into(), Instant::now(), false));
        self.redraw = true;
    }

    pub fn warn(&mut self, message: impl Into<String>) {
        self.notice = Some((message.into(), Instant::now(), true));
        self.redraw = true;
    }

    pub fn expire_notice(&mut self) {
        if let Some((_, at, _)) = &self.notice
            && at.elapsed() > NOTICE_TTL
        {
            self.notice = None;
            self.redraw = true;
        }
    }

    pub fn send(&mut self, cmd: Command) {
        if self.commands.send(cmd).is_err() {
            self.warn("the sync engine has stopped; changes are local only");
        }
    }

    // ---- folders ----

    pub fn reload_folders(&mut self) {
        let Ok(all) = self.store.folders(None) else { return };
        let mut rows = Vec::new();
        let multi = self.config.accounts.len() > 1;

        for account in self.config.accounts.iter().filter(|a| a.enabled) {
            if multi {
                rows.push(FolderRow {
                    account: account.name.clone(),
                    name: String::new(),
                    label: account.name.clone(),
                    depth: 0,
                    unread: 0,
                    total: 0,
                    role: None,
                    is_account_header: true,
                });
            }

            let mut folders: Vec<&FolderState> =
                all.iter().filter(|f| f.account == account.name).collect();
            folders.sort_by_key(|f| (folder_rank(f), f.name.to_lowercase()));

            for f in folders {
                rows.push(FolderRow {
                    account: f.account.clone(),
                    name: f.name.clone(),
                    label: f.leaf().to_string(),
                    depth: f.depth() + usize::from(multi),
                    unread: f.unseen,
                    total: f.exists,
                    role: f.role,
                    is_account_header: false,
                });
            }
        }

        if rows.is_empty() {
            for account in self.config.accounts.iter().filter(|a| a.enabled) {
                rows.push(FolderRow {
                    account: account.name.clone(),
                    name: account.folders.inbox.clone(),
                    label: account.folders.inbox.clone(),
                    depth: 0,
                    unread: 0,
                    total: 0,
                    role: Some(FolderRole::Inbox),
                    is_account_header: false,
                });
            }
        }

        self.folders = rows;
        self.folder_sel = self
            .folder_sel
            .min(self.folders.len().saturating_sub(1));
        if self.current_folder().is_none() {
            self.folder_sel = self
                .folders
                .iter()
                .position(|f| !f.is_account_header)
                .unwrap_or(0);
        }
        self.redraw = true;
    }

    pub fn current_folder(&self) -> Option<&FolderRow> {
        self.folders
            .get(self.folder_sel)
            .filter(|f| !f.is_account_header)
    }

    pub fn select_folder(&mut self, delta: isize) {
        if self.folders.is_empty() {
            return;
        }
        let len = self.folders.len() as isize;
        let mut i = self.folder_sel as isize;
        for _ in 0..len {
            i = (i + delta).rem_euclid(len);
            if !self.folders[i as usize].is_account_header {
                break;
            }
        }
        self.folder_sel = i as usize;
        self.reload_messages();
    }

    // ---- messages ----

    pub fn reload_messages(&mut self) {
        let Some(folder) = self.current_folder().cloned() else {
            self.messages.clear();
            self.rebuild_rows();
            return;
        };

        let mut msgs = match self.query.as_ref() {
            Some(q) => self.search_local(q),
            None => self
                .store
                .envelopes(&folder.account, &folder.name)
                .unwrap_or_default(),
        };

        msgs.retain(|m| !m.flags.contains(Flags::DELETED));
        self.sort_messages(&mut msgs);
        self.messages = msgs;
        self.rebuild_rows();
        self.redraw = true;
    }

    fn sort_messages(&self, msgs: &mut [Envelope]) {
        match self.sort {
            Sort::DateDesc => msgs.sort_by(|a, b| b.date.cmp(&a.date)),
            Sort::DateAsc => msgs.sort_by(|a, b| a.date.cmp(&b.date)),
            Sort::SubjectAsc => msgs.sort_by(|a, b| {
                a.base_subject()
                    .to_lowercase()
                    .cmp(&b.base_subject().to_lowercase())
            }),
            Sort::SenderAsc => msgs.sort_by(|a, b| {
                a.display_from()
                    .to_lowercase()
                    .cmp(&b.display_from().to_lowercase())
            }),
            Sort::SizeDesc => msgs.sort_by(|a, b| b.size.cmp(&a.size)),
            Sort::UnreadFirst => {
                msgs.sort_by(|a, b| b.is_unread().cmp(&a.is_unread()).then(b.date.cmp(&a.date)))
            }
        }
    }

    /// Narrows by the blind index where it can, then applies the full predicate.
    /// The index only answers positive whole-token matches, so it is a filter to
    /// cut work, never the authority on what matches.
    fn search_local(&self, q: &Node) -> Vec<Envelope> {
        let folder = self.current_folder().cloned();
        let terms = q.index_terms();

        let candidates: Option<BTreeSet<MsgKey>> = if terms.is_empty() {
            None
        } else {
            let mut sets = terms.iter().filter_map(|(field, term)| {
                self.store
                    .search_token(field, term)
                    .ok()
                    .map(|v| v.into_iter().collect::<BTreeSet<_>>())
            });
            sets.next().map(|first| {
                sets.fold(first, |acc, next| acc.intersection(&next).cloned().collect())
            })
        };

        let pool: Vec<Envelope> = match candidates {
            Some(keys) => keys
                .iter()
                .filter_map(|k| self.store.envelope(&k.account, &k.folder, k.uid).ok().flatten())
                .collect(),
            None => match &folder {
                Some(f) => self.store.envelopes(&f.account, &f.name).unwrap_or_default(),
                None => Vec::new(),
            },
        };

        pool.into_iter().filter(|e| q.matches(e)).collect()
    }

    pub fn rebuild_rows(&mut self) {
        self.rows.clear();

        if !self.threading {
            self.rows
                .extend((0..self.messages.len()).map(|msg| ListRow::Message { msg, depth: 0 }));
        } else {
            self.threads = thread::build(&self.messages, true);
            if self.sort == Sort::DateAsc {
                self.threads.reverse();
            }
            for (index, t) in self.threads.iter().enumerate() {
                let collapsed = self.collapsed.contains(&t.id) && t.members.len() > 1;
                self.rows.push(ListRow::Thread { index, collapsed });
                if !collapsed {
                    for (msg, depth) in &t.tree {
                        self.rows.push(ListRow::Message { msg: *msg, depth: *depth });
                    }
                }
            }
        }

        self.list_sel = self.list_sel.min(self.rows.len().saturating_sub(1));
        self.redraw = true;
    }

    pub fn selected_message(&self) -> Option<&Envelope> {
        match self.rows.get(self.list_sel)? {
            ListRow::Message { msg, .. } => self.messages.get(*msg),
            ListRow::Thread { index, .. } => {
                let t = self.threads.get(*index)?;
                self.messages.get(*t.members.last()?)
            }
        }
    }

    pub fn selected_key(&self) -> Option<MsgKey> {
        self.selected_message().map(|e| e.key())
    }

    /// Operations apply to the marked set when there is one, otherwise to the
    /// message under the cursor. Expanding a collapsed thread header covers the
    /// whole thread, which is what "delete this conversation" should mean.
    pub fn target_keys(&self) -> Vec<MsgKey> {
        if !self.marked.is_empty() {
            return self.marked.iter().cloned().collect();
        }
        match self.rows.get(self.list_sel) {
            Some(ListRow::Thread { index, collapsed: true }) => self
                .threads
                .get(*index)
                .map(|t| t.members.iter().filter_map(|m| self.messages.get(*m)).map(|e| e.key()).collect())
                .unwrap_or_default(),
            _ => self.selected_key().into_iter().collect(),
        }
    }

    pub fn move_list(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let len = self.rows.len() as isize;
        self.list_sel = (self.list_sel as isize + delta).clamp(0, len - 1) as usize;
        self.on_selection_changed();
    }

    pub fn jump_list(&mut self, to: usize) {
        self.list_sel = to.min(self.rows.len().saturating_sub(1));
        self.on_selection_changed();
    }

    pub fn next_unread(&mut self, forward: bool) {
        let len = self.rows.len();
        if len == 0 {
            return;
        }
        for step in 1..=len {
            let i = if forward {
                (self.list_sel + step) % len
            } else {
                (self.list_sel + len - step % len) % len
            };
            let unread = match &self.rows[i] {
                ListRow::Message { msg, .. } => {
                    self.messages.get(*msg).is_some_and(|e| e.is_unread())
                }
                ListRow::Thread { index, .. } => {
                    self.threads.get(*index).is_some_and(|t| t.unread > 0)
                }
            };
            if unread {
                self.list_sel = i;
                self.on_selection_changed();
                return;
            }
        }
        self.notify("no unread messages in this folder");
    }

    pub fn on_selection_changed(&mut self) {
        self.body_scroll = 0;
        self.redraw = true;

        let Some(key) = self.selected_key() else {
            self.body = None;
            self.body_key = None;
            return;
        };
        if self.body_key.as_ref() == Some(&key) {
            return;
        }

        self.body = None;
        self.body_raw = None;
        self.body_key = Some(key.clone());
        self.last_body_request = Some(Instant::now());
        self.send(Command::FetchBody(key));
    }

    pub fn set_body(&mut self, key: MsgKey, raw: Arc<Vec<u8>>) {
        if self.body_key.as_ref() != Some(&key) {
            return;
        }
        self.body = Some(crate::mail::body::render(&raw, &self.render));
        self.body_raw = Some(raw);
        self.redraw = true;
        self.mark_seen_after_delay(&key);
    }

    fn mark_seen_after_delay(&mut self, key: &MsgKey) {
        let already_read = self
            .selected_message()
            .is_some_and(|e| e.flags.contains(Flags::SEEN));
        if already_read {
            return;
        }
        self.send(Command::SetFlags {
            keys: vec![key.clone()],
            add: Flags::SEEN,
            remove: Flags::EMPTY,
        });
    }

    pub fn toggle_mark(&mut self) {
        let Some(key) = self.selected_key() else { return };
        if !self.marked.insert(key.clone()) {
            self.marked.remove(&key);
        }
        self.redraw = true;
    }

    pub fn toggle_thread(&mut self) {
        let id = match self.rows.get(self.list_sel) {
            Some(ListRow::Thread { index, .. }) => self.threads.get(*index).map(|t| t.id.clone()),
            Some(ListRow::Message { msg, .. }) => self
                .messages
                .get(*msg)
                .and_then(|m| self.thread_of(m).map(|t| t.id.clone())),
            None => None,
        };
        let Some(id) = id else { return };
        if !self.collapsed.insert(id.clone()) {
            self.collapsed.remove(&id);
        }
        self.rebuild_rows();
    }

    fn thread_of(&self, msg: &Envelope) -> Option<&Thread> {
        let key = msg.key();
        self.threads.iter().find(|t| {
            t.members
                .iter()
                .any(|m| self.messages.get(*m).is_some_and(|e| e.key() == key))
        })
    }

    pub fn attachments(&self) -> Vec<AttachmentMeta> {
        self.body
            .as_ref()
            .map(|b| b.attachments.clone())
            .or_else(|| self.selected_message().map(|m| m.attachments.clone()))
            .unwrap_or_default()
    }

    pub fn links(&self) -> Vec<String> {
        self.body.as_ref().map(|b| b.links.clone()).unwrap_or_default()
    }

    pub fn apply_search(&mut self, text: &str) {
        if text.trim().is_empty() {
            self.query = None;
            self.query_text.clear();
            self.reload_messages();
            self.notify("search cleared");
            return;
        }
        match query::parse(text) {
            Ok(node) => {
                self.query = Some(node);
                self.query_text = text.to_string();
                self.reload_messages();
                let n = self.messages.len();
                self.notify(format!("{n} message{} match", if n == 1 { "" } else { "s" }));
            }
            Err(e) => self.warn(e.to_string()),
        }
    }

    pub fn cycle_theme(&mut self) {
        let names = Theme::all();
        let i = names.iter().position(|n| *n == self.theme.name).unwrap_or(0);
        let next = names[(i + 1) % names.len()];
        self.theme = Theme::by_name(next);
        self.notify(format!("theme: {next}"));
    }

    pub fn status_summary(&self) -> String {
        if self.status.is_empty() {
            return SyncStatus::Idle.label().to_string();
        }
        let mut parts: Vec<String> = self
            .status
            .iter()
            .filter(|(_, s)| **s != SyncStatus::Idle)
            .map(|(a, s)| format!("{a}: {}", s.label()))
            .collect();
        parts.sort();
        if parts.is_empty() {
            "idle".into()
        } else {
            parts.join("  ")
        }
    }

    pub fn unread_total(&self) -> u32 {
        self.folders.iter().map(|f| f.unread).sum()
    }

    pub fn input_insert(&mut self, c: char) {
        let idx = self.byte_index(self.input_cursor);
        self.input.insert(idx, c);
        self.input_cursor += 1;
        self.redraw = true;
    }

    pub fn input_backspace(&mut self) {
        if self.input_cursor == 0 {
            return;
        }
        let start = self.byte_index(self.input_cursor - 1);
        let end = self.byte_index(self.input_cursor);
        self.input.replace_range(start..end, "");
        self.input_cursor -= 1;
        self.redraw = true;
    }

    fn byte_index(&self, char_index: usize) -> usize {
        self.input
            .char_indices()
            .nth(char_index)
            .map(|(i, _)| i)
            .unwrap_or(self.input.len())
    }

    pub fn begin_input(&mut self, mode: InputMode, seed: &str) {
        self.input_mode = mode;
        self.input = seed.to_string();
        self.input_cursor = self.input.chars().count();
        self.redraw = true;
    }

    pub fn end_input(&mut self) {
        self.input_mode = InputMode::None;
        self.input.clear();
        self.input_cursor = 0;
        self.pending_secret = None;
        self.redraw = true;
    }

    pub fn accounts(&self) -> Vec<String> {
        self.config
            .accounts
            .iter()
            .filter(|a| a.enabled)
            .map(|a| a.name.clone())
            .collect()
    }

    /// Saves a password typed in the reader, preferring the OS keyring and
    /// falling back to the encrypted vault, and says which one took it.
    pub fn save_password(&mut self, account: String, purpose: String, password: String) {
        if password.is_empty() {
            self.warn("nothing entered; the stored password is unchanged");
            return;
        }
        match self.secrets.store_password(&account, &purpose, &password) {
            Ok(crate::config::Auth::Keyring) => {
                self.notify(format!("{purpose} password for {account} saved to the OS keyring"))
            }
            Ok(_) => self.notify(format!(
                "{purpose} password for {account} saved to the encrypted vault (no keyring available)"
            )),
            Err(e) => self.warn(format!("could not store the password: {e}")),
        }
    }
}

fn folder_rank(f: &FolderState) -> u8 {
    match f.role {
        Some(FolderRole::Inbox) => 0,
        Some(FolderRole::Drafts) => 1,
        Some(FolderRole::Sent) => 2,
        Some(FolderRole::Archive) => 3,
        Some(FolderRole::All) => 4,
        None => 5,
        Some(FolderRole::Spam) => 6,
        Some(FolderRole::Trash) => 7,
    }
}
