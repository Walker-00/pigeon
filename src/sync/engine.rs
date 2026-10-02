use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use secrecy::ExposeSecret;
use tokio::sync::mpsc;

use crate::config::{Account, Config, EncryptPolicy};
use crate::mail::compose::Draft;
use crate::net::imap::{self, Credentials as ImapCreds, ImapSession};
use crate::net::smtp::{Credentials as SmtpCreds, SmtpClient};
use crate::secrets::{Resolved, SecretProvider};
use crate::store::Store;
use crate::store::model::{Envelope, Flags, FolderRole, MsgKey, OutboxItem, PendingOp};

use super::event::{Command, Event, SyncStatus};

const FETCH_BATCH: usize = 200;
/// Bodies asked for ahead of the user. One screenful plus a little, so opening
/// anything near the top of a folder is instant without downloading a mailbox.
const PREFETCH_MAX: usize = 30;
const PREFETCH_CHUNK: usize = 10;
const RETRY_BASE: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(300);

pub struct SyncHandle {
    pub commands: mpsc::UnboundedSender<Command>,
    pub events: mpsc::UnboundedReceiver<Event>,
}

pub struct SyncEngine {
    store: Arc<Store>,
    config: Arc<Config>,
    secrets: Arc<SecretProvider>,
    events: mpsc::UnboundedSender<Event>,
    /// Commands run on their own tasks, so without this a folder change would
    /// open one connection per prefetched message and the server would start
    /// refusing them.
    prefetching: tokio::sync::Mutex<()>,
}

impl SyncEngine {
    pub fn spawn(
        store: Arc<Store>,
        config: Arc<Config>,
        secrets: Arc<SecretProvider>,
    ) -> SyncHandle {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (evt_tx, evt_rx) = mpsc::unbounded_channel();

        let engine = Arc::new(Self {
            store,
            config,
            secrets,
            events: evt_tx,
            prefetching: tokio::sync::Mutex::new(()),
        });

        tokio::spawn({
            let engine = engine.clone();
            async move { engine.run(cmd_rx).await }
        });

        SyncHandle { commands: cmd_tx, events: evt_rx }
    }

    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    fn fail(&self, account: Option<&str>, err: impl std::fmt::Display) {
        tracing::warn!(account = account.unwrap_or("-"), "{err}");
        self.emit(Event::Error {
            account: account.map(str::to_string),
            message: err.to_string(),
        });
    }

    async fn run(self: Arc<Self>, mut commands: mpsc::UnboundedReceiver<Command>) {
        for account in self.config.accounts.iter().filter(|a| a.enabled) {
            let engine = self.clone();
            let account = account.clone();
            tokio::spawn(async move { engine.account_loop(account).await });
        }

        while let Some(cmd) = commands.recv().await {
            if matches!(cmd, Command::Shutdown) {
                break;
            }
            let engine = self.clone();
            tokio::spawn(async move { engine.handle(cmd).await });
        }
    }

    /// One long-lived task per account: connect, sync, then IDLE. Failures back
    /// off exponentially rather than hammering a server that is down.
    async fn account_loop(self: Arc<Self>, account: Account) {
        let mut backoff = RETRY_BASE;

        loop {
            self.emit(Event::Status {
                account: account.name.clone(),
                status: SyncStatus::Connecting,
            });

            match self.session_for(&account).await {
                Ok(session) => {
                    backoff = RETRY_BASE;
                    if let Err(e) = self.serve(&account, session).await {
                        self.fail(Some(&account.name), e);
                    }
                }
                Err(e) => self.fail(Some(&account.name), e),
            }

            self.emit(Event::Status {
                account: account.name.clone(),
                status: SyncStatus::Offline,
            });
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(RETRY_MAX);
        }
    }

    async fn serve(&self, account: &Account, mut session: ImapSession) -> anyhow::Result<()> {
        self.sync_account(account, &mut session).await?;

        let poll = Duration::from_secs(self.config.general.poll_interval_secs.max(30));
        loop {
            self.drain_pending(account, &mut session).await;

            if !(self.config.general.idle && session.caps.idle) {
                tokio::time::sleep(poll).await;
                self.sync_account(account, &mut session).await?;
                continue;
            }

            let inbox = account.folders.inbox.clone();
            session.select(&inbox).await?;

            self.emit(Event::Status {
                account: account.name.clone(),
                status: SyncStatus::Watching,
            });

            // The sender must outlive the select; dropping it early would make
            // the receiver resolve immediately and end the IDLE at once.
            let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let (restored, changed) = session.idle_once(imap::IDLE_TIMEOUT, stop_rx).await?;
            session = restored;

            if changed {
                self.sync_folder(account, &mut session, &inbox, true).await?;
            }
        }
    }

    async fn session_for(&self, account: &Account) -> anyhow::Result<ImapSession> {
        let resolved = self
            .secrets
            .resolve(account, "imap", &account.imap.auth, &account.imap.user)
            .await?;

        let creds = match resolved {
            Resolved::Password(p) => ImapCreds::Password {
                user: account.imap.user.clone(),
                password: p.expose_secret().to_string(),
            },
            Resolved::OAuth { user, access_token } => ImapCreds::XOAuth2 {
                user,
                token: access_token.expose_secret().to_string(),
            },
            Resolved::None => ImapCreds::Password {
                user: account.imap.user.clone(),
                password: String::new(),
            },
        };

        Ok(ImapSession::connect(&account.imap, &creds).await?)
    }

    pub async fn sync_account(
        &self,
        account: &Account,
        session: &mut ImapSession,
    ) -> anyhow::Result<()> {
        self.emit(Event::Status {
            account: account.name.clone(),
            status: SyncStatus::Syncing,
        });

        let mut folders = session.folders(&account.name).await?;
        folders.retain(|f| {
            f.is_selectable()
                && !account.folders.exclude.iter().any(|x| x == &f.name)
                && (!account.folders.subscribed_only || f.subscribed)
        });

        for f in &folders {
            let merged = match self.store.folder(&account.name, &f.name)? {
                Some(existing) => crate::store::model::FolderState {
                    uid_validity: existing.uid_validity,
                    uid_next: existing.uid_next,
                    highest_modseq: existing.highest_modseq,
                    last_sync: existing.last_sync,
                    ..f.clone()
                },
                None => f.clone(),
            };
            self.store.put_folder(&merged)?;
        }

        self.emit(Event::Folders {
            account: account.name.clone(),
            folders: self.store.folders(Some(&account.name))?,
        });

        let order = sync_order(&folders, &account.folders.inbox);
        for name in order {
            if let Err(e) = self.sync_folder(account, session, &name, false).await {
                self.fail(Some(&account.name), format!("{name}: {e}"));
            }
        }

        self.emit(Event::Status {
            account: account.name.clone(),
            status: SyncStatus::Idle,
        });
        Ok(())
    }

    pub async fn sync_folder(
        &self,
        account: &Account,
        session: &mut ImapSession,
        folder: &str,
        announce_new: bool,
    ) -> anyhow::Result<()> {
        let mailbox = session.select(folder).await?;
        let uid_validity = mailbox
            .uid_validity
            .ok_or_else(|| imap::ImapError::NoUidValidity(folder.to_string()))?;

        let mut state = self
            .store
            .folder(&account.name, folder)?
            .unwrap_or_else(|| crate::store::model::FolderState {
                account: account.name.clone(),
                name: folder.to_string(),
                ..Default::default()
            });

        // A changed UIDVALIDITY means every cached UID now refers to a
        // different message, so the local copy of this folder must be dropped.
        let reset = state.uid_validity != 0 && state.uid_validity != uid_validity;
        if reset {
            let stale = self.store.uids(&account.name, folder)?;
            self.store.remove_envelopes(&account.name, folder, &stale)?;
            state.highest_modseq = 0;
            self.emit(Event::Removed {
                account: account.name.clone(),
                folder: folder.to_string(),
                uids: stale,
            });
        }

        let local: BTreeSet<u32> = self
            .store
            .uids(&account.name, folder)?
            .into_iter()
            .collect();

        let remote = session.all_uids().await?;

        // An empty SEARCH in a mailbox the server says is not empty is the
        // search failing, not every message being gone. Believing it would
        // delete the local copy of a folder that is still on the server.
        if remote.is_empty() && mailbox.exists > 0 {
            self.fail(
                Some(&account.name),
                format!("{folder}: the server listed no messages but reports {} — not clearing the local copy", mailbox.exists),
            );
            return Ok(());
        }

        let vanished: Vec<u32> = local.difference(&remote).copied().collect();
        if !vanished.is_empty() {
            self.store.remove_envelopes(&account.name, folder, &vanished)?;
            self.emit(Event::Removed {
                account: account.name.clone(),
                folder: folder.to_string(),
                uids: vanished,
            });
        }

        let missing: Vec<u32> = remote.difference(&local).copied().collect();
        let mut fresh = Vec::new();
        for chunk in missing.chunks(FETCH_BATCH) {
            let set = imap::uid_set(chunk);
            let envelopes = session.fetch_envelopes(&account.name, folder, &set).await?;
            if envelopes.is_empty() {
                continue;
            }
            self.store.put_envelopes(&envelopes)?;
            self.emit(Event::Envelopes {
                account: account.name.clone(),
                folder: folder.to_string(),
                envelopes: envelopes.clone(),
                replaced: false,
            });
            fresh.extend(envelopes);
        }

        // CONDSTORE lets the server report only the flags that moved since the
        // last sync, instead of re-fetching every envelope in the mailbox.
        if session.caps.condstore && state.highest_modseq > 0 && !reset {
            for f in session.changed_since(state.highest_modseq).await? {
                let Some(uid) = f.uid else { continue };
                let (flags, _) = imap::flags_from_fetch(&f);
                if let Some(env) =
                    self.store
                        .update_flags(&account.name, folder, uid, flags, !flags)?
                {
                    self.emit(Event::FlagsChanged { key: env.key(), flags: env.flags });
                }
            }
        }

        state.uid_validity = uid_validity;
        state.uid_next = mailbox.uid_next.unwrap_or(0);
        state.exists = mailbox.exists;
        state.highest_modseq = mailbox.highest_modseq.unwrap_or(state.highest_modseq);
        state.last_sync = Some(Utc::now());
        state.unseen = self
            .store
            .envelopes(&account.name, folder)?
            .iter()
            .filter(|e| e.is_unread())
            .count() as u32;
        self.store.put_folder(&state)?;

        if announce_new && !fresh.is_empty() {
            let unread: Vec<Envelope> = fresh.into_iter().filter(|e| e.is_unread()).collect();
            if !unread.is_empty() {
                self.emit(Event::NewMail {
                    account: account.name.clone(),
                    folder: folder.to_string(),
                    envelopes: unread,
                });
            }
        }

        Ok(())
    }

    /// Replays operations that were queued while offline. Each one is dropped
    /// from the queue only after the server accepts it, so a crash mid-replay
    /// retries rather than silently losing the change.
    async fn drain_pending(&self, account: &Account, session: &mut ImapSession) {
        let Ok(pending) = self.store.pending() else { return };

        for (seq, op) in pending {
            let result = self.apply_pending(account, session, &op).await;
            match result {
                Ok(true) => {
                    let _ = self.store.drop_pending(seq);
                }
                Ok(false) => {}
                Err(e) => {
                    // A NO/BAD is the server refusing this exact command — retrying
                    // it verbatim would fail forever and block every op queued
                    // behind it. Anything else (a dropped connection, a timeout) is
                    // worth retrying, so leave it queued and stop for this round.
                    let permanent = matches!(
                        e.downcast_ref::<imap::ImapError>(),
                        Some(imap::ImapError::Imap(
                            async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_)
                        ))
                    );
                    self.fail(Some(&account.name), &e);
                    if permanent {
                        let _ = self.store.drop_pending(seq);
                        continue;
                    }
                    break;
                }
            }
        }
    }

    async fn apply_pending(
        &self,
        account: &Account,
        session: &mut ImapSession,
        op: &PendingOp,
    ) -> anyhow::Result<bool> {
        let belongs = |a: &str| a == account.name;

        match op {
            PendingOp::AddFlags { key, flags } | PendingOp::RemoveFlags { key, flags } => {
                if !belongs(&key.account) {
                    return Ok(false);
                }
                let add = matches!(op, PendingOp::AddFlags { .. });
                session.select(&key.folder).await?;
                session
                    .store_flags(&key.uid.to_string(), *flags, &[], add)
                    .await?;
            }
            PendingOp::Move { key, to } => {
                if !belongs(&key.account) {
                    return Ok(false);
                }
                session.select(&key.folder).await?;
                session.move_to(&key.uid.to_string(), to).await?;
            }
            PendingOp::Copy { key, to } => {
                if !belongs(&key.account) {
                    return Ok(false);
                }
                session.select(&key.folder).await?;
                session.copy_to(&key.uid.to_string(), to).await?;
            }
            PendingOp::Delete { key } => {
                if !belongs(&key.account) {
                    return Ok(false);
                }
                session.select(&key.folder).await?;
                session
                    .store_flags(&key.uid.to_string(), Flags::DELETED, &[], true)
                    .await?;
                session.expunge_uids(&key.uid.to_string()).await?;
            }
            PendingOp::Expunge { account: a, folder } => {
                if !belongs(a) {
                    return Ok(false);
                }
                session.select(folder).await?;
                session.expunge_uids("1:*").await?;
            }
            PendingOp::CreateFolder { account: a, name } => {
                if !belongs(a) {
                    return Ok(false);
                }
                session.create_folder(name).await?;
            }
            PendingOp::DeleteFolder { account: a, name } => {
                if !belongs(a) {
                    return Ok(false);
                }
                session.delete_folder(name).await?;
            }
            PendingOp::RenameFolder { account: a, from, to } => {
                if !belongs(a) {
                    return Ok(false);
                }
                session.rename_folder(from, to).await?;
            }
        }
        Ok(true)
    }

    async fn handle(self: Arc<Self>, cmd: Command) {
        let result = self.dispatch(cmd).await;
        if let Err(e) = result {
            self.fail(None, e);
        }
    }

    async fn dispatch(&self, cmd: Command) -> anyhow::Result<()> {
        match cmd {
            Command::SetFlags { keys, add, remove } => {
                for key in keys {
                    if let Some(env) = self.store.update_flags(
                        &key.account,
                        &key.folder,
                        key.uid,
                        add,
                        remove,
                    )? {
                        self.emit(Event::FlagsChanged { key: key.clone(), flags: env.flags });
                    }
                    if !add.is_empty() {
                        self.store.push_pending(&PendingOp::AddFlags { key: key.clone(), flags: add })?;
                    }
                    if !remove.is_empty() {
                        self.store.push_pending(&PendingOp::RemoveFlags { key, flags: remove })?;
                    }
                }
            }
            Command::Move { keys, to } => {
                for key in keys {
                    self.store.push_pending(&PendingOp::Move { key: key.clone(), to: to.clone() })?;
                    self.store
                        .remove_envelopes(&key.account, &key.folder, &[key.uid])?;
                    self.emit(Event::Removed {
                        account: key.account.clone(),
                        folder: key.folder.clone(),
                        uids: vec![key.uid],
                    });
                }
            }
            Command::Copy { keys, to } => {
                for key in keys {
                    self.store.push_pending(&PendingOp::Copy { key, to: to.clone() })?;
                }
            }
            Command::Delete { keys, permanent } => {
                for key in keys {
                    let trash = self.trash_folder(&key.account);
                    // A message already in Trash has nowhere left to move to — the
                    // server refuses a move into the mailbox it is already in, the
                    // pending op then fails forever, and the next sync re-adds the
                    // "deleted" message because the server never actually lost it.
                    let already_in_trash = trash.as_deref() == Some(key.folder.as_str());
                    if permanent || already_in_trash {
                        self.store.push_pending(&PendingOp::Delete { key: key.clone() })?;
                    } else if let Some(trash) = trash {
                        self.store
                            .push_pending(&PendingOp::Move { key: key.clone(), to: trash })?;
                    } else {
                        self.store.push_pending(&PendingOp::AddFlags {
                            key: key.clone(),
                            flags: Flags::DELETED,
                        })?;
                    }
                    self.store
                        .remove_envelopes(&key.account, &key.folder, &[key.uid])?;
                    self.emit(Event::Removed {
                        account: key.account.clone(),
                        folder: key.folder.clone(),
                        uids: vec![key.uid],
                    });
                }
            }
            Command::Send(draft) => self.queue_send(*draft).await?,
            Command::FlushOutbox => self.flush_outbox().await?,
            Command::SaveDraft(draft) => self.save_draft(*draft).await?,
            Command::CreateFolder { account, name } => {
                self.store.push_pending(&PendingOp::CreateFolder { account, name })?;
            }
            Command::DeleteFolder { account, name } => {
                self.store.push_pending(&PendingOp::DeleteFolder { account, name })?;
            }
            Command::RenameFolder { account, from, to } => {
                self.store
                    .push_pending(&PendingOp::RenameFolder { account, from, to })?;
            }
            Command::FetchBody(key) => self.fetch_body(key).await?,
            Command::PrefetchBodies { account, folder, uids } => {
                self.prefetch_bodies(&account, &folder, uids).await?
            }
            Command::SyncAll => {
                for account in self.config.accounts.iter().filter(|a| a.enabled) {
                    self.sync_now(&account.name, None).await?;
                }
            }
            Command::SyncAccount(account) => self.sync_now(&account, None).await?,
            Command::SyncFolder { account, folder } => {
                self.sync_now(&account, Some(&folder)).await?
            }
            Command::ServerSearch { .. } | Command::Reconnect | Command::Shutdown => {}
        }
        Ok(())
    }

    fn trash_folder(&self, account: &str) -> Option<String> {
        let acct = self.config.account(account)?;
        if let Some(t) = &acct.folders.trash {
            return Some(t.clone());
        }
        self.store
            .folders(Some(account))
            .ok()?
            .into_iter()
            .find(|f| f.role == Some(FolderRole::Trash))
            .map(|f| f.name)
    }

    fn sent_folder(&self, account: &str) -> Option<String> {
        let acct = self.config.account(account)?;
        if let Some(t) = &acct.folders.sent {
            return Some(t.clone());
        }
        self.store
            .folders(Some(account))
            .ok()?
            .into_iter()
            .find(|f| f.role == Some(FolderRole::Sent))
            .map(|f| f.name)
    }

    /// A sync asked for by hand. The account's own loop is usually parked in
    /// IDLE, which it will not leave until the server says something, so the
    /// refresh button needs a connection of its own.
    async fn sync_now(&self, account: &str, folder: Option<&str>) -> anyhow::Result<()> {
        let account = self
            .config
            .account(account)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{account}`"))?
            .clone();

        let mut session = self.session_for(&account).await?;
        // A move or delete just queues a pending op and updates the local copy
        // right away; the op itself is normally sent by the account's own IDLE
        // loop. A sync run on a separate connection before that happens would see
        // the message still on the server and fetch it right back — this is what
        // made a delete or move look like it "undid itself" on refresh.
        self.drain_pending(&account, &mut session).await;
        let result = match folder {
            Some(folder) => self.sync_folder(&account, &mut session, folder, true).await,
            None => self.sync_account(&account, &mut session).await,
        };
        session.logout().await;
        result
    }

    async fn fetch_body(&self, key: MsgKey) -> anyhow::Result<()> {
        let blob_id = blob_id(&key);
        if let Ok(raw) = self.store.blob(&blob_id) {
            self.emit(Event::Body { key, raw: Arc::new(raw) });
            return Ok(());
        }

        let account = self
            .config
            .account(&key.account)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{}`", key.account))?
            .clone();

        let mut session = self.session_for(&account).await?;
        session.select(&key.folder).await?;
        let fetched = session.fetch_body(key.uid).await?;
        session.logout().await;

        let Some(raw) = fetched else {
            anyhow::bail!("message {} is no longer on the server", key.uid);
        };

        let envelope = self.absorb_body(&key, &raw)?;
        self.emit(Event::Body { key: key.clone(), raw: Arc::new(raw) });
        if let Some(envelope) = envelope {
            self.emit(Event::Envelopes {
                account: key.account,
                folder: key.folder,
                envelopes: vec![envelope],
                replaced: false,
            });
        }
        Ok(())
    }

    /// Downloads bodies the user has not asked for yet, so that opening a
    /// message is a store read rather than a round trip to the server.
    async fn prefetch_bodies(
        &self,
        account: &str,
        folder: &str,
        uids: Vec<u32>,
    ) -> anyhow::Result<()> {
        let mut wanted = Vec::new();
        let mut repaired = Vec::new();
        for uid in uids {
            let key = MsgKey {
                account: account.to_string(),
                folder: folder.to_string(),
                uid,
            };
            if !self.store.has_blob(&blob_id(&key)).unwrap_or(false) {
                if wanted.len() < PREFETCH_MAX {
                    wanted.push(uid);
                }
                continue;
            }
            // Envelopes filed before their body arrived carry no preview and a
            // guessed html flag. The body is already on disk, so that is worth
            // correcting without asking the server for anything.
            let stale = self
                .store
                .envelope(account, folder, uid)?
                .is_some_and(|e| crate::mail::parse::is_blank_preview(&e.preview));
            if !stale {
                continue;
            }
            if let Ok(raw) = self.store.blob(&blob_id(&key)) {
                match self.absorb_body(&key, &raw) {
                    Ok(Some(envelope)) if !crate::mail::parse::is_blank_preview(&envelope.preview) => {
                        repaired.push(envelope)
                    }
                    _ => {}
                }
            }
        }

        if !repaired.is_empty() {
            self.emit(Event::Envelopes {
                account: account.to_string(),
                folder: folder.to_string(),
                envelopes: repaired,
                replaced: false,
            });
        }

        if wanted.is_empty() {
            return Ok(());
        }

        let acct = self
            .config
            .account(account)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{account}`"))?
            .clone();

        let _one_at_a_time = self.prefetching.lock().await;

        let mut session = self.session_for(&acct).await?;
        session.select(folder).await?;

        for chunk in wanted.chunks(PREFETCH_CHUNK) {
            let set = chunk.iter().map(u32::to_string).collect::<Vec<_>>().join(",");
            let bodies = match session.fetch_bodies(&set).await {
                Ok(bodies) => bodies,
                // A prefetch is a convenience; failing it must not surface as an
                // error the user has to read.
                Err(_) => break,
            };

            let mut updated = Vec::with_capacity(bodies.len());
            for (uid, raw) in bodies {
                let key = MsgKey {
                    account: account.to_string(),
                    folder: folder.to_string(),
                    uid,
                };
                if let Ok(Some(envelope)) = self.absorb_body(&key, &raw) {
                    updated.push(envelope);
                }
                self.emit(Event::Body { key, raw: Arc::new(raw) });
            }

            if !updated.is_empty() {
                self.emit(Event::Envelopes {
                    account: account.to_string(),
                    folder: folder.to_string(),
                    envelopes: updated,
                    replaced: false,
                });
            }
        }

        session.logout().await;
        Ok(())
    }

    /// Stores a body and re-reads the envelope from it. The list is built from
    /// header-only fetches, so the preview, the html flag and the attachment
    /// list are guesses until the whole message is on disk.
    fn absorb_body(&self, key: &MsgKey, raw: &[u8]) -> anyhow::Result<Option<Envelope>> {
        let id = blob_id(key);
        self.store.put_blob(&id, raw)?;

        let Some(old) = self.store.envelope(&key.account, &key.folder, key.uid)? else {
            return Ok(None);
        };

        let mut envelope = match crate::mail::parse::parse_message(
            &key.account,
            &key.folder,
            key.uid,
            raw,
            old.flags,
            old.keywords.clone(),
        ) {
            Some(parsed) => Envelope {
                modseq: old.modseq,
                received: old.received,
                size: old.size,
                tags: old.tags.clone(),
                thread_id: old.thread_id.clone(),
                ..parsed.envelope
            },
            None => old,
        };
        envelope.body_blob = Some(id);
        self.store.put_envelopes(std::slice::from_ref(&envelope))?;
        Ok(Some(envelope))
    }

    async fn save_draft(&self, draft: Draft) -> anyhow::Result<()> {
        let account = self
            .config
            .account(&draft.account)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{}`", draft.account))?
            .clone();
        let raw = draft.to_mime()?;

        let folder = account
            .folders
            .drafts
            .clone()
            .or_else(|| {
                self.store
                    .folders(Some(&account.name))
                    .ok()?
                    .into_iter()
                    .find(|f| f.role == Some(FolderRole::Drafts))
                    .map(|f| f.name)
            })
            .ok_or_else(|| anyhow::anyhow!("no Drafts folder configured for this account"))?;

        let mut session = self.session_for(&account).await?;
        let result = session.append(&folder, &raw, Flags::DRAFT | Flags::SEEN).await;
        session.logout().await;
        result?;

        self.emit(Event::Notice(format!("draft saved to {folder}")));
        Ok(())
    }

    async fn queue_send(&self, draft: Draft) -> anyhow::Result<()> {
        let account = self
            .config
            .account(&draft.account)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{}`", draft.account))?
            .clone();

        if account.pgp.encrypt_policy == EncryptPolicy::Always && !draft.encrypt {
            anyhow::bail!(
                "account `{}` requires encryption, but no usable key was found for every recipient",
                account.name
            );
        }

        let raw = draft.to_mime()?;
        let blob = format!("outbox:{}", uuid::Uuid::new_v4());
        self.store.put_blob(&blob, &raw)?;

        let item = OutboxItem {
            id: if draft.id.is_empty() { uuid::Uuid::new_v4().to_string() } else { draft.id.clone() },
            account: draft.account.clone(),
            from: draft.from.clone().unwrap_or_default(),
            to: draft.to.clone(),
            cc: draft.cc.clone(),
            bcc: draft.bcc.clone(),
            subject: draft.subject.clone(),
            queued_at: Utc::now(),
            send_after: None,
            attempts: 0,
            last_error: None,
            raw_blob: blob,
            save_to_sent: true,
        };
        self.store.enqueue(&item)?;
        self.emit(Event::OutboxChanged { pending: self.store.outbox()? });

        self.flush_outbox().await
    }

    pub async fn flush_outbox(&self) -> anyhow::Result<()> {
        for mut item in self.store.outbox()? {
            if item.send_after.is_some_and(|t| t > Utc::now()) {
                continue;
            }
            match self.send_one(&item).await {
                Ok(sent_folder) => {
                    let _ = self.store.delete_blob(&item.raw_blob);
                    self.store.dequeue(&item.id)?;
                    self.emit(Event::Sent { id: item.id.clone() });
                    // The message is on the server's Sent folder now, but only the
                    // account's own IDLE loop would otherwise notice — which can sit
                    // parked on INBOX for a long time. Pull the new envelope in now
                    // so Sent shows it without the user having to refresh by hand.
                    if let Some(folder) = sent_folder
                        && let Err(e) = self.sync_now(&item.account, Some(&folder)).await
                    {
                        self.fail(Some(&item.account), format!("{folder}: {e}"));
                    }
                }
                Err(e) => {
                    item.attempts += 1;
                    item.last_error = Some(e.to_string());
                    // Back off so a permanently broken message does not spin.
                    item.send_after =
                        Some(Utc::now() + chrono::Duration::seconds(30 * item.attempts as i64));
                    self.emit(Event::SendFailed { id: item.id.clone(), message: e.to_string() });
                    self.store.enqueue(&item)?;
                    self.fail(Some(&item.account), e);
                }
            }
        }
        self.emit(Event::OutboxChanged { pending: self.store.outbox()? });
        Ok(())
    }

    /// Sends the message and, if a copy went to Sent, returns that folder's name.
    async fn send_one(&self, item: &OutboxItem) -> anyhow::Result<Option<String>> {
        let account = self
            .config
            .account(&item.account)
            .ok_or_else(|| anyhow::anyhow!("unknown account `{}`", item.account))?
            .clone();
        let raw = self.store.blob(&item.raw_blob)?;

        let user = account
            .smtp
            .user
            .clone()
            .unwrap_or_else(|| account.address.clone());
        let resolved = self
            .secrets
            .resolve(&account, "smtp", &account.smtp.auth, &user)
            .await?;

        let creds = match resolved {
            Resolved::None => SmtpCreds::None,
            Resolved::Password(p) => SmtpCreds::Plain {
                user,
                password: p.expose_secret().to_string(),
            },
            Resolved::OAuth { user, access_token } => SmtpCreds::XOAuth2 {
                user,
                token: access_token.expose_secret().to_string(),
            },
        };

        let ehlo = account.address.rsplit('@').next().unwrap_or("localhost");
        let mut client = SmtpClient::connect(&account.smtp, ehlo).await?;
        client.authenticate(&creds).await?;

        let recipients: Vec<String> = item
            .to
            .iter()
            .chain(&item.cc)
            .chain(&item.bcc)
            .map(|a| a.email.clone())
            .collect();

        client.send(&item.from.email, &recipients, &raw).await?;
        client.quit().await;

        if item.save_to_sent
            && let Some(sent) = self.sent_folder(&account.name)
        {
            let mut session = self.session_for(&account).await?;
            let r = session.append(&sent, &raw, Flags::SEEN).await;
            session.logout().await;
            r?;
            return Ok(Some(sent));
        }

        Ok(None)
    }
}

pub fn blob_id(key: &MsgKey) -> String {
    format!("body:{}:{}:{}", key.account, key.folder, key.uid)
}

/// INBOX first, then the well-known roles, then everything else: the folders a
/// user is most likely to open should be populated soonest.
fn sync_order(folders: &[crate::store::model::FolderState], inbox: &str) -> Vec<String> {
    let rank = |f: &crate::store::model::FolderState| match f.role {
        _ if f.name == inbox => 0,
        Some(FolderRole::Inbox) => 1,
        Some(FolderRole::Sent) => 2,
        Some(FolderRole::Drafts) => 3,
        Some(FolderRole::Archive) => 4,
        Some(FolderRole::All) => 5,
        Some(FolderRole::Trash) => 7,
        Some(FolderRole::Spam) => 8,
        _ => 6,
    };
    let mut v: Vec<&crate::store::model::FolderState> = folders.iter().collect();
    v.sort_by_key(|f| (rank(f), f.name.clone()));
    v.into_iter().map(|f| f.name.clone()).collect()
}
