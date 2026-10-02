use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::Arc;
use regex::Regex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{RwLock, broadcast, mpsc};

use crate::cli;
use crate::config::{Config, Unlock};
use crate::crypto::{MasterKey, Vault};
use crate::mail::body::{self, RenderOptions};
use crate::mail::compose::{Draft, DraftAttachment, parse_address_list};
use crate::mail::{query, thread};
use crate::secrets::SecretProvider;
use crate::store::Store;
use crate::store::model::{Addr, Envelope, Flags, MsgKey};
use crate::sync::event::{Command, Event};
use crate::sync::SyncEngine;
use crate::sync::engine::blob_id;

use super::proto::{
    AccountView, FolderView, KeyRef, MessageView, OutboxView, Push, Request, Response,
};

const UNREAD_DEBOUNCE: Duration = Duration::from_millis(1500);
const BODY_WAIT: Duration = Duration::from_secs(30);
const PUSH_BACKLOG: usize = 256;

/// Everything that only exists once the vault is unlocked. Keeping it behind one
/// option means a locked daemon holds no key material at all, and `lock` can
/// drop the whole thing.
struct Active {
    config: Arc<Config>,
    store: Arc<Store>,
    secrets: Arc<SecretProvider>,
    commands: mpsc::UnboundedSender<Command>,
    data_dir: PathBuf,
}

pub struct Daemon {
    pub(crate) config_path: PathBuf,
    pub(crate) data_dir: PathBuf,
    no_encrypt: bool,
    active: RwLock<Option<Active>>,
    pushes: broadcast::Sender<Arc<String>>,
    bodies: broadcast::Sender<MsgKey>,
    statuses: RwLock<BTreeMap<String, &'static str>>,
    dirty: RwLock<BTreeSet<(String, String)>>,
    subscribers: AtomicUsize,
}

/// `$XDG_RUNTIME_DIR` is per-user and mode 0700, which is what makes it safe to
/// accept a vault passphrase over this socket at all. Without it, fall back to a
/// directory of our own that we create with the same permissions.
pub fn socket_path(explicit: Option<&Path>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(dir).join("pigeon").join("daemon.sock"));
    }
    let uid = std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .context("no XDG_RUNTIME_DIR and /proc is unavailable")?;
    Ok(PathBuf::from(format!("/tmp/pigeon-{uid}")).join("daemon.sock"))
}

fn private_dir(path: &Path) -> anyhow::Result<()> {
    let Some(parent) = path.parent() else { return Ok(()) };
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// A socket file left behind by a crash looks identical to a live one, so the
/// only reliable test is whether anything answers on it.
async fn clear_stale(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if UnixStream::connect(path).await.is_ok() {
        bail!("a pigeon daemon is already listening on {}", path.display());
    }
    std::fs::remove_file(path)?;
    Ok(())
}

pub async fn serve(args: &cli::Args, socket: Option<&Path>) -> anyhow::Result<()> {
    let config_path = match &args.config {
        Some(p) => p.clone(),
        None => Config::default_path()?,
    };

    let existing = match Config::load(Some(&config_path)) {
        Ok(c) => Some(c),
        Err(crate::config::ConfigError::Missing(_)) => None,
        Err(e) => return Err(e.into()),
    };

    let data_dir = match (&args.data_dir, &existing) {
        (Some(d), _) => d.clone(),
        (None, Some(c)) => c.data_dir()?,
        (None, None) => Config::default_data_dir()?,
    };
    std::fs::create_dir_all(&data_dir)?;

    let path = socket_path(socket)?;
    private_dir(&path)?;
    clear_stale(&path).await?;

    let listener = UnixListener::bind(&path)
        .with_context(|| format!("could not listen on {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    let (pushes, _) = broadcast::channel(PUSH_BACKLOG);
    let (bodies, _) = broadcast::channel(PUSH_BACKLOG);

    let daemon = Arc::new(Daemon {
        config_path,
        data_dir,
        no_encrypt: args.no_encrypt,
        active: RwLock::new(None),
        pushes,
        bodies,
        statuses: RwLock::new(BTreeMap::new()),
        dirty: RwLock::new(BTreeSet::new()),
        subscribers: AtomicUsize::new(0),
    });

    // A daemon meant to be started by a session manager cannot ask for a
    // passphrase, so it unlocks itself whenever the config says how. Otherwise
    // it serves in a locked state until a client sends one.
    let auto = existing
        .as_ref()
        .map(|c| args.no_encrypt || !c.general.encrypt_at_rest || c.general.unlock != Unlock::Prompt)
        .unwrap_or(false);

    if auto {
        match daemon.clone().unlock(None).await {
            Ok(_) => tracing::info!("vault unlocked from the config"),
            Err(e) => tracing::warn!("could not unlock automatically: {e:#}"),
        }
    } else if existing.is_none() {
        tracing::warn!("no config yet; clients must run setup before mail can sync");
    } else {
        tracing::info!("waiting for a client to send the vault passphrase");
    }

    eprintln!("pigeon daemon listening on {}", path.display());

    tokio::spawn(daemon.clone().unread_ticker());

    let accept = async {
        loop {
            let (stream, _) = listener.accept().await?;
            let daemon = daemon.clone();
            tokio::spawn(async move {
                if let Err(e) = daemon.client(stream).await {
                    tracing::debug!("client ended: {e:#}");
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = tokio::select! {
        r = accept => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = term.recv() => Ok(()),
    };

    daemon.broadcast(Push::Shutdown);
    let _ = std::fs::remove_file(&path);
    result
}

impl Daemon {
    fn broadcast(&self, push: Push) {
        let Ok(line) = serde_json::to_string(&push) else { return };
        let _ = self.pushes.send(Arc::new(line));
    }

    async fn with_active<T>(&self, f: impl FnOnce(&Active) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let guard = self.active.read().await;
        match guard.as_ref() {
            Some(a) => f(a),
            None => Err(anyhow!("locked: send `unlock` with the vault passphrase first")),
        }
    }

    pub(crate) async fn store(&self) -> anyhow::Result<Arc<Store>> {
        self.with_active(|a| Ok(a.store.clone())).await
    }

    pub(crate) async fn config(&self) -> anyhow::Result<Arc<Config>> {
        self.with_active(|a| Ok(a.config.clone())).await
    }

    pub(crate) async fn secrets(&self) -> anyhow::Result<Arc<SecretProvider>> {
        self.with_active(|a| Ok(a.secrets.clone())).await
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        !self.no_encrypt
    }

    /// Restarts the sync engine against a freshly read config, keeping the open
    /// store — so adding an account from the shell takes effect at once instead
    /// of needing the daemon restarted.
    pub(crate) async fn reload(self: Arc<Self>) -> anyhow::Result<Vec<AccountView>> {
        let (store, secrets) = {
            let guard = self.active.read().await;
            let active = guard
                .as_ref()
                .ok_or_else(|| anyhow!("locked: send `unlock` with the vault passphrase first"))?;
            let _ = active.commands.send(Command::Shutdown);
            (active.store.clone(), active.secrets.clone())
        };

        let config = Config::load(Some(&self.config_path))?;
        config.validate()?;
        let config = Arc::new(config);

        let handle = SyncEngine::spawn(store.clone(), config.clone(), secrets.clone());
        let events = handle.events;

        self.statuses.write().await.clear();
        *self.active.write().await = Some(Active {
            config,
            store,
            secrets,
            commands: handle.commands,
            data_dir: self.data_dir.clone(),
        });

        tokio::spawn(self.clone().pump(events));

        let accounts = self.accounts().await?;
        self.broadcast(Push::Unlocked { accounts: accounts.clone() });
        Ok(accounts)
    }

    async fn send_command(&self, cmd: Command) -> anyhow::Result<()> {
        self.with_active(|a| {
            a.commands
                .send(cmd)
                .map_err(|_| anyhow!("the sync engine has stopped"))
        })
        .await
    }

    async fn unlock(self: Arc<Self>, passphrase: Option<&str>) -> anyhow::Result<Vec<AccountView>> {
        if self.active.read().await.is_some() {
            return self.accounts().await;
        }

        // An empty config is a valid starting point: unlocking opens the store,
        // and the store is what `account-add` needs to file the first password.
        // Refusing to unlock without a config would make first-run setup over
        // this socket impossible.
        let config = match Config::load(Some(&self.config_path)) {
            Ok(c) => c,
            Err(crate::config::ConfigError::Missing(_)) => Config::default(),
            Err(e) => return Err(e.into()),
        };

        let master = self.master_key(&config, passphrase).await?;
        let store = Store::open(&self.data_dir.join("mail.redb"), &master)?;

        let config = Arc::new(config);
        let secrets = Arc::new(SecretProvider::new(
            config.general.keyring_service.clone(),
            store.clone(),
        ));

        let handle = SyncEngine::spawn(store.clone(), config.clone(), secrets.clone());
        let events = handle.events;

        *self.active.write().await = Some(Active {
            config: config.clone(),
            store: store.clone(),
            secrets,
            commands: handle.commands,
            data_dir: self.data_dir.clone(),
        });

        tokio::spawn(self.clone().pump(events));

        let accounts = self.accounts().await?;
        self.broadcast(Push::Unlocked { accounts: accounts.clone() });
        Ok(accounts)
    }

    async fn master_key(
        &self,
        config: &Config,
        passphrase: Option<&str>,
    ) -> anyhow::Result<MasterKey> {
        if self.no_encrypt || !config.general.encrypt_at_rest {
            return Ok(MasterKey::from_bytes(*b"pigeon-unencrypted-local-store!!"));
        }

        let vault_path = self.data_dir.join("vault.key");

        let pass = match passphrase {
            Some(p) => secrecy::SecretString::from(p.to_string()),
            None if config.general.unlock == Unlock::Prompt => {
                bail!("this vault needs a passphrase; send `unlock` with one")
            }
            None => crate::secrets::vault_passphrase(config, false).await?,
        };

        if !Vault::exists(&vault_path) {
            let vault = Vault::create(&vault_path, pass.expose_secret().as_bytes())?;
            return Ok(vault.key().clone());
        }

        let vault = Vault::unlock(&vault_path, pass.expose_secret().as_bytes())?;
        Ok(vault.key().clone())
    }

    async fn lock(&self) -> anyhow::Result<()> {
        if let Some(active) = self.active.write().await.take() {
            let _ = active.commands.send(Command::Shutdown);
        }
        self.statuses.write().await.clear();
        self.broadcast(Push::Locked);
        Ok(())
    }

    /// Translates engine events into wire pushes. Everything here is already
    /// persisted by the engine, so this loop only fans out and, when no client is
    /// listening, falls back to a desktop notification so new mail is never
    /// silently dropped.
    async fn pump(self: Arc<Self>, mut events: mpsc::UnboundedReceiver<Event>) {
        while let Some(event) = events.recv().await {
            match event {
                Event::Status { account, status } => {
                    let label = status.label();
                    self.statuses.write().await.insert(account.clone(), label);
                    self.broadcast(Push::Status { account, status: label });
                }
                Event::Folders { account, folders } => {
                    let folders = folders.iter().map(FolderView::of).collect();
                    self.broadcast(Push::Folders { account, folders });
                    self.push_unread().await;
                }
                Event::Envelopes { account, folder, envelopes, replaced } => {
                    self.mark_dirty(&account, &folder).await;
                    self.broadcast(Push::Messages {
                        account,
                        folder,
                        messages: self.views(&envelopes).await,
                        replaced,
                    });
                }
                Event::NewMail { account, folder, envelopes } => {
                    self.mark_dirty(&account, &folder).await;
                    self.prefetch(&account, &folder, envelopes.iter().map(|e| e.uid)).await;
                    if self.subscribers.load(Ordering::Relaxed) == 0 {
                        crate::notify::desktop_new_mail(&envelopes);
                    }
                    self.broadcast(Push::NewMail {
                        account,
                        folder,
                        messages: self.views(&envelopes).await,
                    });
                }
                Event::Removed { account, folder, uids } => {
                    self.mark_dirty(&account, &folder).await;
                    self.broadcast(Push::Removed { account, folder, uids });
                }
                Event::FlagsChanged { key, flags } => {
                    self.mark_dirty(&key.account, &key.folder).await;
                    self.broadcast(Push::Flags {
                        account: key.account,
                        folder: key.folder,
                        uid: key.uid,
                        seen: flags.contains(Flags::SEEN),
                        flagged: flags.contains(Flags::FLAGGED),
                        answered: flags.contains(Flags::ANSWERED),
                        draft: flags.contains(Flags::DRAFT),
                        flags: flags.wire_names().into_iter().map(str::to_string).collect(),
                    });
                }
                Event::Body { key, .. } => {
                    let _ = self.bodies.send(key);
                }
                Event::OutboxChanged { pending } => {
                    self.broadcast(Push::Outbox {
                        items: pending.iter().map(OutboxView::of).collect(),
                    });
                }
                Event::Sent { id } => self.broadcast(Push::Sent { id }),
                Event::SendFailed { id, message } => {
                    self.broadcast(Push::SendFailed { id, message })
                }
                Event::Notice(message) => self.broadcast(Push::Notice { message }),
                Event::Error { account, message } => {
                    self.broadcast(Push::Error { account, message })
                }
            }
        }
    }

    async fn views(&self, envelopes: &[Envelope]) -> Vec<MessageView> {
        let store = self.active.read().await.as_ref().map(|a| a.store.clone());
        envelopes
            .iter()
            .map(|e| {
                let cached = store
                    .as_ref()
                    .and_then(|s| s.has_blob(&blob_id(&e.key())).ok())
                    .unwrap_or(false);
                MessageView::of(e, cached)
            })
            .collect()
    }

    async fn mark_dirty(&self, account: &str, folder: &str) {
        self.dirty
            .write()
            .await
            .insert((account.to_string(), folder.to_string()));
    }

    /// Unread counts move on every flag change, and a sync moves thousands of
    /// them. Recomputing on a timer collapses that into one pass per folder.
    async fn unread_ticker(self: Arc<Self>) {
        let mut tick = tokio::time::interval(UNREAD_DEBOUNCE);
        loop {
            tick.tick().await;
            let pending = std::mem::take(&mut *self.dirty.write().await);
            if pending.is_empty() {
                continue;
            }
            let Ok(store) = self.store().await else { continue };
            for (account, folder) in pending {
                let Ok(envelopes) = store.envelopes(&account, &folder) else { continue };
                let unseen = envelopes.iter().filter(|e| e.is_unread()).count() as u32;
                if let Ok(Some(mut state)) = store.folder(&account, &folder) {
                    if state.unseen != unseen {
                        state.unseen = unseen;
                        let _ = store.put_folder(&state);
                    }
                }
            }
            self.push_unread().await;
        }
    }

    async fn push_unread(&self) {
        let Ok(store) = self.store().await else { return };
        let Ok(folders) = store.folders(None) else { return };

        let mut by_account: BTreeMap<String, u32> = BTreeMap::new();
        let mut total = 0;
        for f in folders.iter().filter(|f| is_countable(&f.name, f.role)) {
            *by_account.entry(f.account.clone()).or_default() += f.unseen;
            total += f.unseen;
        }
        self.broadcast(Push::Unread { total, by_account });
    }

    async fn accounts(&self) -> anyhow::Result<Vec<AccountView>> {
        let config = self.config().await?;
        let statuses = self.statuses.read().await.clone();
        Ok(config
            .accounts
            .iter()
            .map(|a| AccountView {
                name: a.name.clone(),
                email: a.address.clone(),
                display_name: a.display_name.clone().unwrap_or_else(|| a.name.clone()),
                enabled: a.enabled,
                aliases: a.aliases.clone(),
                status: statuses.get(&a.name).copied().unwrap_or("idle"),
                imap_host: a.imap.host.clone(),
                smtp_host: a.smtp.host.clone(),
            })
            .collect())
    }

    async fn client(self: Arc<Self>, stream: UnixStream) -> anyhow::Result<()> {
        let (read, mut write) = stream.into_split();
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Arc<String>>();

        // One writer task per connection: responses and pushes share a socket,
        // and interleaving half-written lines would corrupt the stream.
        let writer = tokio::spawn(async move {
            while let Some(line) = out_rx.recv().await {
                if write.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                if write.write_all(b"\n").await.is_err() {
                    break;
                }
            }
        });

        let mut lines = BufReader::new(read).lines();
        let mut subscription: Option<tokio::task::JoinHandle<()>> = None;

        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }

            let request: Request = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    let _ = out_tx.send(Arc::new(serde_json::to_string(&Response::err(
                        None,
                        format!("malformed request: {e}"),
                    ))?));
                    continue;
                }
            };

            let id = request.id;

            if request.method == "subscribe" {
                let on = request.params.get("events").and_then(Value::as_bool).unwrap_or(true);
                if let Some(handle) = subscription.take() {
                    handle.abort();
                    self.subscribers.fetch_sub(1, Ordering::Relaxed);
                }
                if on {
                    self.subscribers.fetch_add(1, Ordering::Relaxed);
                    let mut rx = self.pushes.subscribe();
                    let tx = out_tx.clone();
                    subscription = Some(tokio::spawn(async move {
                        loop {
                            match rx.recv().await {
                                Ok(line) => {
                                    if tx.send(line).is_err() {
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(_) => break,
                            }
                        }
                    }));
                }
                let _ = out_tx.send(Arc::new(serde_json::to_string(&Response::ok(
                    id,
                    json!({ "subscribed": on }),
                ))?));
                continue;
            }

            let quitting = request.method == "shutdown";
            let response = match self.clone().dispatch(request).await {
                Ok(value) => Response::ok(id, value),
                Err(e) => Response::err(id, format!("{e:#}")),
            };
            let _ = out_tx.send(Arc::new(serde_json::to_string(&response)?));

            if quitting {
                break;
            }
        }

        if subscription.take().is_some() {
            self.subscribers.fetch_sub(1, Ordering::Relaxed);
        }
        drop(out_tx);
        let _ = writer.await;
        Ok(())
    }

    async fn dispatch(self: Arc<Self>, req: Request) -> anyhow::Result<Value> {
        let p = &req.params;

        match req.method.as_str() {
            "hello" => Ok(json!({
                "name": "pigeon",
                "version": env!("CARGO_PKG_VERSION"),
                "protocol": 1,
                "locked": self.active.read().await.is_none(),
                "configured": self.config_path.exists(),
                "config": self.config_path.display().to_string(),
            })),

            "status" => self.status().await,

            "unlock" => {
                let pass = p.get("passphrase").and_then(Value::as_str);
                let accounts = self.clone().unlock(pass).await?;
                Ok(json!({ "locked": false, "accounts": accounts }))
            }

            "lock" => {
                self.lock().await?;
                Ok(json!({ "locked": true }))
            }

            "accounts" => Ok(json!(self.accounts().await?)),

            "folders" => {
                let store = self.store().await?;
                let account = p.get("account").and_then(Value::as_str);
                let mut folders = store.folders(account)?;
                folders.sort_by(|a, b| {
                    role_order(a.role)
                        .cmp(&role_order(b.role))
                        .then_with(|| a.name.cmp(&b.name))
                });
                Ok(json!(folders.iter().map(FolderView::of).collect::<Vec<_>>()))
            }

            "messages" => self.messages(p).await,
            "threads" => self.threads(p).await,
            "message" => self.message(p).await,
            "search" => self.search(p).await,
            "attachment" => self.attachment(p).await,

            "mark" => self.mark(p).await,

            "move" => {
                let keys = keys_of(p)?;
                let to = string_of(p, "to")?;
                self.send_command(Command::Move { keys, to }).await?;
                Ok(json!({ "queued": true }))
            }

            "copy" => {
                let keys = keys_of(p)?;
                let to = string_of(p, "to")?;
                self.send_command(Command::Copy { keys, to }).await?;
                Ok(json!({ "queued": true }))
            }

            "delete" => {
                let keys = keys_of(p)?;
                let permanent = p.get("permanent").and_then(Value::as_bool).unwrap_or(false);
                self.send_command(Command::Delete { keys, permanent }).await?;
                Ok(json!({ "queued": true }))
            }

            "sync" => {
                let account = p.get("account").and_then(Value::as_str);
                let folder = p.get("folder").and_then(Value::as_str);
                let cmd = match (account, folder) {
                    (Some(a), Some(f)) => Command::SyncFolder {
                        account: a.to_string(),
                        folder: f.to_string(),
                    },
                    (Some(a), None) => Command::SyncAccount(a.to_string()),
                    _ => Command::SyncAll,
                };
                self.send_command(cmd).await?;
                Ok(json!({ "queued": true }))
            }

            "reconnect" => {
                self.send_command(Command::Reconnect).await?;
                Ok(json!({ "queued": true }))
            }

            "send" => self.compose(p, true).await,
            "draft" => self.compose(p, false).await,

            "outbox" => {
                let store = self.store().await?;
                Ok(json!(
                    store.outbox().unwrap_or_default().iter().map(OutboxView::of).collect::<Vec<_>>()
                ))
            }

            "flush" => {
                self.send_command(Command::FlushOutbox).await?;
                Ok(json!({ "queued": true }))
            }

            "folder-create" => {
                self.send_command(Command::CreateFolder {
                    account: string_of(p, "account")?,
                    name: string_of(p, "name")?,
                })
                .await?;
                Ok(json!({ "queued": true }))
            }

            "folder-delete" => {
                self.send_command(Command::DeleteFolder {
                    account: string_of(p, "account")?,
                    name: string_of(p, "name")?,
                })
                .await?;
                Ok(json!({ "queued": true }))
            }

            "autoconfig" => super::setup::autoconfig(p).await,
            "test-account" => super::setup::test_account(p).await,
            "vault-status" => Ok(json!({
                "exists": Vault::exists(&self.data_dir.join("vault.key")),
                "locked": self.active.read().await.is_none(),
                "encrypting": self.is_encrypting(),
            })),
            "vault-create" => super::setup::vault_create(&self, p).await,
            "account-add" => super::setup::account_add(self.clone(), p).await,
            "account-remove" => super::setup::account_remove(self.clone(), p).await,
            "account-update" => super::setup::account_update(self.clone(), p).await,
            "set-password" => super::setup::set_password(&self, p).await,
            "settings-get" => super::setup::settings_get(&self).await,
            "settings-set" => super::setup::settings_set(self.clone(), p).await,

            "shutdown" => Ok(json!({ "bye": true })),

            other => bail!("unknown method `{other}`"),
        }
    }

    async fn status(&self) -> anyhow::Result<Value> {
        let locked = self.active.read().await.is_none();
        if locked {
            return Ok(json!({
                "locked": true,
                "configured": self.config_path.exists(),
                "accounts": Vec::<AccountView>::new(),
                "unread": 0,
            }));
        }

        let store = self.store().await?;
        let folders = store.folders(None).unwrap_or_default();
        let accounts = self.accounts().await?;

        let mut by_account: BTreeMap<String, u32> = BTreeMap::new();
        let mut total = 0;
        for f in folders.iter().filter(|f| is_countable(&f.name, f.role)) {
            *by_account.entry(f.account.clone()).or_default() += f.unseen;
            total += f.unseen;
        }

        Ok(json!({
            "locked": false,
            "configured": true,
            "accounts": accounts,
            "unread": total,
            "unreadByAccount": by_account,
            "outbox": store.outbox().map(|o| o.len()).unwrap_or(0),
        }))
    }

    /// Resolves the folder a request means: an explicit name, else the account's
    /// configured inbox, so the common case needs no arguments at all.
    async fn target(&self, p: &Value) -> anyhow::Result<(String, String)> {
        let config = self.config().await?;
        let account = match p.get("account").and_then(Value::as_str) {
            Some(a) => config
                .account(a)
                .ok_or_else(|| anyhow!("unknown account `{a}`"))?,
            None => config
                .primary_account()
                .ok_or_else(|| anyhow!("no account is configured"))?,
        };
        let folder = p
            .get("folder")
            .and_then(Value::as_str)
            .unwrap_or(&account.folders.inbox)
            .to_string();
        Ok((account.name.clone(), folder))
    }

    async fn messages(&self, p: &Value) -> anyhow::Result<Value> {
        let (account, folder) = self.target(p).await?;
        let store = self.store().await?;

        let limit = p.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;
        let offset = p.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        let unread_only = p.get("unread").and_then(Value::as_bool).unwrap_or(false);
        let flagged_only = p.get("flagged").and_then(Value::as_bool).unwrap_or(false);

        let mut envelopes = store.envelopes(&account, &folder)?;
        envelopes.retain(|e| !unread_only || e.is_unread());
        envelopes.retain(|e| !flagged_only || e.flags.contains(Flags::FLAGGED));
        envelopes.sort_by(|a, b| b.date.cmp(&a.date));

        let total = envelopes.len();
        let page: Vec<Envelope> = envelopes.into_iter().skip(offset).take(limit).collect();
        let views = self.views(&page).await;
        self.prefetch(&account, &folder, page.iter().map(|e| e.uid)).await;

        Ok(json!({
            "account": account,
            "folder": folder,
            "total": total,
            "messages": views,
        }))
    }

    /// Asks for the bodies behind a list the user is now looking at. Opening a
    /// message then reads the store instead of waiting on a login and a fetch.
    async fn prefetch(&self, account: &str, folder: &str, uids: impl Iterator<Item = u32>) {
        let uids: Vec<u32> = uids.collect();
        if uids.is_empty() {
            return;
        }
        let _ = self
            .send_command(Command::PrefetchBodies {
                account: account.to_string(),
                folder: folder.to_string(),
                uids,
            })
            .await;
    }

    async fn threads(&self, p: &Value) -> anyhow::Result<Value> {
        let (account, folder) = self.target(p).await?;
        let store = self.store().await?;
        let limit = p.get("limit").and_then(Value::as_u64).unwrap_or(50) as usize;

        let envelopes = store.envelopes(&account, &folder)?;
        let threads = thread::build(&envelopes, true);

        let mut out = Vec::new();
        for t in threads.into_iter().take(limit) {
            let members: Vec<Envelope> = t
                .members
                .iter()
                .filter_map(|i| envelopes.get(*i).cloned())
                .collect();
            if members.is_empty() {
                continue;
            }
            out.push(json!({
                "id": t.id,
                "subject": t.subject,
                "count": members.len(),
                "unread": t.unread,
                "flagged": t.flagged,
                "hasAttachments": t.has_attachments,
                "participants": t.participants,
                "newest": t.newest.to_rfc3339(),
                "messages": self.views(&members).await,
            }));
        }

        Ok(json!({ "account": account, "folder": folder, "threads": out }))
    }

    async fn message(&self, p: &Value) -> anyhow::Result<Value> {
        let key = MsgKey {
            account: string_of(p, "account")?,
            folder: string_of(p, "folder")?,
            uid: p
                .get("uid")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("`uid` is required"))? as u32,
        };

        let store = self.store().await?;
        let envelope = store
            .envelope(&key.account, &key.folder, key.uid)?
            .ok_or_else(|| anyhow!("no such message"))?;

        let id = blob_id(&key);
        let raw = match store.blob(&id) {
            Ok(raw) => raw,
            Err(_) => self.fetch_body(&key).await?,
        };

        let width = p.get("width").and_then(Value::as_u64).unwrap_or(100) as usize;
        let want_html = p.get("html").and_then(Value::as_bool).unwrap_or(false);

        let rendered = body::render(
            &raw,
            &RenderOptions {
                width,
                prefer_html: false,
                allow_remote: false,
                show_quoted: true,
                show_headers: false,
            },
        );

        let lines: Vec<Value> = rendered
            .lines
            .iter()
            .map(|l| json!({ "text": l.text, "kind": line_kind(l.kind) }))
            .collect();

        let html = want_html.then(|| sanitised_html(&raw)).flatten();

        Ok(json!({
            "message": MessageView::of(&envelope, true),
            "rawBytes": raw.len(),
            "text": rendered.plain_text(),
            "lines": lines,
            "links": rendered.links,
            "html": html,
            "usedHtml": rendered.used_html,
            "remoteBlocked": rendered.remote_blocked,
            "trackersStripped": rendered.trackers_stripped,
        }))
    }

    /// Asks the engine for a body and waits for the event that says it landed,
    /// rather than polling the store.
    async fn fetch_body(&self, key: &MsgKey) -> anyhow::Result<Vec<u8>> {
        let mut ready = self.bodies.subscribe();
        self.send_command(Command::FetchBody(key.clone())).await?;

        let store = self.store().await?;
        let id = blob_id(key);

        let wait = async {
            loop {
                match ready.recv().await {
                    Ok(k) if &k == key => return Ok(()),
                    Ok(_) => continue,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return Err(anyhow!("the sync engine has stopped")),
                }
            }
        };

        tokio::time::timeout(BODY_WAIT, wait)
            .await
            .map_err(|_| anyhow!("timed out downloading the message body"))??;

        store.blob(&id).map_err(Into::into)
    }

    async fn search(&self, p: &Value) -> anyhow::Result<Value> {
        let store = self.store().await?;
        let text = string_of(p, "query")?;
        let limit = p.get("limit").and_then(Value::as_u64).unwrap_or(100) as usize;

        let node = query::parse(&text)?;

        let mut candidates: Option<BTreeSet<MsgKey>> = None;
        for (field, term) in node.index_terms() {
            let hits: BTreeSet<MsgKey> = store.search_token(field, &term)?.into_iter().collect();
            candidates = Some(match candidates {
                Some(existing) => existing.intersection(&hits).cloned().collect(),
                None => hits,
            });
        }

        // Without a single indexable term the query still has to be answered, so
        // fall back to scanning the folders the client cares about.
        let pool: Vec<Envelope> = match candidates {
            Some(keys) => keys
                .into_iter()
                .filter_map(|k| store.envelope(&k.account, &k.folder, k.uid).ok().flatten())
                .collect(),
            None => {
                let mut all = Vec::new();
                for f in store.folders(p.get("account").and_then(Value::as_str))? {
                    all.extend(store.envelopes(&f.account, &f.name)?);
                }
                all
            }
        };

        let mut hits: Vec<Envelope> = pool.into_iter().filter(|e| node.matches(e)).collect();
        hits.sort_by(|a, b| b.date.cmp(&a.date));
        hits.truncate(limit);

        Ok(json!({ "query": text, "messages": self.views(&hits).await }))
    }

    async fn attachment(&self, p: &Value) -> anyhow::Result<Value> {
        let key = MsgKey {
            account: string_of(p, "account")?,
            folder: string_of(p, "folder")?,
            uid: p
                .get("uid")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("`uid` is required"))? as u32,
        };
        let part = string_of(p, "part")?;

        let store = self.store().await?;
        let raw = match store.blob(&blob_id(&key)) {
            Ok(raw) => raw,
            Err(_) => self.fetch_body(&key).await?,
        };

        let bytes = body::extract_part(&raw, &part)
            .ok_or_else(|| anyhow!("no part `{part}` in that message"))?;

        let envelope = store.envelope(&key.account, &key.folder, key.uid)?;
        let name = body::part_name(&raw, &part)
            .or_else(|| {
                envelope
                    .as_ref()
                    .and_then(|e| e.attachments.iter().find(|a| a.part_id == part))
                    .map(|a| a.name.clone())
            })
            .unwrap_or_else(|| format!("part-{part}"));

        let dir = match p.get("dir").and_then(Value::as_str) {
            Some(d) => PathBuf::from(d),
            None => self
                .with_active(|a| Ok(a.data_dir.join("attachments")))
                .await?
                .join(format!("{}-{}", safe_name(&key.folder), key.uid)),
        };
        std::fs::create_dir_all(&dir)?;

        let dest = dir.join(safe_name(&name));
        std::fs::write(&dest, &bytes)?;
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600))?;

        Ok(json!({ "path": dest.display().to_string(), "size": bytes.len(), "name": name }))
    }

    async fn mark(&self, p: &Value) -> anyhow::Result<Value> {
        let keys = keys_of(p)?;
        let mut add = Flags::EMPTY;
        let mut remove = Flags::EMPTY;

        for (field, flag) in [
            ("seen", Flags::SEEN),
            ("flagged", Flags::FLAGGED),
            ("answered", Flags::ANSWERED),
            ("draft", Flags::DRAFT),
            ("junk", Flags::JUNK),
        ] {
            match p.get(field).and_then(Value::as_bool) {
                Some(true) => add |= flag,
                Some(false) => remove |= flag,
                None => {}
            }
        }

        if add.is_empty() && remove.is_empty() {
            bail!("nothing to change: pass at least one of seen, flagged, answered, draft, junk");
        }

        self.send_command(Command::SetFlags { keys, add, remove }).await?;
        Ok(json!({ "queued": true }))
    }

    async fn compose(&self, p: &Value, send: bool) -> anyhow::Result<Value> {
        let config = self.config().await?;
        let account = match p.get("account").and_then(Value::as_str) {
            Some(a) => config
                .account(a)
                .ok_or_else(|| anyhow!("unknown account `{a}`"))?,
            None => config
                .primary_account()
                .ok_or_else(|| anyhow!("no account is configured"))?,
        };

        let from = Addr {
            name: account.display_name.clone(),
            email: account.address.clone(),
        };
        let mut draft = Draft::new(&account.name, from);

        draft.to = addr_list(p, "to");
        draft.cc = addr_list(p, "cc");
        draft.bcc = addr_list(p, "bcc");
        draft.subject = p.get("subject").and_then(Value::as_str).unwrap_or_default().to_string();
        draft.body = p.get("body").and_then(Value::as_str).unwrap_or_default().to_string();
        draft.html_body = p.get("htmlBody").and_then(Value::as_str).map(str::to_string);
        draft.in_reply_to = p.get("inReplyTo").and_then(Value::as_str).map(str::to_string);
        draft.sign = p.get("sign").and_then(Value::as_bool).unwrap_or(account.pgp.sign_by_default);
        draft.encrypt = p.get("encrypt").and_then(Value::as_bool).unwrap_or(false);

        if let Some(refs) = p.get("references").and_then(Value::as_array) {
            draft.references = refs
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
        }

        if draft.body.is_empty() {
            if let Some(sig) = account.signature_text() {
                draft.body = format!("\n\n-- \n{sig}");
            }
        }

        let max = config.general.max_attachment_mb * 1024 * 1024;
        for path in p.get("attachments").and_then(Value::as_array).unwrap_or(&Vec::new()) {
            let Some(path) = path.as_str() else { continue };
            let path = crate::config::expand(Path::new(path));
            let data = std::fs::read(&path)
                .with_context(|| format!("could not attach {}", path.display()))?;
            if data.len() as u64 > max {
                bail!(
                    "{} is larger than the {} MB attachment limit",
                    path.display(),
                    config.general.max_attachment_mb
                );
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "attachment".into());
            draft.attachments.push(DraftAttachment {
                mime: mime_guess::from_path(&path).first_or_octet_stream().to_string(),
                name,
                data,
                inline_cid: None,
            });
        }

        if send && draft.to.is_empty() && draft.cc.is_empty() && draft.bcc.is_empty() {
            bail!("a message needs at least one recipient");
        }

        // Generated here, not in the engine, so the response can hand it back
        // before the send finishes — the caller matches it against the later
        // `sent` / `send-failed` push instead of trusting "queued" as "sent".
        if send {
            draft.id = uuid::Uuid::new_v4().to_string();
        }
        let id = draft.id.clone();

        let cmd = match send {
            true => Command::Send(Box::new(draft)),
            false => Command::SaveDraft(Box::new(draft)),
        };
        self.send_command(cmd).await?;
        Ok(json!({ "queued": true, "id": id }))
    }
}

fn addr_list(p: &Value, field: &str) -> Vec<Addr> {
    match p.get(field) {
        Some(Value::String(s)) => parse_address_list(s),
        Some(Value::Array(items)) => items
            .iter()
            .flat_map(|i| match i {
                Value::String(s) => parse_address_list(s),
                Value::Object(o) => o
                    .get("email")
                    .and_then(Value::as_str)
                    .map(|e| {
                        vec![Addr {
                            name: o.get("name").and_then(Value::as_str).map(str::to_string),
                            email: e.to_string(),
                        }]
                    })
                    .unwrap_or_default(),
                _ => Vec::new(),
            })
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) fn string_of(p: &Value, field: &str) -> anyhow::Result<String> {
    p.get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow!("`{field}` is required"))
}

fn keys_of(p: &Value) -> anyhow::Result<Vec<MsgKey>> {
    // A single message is by far the common case, so accept it unwrapped as
    // well as a `keys` array.
    if let Some(array) = p.get("keys").and_then(Value::as_array) {
        let refs: Vec<KeyRef> = serde_json::from_value(Value::Array(array.clone()))?;
        return Ok(refs.into_iter().map(Into::into).collect());
    }

    let single: KeyRef = serde_json::from_value(p.clone())
        .map_err(|_| anyhow!("pass `keys: [{{account, folder, uid}}]` or those three fields"))?;
    Ok(vec![single.into()])
}

fn line_kind(kind: body::LineKind) -> String {
    match kind {
        body::LineKind::Body => "body".into(),
        body::LineKind::Quote(depth) => format!("quote{depth}"),
        body::LineKind::Signature => "signature".into(),
        body::LineKind::Header => "header".into(),
        body::LineKind::Separator => "separator".into(),
    }
}

fn role_order(role: Option<crate::store::model::FolderRole>) -> u8 {
    use crate::store::model::FolderRole as R;
    match role {
        Some(R::Inbox) => 0,
        Some(R::Sent) => 1,
        Some(R::Drafts) => 2,
        Some(R::Archive) => 3,
        Some(R::All) => 4,
        None => 5,
        Some(R::Spam) => 6,
        Some(R::Trash) => 7,
    }
}

/// Sent, drafts, trash and spam carry unread messages that nobody wants a badge
/// for, so the total counts only folders a person actually reads.
fn is_countable(name: &str, role: Option<crate::store::model::FolderRole>) -> bool {
    use crate::store::model::FolderRole as R;
    match role {
        Some(R::Sent) | Some(R::Drafts) | Some(R::Trash) | Some(R::Spam) | Some(R::All) => false,
        Some(_) => true,
        None => !["sent", "drafts", "trash", "junk", "spam"]
            .iter()
            .any(|s| name.to_ascii_lowercase().contains(s)),
    }
}

fn safe_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim_matches('.').trim();
    if trimmed.is_empty() { "attachment".into() } else { trimmed.to_string() }
}

/// Mail HTML is hostile by default. This strips the parts that would phone home
/// or execute if a client rendered the result, so a shell can show rich text
/// without leaking that the message was opened.
fn sanitised_html(raw: &[u8]) -> Option<String> {
    use mail_parser::MessageParser;

    let msg = MessageParser::default().parse(raw)?;
    let html = msg.body_html(0)?;

    let mut out = html.into_owned();
    for paired in PAIRED_TAGS.iter() {
        out = paired.replace_all(&out, "").into_owned();
    }
    let out = DROP_VOID.replace_all(&out, "");
    let out = DROP_HANDLERS.replace_all(&out, "");
    let out = DROP_REMOTE.replace_all(&out, " data-blocked-remote=\"1\"");
    let out = DROP_URLS.replace_all(&out, "none");

    Some(out.into_owned())
}

/// Tags whose content is not text to read: scripts and styles can fetch, and
/// the rest either navigate or embed. The `regex` crate has no backreferences,
/// so each tag needs its own pattern rather than one with `\1`.
static PAIRED_TAGS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    ["script", "style", "iframe", "object", "embed", "applet", "form", "link", "meta", "base"]
        .iter()
        .map(|tag| {
            Regex::new(&format!(r"(?is)<\s*{tag}\b[^>]*>.*?<\s*/\s*{tag}\s*>"))
                .expect("static pattern")
        })
        .collect()
});

static DROP_VOID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<\s*(script|iframe|object|embed|link|meta|base)\b[^>]*/?>").expect("static pattern")
});

static DROP_HANDLERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)"#).expect("static pattern")
});

/// Remote images are how mail tracks whether it was opened, so the address is
/// replaced rather than the tag: the layout survives, the request does not.
static DROP_REMOTE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)\s(src|background|poster)\s*=\s*("\s*(?:https?:|//)[^"]*"|'\s*(?:https?:|//)[^']*'|(?:https?:|//)[^\s>]+)"#,
    )
    .expect("static pattern")
});

static DROP_URLS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)url\(\s*['"]?\s*(?:https?:|//)[^)]*\)"#).expect("static pattern")
});
