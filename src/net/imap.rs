use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

use async_imap::extensions::idle::IdleResponse;
use async_imap::types::{Fetch, Flag as ImapFlag, Mailbox, NameAttribute};
use async_imap::{Authenticator, Client, Session};
use futures::TryStreamExt;

use crate::config::{ImapConfig, Security};
use crate::store::model::{Envelope, Flags, FolderRole, FolderState};

use super::tls::{MaybeTls, TlsError, connect_tcp, connect_tls};

pub const FETCH_ENVELOPE: &str =
    "(UID FLAGS RFC822.SIZE INTERNALDATE MODSEQ BODY.PEEK[HEADER])";
pub const FETCH_FULL: &str = "(UID FLAGS RFC822.SIZE BODY.PEEK[])";
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(25 * 60);

#[derive(Debug, thiserror::Error)]
pub enum ImapError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("IMAP error: {0}")]
    Imap(#[from] async_imap::error::Error),
    #[error("IMAP I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the server closed the connection before sending a greeting")]
    NoGreeting,
    #[error("the server does not advertise STARTTLS, and the config requires it")]
    NoStartTls,
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("mailbox `{0}` reported no UIDVALIDITY; it cannot be synchronised safely")]
    NoUidValidity(String),
}

#[derive(Debug, Clone)]
pub enum Credentials {
    Password { user: String, password: String },
    XOAuth2 { user: String, token: String },
}

#[derive(Debug, Clone, Default)]
pub struct ImapCaps {
    pub idle: bool,
    pub condstore: bool,
    pub qresync: bool,
    pub move_ext: bool,
    pub uidplus: bool,
    pub compress: bool,
    pub list_extended: bool,
    pub special_use: bool,
    pub sort: bool,
    pub raw: Vec<String>,
}

pub struct ImapSession {
    session: Session<MaybeTls>,
    pub caps: ImapCaps,
    pub selected: Option<String>,
}

struct XOAuth2 {
    user: String,
    token: String,
}

impl Authenticator for XOAuth2 {
    type Response = String;

    fn process(&mut self, _challenge: &[u8]) -> Self::Response {
        format!("user={}\x01auth=Bearer {}\x01\x01", self.user, self.token)
    }
}

impl ImapSession {
    pub async fn connect(cfg: &ImapConfig, creds: &Credentials) -> Result<Self, ImapError> {
        let client = match cfg.security {
            Security::Tls => {
                let s = connect_tls(&cfg.host, cfg.port, cfg.accept_invalid_certs).await?;
                let mut c = Client::new(MaybeTls::Tls(Box::new(s)));
                c.read_response().await?.ok_or(ImapError::NoGreeting)?;
                c
            }
            Security::Starttls => {
                let tcp = connect_tcp(&cfg.host, cfg.port).await?;
                let mut c = Client::new(MaybeTls::Plain(tcp));
                c.read_response().await?.ok_or(ImapError::NoGreeting)?;
                c.run_command_and_check_ok("STARTTLS", None).await?;
                let upgraded = c
                    .into_inner()
                    .upgrade(&cfg.host, cfg.accept_invalid_certs)
                    .await?;
                Client::new(upgraded)
            }
            Security::None => {
                let tcp = connect_tcp(&cfg.host, cfg.port).await?;
                let mut c = Client::new(MaybeTls::Plain(tcp));
                c.read_response().await?.ok_or(ImapError::NoGreeting)?;
                c
            }
        };

        let session = match creds {
            Credentials::Password { user, password } => client
                .login(user, password)
                .await
                .map_err(|(e, _)| ImapError::Auth(e.to_string()))?,
            Credentials::XOAuth2 { user, token } => {
                let auth = XOAuth2 { user: user.clone(), token: token.clone() };
                client
                    .authenticate("XOAUTH2", auth)
                    .await
                    .map_err(|(e, _)| ImapError::Auth(e.to_string()))?
            }
        };

        let mut s = Self { session, caps: ImapCaps::default(), selected: None };
        s.refresh_capabilities().await?;
        Ok(s)
    }

    pub async fn refresh_capabilities(&mut self) -> Result<(), ImapError> {
        let caps = self.session.capabilities().await?;
        let raw: Vec<String> = caps.iter().map(|c| format!("{c:?}").to_uppercase()).collect();
        let has = |name: &str| raw.iter().any(|c| c.contains(name));

        self.caps = ImapCaps {
            idle: has("IDLE"),
            condstore: has("CONDSTORE"),
            qresync: has("QRESYNC"),
            move_ext: has("MOVE"),
            uidplus: has("UIDPLUS"),
            compress: has("COMPRESS"),
            list_extended: has("LIST-EXTENDED"),
            special_use: has("SPECIAL-USE"),
            sort: has("SORT"),
            raw,
        };
        Ok(())
    }

    pub async fn folders(&mut self, account: &str) -> Result<Vec<FolderState>, ImapError> {
        let names = self.session.list(Some(""), Some("*")).await?;
        let names: Vec<_> = names.try_collect().await?;

        let subscribed: HashSet<String> = {
            let subs = self.session.lsub(Some(""), Some("*")).await?;
            let subs: Vec<_> = subs.try_collect().await?;
            subs.iter().map(|n| n.name().to_string()).collect()
        };

        Ok(names
            .iter()
            .map(|n| {
                let attributes: Vec<String> =
                    n.attributes().iter().map(attr_name).collect();
                FolderState {
                    account: account.to_string(),
                    name: n.name().to_string(),
                    delimiter: n.delimiter().map(|d| d.to_string()),
                    role: folder_role(n.name(), &attributes),
                    subscribed: subscribed.contains(n.name()),
                    attributes,
                    ..Default::default()
                }
            })
            .collect())
    }

    pub async fn select(&mut self, folder: &str) -> Result<Mailbox, ImapError> {
        let mb = if self.caps.condstore {
            self.session.select_condstore(folder).await?
        } else {
            self.session.select(folder).await?
        };
        self.selected = Some(folder.to_string());
        Ok(mb)
    }

    pub async fn examine(&mut self, folder: &str) -> Result<Mailbox, ImapError> {
        let mb = self.session.examine(folder).await?;
        self.selected = Some(folder.to_string());
        Ok(mb)
    }

    pub async fn fetch_envelopes(
        &mut self,
        account: &str,
        folder: &str,
        uid_set: &str,
    ) -> Result<Vec<Envelope>, ImapError> {
        let stream = self.session.uid_fetch(uid_set, FETCH_ENVELOPE).await?;
        let fetches: Vec<Fetch> = stream.try_collect().await?;

        Ok(fetches
            .iter()
            .filter_map(|f| envelope_from_fetch(account, folder, f))
            .collect())
    }

    /// Fetches many bodies over one round trip. Opening a connection per
    /// message costs a TLS handshake and a login each time, which is what makes
    /// reading feel slow; a prefetch is only worth doing in bulk.
    pub async fn fetch_bodies(&mut self, uid_set: &str) -> Result<Vec<(u32, Vec<u8>)>, ImapError> {
        let stream = self.session.uid_fetch(uid_set, FETCH_FULL).await?;
        let fetches: Vec<Fetch> = stream.try_collect().await?;
        Ok(fetches
            .iter()
            .filter_map(|f| Some((f.uid?, f.body()?.to_vec())))
            .collect())
    }

    pub async fn fetch_body(&mut self, uid: u32) -> Result<Option<Vec<u8>>, ImapError> {
        let stream = self.session.uid_fetch(uid.to_string(), FETCH_FULL).await?;
        let fetches: Vec<Fetch> = stream.try_collect().await?;
        Ok(fetches.first().and_then(|f| f.body().map(|b| b.to_vec())))
    }

    /// Returns every UID in the mailbox. Used to detect server-side expunges,
    /// which are otherwise invisible to a client that only ever fetches forward.
    pub async fn all_uids(&mut self) -> Result<BTreeSet<u32>, ImapError> {
        Ok(self.session.uid_search("ALL").await?.into_iter().collect())
    }

    pub async fn search(&mut self, query: &str) -> Result<BTreeSet<u32>, ImapError> {
        Ok(self.session.uid_search(query).await?.into_iter().collect())
    }

    pub async fn changed_since(&mut self, modseq: u64) -> Result<Vec<Fetch>, ImapError> {
        let q = format!("(UID FLAGS MODSEQ) (CHANGEDSINCE {modseq})");
        let stream = self.session.uid_fetch("1:*", q).await?;
        Ok(stream.try_collect().await?)
    }

    pub async fn store_flags(
        &mut self,
        uid_set: &str,
        flags: Flags,
        keywords: &[String],
        add: bool,
    ) -> Result<(), ImapError> {
        let mut names: Vec<String> = flags.wire_names().iter().map(|s| s.to_string()).collect();
        names.extend(keywords.iter().cloned());
        if names.is_empty() {
            return Ok(());
        }
        let op = if add { "+FLAGS.SILENT" } else { "-FLAGS.SILENT" };
        let query = format!("{op} ({})", names.join(" "));
        let stream = self.session.uid_store(uid_set, query).await?;
        let _: Vec<Fetch> = stream.try_collect().await?;
        Ok(())
    }

    pub async fn move_to(&mut self, uid_set: &str, dest: &str) -> Result<(), ImapError> {
        if self.caps.move_ext {
            self.session.uid_mv(uid_set, dest).await?;
            return Ok(());
        }
        // RFC 6851 MOVE is not universal; fall back to the copy/flag/expunge dance.
        self.session.uid_copy(uid_set, dest).await?;
        self.store_flags(uid_set, Flags::DELETED, &[], true).await?;
        self.expunge_uids(uid_set).await
    }

    pub async fn copy_to(&mut self, uid_set: &str, dest: &str) -> Result<(), ImapError> {
        Ok(self.session.uid_copy(uid_set, dest).await?)
    }

    pub async fn expunge_uids(&mut self, uid_set: &str) -> Result<(), ImapError> {
        if self.caps.uidplus {
            let stream = self.session.uid_expunge(uid_set).await?;
            let _: Vec<u32> = stream.try_collect().await?;
        } else {
            let stream = self.session.expunge().await?;
            let _: Vec<u32> = stream.try_collect().await?;
        }
        Ok(())
    }

    pub async fn append(
        &mut self,
        folder: &str,
        message: &[u8],
        flags: Flags,
    ) -> Result<(), ImapError> {
        let names = flags.wire_names();
        let flag_list = (!names.is_empty()).then(|| format!("({})", names.join(" ")));
        self.session
            .append(folder, flag_list.as_deref(), None, message)
            .await?;
        Ok(())
    }

    pub async fn create_folder(&mut self, name: &str) -> Result<(), ImapError> {
        Ok(self.session.create(name).await?)
    }

    pub async fn delete_folder(&mut self, name: &str) -> Result<(), ImapError> {
        Ok(self.session.delete(name).await?)
    }

    pub async fn rename_folder(&mut self, from: &str, to: &str) -> Result<(), ImapError> {
        Ok(self.session.rename(from, to).await?)
    }

    pub async fn noop(&mut self) -> Result<(), ImapError> {
        Ok(self.session.noop().await?)
    }

    pub async fn logout(mut self) {
        let _ = self.session.logout().await;
    }

    /// Blocks until the server reports activity, the timeout elapses, or
    /// `stop` fires. Returns true when something changed and a resync is due.
    pub async fn idle_once(
        self,
        timeout: Duration,
        stop: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(Self, bool), ImapError> {
        let Self { session, caps, selected } = self;
        let mut handle = session.idle();
        handle.init().await?;

        let (idle_future, stop_source) = handle.wait_with_timeout(timeout);
        let changed = tokio::select! {
            res = idle_future => matches!(res?, IdleResponse::NewData(_)),
            _ = stop => {
                drop(stop_source);
                false
            }
        };

        let session = handle.done().await?;
        Ok((Self { session, caps, selected }, changed))
    }
}

pub fn flags_from_fetch(f: &Fetch) -> (Flags, BTreeSet<String>) {
    let mut flags = Flags::EMPTY;
    let mut keywords = BTreeSet::new();
    for fl in f.flags() {
        match fl {
            ImapFlag::Seen => flags.insert(Flags::SEEN),
            ImapFlag::Answered => flags.insert(Flags::ANSWERED),
            ImapFlag::Flagged => flags.insert(Flags::FLAGGED),
            ImapFlag::Deleted => flags.insert(Flags::DELETED),
            ImapFlag::Draft => flags.insert(Flags::DRAFT),
            ImapFlag::Recent => flags.insert(Flags::RECENT),
            ImapFlag::Custom(name) => {
                match Flags::from_wire(&name) {
                    Some(f) => flags.insert(f),
                    None => {
                        keywords.insert(name.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    (flags, keywords)
}

fn envelope_from_fetch(account: &str, folder: &str, f: &Fetch) -> Option<Envelope> {
    let uid = f.uid?;
    let (flags, keywords) = flags_from_fetch(f);
    let header = f.header().or_else(|| f.body())?;

    let mut out = crate::mail::parse::parse_message(account, folder, uid, header, flags, keywords)?;
    out.envelope.modseq = f.modseq.unwrap_or(0);
    if let Some(size) = f.size {
        out.envelope.size = size as u64;
    }
    if let Some(internal) = f.internal_date() {
        out.envelope.received = Some(internal.with_timezone(&chrono::Utc));
    }
    Some(out.envelope)
}

fn attr_name(a: &NameAttribute<'_>) -> String {
    match a {
        NameAttribute::NoInferiors => "\\Noinferiors".into(),
        NameAttribute::NoSelect => "\\Noselect".into(),
        NameAttribute::Marked => "\\Marked".into(),
        NameAttribute::Unmarked => "\\Unmarked".into(),
        NameAttribute::Extension(e) => e.to_string(),
        _ => format!("{a:?}"),
    }
}

/// Prefers the RFC 6154 SPECIAL-USE attributes and only falls back to name
/// matching, because localised servers call the sent folder anything at all.
fn folder_role(name: &str, attributes: &[String]) -> Option<FolderRole> {
    for a in attributes {
        let role = match a.to_ascii_lowercase().as_str() {
            "\\sent" => Some(FolderRole::Sent),
            "\\drafts" => Some(FolderRole::Drafts),
            "\\trash" => Some(FolderRole::Trash),
            "\\archive" => Some(FolderRole::Archive),
            "\\junk" | "\\spam" => Some(FolderRole::Spam),
            "\\all" => Some(FolderRole::All),
            "\\inbox" => Some(FolderRole::Inbox),
            _ => None,
        };
        if role.is_some() {
            return role;
        }
    }

    let leaf = name.rsplit(['/', '.']).next().unwrap_or(name).to_ascii_lowercase();
    Some(match leaf.as_str() {
        "inbox" => FolderRole::Inbox,
        "sent" | "sent items" | "sent mail" | "gesendet" | "envoyés" => FolderRole::Sent,
        "drafts" | "draft" | "entwürfe" | "brouillons" => FolderRole::Drafts,
        "trash" | "deleted items" | "bin" | "papierkorb" | "corbeille" => FolderRole::Trash,
        "archive" | "all mail" | "archiv" => FolderRole::Archive,
        "all" => FolderRole::All,
        "spam" | "junk" | "junk mail" | "junk e-mail" | "bulk mail" => FolderRole::Spam,
        _ => return None,
    })
}

/// Collapses a sorted UID list into IMAP set syntax (`2,4:7,9`) so a fetch of
/// thousands of messages does not produce a command line the server rejects.
pub fn uid_set(uids: &[u32]) -> String {
    let mut out = String::new();
    let mut iter = uids.iter().copied();
    let Some(mut start) = iter.next() else { return out };
    let mut prev = start;

    let flush = |start: u32, prev: u32, out: &mut String| {
        if !out.is_empty() {
            out.push(',');
        }
        if start == prev {
            out.push_str(&start.to_string());
        } else {
            out.push_str(&format!("{start}:{prev}"));
        }
    };

    for uid in iter {
        if uid == prev + 1 {
            prev = uid;
        } else {
            flush(start, prev, &mut out);
            start = uid;
            prev = uid;
        }
    }
    flush(start, prev, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_uid_ranges() {
        assert_eq!(uid_set(&[2, 4, 5, 6, 7, 9]), "2,4:7,9");
        assert_eq!(uid_set(&[1]), "1");
        assert_eq!(uid_set(&[]), "");
        assert_eq!(uid_set(&[1, 2, 3]), "1:3");
    }

    #[test]
    fn detects_special_use_roles() {
        assert_eq!(folder_role("Whatever", &["\\Sent".into()]), Some(FolderRole::Sent));
        assert_eq!(folder_role("INBOX/Sent Items", &[]), Some(FolderRole::Sent));
        assert_eq!(folder_role("Projects/2026", &[]), None);
    }
}
