use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use redb::{
    Database, MultimapTableDefinition, ReadableDatabase, ReadableTable, TableDefinition,
};

use crate::crypto::blind::{self, BlindIndex};
use crate::crypto::{Cipher, MasterKey};

use super::model::*;

const SCHEMA_VERSION: u32 = 1;

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const SCOPES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("scopes");
const FOLDERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("folders");
const ENVELOPES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("envelopes");
const BLOBS: TableDefinition<&str, &[u8]> = TableDefinition::new("blobs");
const OUTBOX: TableDefinition<&str, &[u8]> = TableDefinition::new("outbox");
const PENDING: TableDefinition<u64, &[u8]> = TableDefinition::new("pending");
const COUNTERS: TableDefinition<&str, u64> = TableDefinition::new("counters");

const SEARCH: MultimapTableDefinition<&[u8], &[u8]> = MultimapTableDefinition::new("search");
const MSGID: MultimapTableDefinition<&[u8], &[u8]> = MultimapTableDefinition::new("msgid");
const THREADS: MultimapTableDefinition<&[u8], &[u8]> = MultimapTableDefinition::new("threads");

pub const SCOPE_LEN: usize = 8;
pub const KEY_LEN: usize = SCOPE_LEN + 4;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error(transparent)]
    Db(#[from] redb::Error),
    #[error(transparent)]
    Txn(#[from] redb::TransactionError),
    #[error(transparent)]
    Table(#[from] redb::TableError),
    #[error(transparent)]
    Storage(#[from] redb::StorageError),
    #[error(transparent)]
    Commit(#[from] redb::CommitError),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),
    #[error("stored record is not valid JSON: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("database schema version {found} is newer than this build supports ({supported})")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("blob {0} is missing from the store")]
    MissingBlob(String),
}

type Result<T> = std::result::Result<T, StoreError>;

pub struct Store {
    db: Database,
    cipher: Cipher,
    index: BlindIndex,
    scope_key: [u8; 32],
    pub path: PathBuf,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").field("path", &self.path).finish_non_exhaustive()
    }
}

impl Store {
    pub fn open(path: &Path, master: &MasterKey) -> Result<Arc<Self>> {
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        let db = Database::create(path).map_err(redb::Error::from)?;

        let store = Self {
            db,
            cipher: master.cipher_for("pigeon:store:v1"),
            index: BlindIndex::new(master.subkey("pigeon:index:v1")),
            scope_key: master.subkey("pigeon:scope:v1"),
            path: path.to_path_buf(),
        };
        store.init_schema()?;
        Ok(Arc::new(store))
    }

    fn init_schema(&self) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            txn.open_table(SCOPES)?;
            txn.open_table(FOLDERS)?;
            txn.open_table(ENVELOPES)?;
            txn.open_table(BLOBS)?;
            txn.open_table(OUTBOX)?;
            txn.open_table(PENDING)?;
            txn.open_table(COUNTERS)?;
            txn.open_multimap_table(SEARCH)?;
            txn.open_multimap_table(MSGID)?;
            txn.open_multimap_table(THREADS)?;

            let found = meta
                .get("schema")?
                .map(|v| u32::from_le_bytes(v.value().try_into().unwrap_or([0; 4])));
            match found {
                Some(found) if found > SCHEMA_VERSION => {
                    return Err(StoreError::SchemaTooNew {
                        found,
                        supported: SCHEMA_VERSION,
                    });
                }
                Some(_) => {}
                None => {
                    meta.insert("schema", SCHEMA_VERSION.to_le_bytes().as_slice())?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    fn scope(&self, account: &str, folder: &str) -> [u8; SCOPE_LEN] {
        let idx = BlindIndex::new(self.scope_key);
        let full = idx.token(account, folder);
        let mut out = [0u8; SCOPE_LEN];
        out.copy_from_slice(&full[..SCOPE_LEN]);
        out
    }

    /// Blob ids are caller-meaningful strings such as `body:work:INBOX:42`.
    /// redb stores keys verbatim, so the id is replaced by a keyed hash before
    /// it reaches the file; otherwise the account and folder names would sit in
    /// the database in the clear.
    fn blob_key(&self, id: &str) -> String {
        let idx = BlindIndex::new(self.scope_key);
        let tag = idx.token("blob", id);
        tag.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn msg_key_bytes(&self, account: &str, folder: &str, uid: u32) -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        k[..SCOPE_LEN].copy_from_slice(&self.scope(account, folder));
        k[SCOPE_LEN..].copy_from_slice(&uid.to_be_bytes());
        k
    }

    fn seal(&self, table: &str, key: &[u8], value: &impl serde::Serialize) -> Result<Vec<u8>> {
        let json = serde_json::to_vec(value)?;
        let mut aad = Vec::with_capacity(table.len() + 1 + key.len());
        aad.extend_from_slice(table.as_bytes());
        aad.push(0x1f);
        aad.extend_from_slice(key);
        Ok(self.cipher.seal(&aad, &json)?)
    }

    fn open_value<T: serde::de::DeserializeOwned>(
        &self,
        table: &str,
        key: &[u8],
        sealed: &[u8],
    ) -> Result<T> {
        let mut aad = Vec::with_capacity(table.len() + 1 + key.len());
        aad.extend_from_slice(table.as_bytes());
        aad.push(0x1f);
        aad.extend_from_slice(key);
        let plain = self.cipher.open(&aad, sealed)?;
        Ok(serde_json::from_slice(&plain)?)
    }

    // ---- folders ----

    pub fn put_folder(&self, f: &FolderState) -> Result<()> {
        let scope = self.scope(&f.account, &f.name);
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(FOLDERS)?;
            let v = self.seal("folders", &scope, f)?;
            t.insert(scope.as_slice(), v.as_slice())?;

            let mut s = txn.open_table(SCOPES)?;
            let pair = (f.account.clone(), f.name.clone());
            let sv = self.seal("scopes", &scope, &pair)?;
            s.insert(scope.as_slice(), sv.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn folder(&self, account: &str, name: &str) -> Result<Option<FolderState>> {
        let scope = self.scope(account, name);
        let txn = self.db.begin_read()?;
        let t = txn.open_table(FOLDERS)?;
        match t.get(scope.as_slice())? {
            Some(v) => Ok(Some(self.open_value("folders", &scope, v.value())?)),
            None => Ok(None),
        }
    }

    pub fn folders(&self, account: Option<&str>) -> Result<Vec<FolderState>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(FOLDERS)?;
        let mut out = Vec::new();
        for row in t.iter()? {
            let (k, v) = row?;
            let f: FolderState = self.open_value("folders", k.value(), v.value())?;
            if account.is_none_or(|a| a == f.account) {
                out.push(f);
            }
        }
        out.sort_by(|a, b| a.account.cmp(&b.account).then_with(|| a.name.cmp(&b.name)));
        Ok(out)
    }

    pub fn delete_folder(&self, account: &str, name: &str) -> Result<()> {
        let scope = self.scope(account, name);
        let uids = self.uids(account, name)?;
        let txn = self.db.begin_write()?;
        {
            txn.open_table(FOLDERS)?.remove(scope.as_slice())?;
            txn.open_table(SCOPES)?.remove(scope.as_slice())?;
            let mut env = txn.open_table(ENVELOPES)?;
            for uid in uids {
                let k = self.msg_key_bytes(account, name, uid);
                env.remove(k.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    // ---- envelopes ----

    pub fn put_envelopes(&self, envs: &[Envelope]) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(ENVELOPES)?;
            let mut search = txn.open_multimap_table(SEARCH)?;
            let mut msgid = txn.open_multimap_table(MSGID)?;
            let mut threads = txn.open_multimap_table(THREADS)?;
            let mut scopes = txn.open_table(SCOPES)?;

            for e in envs {
                let k = self.msg_key_bytes(&e.account, &e.folder, e.uid);

                // Search resolves a hit back to its account and folder through
                // this mapping, so it has to exist before the first envelope is
                // indexed, not only once the folder list has been synced.
                let scope = &k[..SCOPE_LEN];
                if scopes.get(scope)?.is_none() {
                    let pair = (e.account.clone(), e.folder.clone());
                    let sv = self.seal("scopes", scope, &pair)?;
                    scopes.insert(scope, sv.as_slice())?;
                }

                let v = self.seal("envelopes", &k, e)?;
                t.insert(k.as_slice(), v.as_slice())?;

                for tok in self.index_terms(e) {
                    search.insert(tok.as_slice(), k.as_slice())?;
                }
                if let Some(id) = &e.message_id {
                    let tok = self.index.token("msgid", &id.to_lowercase());
                    msgid.insert(tok.as_slice(), k.as_slice())?;
                }
                if let Some(th) = &e.thread_id {
                    let tok = self.index.token("thread", th);
                    threads.insert(tok.as_slice(), k.as_slice())?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    fn index_terms(&self, e: &Envelope) -> Vec<[u8; blind::TOKEN_LEN]> {
        let mut out = Vec::new();
        let mut push = |field: &str, text: &str| {
            for term in blind::tokenize(text) {
                out.push(self.index.token(field, &term));
                out.push(self.index.token("any", &term));
            }
        };
        push("subject", &e.subject);
        push("body", &e.preview);
        for a in e.from.iter().chain(&e.reply_to) {
            push("from", &a.email);
            if let Some(n) = &a.name {
                push("from", n);
            }
        }
        for a in e.to.iter().chain(&e.cc).chain(&e.bcc) {
            push("to", &a.email);
            if let Some(n) = &a.name {
                push("to", n);
            }
        }
        for att in &e.attachments {
            push("attachment", &att.name);
        }
        for t in e.tags.iter().chain(&e.keywords) {
            push("tag", t);
        }
        if let Some(l) = &e.list_id {
            push("list", l);
        }
        out.sort();
        out.dedup();
        out
    }

    pub fn envelope(&self, account: &str, folder: &str, uid: u32) -> Result<Option<Envelope>> {
        let k = self.msg_key_bytes(account, folder, uid);
        let txn = self.db.begin_read()?;
        let t = txn.open_table(ENVELOPES)?;
        match t.get(k.as_slice())? {
            Some(v) => Ok(Some(self.open_value("envelopes", &k, v.value())?)),
            None => Ok(None),
        }
    }

    pub fn envelopes(&self, account: &str, folder: &str) -> Result<Vec<Envelope>> {
        let scope = self.scope(account, folder);
        let lo = {
            let mut k = [0u8; KEY_LEN];
            k[..SCOPE_LEN].copy_from_slice(&scope);
            k
        };
        let hi = {
            let mut k = [0xffu8; KEY_LEN];
            k[..SCOPE_LEN].copy_from_slice(&scope);
            k
        };

        let txn = self.db.begin_read()?;
        let t = txn.open_table(ENVELOPES)?;
        let mut out = Vec::new();
        for row in t.range(lo.as_slice()..=hi.as_slice())? {
            let (k, v) = row?;
            out.push(self.open_value("envelopes", k.value(), v.value())?);
        }
        Ok(out)
    }

    pub fn uids(&self, account: &str, folder: &str) -> Result<Vec<u32>> {
        let scope = self.scope(account, folder);
        let mut lo = [0u8; KEY_LEN];
        lo[..SCOPE_LEN].copy_from_slice(&scope);
        let mut hi = [0xffu8; KEY_LEN];
        hi[..SCOPE_LEN].copy_from_slice(&scope);

        let txn = self.db.begin_read()?;
        let t = txn.open_table(ENVELOPES)?;
        let mut out = Vec::new();
        for row in t.range(lo.as_slice()..=hi.as_slice())? {
            let (k, _) = row?;
            let b = k.value();
            if b.len() == KEY_LEN {
                out.push(u32::from_be_bytes(b[SCOPE_LEN..].try_into().unwrap()));
            }
        }
        Ok(out)
    }

    pub fn remove_envelopes(&self, account: &str, folder: &str, uids: &[u32]) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(ENVELOPES)?;
            for uid in uids {
                let k = self.msg_key_bytes(account, folder, *uid);
                t.remove(k.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub fn update_flags(
        &self,
        account: &str,
        folder: &str,
        uid: u32,
        add: Flags,
        remove: Flags,
    ) -> Result<Option<Envelope>> {
        let k = self.msg_key_bytes(account, folder, uid);
        let txn = self.db.begin_write()?;
        let updated = {
            let mut t = txn.open_table(ENVELOPES)?;
            let current = match t.get(k.as_slice())? {
                Some(v) => Some(self.open_value::<Envelope>("envelopes", &k, v.value())?),
                None => None,
            };
            match current {
                Some(mut e) => {
                    e.flags.insert(add);
                    e.flags.remove(remove);
                    let v = self.seal("envelopes", &k, &e)?;
                    t.insert(k.as_slice(), v.as_slice())?;
                    Some(e)
                }
                None => None,
            }
        };
        txn.commit()?;
        Ok(updated)
    }

    // ---- search ----

    pub fn search_token(&self, field: &str, term: &str) -> Result<Vec<MsgKey>> {
        let tok = self.index.token(field, &term.to_lowercase());
        let txn = self.db.begin_read()?;
        let t = txn.open_multimap_table(SEARCH)?;
        let scopes = txn.open_table(SCOPES)?;
        let envs = txn.open_table(ENVELOPES)?;

        let mut out = Vec::new();
        for row in t.get(tok.as_slice())? {
            let k = row?;
            let kb = k.value();
            if kb.len() != KEY_LEN || envs.get(kb)?.is_none() {
                continue;
            }
            let scope = &kb[..SCOPE_LEN];
            let Some(sv) = scopes.get(scope)? else { continue };
            let (account, folder): (String, String) =
                self.open_value("scopes", scope, sv.value())?;
            out.push(MsgKey {
                account,
                folder,
                uid: u32::from_be_bytes(kb[SCOPE_LEN..].try_into().unwrap()),
            });
        }
        Ok(out)
    }

    pub fn by_message_id(&self, message_id: &str) -> Result<Vec<MsgKey>> {
        let tok = self.index.token("msgid", &message_id.to_lowercase());
        self.lookup_multimap(MSGID, &tok)
    }

    pub fn by_thread(&self, thread_id: &str) -> Result<Vec<MsgKey>> {
        let tok = self.index.token("thread", thread_id);
        self.lookup_multimap(THREADS, &tok)
    }

    fn lookup_multimap(
        &self,
        def: MultimapTableDefinition<&'static [u8], &'static [u8]>,
        tok: &[u8],
    ) -> Result<Vec<MsgKey>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_multimap_table(def)?;
        let scopes = txn.open_table(SCOPES)?;
        let mut out = Vec::new();
        for row in t.get(tok)? {
            let k = row?;
            let kb = k.value();
            if kb.len() != KEY_LEN {
                continue;
            }
            let scope = &kb[..SCOPE_LEN];
            let Some(sv) = scopes.get(scope)? else { continue };
            let (account, folder): (String, String) =
                self.open_value("scopes", scope, sv.value())?;
            out.push(MsgKey {
                account,
                folder,
                uid: u32::from_be_bytes(kb[SCOPE_LEN..].try_into().unwrap()),
            });
        }
        Ok(out)
    }

    // ---- blobs ----

    pub fn put_blob(&self, id: &str, bytes: &[u8]) -> Result<()> {
        let key = self.blob_key(id);
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(BLOBS)?;
            let v = self.cipher.seal(&blob_aad(id), bytes)?;
            t.insert(key.as_str(), v.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn blob(&self, id: &str) -> Result<Vec<u8>> {
        let key = self.blob_key(id);
        let txn = self.db.begin_read()?;
        let t = txn.open_table(BLOBS)?;
        let v = t
            .get(key.as_str())?
            .ok_or_else(|| StoreError::MissingBlob(id.to_string()))?;
        Ok(self.cipher.open(&blob_aad(id), v.value())?)
    }

    pub fn has_blob(&self, id: &str) -> Result<bool> {
        let key = self.blob_key(id);
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(BLOBS)?.get(key.as_str())?.is_some())
    }

    pub fn delete_blob(&self, id: &str) -> Result<()> {
        let key = self.blob_key(id);
        let txn = self.db.begin_write()?;
        txn.open_table(BLOBS)?.remove(key.as_str())?;
        txn.commit()?;
        Ok(())
    }

    // ---- outbox & offline queue ----

    pub fn enqueue(&self, item: &OutboxItem) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(OUTBOX)?;
            let v = self.seal("outbox", item.id.as_bytes(), item)?;
            t.insert(item.id.as_str(), v.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn outbox(&self) -> Result<Vec<OutboxItem>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(OUTBOX)?;
        let mut out: Vec<OutboxItem> = Vec::new();
        for row in t.iter()? {
            let (k, v) = row?;
            out.push(self.open_value("outbox", k.value().as_bytes(), v.value())?);
        }
        out.sort_by_key(|i| i.queued_at);
        Ok(out)
    }

    pub fn dequeue(&self, id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        txn.open_table(OUTBOX)?.remove(id)?;
        txn.commit()?;
        Ok(())
    }

    pub fn push_pending(&self, op: &PendingOp) -> Result<u64> {
        let txn = self.db.begin_write()?;
        let seq = {
            let mut c = txn.open_table(COUNTERS)?;
            let next = c.get("pending")?.map(|v| v.value()).unwrap_or(0) + 1;
            c.insert("pending", next)?;
            let mut t = txn.open_table(PENDING)?;
            let v = self.seal("pending", &next.to_le_bytes(), op)?;
            t.insert(next, v.as_slice())?;
            next
        };
        txn.commit()?;
        Ok(seq)
    }

    pub fn pending(&self) -> Result<Vec<(u64, PendingOp)>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(PENDING)?;
        let mut out = Vec::new();
        for row in t.iter()? {
            let (k, v) = row?;
            let seq = k.value();
            out.push((seq, self.open_value("pending", &seq.to_le_bytes(), v.value())?));
        }
        Ok(out)
    }

    pub fn drop_pending(&self, seq: u64) -> Result<()> {
        let txn = self.db.begin_write()?;
        txn.open_table(PENDING)?.remove(seq)?;
        txn.commit()?;
        Ok(())
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<()> {
        let txn = self.db.begin_write()?;
        txn.open_table(META)?.insert(key, value)?;
        txn.commit()?;
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        Ok(t.get(key)?.map(|v| v.value().to_vec()))
    }

    pub fn compact(&mut self) -> Result<bool> {
        Ok(self.db.compact().map_err(redb::Error::from)?)
    }

    pub fn prune_bodies(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let mut dropped = 0;
        let keep: std::collections::HashSet<String> = {
            let txn = self.db.begin_read()?;
            let t = txn.open_table(ENVELOPES)?;
            let mut keep = std::collections::HashSet::new();
            for row in t.iter()? {
                let (k, v) = row?;
                let e: Envelope = self.open_value("envelopes", k.value(), v.value())?;
                if e.date >= older_than
                    && let Some(b) = e.body_blob
                {
                    keep.insert(b);
                }
            }
            keep
        };

        let ids: Vec<String> = {
            let txn = self.db.begin_read()?;
            let t = txn.open_table(BLOBS)?;
            t.iter()?
                .filter_map(|r| r.ok().map(|(k, _)| k.value().to_string()))
                .collect()
        };

        let keep_keys: std::collections::HashSet<String> =
            keep.iter().map(|id| self.blob_key(id)).collect();

        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(BLOBS)?;
            for id in ids {
                if !keep_keys.contains(&id) {
                    t.remove(id.as_str())?;
                    dropped += 1;
                }
            }
        }
        txn.commit()?;
        Ok(dropped)
    }
}

fn blob_aad(id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(6 + id.len());
    aad.extend_from_slice(b"blobs\x1f");
    aad.extend_from_slice(id.as_bytes());
    aad
}
