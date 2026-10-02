use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::{anyhow, bail};

use serde_json::{Value, json};

use crate::config::{
    Account, Auth, Config, EncryptPolicy, FolderMap, ImapConfig, Layout, PgpConfig, Security,
    SmtpConfig, Unlock,
};
use crate::crypto::Vault;
use crate::net::autoconfig;
use crate::net::imap::{Credentials as ImapCreds, ImapSession};
use crate::net::smtp::{Credentials as SmtpCreds, SmtpClient};

use super::server::{Daemon, string_of};

pub async fn autoconfig(p: &Value) -> anyhow::Result<Value> {
    let email = string_of(p, "email")?;
    if !email.contains('@') {
        bail!("`email` must be a full address");
    }

    let found = autoconfig::discover(&email).await;
    let local = email.split('@').next().unwrap_or(&email).to_string();
    let user = if found.username_is_local_part { local } else { email.clone() };

    Ok(json!({
        "email": email,
        "user": user,
        "source": found.source.label(),
        "oauth": found.oauth.map(provider_name),
        "imap": {
            "host": found.imap.host,
            "port": found.imap.port,
            "security": security_name(found.imap.security),
        },
        "smtp": {
            "host": found.smtp.host,
            "port": found.smtp.port,
            "security": security_name(found.smtp.security),
        },
    }))
}

/// Logs in for real against both servers. Settings that merely look plausible
/// are worth nothing, and the shell should be able to say which half is wrong.
pub async fn test_account(p: &Value) -> anyhow::Result<Value> {
    let account = account_from(p, None)?;
    let password = p
        .get("password")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let imap = match ImapSession::connect(
        &account.imap,
        &ImapCreds::Password {
            user: account.imap.user.clone(),
            password: password.clone(),
        },
    )
    .await
    {
        Ok(mut s) => {
            let folders = s.folders(&account.name).await.map(|f| f.len()).unwrap_or(0);
            let caps = json!({
                "ok": true,
                "folders": folders,
                "idle": s.caps.idle,
                "condstore": s.caps.condstore,
            });
            s.logout().await;
            caps
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    };

    let user = account
        .smtp
        .user
        .clone()
        .unwrap_or_else(|| account.address.clone());
    let ehlo = account.address.rsplit('@').next().unwrap_or("localhost");

    let smtp = match SmtpClient::connect(&account.smtp, ehlo).await {
        Ok(mut c) => {
            let auth = c.authenticate(&SmtpCreds::Plain { user, password }).await;
            let mechanisms = c.caps.auth.clone();
            c.quit().await;
            match auth {
                Ok(()) => json!({ "ok": true, "auth": mechanisms }),
                Err(e) => json!({ "ok": false, "error": e.to_string() }),
            }
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    };

    Ok(json!({
        "ok": imap["ok"] == json!(true) && smtp["ok"] == json!(true),
        "imap": imap,
        "smtp": smtp,
    }))
}

pub async fn vault_create(daemon: &Arc<Daemon>, p: &Value) -> anyhow::Result<Value> {
    let path = daemon.data_dir.join("vault.key");
    if Vault::exists(&path) {
        bail!("a vault already exists; use `unlock` instead");
    }

    let pass = string_of(p, "passphrase")?;
    if pass.len() < 8 {
        bail!("choose a passphrase of at least 8 characters");
    }

    std::fs::create_dir_all(&daemon.data_dir)?;
    Vault::create(&path, pass.as_bytes())?;
    Ok(json!({ "created": true, "path": path.display().to_string() }))
}

/// Adds an account to the config, files its password and restarts the engine.
/// The config is rewritten whole, so it goes through the lossless writer.
pub async fn account_add(daemon: Arc<Daemon>, p: &Value) -> anyhow::Result<Value> {
    let mut config = match Config::load(Some(&daemon.config_path)) {
        Ok(c) => c,
        Err(crate::config::ConfigError::Missing(_)) => Config::default(),
        Err(e) => return Err(e.into()),
    };

    let mut account = account_from(p, Some(&config))?;

    if config.accounts.iter().any(|a| a.name == account.name) {
        bail!("an account named `{}` already exists", account.name);
    }

    let password = p.get("password").and_then(Value::as_str).unwrap_or_default();
    let is_oauth = matches!(account.imap.auth, Auth::Oauth2 { .. });

    // The store has to be open before a password can go into the vault, which is
    // the fallback when no OS keyring answers.
    if !password.is_empty() && !is_oauth {
        let secrets = daemon.secrets().await?;
        let chosen = secrets
            .store_password(&account.name, "imap", password)
            .unwrap_or(Auth::Vault);
        let _ = secrets.store_password(&account.name, "smtp", password);
        account.imap.auth = chosen.clone();
        account.smtp.auth = chosen;
    }

    // Only the very first account becomes the default; adding a second one must
    // not quietly move where new mail is composed from.
    if config.accounts.is_empty() {
        config.general.default_account = Some(account.name.clone());
    }

    let name = account.name.clone();
    config.accounts.push(account);
    write_config(&daemon, &config)?;

    let accounts = daemon.reload().await?;
    Ok(json!({ "added": name, "accounts": accounts }))
}

pub async fn account_remove(daemon: Arc<Daemon>, p: &Value) -> anyhow::Result<Value> {
    let name = string_of(p, "name")?;
    let mut config = Config::load(Some(&daemon.config_path))?;

    let before = config.accounts.len();
    config.accounts.retain(|a| a.name != name);
    if config.accounts.len() == before {
        bail!("no account named `{name}`");
    }

    if config.general.default_account.as_deref() == Some(name.as_str()) {
        config.general.default_account = config.accounts.first().map(|a| a.name.clone());
    }

    write_config(&daemon, &config)?;

    // Leaving the password behind would let a re-added account silently reuse a
    // credential the user thought they had removed.
    let secrets = daemon.secrets().await?;
    for purpose in ["imap", "smtp"] {
        let _ = secrets.forget(&name, purpose);
    }

    let accounts = daemon.reload().await?;
    Ok(json!({ "removed": name, "accounts": accounts }))
}

pub async fn account_update(daemon: Arc<Daemon>, p: &Value) -> anyhow::Result<Value> {
    let name = string_of(p, "name")?;
    let mut config = Config::load(Some(&daemon.config_path))?;

    let account = config
        .accounts
        .iter_mut()
        .find(|a| a.name == name)
        .ok_or_else(|| anyhow!("no account named `{name}`"))?;

    if let Some(v) = p.get("displayName").and_then(Value::as_str) {
        account.display_name = (!v.trim().is_empty()).then(|| v.trim().to_string());
    }
    if let Some(v) = p.get("signature").and_then(Value::as_str) {
        account.signature = (!v.is_empty()).then(|| v.to_string());
    }
    if let Some(v) = p.get("enabled").and_then(Value::as_bool) {
        account.enabled = v;
    }
    if let Some(v) = p.get("aliases").and_then(Value::as_array) {
        account.aliases = v.iter().filter_map(Value::as_str).map(str::to_string).collect();
    }
    if let Some(servers) = p.get("imap") {
        apply_imap(&mut account.imap, servers);
    }
    if let Some(servers) = p.get("smtp") {
        apply_smtp(&mut account.smtp, servers);
    }
    if let Some(folders) = p.get("folders") {
        apply_folders(&mut account.folders, folders);
    }
    if let Some(pgp) = p.get("pgp") {
        apply_pgp(&mut account.pgp, pgp);
    }

    write_config(&daemon, &config)?;
    let accounts = daemon.reload().await?;
    Ok(json!({ "updated": name, "accounts": accounts }))
}

pub async fn set_password(daemon: &Arc<Daemon>, p: &Value) -> anyhow::Result<Value> {
    let account = string_of(p, "account")?;
    let password = string_of(p, "password")?;
    let purpose = p.get("kind").and_then(Value::as_str).unwrap_or("imap");

    if !matches!(purpose, "imap" | "smtp") {
        bail!("`kind` must be `imap` or `smtp`");
    }

    let secrets = daemon.secrets().await?;
    let chosen = secrets.store_password(&account, purpose, &password)?;

    Ok(json!({
        "account": account,
        "kind": purpose,
        "storedIn": match chosen {
            Auth::Vault => "vault",
            _ => "keyring",
        },
    }))
}

pub async fn settings_get(daemon: &Arc<Daemon>) -> anyhow::Result<Value> {
    let config = daemon.config().await?;
    let g = &config.general;
    let u = &config.ui;

    Ok(json!({
        "general": {
            "encryptAtRest": g.encrypt_at_rest,
            "unlock": match g.unlock {
                Unlock::Prompt => "prompt",
                Unlock::Keyring => "keyring",
                Unlock::Command => "command",
            },
            "pollIntervalSecs": g.poll_interval_secs,
            "idle": g.idle,
            "notify": g.notify,
            "defaultAccount": g.default_account,
            "bodyCacheDays": g.body_cache_days,
            "downloadFullBodies": g.download_full_bodies,
            "maxAttachmentMb": g.max_attachment_mb,
            "logLevel": g.log_level,
        },
        "ui": {
            "theme": u.theme,
            "threading": u.threading,
            "preview": u.preview,
            "relativeDates": u.relative_dates,
            "dateFormat": u.date_format,
            "markReadDelayMs": u.mark_read_delay_ms,
            "vimKeys": u.vim_keys,
        },
    }))
}

pub async fn settings_set(daemon: Arc<Daemon>, p: &Value) -> anyhow::Result<Value> {
    let mut config = Config::load(Some(&daemon.config_path))?;
    let mut restart = false;

    if let Some(g) = p.get("general") {
        if let Some(v) = g.get("pollIntervalSecs").and_then(Value::as_u64) {
            config.general.poll_interval_secs = v.max(30);
            restart = true;
        }
        if let Some(v) = g.get("idle").and_then(Value::as_bool) {
            config.general.idle = v;
            restart = true;
        }
        if let Some(v) = g.get("notify").and_then(Value::as_bool) {
            config.general.notify = v;
        }
        if let Some(v) = g.get("defaultAccount").and_then(Value::as_str) {
            if !config.accounts.iter().any(|a| a.name == v) {
                bail!("no account named `{v}`");
            }
            config.general.default_account = Some(v.to_string());
        }
        if let Some(v) = g.get("bodyCacheDays").and_then(Value::as_u64) {
            config.general.body_cache_days = v as u32;
        }
        if let Some(v) = g.get("downloadFullBodies").and_then(Value::as_bool) {
            config.general.download_full_bodies = v;
            restart = true;
        }
        if let Some(v) = g.get("maxAttachmentMb").and_then(Value::as_u64) {
            config.general.max_attachment_mb = v;
        }
        if let Some(v) = g.get("logLevel").and_then(Value::as_str) {
            config.general.log_level = v.to_string();
        }
    }

    if let Some(u) = p.get("ui") {
        if let Some(v) = u.get("theme").and_then(Value::as_str) {
            config.ui.theme = v.to_string();
        }
        if let Some(v) = u.get("threading").and_then(Value::as_bool) {
            config.ui.threading = v;
        }
        if let Some(v) = u.get("preview").and_then(Value::as_bool) {
            config.ui.preview = v;
        }
        if let Some(v) = u.get("relativeDates").and_then(Value::as_bool) {
            config.ui.relative_dates = v;
        }
        if let Some(v) = u.get("dateFormat").and_then(Value::as_str) {
            config.ui.date_format = v.to_string();
        }
        if let Some(v) = u.get("markReadDelayMs").and_then(Value::as_u64) {
            config.ui.mark_read_delay_ms = v;
        }
        if let Some(v) = u.get("vimKeys").and_then(Value::as_bool) {
            config.ui.vim_keys = v;
        }
        if let Some(v) = u.get("layout").and_then(Value::as_str) {
            config.ui.layout = match v {
                "two-pane" => Layout::TwoPane,
                "list-only" => Layout::ListOnly,
                _ => Layout::ThreePane,
            };
        }
    }

    write_config(&daemon, &config)?;

    if restart {
        daemon.clone().reload().await?;
    }

    settings_get(&daemon).await
}

fn write_config(daemon: &Arc<Daemon>, config: &Config) -> anyhow::Result<()> {
    config.validate()?;
    let text = crate::config::render_config(config);

    // Re-parsing before the file is replaced means a bad edit is rejected while
    // the previous config is still on disk.
    let check: Config = toml::from_str(&text)?;
    check.validate()?;

    if let Some(dir) = daemon.config_path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    let tmp = daemon.config_path.with_extension("toml.tmp");
    std::fs::write(&tmp, &text)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, &daemon.config_path)?;
    Ok(())
}

fn account_from(p: &Value, existing: Option<&Config>) -> anyhow::Result<Account> {
    let address = string_of(p, "email")?;
    if !address.contains('@') || address.starts_with('@') || address.ends_with('@') {
        bail!("`email` must look like name@example.org");
    }

    let name = match p.get("name").and_then(Value::as_str) {
        Some(n) if !n.trim().is_empty() => n.trim().to_string(),
        _ => unique_label(&address, existing),
    };

    let imap = p
        .get("imap")
        .ok_or_else(|| anyhow!("`imap` settings are required"))?;
    let smtp = p
        .get("smtp")
        .ok_or_else(|| anyhow!("`smtp` settings are required"))?;

    let local = address.split('@').next().unwrap_or(&address).to_string();
    let default_user = imap
        .get("user")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| address.clone());

    let auth = match p.get("oauth").and_then(Value::as_str) {
        Some(provider) => Auth::Oauth2 {
            provider: parse_provider(provider),
            client_id: p.get("clientId").and_then(Value::as_str).map(str::to_string),
            client_secret: p.get("clientSecret").and_then(Value::as_str).map(str::to_string),
        },
        None => Auth::Keyring,
    };

    let mut account = Account {
        name,
        address: address.clone(),
        display_name: p
            .get("displayName")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string()),
        aliases: Vec::new(),
        signature: p.get("signature").and_then(Value::as_str).map(str::to_string),
        signature_file: None,
        imap: ImapConfig {
            host: string_of(imap, "host")?,
            port: port_of(imap, 993),
            security: parse_security(imap.get("security").and_then(Value::as_str)),
            user: default_user,
            auth: auth.clone(),
            accept_invalid_certs: false,
            use_condstore: true,
            use_compress: true,
        },
        smtp: SmtpConfig {
            host: string_of(smtp, "host")?,
            port: port_of(smtp, 465),
            security: parse_security(smtp.get("security").and_then(Value::as_str)),
            user: Some(
                smtp.get("user")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| address.clone()),
            ),
            auth,
            accept_invalid_certs: false,
        },
        pgp: PgpConfig::default(),
        folders: FolderMap::default(),
        enabled: true,
    };

    if p.get("userIsLocalPart").and_then(Value::as_bool) == Some(true) {
        account.imap.user = local.clone();
        account.smtp.user = Some(local);
    }

    if let Some(folders) = p.get("folders") {
        apply_folders(&mut account.folders, folders);
    }

    Ok(account)
}

/// Two addresses at different providers can share a local part, and the account
/// label is a key, so an unlabelled second `me@…` becomes `me-2`.
fn unique_label(address: &str, existing: Option<&Config>) -> String {
    let base = address.split('@').next().unwrap_or("mail").to_string();
    let taken = |candidate: &str| {
        existing
            .map(|c| c.accounts.iter().any(|a| a.name == candidate))
            .unwrap_or(false)
    };

    if !taken(&base) {
        return base;
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|candidate| !taken(candidate))
        .unwrap_or(base)
}

fn apply_imap(imap: &mut ImapConfig, p: &Value) {
    if let Some(v) = p.get("host").and_then(Value::as_str) {
        imap.host = v.to_string();
    }
    if let Some(v) = p.get("port").and_then(Value::as_u64) {
        imap.port = v as u16;
    }
    if let Some(v) = p.get("security").and_then(Value::as_str) {
        imap.security = parse_security(Some(v));
    }
    if let Some(v) = p.get("user").and_then(Value::as_str) {
        imap.user = v.to_string();
    }
}

fn apply_smtp(smtp: &mut SmtpConfig, p: &Value) {
    if let Some(v) = p.get("host").and_then(Value::as_str) {
        smtp.host = v.to_string();
    }
    if let Some(v) = p.get("port").and_then(Value::as_u64) {
        smtp.port = v as u16;
    }
    if let Some(v) = p.get("security").and_then(Value::as_str) {
        smtp.security = parse_security(Some(v));
    }
    if let Some(v) = p.get("user").and_then(Value::as_str) {
        smtp.user = Some(v.to_string());
    }
}

fn apply_folders(folders: &mut FolderMap, p: &Value) {
    if let Some(v) = p.get("inbox").and_then(Value::as_str) {
        folders.inbox = v.to_string();
    }
    for (field, slot) in [
        ("sent", &mut folders.sent),
        ("drafts", &mut folders.drafts),
        ("trash", &mut folders.trash),
        ("archive", &mut folders.archive),
        ("spam", &mut folders.spam),
    ] {
        if let Some(v) = p.get(field).and_then(Value::as_str) {
            *slot = (!v.is_empty()).then(|| v.to_string());
        }
    }
}

fn apply_pgp(pgp: &mut PgpConfig, p: &Value) {
    if let Some(v) = p.get("enabled").and_then(Value::as_bool) {
        pgp.enabled = v;
    }
    if let Some(v) = p.get("keyId").and_then(Value::as_str) {
        pgp.key_id = (!v.is_empty()).then(|| v.to_string());
    }
    if let Some(v) = p.get("signByDefault").and_then(Value::as_bool) {
        pgp.sign_by_default = v;
    }
    if let Some(v) = p.get("autocrypt").and_then(Value::as_bool) {
        pgp.autocrypt = v;
    }
    if let Some(v) = p.get("encryptPolicy").and_then(Value::as_str) {
        pgp.encrypt_policy = match v {
            "never" => EncryptPolicy::Never,
            "always" => EncryptPolicy::Always,
            _ => EncryptPolicy::IfPossible,
        };
    }
}

fn port_of(p: &Value, fallback: u16) -> u16 {
    p.get("port")
        .and_then(Value::as_u64)
        .map(|v| v as u16)
        .filter(|v| *v > 0)
        .unwrap_or(fallback)
}

fn parse_security(s: Option<&str>) -> Security {
    match s {
        Some("starttls") => Security::Starttls,
        Some("none") => Security::None,
        _ => Security::Tls,
    }
}

fn security_name(s: Security) -> &'static str {
    match s {
        Security::Tls => "tls",
        Security::Starttls => "starttls",
        Security::None => "none",
    }
}

fn parse_provider(s: &str) -> crate::config::OauthProvider {
    use crate::config::OauthProvider as P;
    match s {
        "gmail" => P::Gmail,
        "outlook" => P::Outlook,
        "yahoo" => P::Yahoo,
        _ => P::Custom,
    }
}

fn provider_name(p: crate::config::OauthProvider) -> &'static str {
    use crate::config::OauthProvider as P;
    match p {
        P::Gmail => "gmail",
        P::Outlook => "outlook",
        P::Yahoo => "yahoo",
        P::Custom => "custom",
    }
}
