use pigeon::{cli, config, crypto, daemon, net, pgp, secrets, store, sync, ui};

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use secrecy::{ExposeSecret, SecretString};

use cli::{Cmd, USAGE};
use config::{Config, Unlock};
use crypto::{MasterKey, Vault};
use secrets::SecretProvider;
use store::Store;
use sync::SyncEngine;

fn main() -> anyhow::Result<()> {
    let args = match cli::parse(std::env::args()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("pigeon: {e}");
            std::process::exit(2);
        }
    };

    match args.cmd {
        Cmd::Help => {
            println!("{USAGE}");
            return Ok(());
        }
        Cmd::Version => {
            println!("pigeon {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        _ => {}
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("could not start the async runtime")?;

    runtime.block_on(async move {
        if let Err(e) = dispatch(args).await {
            eprintln!("pigeon: {e:#}");
            std::process::exit(1);
        }
        Ok(())
    })
}

struct Session {
    config: Arc<Config>,
    store: Arc<Store>,
    secrets: Arc<SecretProvider>,
    data_dir: PathBuf,
}

async fn dispatch(args: cli::Args) -> anyhow::Result<()> {
    if args.cmd == Cmd::Init {
        return init(&args).await;
    }

    let logging = init_logging(&args)?;

    if args.cmd == Cmd::Tui {
        let result = run_tui(&args).await;
        drop(logging);
        return result;
    }

    // The daemon unlocks itself from the config or from a client, so it must not
    // go through `open_session`, which would try to prompt on a terminal it has
    // no reason to own.
    if args.cmd == Cmd::Daemon {
        let result = daemon::serve(&args, args.socket.as_deref()).await;
        drop(logging);
        return result;
    }

    let session = open_session(&args).await?;

    let result = match args.cmd.clone() {
        Cmd::Tui => Ok(()),
        Cmd::Sync(account) => run_sync(session, account).await,
        Cmd::Send => run_send(session).await,
        Cmd::Doctor => run_doctor(session).await,
        Cmd::AuthStore { account, kind } => auth_store(&session, &account, &kind),
        Cmd::AuthLogin { account } => auth_login(&session, &account).await,
        Cmd::AuthForget { account } => auth_forget(&session, &account),
        Cmd::VaultPasswd => vault_passwd(&session, &args).await,
        Cmd::VaultInfo => vault_info(&session),
        Cmd::PgpList => pgp_list(&session),
        Cmd::PgpImport(path) => pgp_import(&session, &path),
        Cmd::PgpExport(email) => pgp_export(&session, &email),
        Cmd::Daemon | Cmd::Init | Cmd::Help | Cmd::Version => Ok(()),
    };

    drop(logging);
    result
}

fn init_logging(args: &cli::Args) -> anyhow::Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    use tracing_subscriber::EnvFilter;

    let level = if args.verbose { "debug" } else { "info" };
    let filter = EnvFilter::try_from_env("PIGEON_LOG")
        .unwrap_or_else(|_| EnvFilter::new(format!("pigeon={level},warn")));

    // The TUI owns the terminal, so logs go to a file; anything written to
    // stdout would corrupt the display.
    let Ok(dir) = Config::default_data_dir() else {
        return Ok(None);
    };
    let _ = std::fs::create_dir_all(&dir);
    let file = tracing_appender::rolling::daily(&dir, "pigeon.log");
    let (writer, guard) = tracing_appender::non_blocking(file);

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(false)
        .try_init()
        .ok();

    Ok(Some(guard))
}

async fn init(args: &cli::Args) -> anyhow::Result<()> {
    let config_path = match &args.config {
        Some(p) => p.clone(),
        None => Config::default_path()?,
    };

    if config_path.exists() {
        println!("config already exists at {}", config_path.display());
    } else {
        Config::write_template(&config_path)?;
        println!("wrote a starter config to {}", config_path.display());
    }

    let data_dir = match &args.data_dir {
        Some(d) => d.clone(),
        None => Config::default_data_dir()?,
    };
    std::fs::create_dir_all(&data_dir)?;

    let vault_path = data_dir.join("vault.key");
    if Vault::exists(&vault_path) {
        println!("vault already exists at {}", vault_path.display());
    } else {
        println!("Choose a passphrase for the local vault.");
        println!("It encrypts every message, index and attachment pigeon stores on this machine.");
        let pass = secrets::prompt_passphrase(true)?;
        Vault::create(&vault_path, pass.expose_secret().as_bytes())?;
        println!("created an encrypted vault at {}", vault_path.display());
    }

    println!("\nNext: edit the config, then run `pigeon auth store <account> imap`.");
    Ok(())
}

async fn open_session(args: &cli::Args) -> anyhow::Result<Session> {
    let config = Config::load(args.config.as_deref())
        .with_context(|| "no account is set up yet — run `pigeon` and the setup wizard opens")?;

    let data_dir = match &args.data_dir {
        Some(d) => d.clone(),
        None => config.data_dir()?,
    };
    std::fs::create_dir_all(&data_dir)?;

    let master = unlock_master_key(&config, &data_dir, args.no_encrypt).await?;
    let store = Store::open(&data_dir.join("mail.redb"), &master)?;

    let config = Arc::new(config);
    let secrets = Arc::new(SecretProvider::new(
        config.general.keyring_service.clone(),
        store.clone(),
    ));

    Ok(Session { config, store, secrets, data_dir })
}

/// With encryption disabled the database is still keyed, just by a fixed
/// value — so the on-disk format never changes and a user can turn encryption
/// on later without losing their mail. It is not a security boundary, and the
/// flag says so.
async fn unlock_master_key(
    config: &Config,
    data_dir: &Path,
    no_encrypt: bool,
) -> anyhow::Result<MasterKey> {
    if no_encrypt || !config.general.encrypt_at_rest {
        eprintln!("warning: encryption at rest is off; mail is stored with a fixed key");
        return Ok(MasterKey::from_bytes(*b"pigeon-unencrypted-local-store!!"));
    }

    let vault_path = data_dir.join("vault.key");

    if !Vault::exists(&vault_path) {
        eprintln!("No vault found. Creating one at {}", vault_path.display());
        let pass = match config.general.unlock {
            Unlock::Prompt => secrets::prompt_passphrase(true)?,
            _ => secrets::vault_passphrase(config, true).await?,
        };
        let vault = Vault::create(&vault_path, pass.expose_secret().as_bytes())?;
        return Ok(vault.key().clone());
    }

    let pass = secrets::vault_passphrase(config, false).await?;
    let vault = Vault::unlock(&vault_path, pass.expose_secret().as_bytes())?;
    Ok(vault.key().clone())
}

/// The reader owns first-run setup: a missing config, a missing vault or a
/// locked vault all lead into the wizard on the same screen, rather than an
/// error telling the user to go and run something else.
async fn run_tui(args: &cli::Args) -> anyhow::Result<()> {
    let config_path = match &args.config {
        Some(p) => p.clone(),
        None => Config::default_path()?,
    };

    let existing = match Config::load(Some(&config_path)) {
        Ok(c) => Some(c),
        Err(config::ConfigError::Missing(_)) => None,
        Err(e) => return Err(e.into()),
    };

    let data_dir = match (&args.data_dir, &existing) {
        (Some(d), _) => d.clone(),
        (None, Some(c)) => c.data_dir()?,
        (None, None) => Config::default_data_dir()?,
    };
    std::fs::create_dir_all(&data_dir)?;

    let theme = existing
        .as_ref()
        .map(|c| ui::theme::Theme::by_name(&c.ui.theme))
        .unwrap_or_default();

    let encrypting = existing
        .as_ref()
        .map(|c| c.general.encrypt_at_rest)
        .unwrap_or(true)
        && !args.no_encrypt;

    let mut terminal = ratatui::try_init().map_err(|e| {
        anyhow::anyhow!(
            "pigeon needs an interactive terminal to run ({e}). \
             For scripts use `pigeon sync`, `pigeon send` or `pigeon doctor`."
        )
    })?;

    let boot = if encrypting || existing.is_none() {
        ui::wizard::run(&mut terminal, config_path, data_dir.clone(), existing, theme).await
    } else {
        let config = existing.expect("checked above");
        Ok(ui::wizard::Bootstrap {
            master: MasterKey::from_bytes(*b"pigeon-unencrypted-local-store!!"),
            config,
            config_path,
            data_dir: data_dir.clone(),
        })
    };

    let boot = match boot {
        Ok(b) => b,
        Err(e) => {
            ratatui::restore();
            if matches!(e, ui::wizard::WizardError::Cancelled) {
                return Ok(());
            }
            return Err(e.into());
        }
    };

    let result = start_reader(&mut terminal, boot).await;
    ratatui::restore();
    result
}

async fn start_reader(
    terminal: &mut ratatui::DefaultTerminal,
    boot: ui::wizard::Bootstrap,
) -> anyhow::Result<()> {
    let store = Store::open(&boot.data_dir.join("mail.redb"), &boot.master)?;
    let config = Arc::new(boot.config);
    let secrets = Arc::new(SecretProvider::new(
        config.general.keyring_service.clone(),
        store.clone(),
    ));

    let handle = SyncEngine::spawn(store.clone(), config.clone(), secrets.clone());
    let app = ui::App::new(store, secrets, config, handle.commands);
    ui::run_on(terminal, app, handle.events).await
}

async fn run_sync(session: Session, account: Option<String>) -> anyhow::Result<()> {
    let engine = SyncEngine::spawn(
        session.store.clone(),
        session.config.clone(),
        session.secrets.clone(),
    );
    let mut events = engine.events;

    let wanted: Vec<String> = match account {
        Some(a) => vec![a],
        None => session
            .config
            .accounts
            .iter()
            .filter(|a| a.enabled)
            .map(|a| a.name.clone())
            .collect(),
    };

    let mut done: std::collections::HashSet<String> = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);

    while done.len() < wanted.len() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("timed out waiting for the sync to finish");
        }
        let Ok(Some(event)) = tokio::time::timeout(remaining, events.recv()).await else {
            break;
        };
        match event {
            sync::Event::Status { account, status }
                if status == sync::SyncStatus::Idle && wanted.contains(&account) =>
            {
                println!("{account}: up to date");
                done.insert(account);
            }
            sync::Event::Envelopes { account, folder, envelopes, .. } => {
                println!("{account}/{folder}: +{} messages", envelopes.len());
            }
            sync::Event::Error { account, message } => {
                let who = account.unwrap_or_else(|| "pigeon".into());
                eprintln!("{who}: {message}");
            }
            _ => {}
        }
    }
    Ok(())
}

async fn run_send(session: Session) -> anyhow::Result<()> {
    let pending = session.store.outbox()?;
    if pending.is_empty() {
        println!("the outbox is empty");
        return Ok(());
    }
    println!("sending {} queued message(s)…", pending.len());

    let engine = SyncEngine::spawn(
        session.store.clone(),
        session.config.clone(),
        session.secrets.clone(),
    );
    let _ = engine.commands.send(sync::Command::FlushOutbox);

    let mut events = engine.events;
    let deadline = std::time::Duration::from_secs(120);
    while let Ok(Some(e)) = tokio::time::timeout(deadline, events.recv()).await {
        match e {
            sync::Event::Sent { .. } => println!("sent"),
            sync::Event::SendFailed { message, .. } => println!("send failed: {message}"),
            sync::Event::OutboxChanged { pending } if pending.is_empty() => {
                println!("outbox drained");
                return Ok(());
            }
            sync::Event::Error { message, .. } => eprintln!("error: {message}"),
            _ => {}
        }
    }
    Ok(())
}

async fn run_doctor(session: Session) -> anyhow::Result<()> {
    use net::imap::{Credentials as ImapCreds, ImapSession};

    println!("config       {}", session
        .config
        .source
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "(defaults)".into()));
    println!("data dir     {}", session.data_dir.display());
    println!("database     {}", session.store.path.display());
    println!(
        "encryption   {}",
        if session.config.general.encrypt_at_rest { "on" } else { "OFF" }
    );
    println!("accounts     {}", session.config.accounts.len());
    println!();

    for account in session.config.accounts.iter().filter(|a| a.enabled) {
        print!("{:<16} imap {}:{} … ", account.name, account.imap.host, account.imap.port);
        let resolved = session
            .secrets
            .resolve(account, "imap", &account.imap.auth, &account.imap.user)
            .await;

        match resolved {
            Err(e) => println!("no credentials ({e})"),
            Ok(r) => {
                let creds = match r {
                    secrets::Resolved::Password(p) => ImapCreds::Password {
                        user: account.imap.user.clone(),
                        password: p.expose_secret().to_string(),
                    },
                    secrets::Resolved::OAuth { user, access_token } => ImapCreds::XOAuth2 {
                        user,
                        token: access_token.expose_secret().to_string(),
                    },
                    secrets::Resolved::None => ImapCreds::Password {
                        user: account.imap.user.clone(),
                        password: String::new(),
                    },
                };
                match ImapSession::connect(&account.imap, &creds).await {
                    Ok(mut s) => {
                        let folders = s.folders(&account.name).await.map(|f| f.len()).unwrap_or(0);
                        let caps = &s.caps;
                        println!(
                            "ok — {folders} folders, idle={} condstore={} move={}",
                            caps.idle, caps.condstore, caps.move_ext
                        );
                        s.logout().await;
                    }
                    Err(e) => println!("FAILED — {e}"),
                }
            }
        }
    }
    Ok(())
}

fn auth_store(session: &Session, account: &str, kind: &str) -> anyhow::Result<()> {
    let acct = session
        .config
        .account(account)
        .ok_or_else(|| anyhow::anyhow!("no account named `{account}` in the config"))?;
    let kind = kind.to_ascii_lowercase();
    if kind != "imap" && kind != "smtp" {
        anyhow::bail!("the kind must be `imap` or `smtp`");
    }

    eprintln!(
        "Storing the {kind} password for {} ({}).",
        acct.name, acct.address
    );
    let password = secrets::prompt_passphrase(false)?;
    secrets::keyring_set(
        &session.config.general.keyring_service,
        &secrets::keyring_key(account, &kind),
        password.expose_secret(),
    )?;
    println!("stored in the OS keyring");
    Ok(())
}

async fn auth_login(session: &Session, account: &str) -> anyhow::Result<()> {
    use config::Auth;
    use net::oauth;

    let acct = session
        .config
        .account(account)
        .ok_or_else(|| anyhow::anyhow!("no account named `{account}` in the config"))?;

    let Auth::Oauth2 { provider, client_id, client_secret } = &acct.imap.auth else {
        anyhow::bail!("account `{account}` is not configured with auth = \"oauth2\"");
    };

    let client_id = client_id
        .clone()
        .or_else(|| secrets::default_client_id(*provider).map(str::to_string))
        .ok_or_else(|| anyhow::anyhow!("set client_id for account `{account}`"))?;

    let request = oauth::begin(*provider, &client_id, None).await?;
    println!("Open this URL to authorise pigeon:\n\n  {}\n", request.url);
    let _ = open::that_detached(&request.url);

    let (code, request) = request
        .wait_for_code(std::time::Duration::from_secs(300))
        .await?;
    let tokens = request
        .exchange(*provider, &client_id, client_secret.as_deref(), &code)
        .await?;

    session.secrets.save_tokens(account, &tokens)?;
    println!("authorised; the refresh token is stored in the encrypted vault");
    Ok(())
}

fn auth_forget(session: &Session, account: &str) -> anyhow::Result<()> {
    for kind in ["imap", "smtp"] {
        session.secrets.forget(account, kind)?;
    }
    println!("removed stored secrets for `{account}`");
    Ok(())
}

async fn vault_passwd(session: &Session, args: &cli::Args) -> anyhow::Result<()> {
    let data_dir = match &args.data_dir {
        Some(d) => d.clone(),
        None => session.config.data_dir()?,
    };
    let path = data_dir.join("vault.key");

    let current = secrets::vault_passphrase(&session.config, false).await?;
    let mut vault = Vault::unlock(&path, current.expose_secret().as_bytes())?;

    eprintln!("Choose a new passphrase.");
    let next: SecretString = secrets::prompt_passphrase(true)?;
    vault.change_passphrase(next.expose_secret().as_bytes())?;

    println!("passphrase changed; the master key and your mail were not re-encrypted");
    Ok(())
}

fn vault_info(session: &Session) -> anyhow::Result<()> {
    let dir = &session.data_dir;
    let vault_path = dir.join("vault.key");

    println!("vault        {}", vault_path.display());
    println!(
        "state        {}",
        if Vault::exists(&vault_path) { "present" } else { "missing" }
    );
    println!("database     {}", session.store.path.display());
    if let Ok(meta) = std::fs::metadata(&session.store.path) {
        println!("size         {}", ui::draw::human_size(meta.len()));
    }
    println!(
        "encryption   {}",
        if session.config.general.encrypt_at_rest {
            "XChaCha20-Poly1305, key wrapped with Argon2id"
        } else {
            "OFF"
        }
    );
    println!("unlock       {:?}", session.config.general.unlock);
    println!("outbox       {}", session.store.outbox()?.len());
    Ok(())
}

fn keyring_dir(session: &Session) -> PathBuf {
    session.data_dir.join("keys")
}

fn load_keyring(session: &Session) -> pgp::Keyring {
    let mut ring = pgp::Keyring::default();
    let dir = keyring_dir(session);
    let Ok(entries) = std::fs::read_dir(&dir) else { return ring };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if name.contains("secret") || name.ends_with(".sec.asc") {
            let _ = ring.load_secret(&path);
        } else {
            let _ = ring.load_public(&path);
        }
    }

    for account in &session.config.accounts {
        if let Some(p) = &account.pgp.secret_key_file {
            let _ = ring.load_secret(&config::expand(p));
        }
        if let Some(p) = &account.pgp.public_keyring {
            let _ = ring.load_public(&config::expand(p));
        }
    }
    ring
}

fn pgp_list(session: &Session) -> anyhow::Result<()> {
    let ring = load_keyring(session);
    let keys = ring.fingerprints();
    if keys.is_empty() {
        println!("no OpenPGP keys; import one with `pigeon pgp import KEYFILE`");
        return Ok(());
    }
    println!("{} public key(s), {} secret key(s)\n", ring.public.len(), ring.secret.len());
    for (fp, uids) in keys {
        println!("{fp}");
        for uid in uids {
            println!("    {uid}");
        }
    }
    Ok(())
}

fn pgp_import(session: &Session, path: &Path) -> anyhow::Result<()> {
    let dir = keyring_dir(session);
    std::fs::create_dir_all(&dir)?;

    let mut ring = pgp::Keyring::default();
    let public = ring.load_public(path).unwrap_or(0);
    let secret = ring.load_secret(path).unwrap_or(0);
    if public == 0 && secret == 0 {
        anyhow::bail!("no OpenPGP keys found in {}", path.display());
    }

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "imported.asc".into());
    let suffix = if secret > 0 { "secret-" } else { "" };
    let dest = dir.join(format!("{suffix}{name}"));
    std::fs::copy(path, &dest)?;

    #[cfg(unix)]
    if secret > 0 {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
    }

    println!("imported {public} public and {secret} secret key(s) into {}", dest.display());
    Ok(())
}

fn pgp_export(session: &Session, email: &str) -> anyhow::Result<()> {
    let ring = load_keyring(session);
    println!("{}", ring.export_public(email)?);
    Ok(())
}
