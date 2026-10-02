use std::process::Stdio;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use tokio::process::Command;

use crate::config::{Account, Auth, Config, OauthProvider, Unlock};
use crate::net::oauth::{self, Tokens};
use crate::store::Store;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("the OS keyring has no entry for `{0}`; add it from the account screen")]
    NotInKeyring(String),
    #[error("no password stored in the vault for `{0}`; add it from the account screen")]
    NotInVault(String),
    #[error("keyring error: {0}")]
    Keyring(String),
    #[error("password command failed with status {status}: {stderr}")]
    CommandFailed { status: String, stderr: String },
    #[error("could not run password command: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("the password command produced no output")]
    EmptyCommand,
    #[error("account `{0}` uses OAuth2 but has never been authorised; run `pigeon auth login {0}`")]
    NoTokens(String),
    #[error("account `{0}` has no client_id; set one under [account.imap] or [account.smtp]")]
    NoClientId(String),
    #[error(transparent)]
    Oauth(#[from] oauth::OauthError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error("could not read the passphrase: {0}")]
    Tty(#[source] std::io::Error),
    #[error(
        "no terminal is attached, so the passphrase cannot be prompted for; \
         set general.unlock to \"keyring\" or \"command\", or run pigeon from a terminal"
    )]
    NoTty,
}

pub fn keyring_key(account: &str, purpose: &str) -> String {
    format!("{account}:{purpose}")
}

pub fn keyring_get(service: &str, key: &str) -> Result<SecretString, SecretError> {
    let entry = keyring::Entry::new(service, key).map_err(|e| SecretError::Keyring(e.to_string()))?;
    match entry.get_password() {
        Ok(p) => Ok(SecretString::from(p)),
        Err(keyring::Error::NoEntry) => Err(SecretError::NotInKeyring(key.to_string())),
        Err(e) => Err(SecretError::Keyring(e.to_string())),
    }
}

pub fn keyring_set(service: &str, key: &str, value: &str) -> Result<(), SecretError> {
    let entry = keyring::Entry::new(service, key).map_err(|e| SecretError::Keyring(e.to_string()))?;
    entry
        .set_password(value)
        .map_err(|e| SecretError::Keyring(e.to_string()))
}

pub fn keyring_delete(service: &str, key: &str) -> Result<(), SecretError> {
    let entry = keyring::Entry::new(service, key).map_err(|e| SecretError::Keyring(e.to_string()))?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(SecretError::Keyring(e.to_string())),
    }
}

/// Runs a user-supplied command (`pass show …`, `gpg -d …`) and takes the first
/// line of stdout. Only the first line is used so a password store that prints
/// notes below the secret still works.
pub async fn run_password_command(cmd: &str) -> Result<SecretString, SecretError> {
    let out = Command::new("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(SecretError::Spawn)?;

    if !out.status.success() {
        return Err(SecretError::CommandFailed {
            status: out.status.to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next().unwrap_or("").trim();
    if first.is_empty() {
        return Err(SecretError::EmptyCommand);
    }
    Ok(SecretString::from(first.to_string()))
}

#[derive(Debug, Clone)]
pub enum Resolved {
    None,
    Password(SecretString),
    OAuth { user: String, access_token: SecretString },
}

pub struct SecretProvider {
    pub service: String,
    pub store: Arc<Store>,
}

impl SecretProvider {
    pub fn new(service: impl Into<String>, store: Arc<Store>) -> Self {
        Self { service: service.into(), store }
    }

    pub async fn resolve(
        &self,
        account: &Account,
        purpose: &str,
        auth: &Auth,
        user: &str,
    ) -> Result<Resolved, SecretError> {
        match auth {
            Auth::None => Ok(Resolved::None),
            Auth::Password { password } => {
                Ok(Resolved::Password(SecretString::from(password.clone())))
            }
            Auth::PasswordCommand { password_command } => Ok(Resolved::Password(
                run_password_command(password_command).await?,
            )),
            Auth::Keyring => {
                let key = keyring_key(&account.name, purpose);
                match keyring_get(&self.service, &key) {
                    Ok(p) => Ok(Resolved::Password(p)),
                    // A login keyring that is absent or locked is common on
                    // headless machines; the vault copy is the fallback.
                    Err(e) => match self.vault_password(&account.name, purpose)? {
                        Some(p) => Ok(Resolved::Password(p)),
                        None => Err(e),
                    },
                }
            }
            Auth::Vault => self
                .vault_password(&account.name, purpose)?
                .map(Resolved::Password)
                .ok_or_else(|| SecretError::NotInVault(account.name.clone())),
            Auth::Oauth2 { provider, client_id, client_secret } => {
                let token = self
                    .access_token(account, *provider, client_id.as_deref(), client_secret.as_deref())
                    .await?;
                Ok(Resolved::OAuth { user: user.to_string(), access_token: token })
            }
        }
    }

    fn token_key(account: &str) -> String {
        format!("oauth:{account}")
    }

    fn password_key(account: &str, purpose: &str) -> String {
        format!("password:{account}:{purpose}")
    }

    pub fn vault_password(
        &self,
        account: &str,
        purpose: &str,
    ) -> Result<Option<SecretString>, SecretError> {
        let Some(raw) = self.store.meta(&Self::password_key(account, purpose))? else {
            return Ok(None);
        };
        if raw.is_empty() {
            return Ok(None);
        }
        Ok(String::from_utf8(raw).ok().map(SecretString::from))
    }

    pub fn set_vault_password(
        &self,
        account: &str,
        purpose: &str,
        password: &str,
    ) -> Result<(), SecretError> {
        self.store.set_meta(
            &Self::password_key(account, purpose),
            password.as_bytes(),
        )?;
        Ok(())
    }

    /// Prefers the OS keyring and falls back to the encrypted store, returning
    /// which one accepted it so the config can record the right `auth` value.
    pub fn store_password(
        &self,
        account: &str,
        purpose: &str,
        password: &str,
    ) -> Result<crate::config::Auth, SecretError> {
        let key = keyring_key(account, purpose);
        match keyring_set(&self.service, &key, password) {
            Ok(()) => Ok(crate::config::Auth::Keyring),
            Err(_) => {
                self.set_vault_password(account, purpose, password)?;
                Ok(crate::config::Auth::Vault)
            }
        }
    }

    /// Removes every credential an account can have: the keyring entry, the
    /// copy in the encrypted store and any OAuth2 tokens. Clearing only the
    /// keyring would leave a vault-stored password working.
    pub fn forget(&self, account: &str, purpose: &str) -> Result<(), SecretError> {
        let _ = keyring_delete(&self.service, &keyring_key(account, purpose));
        self.store
            .set_meta(&Self::password_key(account, purpose), b"")?;
        self.store.set_meta(&Self::token_key(account), b"")?;
        Ok(())
    }

    pub fn load_tokens(&self, account: &str) -> Result<Option<Tokens>, SecretError> {
        let Some(raw) = self.store.meta(&Self::token_key(account))? else {
            return Ok(None);
        };
        Ok(serde_json::from_slice(&raw).ok())
    }

    pub fn save_tokens(&self, account: &str, tokens: &Tokens) -> Result<(), SecretError> {
        let raw = serde_json::to_vec(tokens).unwrap_or_default();
        self.store.set_meta(&Self::token_key(account), &raw)?;
        Ok(())
    }

    /// Returns a live access token, refreshing it first when it is within a
    /// minute of expiry. Tokens live in the encrypted store rather than the OS
    /// keyring so that a refresh token is protected by the same master key as
    /// the mail it unlocks.
    pub async fn access_token(
        &self,
        account: &Account,
        provider: OauthProvider,
        client_id: Option<&str>,
        client_secret: Option<&str>,
    ) -> Result<SecretString, SecretError> {
        let tokens = self
            .load_tokens(&account.name)?
            .ok_or_else(|| SecretError::NoTokens(account.name.clone()))?;

        if !tokens.is_expired() {
            return Ok(SecretString::from(tokens.access_token));
        }

        let client_id = client_id
            .map(str::to_string)
            .or_else(|| default_client_id(provider).map(str::to_string))
            .ok_or_else(|| SecretError::NoClientId(account.name.clone()))?;
        let refresh_token = tokens
            .refresh_token
            .ok_or_else(|| SecretError::NoTokens(account.name.clone()))?;

        let fresh = oauth::refresh(provider, &client_id, client_secret, &refresh_token).await?;
        self.save_tokens(&account.name, &fresh)?;
        Ok(SecretString::from(fresh.access_token))
    }
}

/// Google and Microsoft both publish client ids for installed applications;
/// these are the ones Thunderbird ships, which most providers already trust.
pub fn default_client_id(provider: OauthProvider) -> Option<&'static str> {
    match provider {
        OauthProvider::Gmail => {
            Some("406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com")
        }
        OauthProvider::Outlook => Some("9e5f94bc-e8a4-4e73-b8be-63364c29d753"),
        OauthProvider::Yahoo | OauthProvider::Custom => None,
    }
}

/// Obtains the passphrase that unwraps the vault master key, by whichever route
/// the config selects.
pub async fn vault_passphrase(cfg: &Config, confirm: bool) -> Result<SecretString, SecretError> {
    match cfg.general.unlock {
        Unlock::Keyring => {
            let key = keyring_key("_vault", "passphrase");
            keyring_get(&cfg.general.keyring_service, &key)
        }
        Unlock::Command => {
            let cmd = cfg
                .general
                .unlock_command
                .as_deref()
                .expect("validated at config load");
            run_password_command(cmd).await
        }
        Unlock::Prompt => prompt_passphrase(confirm),
    }
}

pub fn prompt_passphrase(confirm: bool) -> Result<SecretString, SecretError> {
    let first = read_hidden("Vault passphrase: ")?;
    if confirm {
        let again = read_hidden("Confirm passphrase: ")?;
        if first.expose_secret() != again.expose_secret() {
            return Err(SecretError::Tty(std::io::Error::other(
                "the two passphrases did not match",
            )));
        }
    }
    Ok(first)
}

/// Reads a passphrase without echoing it. Uses crossterm's raw mode rather
/// than hand-rolled termios FFI, since the TUI already depends on it.
fn read_hidden(prompt: &str) -> Result<SecretString, SecretError> {
    use std::io::{IsTerminal, Write};

    use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    if !std::io::stdin().is_terminal() {
        return Err(SecretError::NoTty);
    }

    let mut out = std::io::stderr();
    let _ = write!(out, "{prompt}");
    let _ = out.flush();

    enable_raw_mode().map_err(SecretError::Tty)?;
    let result = (|| -> Result<String, SecretError> {
        let mut buf = String::new();
        loop {
            let Event::Key(k) = event::read().map_err(SecretError::Tty)? else {
                continue;
            };
            if k.kind != KeyEventKind::Press {
                continue;
            }
            match k.code {
                KeyCode::Enter => return Ok(buf),
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Esc => {
                    return Err(SecretError::Tty(std::io::Error::other("cancelled")));
                }
                KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Err(SecretError::Tty(std::io::Error::other("cancelled")));
                }
                KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => buf.clear(),
                KeyCode::Char(c) => buf.push(c),
                _ => {}
            }
        }
    })();
    disable_raw_mode().map_err(SecretError::Tty)?;
    let _ = writeln!(out);

    Ok(SecretString::from(result?))
}
