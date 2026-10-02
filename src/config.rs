use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no config file found; looked in {0}")]
    Missing(PathBuf),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("could not determine your home directory")]
    NoHome,
    #[error("account `{0}` is not defined in the config")]
    UnknownAccount(String),
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: General,
    pub ui: Ui,
    #[serde(rename = "account")]
    pub accounts: Vec<Account>,
    #[serde(rename = "rule", default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub bindings: BTreeMap<String, String>,
    #[serde(skip)]
    pub source: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct General {
    pub data_dir: Option<PathBuf>,
    pub encrypt_at_rest: bool,
    pub unlock: Unlock,
    pub unlock_command: Option<String>,
    pub keyring_service: String,
    pub poll_interval_secs: u64,
    pub idle: bool,
    pub notify: bool,
    pub editor: Option<String>,
    pub default_account: Option<String>,
    pub body_cache_days: u32,
    pub download_full_bodies: bool,
    pub max_attachment_mb: u64,
    pub log_level: String,
}

impl Default for General {
    fn default() -> Self {
        Self {
            data_dir: None,
            encrypt_at_rest: true,
            unlock: Unlock::Prompt,
            unlock_command: None,
            keyring_service: "pigeon".into(),
            poll_interval_secs: 300,
            idle: true,
            notify: true,
            editor: None,
            default_account: None,
            body_cache_days: 90,
            download_full_bodies: true,
            max_attachment_mb: 25,
            log_level: "info".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Unlock {
    Prompt,
    Keyring,
    Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ui {
    pub theme: String,
    pub layout: Layout,
    pub preview: bool,
    pub threading: bool,
    pub mouse: bool,
    pub sidebar_width: u16,
    pub list_height_pct: u16,
    pub date_format: String,
    pub relative_dates: bool,
    pub show_avatars: bool,
    pub wrap_width: u16,
    pub mark_read_delay_ms: u64,
    pub confirm_quit: bool,
    pub vim_keys: bool,
}

impl Default for Ui {
    fn default() -> Self {
        Self {
            theme: "default-dark".into(),
            layout: Layout::ThreePane,
            preview: true,
            threading: true,
            mouse: true,
            sidebar_width: 28,
            list_height_pct: 45,
            date_format: "%Y-%m-%d %H:%M".into(),
            relative_dates: true,
            show_avatars: false,
            wrap_width: 100,
            mark_read_delay_ms: 1200,
            confirm_quit: false,
            vim_keys: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Layout {
    ThreePane,
    TwoPane,
    ListOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    pub name: String,
    pub address: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signature_file: Option<PathBuf>,
    pub imap: ImapConfig,
    pub smtp: SmtpConfig,
    #[serde(default)]
    pub pgp: PgpConfig,
    #[serde(default)]
    pub folders: FolderMap,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapConfig {
    pub host: String,
    #[serde(default = "default_imap_port")]
    pub port: u16,
    #[serde(default)]
    pub security: Security,
    pub user: String,
    #[serde(flatten)]
    pub auth: Auth,
    #[serde(default)]
    pub accept_invalid_certs: bool,
    #[serde(default = "yes")]
    pub use_condstore: bool,
    #[serde(default = "yes")]
    pub use_compress: bool,
}

fn default_imap_port() -> u16 {
    993
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default)]
    pub security: Security,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(flatten)]
    pub auth: Auth,
    #[serde(default)]
    pub accept_invalid_certs: bool,
}

fn default_smtp_port() -> u16 {
    465
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Security {
    #[default]
    Tls,
    Starttls,
    None,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "auth", rename_all = "kebab-case")]
pub enum Auth {
    #[default]
    Keyring,
    Password {
        password: String,
    },
    PasswordCommand {
        password_command: String,
    },
    Vault,
    Oauth2 {
        provider: OauthProvider,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        client_secret: Option<String>,
    },
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OauthProvider {
    Gmail,
    Outlook,
    Yahoo,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PgpConfig {
    pub enabled: bool,
    pub key_id: Option<String>,
    pub secret_key_file: Option<PathBuf>,
    pub public_keyring: Option<PathBuf>,
    pub sign_by_default: bool,
    pub encrypt_policy: EncryptPolicy,
    pub autocrypt: bool,
    pub attach_public_key: bool,
}

impl Default for PgpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_id: None,
            secret_key_file: None,
            public_keyring: None,
            sign_by_default: false,
            encrypt_policy: EncryptPolicy::IfPossible,
            autocrypt: true,
            attach_public_key: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptPolicy {
    Never,
    IfPossible,
    Always,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FolderMap {
    pub inbox: String,
    pub sent: Option<String>,
    pub drafts: Option<String>,
    pub trash: Option<String>,
    pub archive: Option<String>,
    pub spam: Option<String>,
    pub subscribed_only: bool,
    pub exclude: Vec<String>,
}

impl Default for FolderMap {
    fn default() -> Self {
        Self {
            inbox: "INBOX".into(),
            sent: None,
            drafts: None,
            trash: None,
            archive: None,
            spam: None,
            subscribed_only: false,
            exclude: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub account: Option<String>,
    pub when: String,
    #[serde(default)]
    pub move_to: Option<String>,
    #[serde(default)]
    pub add_flags: Vec<String>,
    #[serde(default)]
    pub remove_flags: Vec<String>,
    #[serde(default)]
    pub tag: Vec<String>,
    #[serde(default)]
    pub notify: Option<bool>,
    #[serde(default)]
    pub stop: bool,
}

impl Config {
    pub fn default_path() -> Result<PathBuf, ConfigError> {
        let dirs = directories::ProjectDirs::from("", "", "pigeon").ok_or(ConfigError::NoHome)?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    pub fn default_data_dir() -> Result<PathBuf, ConfigError> {
        let dirs = directories::ProjectDirs::from("", "", "pigeon").ok_or(ConfigError::NoHome)?;
        Ok(dirs.data_dir().to_path_buf())
    }

    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let path = match path {
            Some(p) => p.to_path_buf(),
            None => Self::default_path()?,
        };
        if !path.exists() {
            return Err(ConfigError::Missing(path));
        }
        let raw = std::fs::read_to_string(&path).map_err(|source| ConfigError::Io {
            path: path.clone(),
            source,
        })?;
        let mut cfg: Config = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source,
        })?;
        cfg.source = Some(path);
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.accounts.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one [[account]] must be configured".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for a in &self.accounts {
            if !seen.insert(&a.name) {
                return Err(ConfigError::Invalid(format!(
                    "duplicate account name `{}`",
                    a.name
                )));
            }
            if !a.address.contains('@') {
                return Err(ConfigError::Invalid(format!(
                    "account `{}` has an invalid address `{}`",
                    a.name, a.address
                )));
            }
        }
        if let Some(d) = &self.general.default_account
            && !self.accounts.iter().any(|a| &a.name == d)
        {
            return Err(ConfigError::UnknownAccount(d.clone()));
        }
        if self.general.unlock == Unlock::Command && self.general.unlock_command.is_none() {
            return Err(ConfigError::Invalid(
                "general.unlock = \"command\" requires general.unlock_command".into(),
            ));
        }
        Ok(())
    }

    pub fn data_dir(&self) -> Result<PathBuf, ConfigError> {
        match &self.general.data_dir {
            Some(p) => Ok(expand(p)),
            None => Self::default_data_dir(),
        }
    }

    pub fn account(&self, name: &str) -> Option<&Account> {
        self.accounts.iter().find(|a| a.name == name)
    }

    pub fn primary_account(&self) -> Option<&Account> {
        self.general
            .default_account
            .as_deref()
            .and_then(|n| self.account(n))
            .or_else(|| self.accounts.iter().find(|a| a.enabled))
    }

    pub fn write_template(path: &Path) -> Result<(), ConfigError> {
        let io = |source: std::io::Error| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        };
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(io)?;
        }
        std::fs::write(path, TEMPLATE).map_err(io)
    }
}

impl Account {
    pub fn from_line(&self) -> String {
        match &self.display_name {
            Some(n) => format!("{n} <{}>", self.address),
            None => self.address.clone(),
        }
    }

    pub fn owns_address(&self, addr: &str) -> bool {
        let addr = addr.to_ascii_lowercase();
        self.address.eq_ignore_ascii_case(&addr)
            || self.aliases.iter().any(|a| a.eq_ignore_ascii_case(&addr))
    }

    pub fn signature_text(&self) -> Option<String> {
        if let Some(s) = &self.signature {
            return Some(s.clone());
        }
        let f = self.signature_file.as_ref()?;
        std::fs::read_to_string(expand(f)).ok()
    }
}

/// Emits a config file as text rather than through `toml::to_string`, because
/// a serialised `Auth` (an internally tagged enum behind `#[serde(flatten)]`)
/// round-trips poorly, and because a generated file people are expected to edit
/// by hand should keep its comments and ordering.
pub fn render(general: &General, ui: &Ui, accounts: &[Account]) -> String {
    let mut out = String::from("# pigeon configuration\n# Written by the setup wizard; edit freely.\n\n");

    out.push_str("[general]\n");
    if let Some(d) = &general.data_dir {
        out.push_str(&format!("data_dir = {}\n", quote(&d.to_string_lossy())));
    }
    out.push_str(&format!("encrypt_at_rest = {}\n", general.encrypt_at_rest));
    out.push_str(&format!("unlock = \"{}\"\n", unlock_name(general.unlock)));
    if let Some(c) = &general.unlock_command {
        out.push_str(&format!("unlock_command = {}\n", quote(c)));
    }
    out.push_str(&format!("keyring_service = {}\n", quote(&general.keyring_service)));
    out.push_str(&format!("poll_interval_secs = {}\n", general.poll_interval_secs));
    out.push_str(&format!("idle = {}\n", general.idle));
    out.push_str(&format!("notify = {}\n", general.notify));
    if let Some(e) = &general.editor {
        out.push_str(&format!("editor = {}\n", quote(e)));
    }
    if let Some(d) = &general.default_account {
        out.push_str(&format!("default_account = {}\n", quote(d)));
    }
    out.push_str(&format!("body_cache_days = {}\n", general.body_cache_days));
    out.push_str(&format!("download_full_bodies = {}\n", general.download_full_bodies));
    out.push_str(&format!("max_attachment_mb = {}\n", general.max_attachment_mb));
    out.push_str(&format!("log_level = {}\n", quote(&general.log_level)));

    out.push_str(&format!("\n[ui]\ntheme = {}\n", quote(&ui.theme)));
    out.push_str(&format!("layout = \"{}\"\n", layout_name(ui.layout)));
    out.push_str(&format!("preview = {}\n", ui.preview));
    out.push_str(&format!("threading = {}\n", ui.threading));
    out.push_str(&format!("mouse = {}\n", ui.mouse));
    out.push_str(&format!("sidebar_width = {}\n", ui.sidebar_width));
    out.push_str(&format!("list_height_pct = {}\n", ui.list_height_pct));
    out.push_str(&format!("date_format = {}\n", quote(&ui.date_format)));
    out.push_str(&format!("relative_dates = {}\n", ui.relative_dates));
    out.push_str(&format!("show_avatars = {}\n", ui.show_avatars));
    out.push_str(&format!("wrap_width = {}\n", ui.wrap_width));
    out.push_str(&format!("mark_read_delay_ms = {}\n", ui.mark_read_delay_ms));
    out.push_str(&format!("confirm_quit = {}\n", ui.confirm_quit));
    out.push_str(&format!("vim_keys = {}\n", ui.vim_keys));

    for a in accounts {
        out.push_str(&format!("\n[[account]]\nname = {}\n", quote(&a.name)));
        out.push_str(&format!("address = {}\n", quote(&a.address)));
        if let Some(n) = &a.display_name {
            out.push_str(&format!("display_name = {}\n", quote(n)));
        }
        if !a.aliases.is_empty() {
            let list: Vec<String> = a.aliases.iter().map(|x| quote(x)).collect();
            out.push_str(&format!("aliases = [{}]\n", list.join(", ")));
        }
        if let Some(sig) = &a.signature {
            out.push_str(&format!("signature = {}\n", quote(sig)));
        }
        if let Some(f) = &a.signature_file {
            out.push_str(&format!("signature_file = {}\n", quote(&f.to_string_lossy())));
        }
        if !a.enabled {
            out.push_str("enabled = false\n");
        }

        out.push_str(&format!("\n[account.imap]\nhost = {}\n", quote(&a.imap.host)));
        out.push_str(&format!("port = {}\n", a.imap.port));
        out.push_str(&format!("security = \"{}\"\n", security_name(a.imap.security)));
        out.push_str(&format!("user = {}\n", quote(&a.imap.user)));
        out.push_str(&render_auth(&a.imap.auth));
        if a.imap.accept_invalid_certs {
            out.push_str("accept_invalid_certs = true\n");
        }
        if !a.imap.use_condstore {
            out.push_str("use_condstore = false\n");
        }
        if !a.imap.use_compress {
            out.push_str("use_compress = false\n");
        }

        out.push_str(&format!("\n[account.smtp]\nhost = {}\n", quote(&a.smtp.host)));
        out.push_str(&format!("port = {}\n", a.smtp.port));
        out.push_str(&format!("security = \"{}\"\n", security_name(a.smtp.security)));
        if let Some(u) = &a.smtp.user {
            out.push_str(&format!("user = {}\n", quote(u)));
        }
        out.push_str(&render_auth(&a.smtp.auth));
        if a.smtp.accept_invalid_certs {
            out.push_str("accept_invalid_certs = true\n");
        }

        out.push_str("\n[account.folders]\n");
        out.push_str(&format!("inbox = {}\n", quote(&a.folders.inbox)));
        for (key, value) in [
            ("sent", &a.folders.sent),
            ("drafts", &a.folders.drafts),
            ("trash", &a.folders.trash),
            ("archive", &a.folders.archive),
            ("spam", &a.folders.spam),
        ] {
            if let Some(v) = value {
                out.push_str(&format!("{key} = {}\n", quote(v)));
            }
        }
        if a.folders.subscribed_only {
            out.push_str("subscribed_only = true\n");
        }
        if !a.folders.exclude.is_empty() {
            let list: Vec<String> = a.folders.exclude.iter().map(|x| quote(x)).collect();
            out.push_str(&format!("exclude = [{}]\n", list.join(", ")));
        }

        if a.pgp.enabled {
            out.push_str("\n[account.pgp]\nenabled = true\n");
            if let Some(k) = &a.pgp.key_id {
                out.push_str(&format!("key_id = {}\n", quote(k)));
            }
            out.push_str(&format!("autocrypt = {}\n", a.pgp.autocrypt));
            out.push_str(&format!("attach_public_key = {}\n", a.pgp.attach_public_key));
            out.push_str(&format!("sign_by_default = {}\n", a.pgp.sign_by_default));
            out.push_str(&format!(
                "encrypt_policy = \"{}\"\n",
                match a.pgp.encrypt_policy {
                    EncryptPolicy::Never => "never",
                    EncryptPolicy::IfPossible => "if-possible",
                    EncryptPolicy::Always => "always",
                }
            ));
            if let Some(p) = &a.pgp.secret_key_file {
                out.push_str(&format!("secret_key_file = {}\n", quote(&p.to_string_lossy())));
            }
            if let Some(p) = &a.pgp.public_keyring {
                out.push_str(&format!("public_keyring = {}\n", quote(&p.to_string_lossy())));
            }
        }
    }

    out
}

/// The whole config, not just the parts the setup wizard writes. Anything that
/// rewrites an existing file must go through this, because a rewrite that drops
/// `[[rule]]` or `[bindings]` would silently delete the user's work.
pub fn render_config(config: &Config) -> String {
    let mut out = render(&config.general, &config.ui, &config.accounts);

    for r in &config.rules {
        out.push_str(&format!("\n[[rule]]\nname = {}\n", quote(&r.name)));
        if let Some(a) = &r.account {
            out.push_str(&format!("account = {}\n", quote(a)));
        }
        out.push_str(&format!("when = {}\n", quote(&r.when)));
        if let Some(m) = &r.move_to {
            out.push_str(&format!("move_to = {}\n", quote(m)));
        }
        for (key, list) in [
            ("add_flags", &r.add_flags),
            ("remove_flags", &r.remove_flags),
            ("tag", &r.tag),
        ] {
            if !list.is_empty() {
                let items: Vec<String> = list.iter().map(|x| quote(x)).collect();
                out.push_str(&format!("{key} = [{}]\n", items.join(", ")));
            }
        }
        if let Some(n) = r.notify {
            out.push_str(&format!("notify = {n}\n"));
        }
        if r.stop {
            out.push_str("stop = true\n");
        }
    }

    if !config.bindings.is_empty() {
        out.push_str("\n[bindings]\n");
        for (key, action) in &config.bindings {
            out.push_str(&format!("{} = {}\n", quote(key), quote(action)));
        }
    }

    out
}

fn render_auth(auth: &Auth) -> String {
    match auth {
        Auth::Keyring => "auth = \"keyring\"\n".into(),
        Auth::Vault => "auth = \"vault\"\n".into(),
        Auth::None => "auth = \"none\"\n".into(),
        Auth::Password { password } => {
            format!("auth = \"password\"\npassword = {}\n", quote(password))
        }
        Auth::PasswordCommand { password_command } => format!(
            "auth = \"password-command\"\npassword_command = {}\n",
            quote(password_command)
        ),
        Auth::Oauth2 { provider, client_id, client_secret } => {
            let mut s = format!(
                "auth = \"oauth2\"\nprovider = \"{}\"\n",
                match provider {
                    OauthProvider::Gmail => "gmail",
                    OauthProvider::Outlook => "outlook",
                    OauthProvider::Yahoo => "yahoo",
                    OauthProvider::Custom => "custom",
                }
            );
            if let Some(c) = client_id {
                s.push_str(&format!("client_id = {}\n", quote(c)));
            }
            if let Some(c) = client_secret {
                s.push_str(&format!("client_secret = {}\n", quote(c)));
            }
            s
        }
    }
}

fn unlock_name(u: Unlock) -> &'static str {
    match u {
        Unlock::Prompt => "prompt",
        Unlock::Keyring => "keyring",
        Unlock::Command => "command",
    }
}

fn layout_name(l: Layout) -> &'static str {
    match l {
        Layout::ThreePane => "three-pane",
        Layout::TwoPane => "two-pane",
        Layout::ListOnly => "list-only",
    }
}

fn security_name(s: Security) -> &'static str {
    match s {
        Security::Tls => "tls",
        Security::Starttls => "starttls",
        Security::None => "none",
    }
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn expand(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    PathBuf::from(shellexpand::tilde(&s).into_owned())
}

pub const TEMPLATE: &str = r#"# pigeon configuration

[general]
encrypt_at_rest = true
unlock = "prompt"          # prompt | keyring | command
poll_interval_secs = 300
idle = true
notify = true
default_account = "personal"

[ui]
theme = "default-dark"
layout = "three-pane"      # three-pane | two-pane | list-only
threading = true
relative_dates = true
vim_keys = true

[[account]]
name = "personal"
address = "you@example.org"
display_name = "Your Name"

[account.imap]
host = "imap.example.org"
port = 993
security = "tls"           # tls | starttls | none
user = "you@example.org"
auth = "keyring"           # keyring | password | password-command | oauth2 | none

[account.smtp]
host = "smtp.example.org"
port = 465
security = "tls"
auth = "keyring"

[account.folders]
inbox = "INBOX"
sent = "Sent"
drafts = "Drafts"
trash = "Trash"
archive = "Archive"

[account.pgp]
enabled = false
sign_by_default = false
encrypt_policy = "if-possible"

# [[rule]]
# name = "CI noise"
# when = 'from:ci@example.org'
# move_to = "CI"
# add_flags = ["\\Seen"]
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// `pigeon init` writes TEMPLATE, so a template that does not parse would
    /// leave a new user with a config the program refuses to load.
    #[test]
    fn shipped_template_parses() {
        let cfg: Config = toml::from_str(TEMPLATE).expect("template must parse");
        cfg.validate().expect("template must validate");
        assert_eq!(cfg.accounts.len(), 1);
        assert_eq!(cfg.accounts[0].name, "personal");
        assert!(matches!(cfg.accounts[0].imap.auth, Auth::Keyring));
        assert_eq!(cfg.accounts[0].imap.port, 993);
    }

    #[test]
    fn parses_every_auth_variant() {
        let base = |auth: &str| {
            let mut out = String::from("[[account]]\nname = \"a\"\naddress = \"a@example.org\"\n");
            out.push_str("[account.imap]\nhost = \"h\"\nuser = \"u\"\n");
            out.push_str(auth);
            out.push_str("\n[account.smtp]\nhost = \"h\"\n");
            out.push_str(auth);
            out.push('\n');
            out
        };

        let cases = [
            r#"auth = "keyring""#,
            r#"auth = "none""#,
            "auth = \"password\"\npassword = \"s\"",
            "auth = \"password-command\"\npassword_command = \"pass show x\"",
            "auth = \"oauth2\"\nprovider = \"gmail\"",
        ];

        for case in cases {
            let doc = base(case);
            let cfg: Config = toml::from_str(&doc)
                .unwrap_or_else(|e| panic!("this should parse:\n{doc}\n{e}"));
            assert_eq!(cfg.accounts.len(), 1);
        }
    }

    #[test]
    fn rejects_an_account_without_an_at_sign() {
        let cfg: Config = toml::from_str(
            r#"
[[account]]
name = "a"
address = "not-an-address"
[account.imap]
host = "h"
user = "u"
auth = "none"
[account.smtp]
host = "h"
auth = "none"
"#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rewriting_a_config_keeps_rules_and_bindings() {
        let original: Config = toml::from_str(
            r#"
[general]
poll_interval_secs = 42
max_attachment_mb = 7

[ui]
sidebar_width = 33
date_format = "%H:%M"

[[account]]
name = "work"
address = "me@example.org"
signature = "sent from pigeon"
[account.imap]
host = "imap.example.org"
user = "me@example.org"
auth = "vault"
accept_invalid_certs = true
[account.smtp]
host = "smtp.example.org"
auth = "vault"
[account.folders]
inbox = "INBOX"
exclude = ["Junk"]

[[rule]]
name = "lists"
when = "list:rust-dev"
move_to = "Lists"
tag = ["rust"]
stop = true

[bindings]
"g i" = "goto-inbox"
"#,
        )
        .unwrap();

        let rewritten: Config = toml::from_str(&render_config(&original)).expect("must re-parse");

        assert_eq!(rewritten.general.poll_interval_secs, 42);
        assert_eq!(rewritten.general.max_attachment_mb, 7);
        assert_eq!(rewritten.ui.sidebar_width, 33);
        assert_eq!(rewritten.ui.date_format, "%H:%M");
        assert_eq!(rewritten.rules.len(), 1);
        assert_eq!(rewritten.rules[0].move_to.as_deref(), Some("Lists"));
        assert!(rewritten.rules[0].stop);
        assert_eq!(rewritten.bindings.get("g i").map(String::as_str), Some("goto-inbox"));
        assert_eq!(rewritten.accounts[0].signature.as_deref(), Some("sent from pigeon"));
        assert!(rewritten.accounts[0].imap.accept_invalid_certs);
        assert_eq!(rewritten.accounts[0].folders.exclude, vec!["Junk".to_string()]);
    }
}
