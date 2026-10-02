use std::path::PathBuf;
use std::sync::Arc;

use ratatui::DefaultTerminal;
use ratatui::crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};

use crate::config::{
    Account, Auth, Config, FolderMap, General, ImapConfig, OauthProvider, PgpConfig, Security,
    SmtpConfig, Ui,
};
use crate::crypto::{MasterKey, Vault};
use crate::net::autoconfig::{self, Autoconfig};
use crate::net::imap::{Credentials as ImapCreds, ImapSession};
use crate::net::smtp::{Credentials as SmtpCreds, SmtpClient};
use crate::secrets::SecretProvider;
use crate::store::Store;

use super::field::{Field, FieldKind};
use super::theme::Theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Welcome,
    Passphrase,
    Account,
    Servers,
    Testing,
    Finished,
}

#[derive(Debug)]
pub struct Bootstrap {
    pub config: Config,
    pub master: MasterKey,
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum WizardError {
    #[error("setup was cancelled")]
    Cancelled,
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Vault(#[from] crate::crypto::VaultError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
}

#[derive(Debug, Clone, PartialEq)]
enum TestState {
    Idle,
    Running(&'static str),
    Report { imap: Result<String, String>, smtp: Result<String, String> },
}

pub struct Wizard {
    theme: Theme,
    step: Step,
    focus: usize,
    notice: Option<(String, bool)>,

    vault_exists: bool,
    pass: Field,
    pass_confirm: Field,

    account: Vec<Field>,
    servers: Vec<Field>,

    detected: Option<Autoconfig>,
    test: TestState,

    config_path: PathBuf,
    data_dir: PathBuf,
    master: Option<MasterKey>,
    existing: Option<Config>,
}

const ACCOUNT_EMAIL: usize = 0;
const ACCOUNT_NAME: usize = 1;
const ACCOUNT_LABEL: usize = 2;
const ACCOUNT_PASSWORD: usize = 3;

const SRV_IMAP_HOST: usize = 0;
const SRV_IMAP_PORT: usize = 1;
const SRV_IMAP_SEC: usize = 2;
const SRV_IMAP_USER: usize = 3;
const SRV_SMTP_HOST: usize = 4;
const SRV_SMTP_PORT: usize = 5;
const SRV_SMTP_SEC: usize = 6;
const SRV_SMTP_USER: usize = 7;
const SRV_OAUTH: usize = 8;

impl Wizard {
    pub fn new(
        config_path: PathBuf,
        data_dir: PathBuf,
        existing: Option<Config>,
        vault_exists: bool,
        theme: Theme,
    ) -> Self {
        Self {
            theme,
            step: if existing.is_some() && vault_exists { Step::Passphrase } else { Step::Welcome },
            focus: 0,
            notice: None,
            vault_exists,
            pass: Field::secret("Passphrase", "Unlocks the encrypted local store"),
            pass_confirm: Field::secret("Confirm", "Type it a second time"),
            account: vec![
                Field::text("Email", "The address you send and receive as", ""),
                Field::text("Your name", "Shown to the people you write to", ""),
                Field::text("Label", "Short name for this account inside pigeon", ""),
                Field::secret("Password", "Stored in your OS keyring, or the encrypted vault"),
            ],
            servers: vec![
                Field::text("IMAP host", "Incoming mail server", ""),
                Field::number("IMAP port", "993 for TLS, 143 for STARTTLS", 993),
                Field::choice("IMAP security", "Transport encryption", &["tls", "starttls", "none"], "tls"),
                Field::text("IMAP user", "Usually your full email address", ""),
                Field::text("SMTP host", "Outgoing mail server", ""),
                Field::number("SMTP port", "465 for TLS, 587 for STARTTLS", 465),
                Field::choice("SMTP security", "Transport encryption", &["tls", "starttls", "none"], "tls"),
                Field::text("SMTP user", "Leave blank to reuse the IMAP user", ""),
                Field::toggle("Use OAuth2", "Required by Gmail and Outlook", false),
            ],
            detected: None,
            test: TestState::Idle,
            config_path,
            data_dir,
            master: None,
            existing,
        }
    }

    fn fields_mut(&mut self) -> &mut Vec<Field> {
        match self.step {
            Step::Servers => &mut self.servers,
            _ => &mut self.account,
        }
    }

    fn fields(&self) -> &Vec<Field> {
        match self.step {
            Step::Servers => &self.servers,
            _ => &self.account,
        }
    }

    fn say(&mut self, msg: impl Into<String>) {
        self.notice = Some((msg.into(), false));
    }

    fn complain(&mut self, msg: impl Into<String>) {
        self.notice = Some((msg.into(), true));
    }
}

/// Runs first-run setup inside the terminal the reader will use, so a new user
/// never has to leave the TUI to get a working account.
pub async fn run(
    terminal: &mut DefaultTerminal,
    config_path: PathBuf,
    data_dir: PathBuf,
    existing: Option<Config>,
    theme: Theme,
) -> Result<Bootstrap, WizardError> {
    let vault_path = data_dir.join("vault.key");
    let mut w = Wizard::new(
        config_path,
        data_dir,
        existing,
        Vault::exists(&vault_path),
        theme,
    );

    let keys = super::run::spawn_input_reader();
    let mut keys = keys;

    loop {
        terminal.draw(|f| draw(f, &w))?;

        let Some(ev) = keys.recv().await else {
            return Err(WizardError::Cancelled);
        };
        let Event::Key(k) = ev else { continue };
        if k.kind != KeyEventKind::Press {
            continue;
        }

        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            return Err(WizardError::Cancelled);
        }

        match w.step {
            Step::Welcome => match k.code {
                KeyCode::Enter => w.step = Step::Passphrase,
                KeyCode::Esc => return Err(WizardError::Cancelled),
                _ => {}
            },
            Step::Passphrase => handle_passphrase(&mut w, k)?,
            Step::Account | Step::Servers => handle_form(&mut w, k).await,
            Step::Testing => match k.code {
                KeyCode::Esc => {
                    w.step = Step::Servers;
                    w.test = TestState::Idle;
                    w.notice = None;
                }
                // Saving over a failed check is allowed on purpose: a server
                // that is merely unreachable right now should not block setup.
                KeyCode::Enter if !matches!(w.test, TestState::Running(_)) => {
                    w.step = Step::Finished;
                    w.notice = None;
                }
                _ => {}
            },
            Step::Finished => {
                if k.code == KeyCode::Enter {
                    break;
                }
            }
        }

        if w.step == Step::Testing && w.test == TestState::Idle {
            run_tests(&mut w, terminal).await;
        }
    }

    finish(w)
}

fn handle_passphrase(w: &mut Wizard, k: KeyEvent) -> Result<(), WizardError> {
    let confirming = !w.vault_exists;

    match k.code {
        KeyCode::Esc => return Err(WizardError::Cancelled),
        KeyCode::Tab | KeyCode::Down if confirming => w.focus = 1 - w.focus,
        KeyCode::BackTab | KeyCode::Up if confirming => w.focus = 1 - w.focus,
        KeyCode::Backspace => {
            if w.focus == 0 { w.pass.backspace() } else { w.pass_confirm.backspace() }
        }
        KeyCode::Char(c) => {
            if w.focus == 0 { w.pass.insert(c) } else { w.pass_confirm.insert(c) }
        }
        KeyCode::Enter => {
            if confirming && w.focus == 0 {
                w.focus = 1;
                return Ok(());
            }
            return unlock_or_create(w);
        }
        _ => {}
    }
    Ok(())
}

fn unlock_or_create(w: &mut Wizard) -> Result<(), WizardError> {
    let vault_path = w.data_dir.join("vault.key");
    let pass = w.pass.value.clone();

    if w.vault_exists {
        match Vault::unlock(&vault_path, pass.as_bytes()) {
            Ok(v) => {
                w.master = Some(v.key().clone());
                w.pass.clear();
                advance_past_passphrase(w);
            }
            Err(crate::crypto::VaultError::WrongPassphrase) => {
                w.pass.clear();
                w.complain("That passphrase does not unlock this vault. Try again.");
            }
            Err(e) => return Err(e.into()),
        }
        return Ok(());
    }

    if pass.chars().count() < 8 {
        w.complain("Use at least 8 characters — this key protects every message on disk.");
        return Ok(());
    }
    if pass != w.pass_confirm.value {
        w.pass_confirm.clear();
        w.focus = 1;
        w.complain("The two passphrases do not match.");
        return Ok(());
    }

    std::fs::create_dir_all(&w.data_dir)?;
    let vault = Vault::create(&vault_path, pass.as_bytes())?;
    w.master = Some(vault.key().clone());
    w.pass.clear();
    w.pass_confirm.clear();
    w.vault_exists = true;
    w.say("Vault created. Your mail will be encrypted on this machine.");
    advance_past_passphrase(w);
    Ok(())
}

fn advance_past_passphrase(w: &mut Wizard) {
    let has_account = w.existing.as_ref().is_some_and(|c| !c.accounts.is_empty());
    w.step = if has_account { Step::Finished } else { Step::Account };
    w.focus = 0;
}

async fn handle_form(w: &mut Wizard, k: KeyEvent) {
    let last = w.fields().len() - 1;

    match k.code {
        KeyCode::Esc => {
            if w.step == Step::Servers {
                w.step = Step::Account;
                w.focus = 0;
            }
        }
        KeyCode::Tab | KeyCode::Down => w.focus = (w.focus + 1).min(last),
        KeyCode::BackTab | KeyCode::Up => w.focus = w.focus.saturating_sub(1),
        KeyCode::Left => {
            let step = w.step;
            let focus = w.focus;
            let f = &mut w.fields_mut()[focus];
            if matches!(f.kind, FieldKind::Choice | FieldKind::Toggle) {
                f.cycle(false);
                if step == Step::Servers {
                    sync_port_with_security(w, focus);
                }
            } else {
                f.left();
            }
        }
        KeyCode::Right => {
            let step = w.step;
            let focus = w.focus;
            let f = &mut w.fields_mut()[focus];
            if matches!(f.kind, FieldKind::Choice | FieldKind::Toggle) {
                f.cycle(true);
                if step == Step::Servers {
                    sync_port_with_security(w, focus);
                }
            } else {
                f.right();
            }
        }
        KeyCode::Home => {
            let focus = w.focus;
            w.fields_mut()[focus].home();
        }
        KeyCode::End => {
            let focus = w.focus;
            w.fields_mut()[focus].end();
        }
        KeyCode::Backspace => {
            let focus = w.focus;
            w.fields_mut()[focus].backspace();
        }
        KeyCode::Delete => {
            let focus = w.focus;
            w.fields_mut()[focus].delete_forward();
        }
        KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => {
            let focus = w.focus;
            w.fields_mut()[focus].clear();
        }
        KeyCode::Char(c) => {
            let focus = w.focus;
            w.fields_mut()[focus].insert(c);
        }
        KeyCode::Enter => match w.step {
            Step::Account => {
                if w.focus < last {
                    w.focus += 1;
                } else {
                    finish_account_step(w).await;
                }
            }
            Step::Servers => {
                if w.focus < last {
                    w.focus += 1;
                } else if validate_servers(w) {
                    w.step = Step::Testing;
                    w.test = TestState::Idle;
                }
            }
            _ => {}
        },
        _ => {}
    }
}

/// Keeps the port in step with the chosen transport, since the pairing is fixed
/// and getting it wrong is the most common setup mistake.
fn sync_port_with_security(w: &mut Wizard, focus: usize) {
    let (sec_idx, port_idx, tls_port, starttls_port) = match focus {
        SRV_IMAP_SEC => (SRV_IMAP_SEC, SRV_IMAP_PORT, 993u16, 143u16),
        SRV_SMTP_SEC => (SRV_SMTP_SEC, SRV_SMTP_PORT, 465, 587),
        _ => return,
    };
    let security = w.servers[sec_idx].value.clone();
    let port = match security.as_str() {
        "tls" => tls_port,
        "starttls" => starttls_port,
        _ => if port_idx == SRV_IMAP_PORT { 143 } else { 25 },
    };
    w.servers[port_idx].set(port.to_string());
}

async fn finish_account_step(w: &mut Wizard) {
    let email = w.account[ACCOUNT_EMAIL].value.trim().to_string();
    if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        w.account[ACCOUNT_EMAIL].error = Some("needs to look like name@example.org".into());
        w.focus = ACCOUNT_EMAIL;
        w.complain("Enter a full email address.");
        return;
    }

    if w.account[ACCOUNT_LABEL].value.trim().is_empty() {
        let label = email.split('@').next().unwrap_or("mail").to_string();
        w.account[ACCOUNT_LABEL].set(label);
    }

    w.say("Looking up your provider…");
    let found = autoconfig::discover(&email).await;

    let local = email.split('@').next().unwrap_or(&email).to_string();
    let user = if found.username_is_local_part { local } else { email.clone() };

    w.servers[SRV_IMAP_HOST].set(found.imap.host.clone());
    w.servers[SRV_IMAP_PORT].set(found.imap.port.to_string());
    w.servers[SRV_IMAP_SEC].set(security_name(found.imap.security));
    w.servers[SRV_IMAP_USER].set(user.clone());
    w.servers[SRV_SMTP_HOST].set(found.smtp.host.clone());
    w.servers[SRV_SMTP_PORT].set(found.smtp.port.to_string());
    w.servers[SRV_SMTP_SEC].set(security_name(found.smtp.security));
    w.servers[SRV_SMTP_USER].set(user);
    w.servers[SRV_OAUTH].set(if found.oauth.is_some() { "yes" } else { "no" });

    let source = found.source.label();
    w.detected = Some(found);
    w.say(format!("Settings filled in from the {source}. Check them, then press Enter."));
    w.step = Step::Servers;
    w.focus = 0;
}

fn validate_servers(w: &mut Wizard) -> bool {
    if w.servers[SRV_IMAP_HOST].value.trim().is_empty() {
        w.focus = SRV_IMAP_HOST;
        w.complain("An IMAP host is required.");
        return false;
    }
    if w.servers[SRV_SMTP_HOST].value.trim().is_empty() {
        w.focus = SRV_SMTP_HOST;
        w.complain("An SMTP host is required.");
        return false;
    }
    true
}

async fn run_tests(w: &mut Wizard, terminal: &mut DefaultTerminal) {
    let account = build_account(w);
    let password = w.account[ACCOUNT_PASSWORD].value.clone();
    let oauth = w.servers[SRV_OAUTH].is_on();

    w.test = TestState::Running("Connecting to the IMAP server…");
    let _ = terminal.draw(|f| draw(f, w));

    let imap = if oauth {
        Err("skipped — finish OAuth2 sign-in after setup with `pigeon auth login`".to_string())
    } else {
        match ImapSession::connect(
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
                let caps = format!(
                    "{folders} folders, idle={} condstore={}",
                    s.caps.idle, s.caps.condstore
                );
                s.logout().await;
                Ok(caps)
            }
            Err(e) => Err(e.to_string()),
        }
    };

    w.test = TestState::Running("Connecting to the SMTP server…");
    let _ = terminal.draw(|f| draw(f, w));

    let smtp = if oauth {
        Err("skipped — OAuth2".to_string())
    } else {
        let user = account
            .smtp
            .user
            .clone()
            .unwrap_or_else(|| account.address.clone());
        let ehlo = account.address.rsplit('@').next().unwrap_or("localhost");
        match SmtpClient::connect(&account.smtp, ehlo).await {
            Ok(mut c) => {
                let auth = c
                    .authenticate(&SmtpCreds::Plain { user, password: password.clone() })
                    .await;
                let caps = c.caps.auth.join(" ");
                c.quit().await;
                match auth {
                    Ok(()) => Ok(format!("authenticated ({caps})")),
                    Err(e) => Err(e.to_string()),
                }
            }
            Err(e) => Err(e.to_string()),
        }
    };

    let ok = imap.is_ok() && smtp.is_ok();
    w.test = TestState::Report { imap, smtp };
    if ok {
        w.say("Both servers accepted the settings.");
    } else {
        w.complain("Press esc to go back and correct the settings, or Enter to save anyway.");
    }
    w.step = Step::Testing;
}

fn security_name(s: Security) -> &'static str {
    match s {
        Security::Tls => "tls",
        Security::Starttls => "starttls",
        Security::None => "none",
    }
}

fn parse_security(s: &str) -> Security {
    match s {
        "starttls" => Security::Starttls,
        "none" => Security::None,
        _ => Security::Tls,
    }
}

fn build_account(w: &Wizard) -> Account {
    let email = w.account[ACCOUNT_EMAIL].value.trim().to_string();
    let label = w.account[ACCOUNT_LABEL].value.trim().to_string();
    let display = w.account[ACCOUNT_NAME].value.trim().to_string();
    let oauth = w.servers[SRV_OAUTH].is_on();

    let provider = w
        .detected
        .as_ref()
        .and_then(|d| d.oauth)
        .unwrap_or(OauthProvider::Custom);

    let auth = if oauth {
        Auth::Oauth2 { provider, client_id: None, client_secret: None }
    } else {
        Auth::Keyring
    };

    let smtp_user = {
        let u = w.servers[SRV_SMTP_USER].value.trim();
        if u.is_empty() {
            w.servers[SRV_IMAP_USER].value.trim().to_string()
        } else {
            u.to_string()
        }
    };

    Account {
        name: if label.is_empty() { "mail".into() } else { label },
        address: email.clone(),
        display_name: (!display.is_empty()).then_some(display),
        aliases: Vec::new(),
        signature: None,
        signature_file: None,
        imap: ImapConfig {
            host: w.servers[SRV_IMAP_HOST].value.trim().to_string(),
            port: w.servers[SRV_IMAP_PORT].number_value(),
            security: parse_security(&w.servers[SRV_IMAP_SEC].value),
            user: w.servers[SRV_IMAP_USER].value.trim().to_string(),
            auth: auth.clone(),
            accept_invalid_certs: false,
            use_condstore: true,
            use_compress: true,
        },
        smtp: SmtpConfig {
            host: w.servers[SRV_SMTP_HOST].value.trim().to_string(),
            port: w.servers[SRV_SMTP_PORT].number_value(),
            security: parse_security(&w.servers[SRV_SMTP_SEC].value),
            user: Some(smtp_user),
            auth,
            accept_invalid_certs: false,
        },
        pgp: PgpConfig::default(),
        folders: FolderMap::default(),
        enabled: true,
    }
}

fn finish(w: Wizard) -> Result<Bootstrap, WizardError> {
    let master = w.master.clone().ok_or(WizardError::Cancelled)?;

    if let Some(existing) = w.existing.clone()
        && w.step == Step::Finished
        && !existing.accounts.is_empty()
    {
        return Ok(Bootstrap {
            config: existing,
            master,
            config_path: w.config_path,
            data_dir: w.data_dir,
        });
    }

    let mut account = build_account(&w);
    let password = w.account[ACCOUNT_PASSWORD].value.clone();

    // The store has to exist before the password can be filed in the vault,
    // and the vault is the fallback when no OS keyring answers.
    let store = Store::open(&w.data_dir.join("mail.redb"), &master)?;
    let general = General {
        default_account: Some(account.name.clone()),
        ..General::default()
    };
    let provider = SecretProvider::new(general.keyring_service.clone(), Arc::clone(&store));

    if !password.is_empty() && !matches!(account.imap.auth, Auth::Oauth2 { .. }) {
        let chosen = provider
            .store_password(&account.name, "imap", &password)
            .unwrap_or(Auth::Vault);
        let _ = provider.store_password(&account.name, "smtp", &password);
        account.imap.auth = chosen.clone();
        account.smtp.auth = chosen;
    }

    let ui = Ui::default();
    let accounts = vec![account];
    let text = crate::config::render(&general, &ui, &accounts);

    if let Some(dir) = w.config_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&w.config_path, &text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&w.config_path, std::fs::Permissions::from_mode(0o600));
    }

    let mut config: Config = toml::from_str(&text).map_err(|source| {
        crate::config::ConfigError::Parse { path: w.config_path.clone(), source }
    })?;
    config.source = Some(w.config_path.clone());
    config.validate()?;

    Ok(Bootstrap {
        config,
        master,
        config_path: w.config_path,
        data_dir: w.data_dir,
    })
}

// ---- rendering ----

fn draw(f: &mut ratatui::Frame, w: &Wizard) {
    let t = &w.theme;
    let area = f.area();
    f.render_widget(Clear, area);

    let box_area = centered(area, 72, 82);

    let title = match w.step {
        Step::Welcome => "Welcome",
        Step::Passphrase => if w.vault_exists { "Unlock" } else { "Protect your mail" },
        Step::Account => "Your account",
        Step::Servers => "Servers",
        Step::Testing => "Checking",
        Step::Finished => "Ready",
    };

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(t.border_focus))
        .title(Span::styled(
            format!(" pigeon setup · {title} "),
            Style::default().fg(t.accent).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(outer, box_area);

    let inner = Rect {
        x: box_area.x + 2,
        y: box_area.y + 1,
        width: box_area.width.saturating_sub(4),
        height: box_area.height.saturating_sub(2),
    };
    match w.step {
        Step::Welcome => draw_welcome(f, w, inner),
        Step::Passphrase => draw_passphrase(f, w, inner),
        Step::Account | Step::Servers => draw_form(f, w, inner),
        Step::Testing => draw_testing(f, w, inner),
        Step::Finished => draw_finished(f, w, inner),
    }
}

fn centered(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    let h = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v[1]);
    h[1]
}

fn footer(w: &Wizard, hint: &str) -> Vec<Line<'static>> {
    let t = &w.theme;
    let mut lines = vec![Line::from("")];
    if let Some((msg, bad)) = &w.notice {
        lines.push(Line::from(Span::styled(
            msg.clone(),
            Style::default().fg(if *bad { t.danger } else { t.success }),
        )));
    }
    lines.push(Line::from(Span::styled(
        hint.to_string(),
        Style::default().fg(t.dim),
    )));
    lines
}

fn draw_welcome(f: &mut ratatui::Frame, w: &Wizard, area: Rect) {
    let t = &w.theme;
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "pigeon keeps your mail encrypted on this machine.",
            Style::default().fg(t.fg).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Setup takes three short steps:",
            Style::default().fg(t.fg),
        )),
        Line::from(""),
        Line::from(Span::styled("  1.  Choose a passphrase for the local vault.", Style::default().fg(t.fg))),
        Line::from(Span::styled("  2.  Enter your email address and password.", Style::default().fg(t.fg))),
        Line::from(Span::styled("  3.  Confirm the server settings — pigeon fills these in for you.", Style::default().fg(t.fg))),
        Line::from(""),
        Line::from(Span::styled(
            "Nothing leaves this machine except the connection to your mail provider.",
            Style::default().fg(t.dim),
        )),
    ];
    lines.extend(footer(w, "enter  continue        esc  quit"));

    f.render_widget(Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }), area);
}

fn draw_passphrase(f: &mut ratatui::Frame, w: &Wizard, area: Rect) {
    let t = &w.theme;
    let creating = !w.vault_exists;

    let mut lines = vec![Line::from("")];
    if creating {
        lines.push(Line::from(Span::styled(
            "This passphrase encrypts every message, search index and attachment",
            Style::default().fg(t.fg),
        )));
        lines.push(Line::from(Span::styled(
            "pigeon stores. There is no way to recover it — write it down somewhere safe.",
            Style::default().fg(t.fg),
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "Enter your passphrase to unlock the local mail store.",
            Style::default().fg(t.fg),
        )));
    }
    lines.push(Line::from(""));

    let style = |focused: bool| {
        if focused {
            Style::default().fg(t.selection_fg).bg(t.selection_bg)
        } else {
            Style::default().fg(t.fg)
        }
    };
    let hint = Style::default().fg(t.dim);

    lines.push(w.pass.render(w.focus == 0, area.width as usize, style(w.focus == 0), hint));
    if creating {
        lines.push(
            w.pass_confirm
                .render(w.focus == 1, area.width as usize, style(w.focus == 1), hint),
        );
    }

    let hint_text = if creating {
        "enter  continue        tab  next field        C-c  quit"
    } else {
        "enter  unlock        C-c  quit"
    };
    lines.extend(footer(w, hint_text));

    f.render_widget(Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }), area);

    let row = if w.focus == 0 { 3 } else { 4 };
    let field = if w.focus == 0 { &w.pass } else { &w.pass_confirm };
    f.set_cursor_position((area.x + 14 + field.cursor_column(), area.y + row));
}

fn draw_form(f: &mut ratatui::Frame, w: &Wizard, area: Rect) {
    let t = &w.theme;
    let fields = w.fields();

    let intro = match w.step {
        Step::Account => "Who are you? pigeon works out the server settings from your address.",
        _ => "Check these before continuing. Left and right change the highlighted choice.",
    };

    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(intro.to_string(), Style::default().fg(t.dim))),
        Line::from(""),
    ];

    for (i, field) in fields.iter().enumerate() {
        let focused = i == w.focus;
        let style = if focused {
            Style::default().fg(t.selection_fg).bg(t.selection_bg)
        } else {
            Style::default().fg(t.fg)
        };
        lines.push(field.render(focused, area.width as usize, style, Style::default().fg(t.dim)));
        if let Some(err) = &field.error {
            lines.push(Line::from(Span::styled(
                format!("{:<14}{err}", ""),
                Style::default().fg(t.danger),
            )));
        }
        if w.step == Step::Servers && i == SRV_IMAP_USER {
            lines.push(Line::from(""));
        }
    }

    lines.push(Line::from(""));
    if let Some(field) = fields.get(w.focus) {
        lines.push(Line::from(Span::styled(
            field.help.to_string(),
            Style::default().fg(t.accent),
        )));
    }

    let hint = match w.step {
        Step::Account => "enter  next        tab/↑↓  move        C-c  quit",
        _ => "enter  test and continue        esc  back        ←→  change        C-c  quit",
    };
    lines.extend(footer(w, hint));

    f.render_widget(Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }), area);

    if let Some(field) = fields.get(w.focus)
        && !matches!(field.kind, FieldKind::Choice | FieldKind::Toggle)
    {
        let mut row = 3u16;
        for (i, fl) in fields.iter().enumerate() {
            if i == w.focus {
                break;
            }
            row += 1;
            if fl.error.is_some() {
                row += 1;
            }
            if w.step == Step::Servers && i == SRV_IMAP_USER {
                row += 1;
            }
        }
        f.set_cursor_position((area.x + 14 + field.cursor_column(), area.y + row));
    }
}

fn draw_testing(f: &mut ratatui::Frame, w: &Wizard, area: Rect) {
    let t = &w.theme;
    let mut lines = vec![Line::from("")];

    match &w.test {
        TestState::Idle => lines.push(Line::from(Span::styled(
            "Starting…",
            Style::default().fg(t.dim),
        ))),
        TestState::Running(what) => lines.push(Line::from(Span::styled(
            what.to_string(),
            Style::default().fg(t.accent),
        ))),
        TestState::Report { imap, smtp } => {
            for (label, result) in [("IMAP", imap), ("SMTP", smtp)] {
                let (mark, text, style) = match result {
                    Ok(detail) => ("✔", detail.clone(), Style::default().fg(t.success)),
                    Err(e) => ("✘", e.clone(), Style::default().fg(t.danger)),
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{mark} {label:<6}"), style),
                    Span::styled(text, Style::default().fg(t.fg)),
                ]));
                lines.push(Line::from(""));
            }
        }
    }

    lines.extend(footer(
        w,
        "enter  save and open my mail        esc  back to the server settings",
    ));
    f.render_widget(Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }), area);
}

fn draw_finished(f: &mut ratatui::Frame, w: &Wizard, area: Rect) {
    let t = &w.theme;
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "All set.",
            Style::default().fg(t.success).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "pigeon will start syncing as soon as the reader opens.",
            Style::default().fg(t.fg),
        )),
        Line::from(Span::styled(
            "Press ? at any time for the full list of keys.",
            Style::default().fg(t.dim),
        )),
    ];
    lines.extend(footer(w, "enter  open my mail"));
    f.render_widget(
        Paragraph::new(Text::from(lines))
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: false }),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wizard() -> Wizard {
        Wizard::new(
            PathBuf::from("/tmp/x/config.toml"),
            PathBuf::from("/tmp/x"),
            None,
            false,
            Theme::dark(),
        )
    }

    #[test]
    fn security_choice_drives_the_port() {
        let mut w = wizard();
        w.servers[SRV_IMAP_SEC].set("starttls");
        sync_port_with_security(&mut w, SRV_IMAP_SEC);
        assert_eq!(w.servers[SRV_IMAP_PORT].value, "143");

        w.servers[SRV_SMTP_SEC].set("starttls");
        sync_port_with_security(&mut w, SRV_SMTP_SEC);
        assert_eq!(w.servers[SRV_SMTP_PORT].value, "587");

        w.servers[SRV_SMTP_SEC].set("tls");
        sync_port_with_security(&mut w, SRV_SMTP_SEC);
        assert_eq!(w.servers[SRV_SMTP_PORT].value, "465");
    }

    #[test]
    fn smtp_user_defaults_to_the_imap_user() {
        let mut w = wizard();
        w.account[ACCOUNT_EMAIL].set("ada@example.org");
        w.account[ACCOUNT_LABEL].set("work");
        w.servers[SRV_IMAP_HOST].set("imap.example.org");
        w.servers[SRV_IMAP_USER].set("ada@example.org");
        w.servers[SRV_SMTP_HOST].set("smtp.example.org");
        w.servers[SRV_SMTP_USER].clear();

        let a = build_account(&w);
        assert_eq!(a.smtp.user.as_deref(), Some("ada@example.org"));
        assert_eq!(a.name, "work");
        assert!(matches!(a.imap.auth, Auth::Keyring));
    }

    #[test]
    fn oauth_toggle_selects_the_detected_provider() {
        let mut w = wizard();
        w.account[ACCOUNT_EMAIL].set("ada@gmail.com");
        w.detected = autoconfig::builtin("gmail.com");
        w.servers[SRV_OAUTH].set("yes");

        let a = build_account(&w);
        assert!(matches!(
            a.imap.auth,
            Auth::Oauth2 { provider: OauthProvider::Gmail, .. }
        ));
    }

    #[test]
    fn generated_config_round_trips() {
        let mut w = wizard();
        w.account[ACCOUNT_EMAIL].set("ada@example.org");
        w.account[ACCOUNT_NAME].set("Ada Lovelace");
        w.account[ACCOUNT_LABEL].set("personal");
        w.servers[SRV_IMAP_HOST].set("imap.example.org");
        w.servers[SRV_IMAP_USER].set("ada@example.org");
        w.servers[SRV_SMTP_HOST].set("smtp.example.org");
        w.servers[SRV_SMTP_SEC].set("starttls");
        w.servers[SRV_SMTP_PORT].set("587");

        let account = build_account(&w);
        let text = crate::config::render(&General::default(), &Ui::default(), &[account]);
        let parsed: Config = toml::from_str(&text).expect("generated config must parse");
        parsed.validate().expect("generated config must validate");

        assert_eq!(parsed.accounts[0].address, "ada@example.org");
        assert_eq!(parsed.accounts[0].display_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(parsed.accounts[0].smtp.port, 587);
        assert_eq!(parsed.accounts[0].smtp.security, Security::Starttls);
    }
}
