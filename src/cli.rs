use std::path::PathBuf;

pub const USAGE: &str = concat!(
    "pigeon ",
    env!("CARGO_PKG_VERSION"),
    r#" — a keyboard-driven terminal email client

USAGE
    pigeon [OPTIONS] [COMMAND]

COMMANDS
    (none)                  open the mail reader
    daemon                  run headless and serve a unix socket (for a desktop shell)
    init                    write a starter config and create the encrypted vault
    sync [ACCOUNT]          synchronise once and exit
    send                    try to send everything waiting in the outbox
    auth store ACCOUNT KIND store an IMAP or SMTP password in the OS keyring
                            (KIND is `imap` or `smtp`)
    auth login ACCOUNT      run the OAuth2 browser flow for an account
    auth forget ACCOUNT     remove an account's stored secrets
    vault passwd            change the vault passphrase
    vault info              show vault and database status
    pgp list                list OpenPGP keys pigeon knows about
    pgp import FILE         import an OpenPGP key
    pgp export EMAIL        print a public key in armoured form
    doctor                  check the configuration and reach every server
    help                    show this text

OPTIONS
    -c, --config PATH       use this config file
    -d, --data-dir PATH     use this data directory
    -a, --account NAME      limit the command to one account
    -s, --socket PATH       daemon socket path
                            (default $XDG_RUNTIME_DIR/pigeon/daemon.sock)
        --no-encrypt        open the database unencrypted (not recommended)
    -v, --verbose           log at debug level
    -V, --version           print the version
    -h, --help              show this text
"#
);

#[derive(Debug, Clone, PartialEq)]
pub enum Cmd {
    Tui,
    Daemon,
    Init,
    Sync(Option<String>),
    Send,
    AuthStore { account: String, kind: String },
    AuthLogin { account: String },
    AuthForget { account: String },
    VaultPasswd,
    VaultInfo,
    PgpList,
    PgpImport(PathBuf),
    PgpExport(String),
    Doctor,
    Help,
    Version,
}

#[derive(Debug, Clone)]
pub struct Args {
    pub cmd: Cmd,
    pub config: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub account: Option<String>,
    pub socket: Option<PathBuf>,
    pub no_encrypt: bool,
    pub verbose: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ArgError {
    #[error("`{0}` needs a value")]
    MissingValue(String),
    #[error("unknown option `{0}` — run `pigeon help`")]
    UnknownFlag(String),
    #[error("unknown command `{0}` — run `pigeon help`")]
    UnknownCommand(String),
    #[error("`{usage}`")]
    BadUsage { usage: String },
}

pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Result<Args, ArgError> {
    let mut args = Args {
        cmd: Cmd::Tui,
        config: None,
        data_dir: None,
        account: None,
        socket: None,
        no_encrypt: false,
        verbose: false,
    };

    let mut rest: Vec<String> = Vec::new();
    let mut it = argv.into_iter().skip(1).peekable();

    while let Some(arg) = it.next() {
        let mut take = |flag: &str| -> Result<String, ArgError> {
            it.next().ok_or_else(|| ArgError::MissingValue(flag.to_string()))
        };
        match arg.as_str() {
            "-c" | "--config" => args.config = Some(PathBuf::from(take("--config")?)),
            "-d" | "--data-dir" => args.data_dir = Some(PathBuf::from(take("--data-dir")?)),
            "-a" | "--account" => args.account = Some(take("--account")?),
            "-s" | "--socket" => args.socket = Some(PathBuf::from(take("--socket")?)),
            "--no-encrypt" => args.no_encrypt = true,
            "-v" | "--verbose" => args.verbose = true,
            "-V" | "--version" => return Ok(Args { cmd: Cmd::Version, ..args }),
            "-h" | "--help" => return Ok(Args { cmd: Cmd::Help, ..args }),
            other if other.starts_with('-') && other.len() > 1 => {
                return Err(ArgError::UnknownFlag(other.to_string()));
            }
            other => rest.push(other.to_string()),
        }
    }

    let word = |i: usize| rest.get(i).map(String::as_str).unwrap_or("");

    args.cmd = match word(0) {
        "" => Cmd::Tui,
        "help" => Cmd::Help,
        "version" => Cmd::Version,
        "init" => Cmd::Init,
        "daemon" | "serve" => Cmd::Daemon,
        "doctor" => Cmd::Doctor,
        "send" => Cmd::Send,
        "sync" => Cmd::Sync(rest.get(1).cloned().or_else(|| args.account.clone())),
        "auth" => match (word(1), word(2), word(3)) {
            ("store", account, kind) if !account.is_empty() && !kind.is_empty() => Cmd::AuthStore {
                account: account.to_string(),
                kind: kind.to_string(),
            },
            ("login", account, _) if !account.is_empty() => Cmd::AuthLogin {
                account: account.to_string(),
            },
            ("forget", account, _) if !account.is_empty() => Cmd::AuthForget {
                account: account.to_string(),
            },
            _ => {
                return Err(ArgError::BadUsage {
                    usage: "pigeon auth store|login|forget ACCOUNT [imap|smtp]".into(),
                });
            }
        },
        "vault" => match word(1) {
            "passwd" | "password" => Cmd::VaultPasswd,
            "info" | "" => Cmd::VaultInfo,
            _ => return Err(ArgError::BadUsage { usage: "pigeon vault passwd|info".into() }),
        },
        "pgp" => match (word(1), word(2)) {
            ("list", _) | ("", _) => Cmd::PgpList,
            ("import", f) if !f.is_empty() => Cmd::PgpImport(PathBuf::from(f)),
            ("export", e) if !e.is_empty() => Cmd::PgpExport(e.to_string()),
            _ => {
                return Err(ArgError::BadUsage {
                    usage: "pigeon pgp list|import FILE|export EMAIL".into(),
                });
            }
        },
        other => return Err(ArgError::UnknownCommand(other.to_string())),
    };

    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Result<Args, ArgError> {
        parse(std::iter::once("pigeon".to_string()).chain(v.iter().map(|s| s.to_string())))
    }

    #[test]
    fn defaults_to_the_reader() {
        assert_eq!(p(&[]).unwrap().cmd, Cmd::Tui);
    }

    #[test]
    fn parses_flags_around_subcommands() {
        let a = p(&["-c", "/tmp/c.toml", "sync", "work"]).unwrap();
        assert_eq!(a.config, Some(PathBuf::from("/tmp/c.toml")));
        assert_eq!(a.cmd, Cmd::Sync(Some("work".into())));
    }

    #[test]
    fn rejects_unknown_flags_and_commands() {
        assert!(matches!(p(&["--nope"]), Err(ArgError::UnknownFlag(_))));
        assert!(matches!(p(&["frobnicate"]), Err(ArgError::UnknownCommand(_))));
        assert!(matches!(p(&["--config"]), Err(ArgError::MissingValue(_))));
    }

    #[test]
    fn parses_the_daemon_command_with_a_socket() {
        let a = p(&["daemon", "--socket", "/run/user/1000/p.sock"]).unwrap();
        assert_eq!(a.cmd, Cmd::Daemon);
        assert_eq!(a.socket, Some(PathBuf::from("/run/user/1000/p.sock")));
    }

    #[test]
    fn parses_auth_subcommands() {
        assert_eq!(
            p(&["auth", "store", "personal", "imap"]).unwrap().cmd,
            Cmd::AuthStore { account: "personal".into(), kind: "imap".into() }
        );
        assert!(p(&["auth", "store"]).is_err());
    }
}
