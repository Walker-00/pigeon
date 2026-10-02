use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::config::{Security, SmtpConfig};

use super::tls::{MaybeTls, TlsError, connect_tcp, connect_tls};

const IO_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum SmtpError {
    #[error(transparent)]
    Tls(#[from] TlsError),
    #[error("SMTP I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the server closed the connection unexpectedly")]
    Closed,
    #[error("SMTP {code}: {message}")]
    Rejected { code: u16, message: String },
    #[error("server sent an unparsable reply: {0:?}")]
    BadReply(String),
    #[error("the server offers no authentication mechanism this client supports (offered: {0})")]
    NoSupportedAuth(String),
    #[error("the server does not support STARTTLS, and the config requires it")]
    NoStartTls,
    #[error("timed out waiting for the server")]
    Timeout,
    #[error("recipient {addr} was rejected: {code} {message}")]
    RecipientRejected { addr: String, code: u16, message: String },
}

#[derive(Debug, Clone)]
pub enum Credentials {
    None,
    Plain { user: String, password: String },
    XOAuth2 { user: String, token: String },
}

#[derive(Debug, Default, Clone)]
pub struct Capabilities {
    pub starttls: bool,
    pub auth: Vec<String>,
    pub size_limit: Option<u64>,
    pub pipelining: bool,
    pub eightbitmime: bool,
    pub smtputf8: bool,
    pub dsn: bool,
}

pub struct SmtpClient {
    stream: BufReader<MaybeTls>,
    pub caps: Capabilities,
    host: String,
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    fn message(&self) -> String {
        self.lines.join("; ")
    }

    fn ok(&self) -> bool {
        (200..400).contains(&self.code)
    }
}

impl SmtpClient {
    pub async fn connect(cfg: &SmtpConfig, ehlo_name: &str) -> Result<Self, SmtpError> {
        let stream = match cfg.security {
            Security::Tls => MaybeTls::Tls(Box::new(
                connect_tls(&cfg.host, cfg.port, cfg.accept_invalid_certs).await?,
            )),
            Security::Starttls | Security::None => {
                MaybeTls::Plain(connect_tcp(&cfg.host, cfg.port).await?)
            }
        };

        let mut client = Self {
            stream: BufReader::new(stream),
            caps: Capabilities::default(),
            host: cfg.host.clone(),
        };

        let greeting = client.read_reply().await?;
        if !greeting.ok() {
            return Err(SmtpError::Rejected {
                code: greeting.code,
                message: greeting.message(),
            });
        }

        client.ehlo(ehlo_name).await?;

        if cfg.security == Security::Starttls {
            if !client.caps.starttls {
                return Err(SmtpError::NoStartTls);
            }
            client.expect("STARTTLS", &[220]).await?;
            let inner = client.stream.into_inner();
            let upgraded = inner.upgrade(&cfg.host, cfg.accept_invalid_certs).await?;
            client.stream = BufReader::new(upgraded);
            client.ehlo(ehlo_name).await?;
        }

        Ok(client)
    }

    async fn ehlo(&mut self, name: &str) -> Result<(), SmtpError> {
        let reply = self.command(&format!("EHLO {name}")).await?;
        if !reply.ok() {
            let helo = self.command(&format!("HELO {name}")).await?;
            if !helo.ok() {
                return Err(SmtpError::Rejected { code: helo.code, message: helo.message() });
            }
            self.caps = Capabilities::default();
            return Ok(());
        }
        self.caps = parse_caps(&reply.lines);
        Ok(())
    }

    pub async fn authenticate(&mut self, creds: &Credentials) -> Result<(), SmtpError> {
        match creds {
            Credentials::None => Ok(()),
            Credentials::XOAuth2 { user, token } => {
                if !self.supports_auth("XOAUTH2") {
                    return Err(SmtpError::NoSupportedAuth(self.caps.auth.join(" ")));
                }
                let payload = B64.encode(format!("user={user}\x01auth=Bearer {token}\x01\x01"));
                let reply = self.command(&format!("AUTH XOAUTH2 {payload}")).await?;
                if reply.ok() {
                    return Ok(());
                }
                // A challenge here carries the error detail; an empty line ends it.
                let _ = self.command("").await;
                Err(SmtpError::Rejected { code: reply.code, message: reply.message() })
            }
            Credentials::Plain { user, password } => {
                if self.supports_auth("PLAIN") {
                    let payload = B64.encode(format!("\0{user}\0{password}"));
                    let reply = self.command(&format!("AUTH PLAIN {payload}")).await?;
                    return self.check(reply);
                }
                if self.supports_auth("LOGIN") {
                    self.expect("AUTH LOGIN", &[334]).await?;
                    self.expect(&B64.encode(user), &[334]).await?;
                    let reply = self.command(&B64.encode(password)).await?;
                    return self.check(reply);
                }
                Err(SmtpError::NoSupportedAuth(self.caps.auth.join(" ")))
            }
        }
    }

    fn supports_auth(&self, mech: &str) -> bool {
        self.caps.auth.iter().any(|m| m.eq_ignore_ascii_case(mech))
    }

    fn check(&self, reply: Reply) -> Result<(), SmtpError> {
        if reply.ok() {
            Ok(())
        } else {
            Err(SmtpError::Rejected { code: reply.code, message: reply.message() })
        }
    }

    pub async fn send(
        &mut self,
        from: &str,
        recipients: &[String],
        message: &[u8],
    ) -> Result<(), SmtpError> {
        let mut mail_from = format!("MAIL FROM:<{from}>");
        if self.caps.eightbitmime {
            mail_from.push_str(" BODY=8BITMIME");
        }
        if self.caps.smtputf8 && !from.is_ascii() {
            mail_from.push_str(" SMTPUTF8");
        }
        if let Some(limit) = self.caps.size_limit
            && message.len() as u64 > limit
        {
            return Err(SmtpError::Rejected {
                code: 552,
                message: format!("message is {} bytes, server limit is {limit}", message.len()),
            });
        }

        self.expect(&mail_from, &[250]).await?;

        for rcpt in recipients {
            let reply = self.command(&format!("RCPT TO:<{rcpt}>")).await?;
            if !reply.ok() {
                let _ = self.command("RSET").await;
                return Err(SmtpError::RecipientRejected {
                    addr: rcpt.clone(),
                    code: reply.code,
                    message: reply.message(),
                });
            }
        }

        self.expect("DATA", &[354]).await?;
        self.write_dot_stuffed(message).await?;
        let reply = self.read_reply().await?;
        self.check(reply)
    }

    pub async fn quit(mut self) {
        let _ = self.command("QUIT").await;
        let _ = self.stream.get_mut().shutdown().await;
    }

    /// RFC 5321 §4.5.2: a line consisting of a single "." ends DATA, so any body
    /// line that begins with "." must have one prepended.
    async fn write_dot_stuffed(&mut self, message: &[u8]) -> Result<(), SmtpError> {
        let mut out = Vec::with_capacity(message.len() + 64);
        let mut at_line_start = true;
        let mut prev_cr = false;

        for &b in message {
            if at_line_start && b == b'.' {
                out.push(b'.');
            }
            if b == b'\n' && !prev_cr {
                out.push(b'\r');
            }
            out.push(b);
            at_line_start = b == b'\n';
            prev_cr = b == b'\r';
        }
        if !at_line_start {
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b".\r\n");

        self.stream.get_mut().write_all(&out).await?;
        self.stream.get_mut().flush().await?;
        Ok(())
    }

    async fn expect(&mut self, cmd: &str, codes: &[u16]) -> Result<Reply, SmtpError> {
        let reply = self.command(cmd).await?;
        if codes.contains(&reply.code) {
            Ok(reply)
        } else {
            Err(SmtpError::Rejected { code: reply.code, message: reply.message() })
        }
    }

    async fn command(&mut self, cmd: &str) -> Result<Reply, SmtpError> {
        tracing::trace!(target: "pigeon::smtp", host = %self.host, "C: {}", redact(cmd));
        self.stream.get_mut().write_all(cmd.as_bytes()).await?;
        self.stream.get_mut().write_all(b"\r\n").await?;
        self.stream.get_mut().flush().await?;
        self.read_reply().await
    }

    async fn read_reply(&mut self) -> Result<Reply, SmtpError> {
        tokio::time::timeout(IO_TIMEOUT, self.read_reply_inner())
            .await
            .map_err(|_| SmtpError::Timeout)?
    }

    async fn read_reply_inner(&mut self) -> Result<Reply, SmtpError> {
        let mut lines = Vec::new();
        let mut code;

        loop {
            let mut line = String::new();
            if self.stream.read_line(&mut line).await? == 0 {
                return Err(SmtpError::Closed);
            }
            let line = line.trim_end_matches(['\r', '\n']);
            tracing::trace!(target: "pigeon::smtp", "S: {line}");

            if line.len() < 3 {
                return Err(SmtpError::BadReply(line.to_string()));
            }
            code = line[..3]
                .parse()
                .map_err(|_| SmtpError::BadReply(line.to_string()))?;
            let rest = line[3..].trim_start_matches([' ', '-']).to_string();
            let more = line.as_bytes().get(3) == Some(&b'-');
            lines.push(rest);
            if !more {
                break;
            }
        }
        Ok(Reply { code, lines })
    }
}

fn redact(cmd: &str) -> String {
    let upper = cmd.to_ascii_uppercase();
    if upper.starts_with("AUTH") {
        let mech = cmd.split_whitespace().nth(1).unwrap_or("");
        format!("AUTH {mech} <redacted>")
    } else if !cmd.contains(' ') && cmd.len() > 16 {
        "<redacted>".into()
    } else {
        cmd.to_string()
    }
}

fn parse_caps(lines: &[String]) -> Capabilities {
    let mut caps = Capabilities::default();
    for line in lines {
        let mut parts = line.split_whitespace();
        let Some(word) = parts.next() else { continue };
        match word.to_ascii_uppercase().as_str() {
            "STARTTLS" => caps.starttls = true,
            "PIPELINING" => caps.pipelining = true,
            "8BITMIME" => caps.eightbitmime = true,
            "SMTPUTF8" => caps.smtputf8 = true,
            "DSN" => caps.dsn = true,
            "SIZE" => caps.size_limit = parts.next().and_then(|n| n.parse().ok()),
            "AUTH" => caps.auth.extend(parts.map(|m| m.to_ascii_uppercase())),
            _ => {}
        }
    }
    caps
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_ehlo_capabilities() {
        let lines: Vec<String> = ["mail.example.org", "SIZE 35882577", "AUTH PLAIN LOGIN XOAUTH2", "STARTTLS", "8BITMIME"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let caps = super::parse_caps(&lines);
        assert!(caps.starttls);
        assert!(caps.eightbitmime);
        assert_eq!(caps.size_limit, Some(35882577));
        assert_eq!(caps.auth, vec!["PLAIN", "LOGIN", "XOAUTH2"]);
    }

    #[test]
    fn redacts_credentials_from_logs() {
        assert_eq!(super::redact("AUTH PLAIN AGFsaWNlAHM="), "AUTH PLAIN <redacted>");
        assert_eq!(super::redact("EHLO localhost"), "EHLO localhost");
    }
}
