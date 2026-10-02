use chrono::Utc;
use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address as BAddress;

use crate::store::model::{Addr, Envelope};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyMode {
    Sender,
    All,
    List,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardMode {
    Inline,
    Attached,
}

#[derive(Debug, Clone)]
pub struct DraftAttachment {
    pub name: String,
    pub mime: String,
    pub data: Vec<u8>,
    pub inline_cid: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Draft {
    /// Set by the daemon before queuing a send, so the caller can match the
    /// `sent`/`send-failed` push that later reports what happened to it.
    pub id: String,
    pub account: String,
    pub from: Option<Addr>,
    pub to: Vec<Addr>,
    pub cc: Vec<Addr>,
    pub bcc: Vec<Addr>,
    pub reply_to: Vec<Addr>,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<DraftAttachment>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub extra_headers: Vec<(String, String)>,
    pub sign: bool,
    pub encrypt: bool,
    pub request_receipt: bool,
    pub html_body: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("a message needs at least one recipient")]
    NoRecipients,
    #[error("no From address; set one on the account")]
    NoSender,
    #[error("could not serialise the message: {0}")]
    Serialize(#[from] std::io::Error),
}

impl Draft {
    pub fn new(account: &str, from: Addr) -> Self {
        Self { account: account.to_string(), from: Some(from), ..Default::default() }
    }

    pub fn reply_to_envelope(
        &mut self,
        env: &Envelope,
        body: &str,
        mode: ReplyMode,
        own_addresses: &[String],
    ) {
        let target = if env.reply_to.is_empty() { &env.from } else { &env.reply_to };
        self.to = target.clone();

        if mode == ReplyMode::All {
            let mine = |a: &Addr| {
                own_addresses
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(&a.email))
            };
            let already: Vec<String> =
                self.to.iter().map(|a| a.email.to_lowercase()).collect();
            self.cc = env
                .to
                .iter()
                .chain(&env.cc)
                .filter(|a| !mine(a) && !already.contains(&a.email.to_lowercase()))
                .cloned()
                .collect();
            self.cc.dedup_by(|a, b| a.email.eq_ignore_ascii_case(&b.email));
        }

        self.subject = prefix_subject("Re: ", &env.subject);
        self.in_reply_to = env.message_id.clone();
        self.references = env.references.clone();
        if let Some(id) = &env.message_id
            && !self.references.contains(id)
        {
            self.references.push(id.clone());
        }
        self.body = format!("{}\n\n{}", attribution(env), quote(body));
    }

    pub fn forward_envelope(&mut self, env: &Envelope, body: &str, mode: ForwardMode, raw: &[u8]) {
        self.subject = prefix_subject("Fwd: ", &env.subject);
        match mode {
            ForwardMode::Inline => {
                self.body = format!(
                    "\n\n---------- Forwarded message ----------\nFrom: {}\nDate: {}\nSubject: {}\nTo: {}\n\n{body}",
                    env.from.iter().map(|a| a.encoded()).collect::<Vec<_>>().join(", "),
                    env.date.to_rfc2822(),
                    env.subject,
                    env.to.iter().map(|a| a.encoded()).collect::<Vec<_>>().join(", "),
                );
            }
            ForwardMode::Attached => {
                self.body = "\n\n".to_string();
                self.attachments.push(DraftAttachment {
                    name: format!("{}.eml", sanitize(env.subject_or_placeholder())),
                    mime: "message/rfc822".into(),
                    data: raw.to_vec(),
                    inline_cid: None,
                });
            }
        }
    }

    pub fn all_recipients(&self) -> Vec<Addr> {
        let mut v = self.to.clone();
        v.extend(self.cc.iter().cloned());
        v.extend(self.bcc.iter().cloned());
        v.dedup_by(|a, b| a.email.eq_ignore_ascii_case(&b.email));
        v
    }

    /// Serialises to RFC 5322. `Bcc` is deliberately not written into the
    /// message: those addresses go in the SMTP envelope only, otherwise every
    /// recipient can read the blind list.
    pub fn to_mime(&self) -> Result<Vec<u8>, ComposeError> {
        let from = self.from.as_ref().ok_or(ComposeError::NoSender)?;
        if self.to.is_empty() && self.cc.is_empty() && self.bcc.is_empty() {
            return Err(ComposeError::NoRecipients);
        }

        let mut b = MessageBuilder::new()
            .from(to_builder(std::slice::from_ref(from)))
            .subject(self.subject.as_str())
            .date(Utc::now().timestamp())
            .message_id(new_message_id(&from.domain()));

        if !self.to.is_empty() {
            b = b.to(to_builder(&self.to));
        }
        if !self.cc.is_empty() {
            b = b.cc(to_builder(&self.cc));
        }
        if !self.reply_to.is_empty() {
            b = b.reply_to(to_builder(&self.reply_to));
        }
        if let Some(irt) = &self.in_reply_to {
            b = b.in_reply_to(format!("<{irt}>"));
        }
        if !self.references.is_empty() {
            let refs: Vec<String> = self.references.iter().map(|r| format!("<{r}>")).collect();
            b = b.references(refs);
        }
        if self.request_receipt {
            b = b.header(
                "Disposition-Notification-To",
                mail_builder::headers::raw::Raw::new(from.email.clone()),
            );
        }
        b = b.header(
            "User-Agent",
            mail_builder::headers::raw::Raw::new(concat!("pigeon/", env!("CARGO_PKG_VERSION"))),
        );
        for (k, v) in &self.extra_headers {
            b = b.header(k.clone(), mail_builder::headers::raw::Raw::new(v.clone()));
        }

        b = b.text_body(self.body.as_str());
        if let Some(h) = &self.html_body {
            b = b.html_body(h.as_str());
        }
        for a in &self.attachments {
            b = match &a.inline_cid {
                Some(cid) => b.inline(a.mime.as_str(), cid.as_str(), a.data.as_slice()),
                None => b.attachment(a.mime.as_str(), a.name.as_str(), a.data.as_slice()),
            };
        }

        Ok(b.write_to_vec()?)
    }
}

fn to_builder(addrs: &[Addr]) -> BAddress<'static> {
    BAddress::new_list(
        addrs
            .iter()
            .map(|a| BAddress::new_address(a.name.clone(), a.email.clone()))
            .collect(),
    )
}

pub fn new_message_id(domain: &str) -> String {
    let domain = if domain.is_empty() { "localhost" } else { domain };
    format!("{}@{domain}", uuid::Uuid::new_v4())
}

fn prefix_subject(prefix: &str, subject: &str) -> String {
    let s = subject.trim();
    if s.to_ascii_lowercase().starts_with(&prefix.trim().to_ascii_lowercase()) {
        s.to_string()
    } else {
        format!("{prefix}{s}")
    }
}

fn attribution(env: &Envelope) -> String {
    let who = env
        .from
        .first()
        .map(|a| a.encoded())
        .unwrap_or_else(|| "someone".into());
    format!("On {}, {who} wrote:", env.date.format("%Y-%m-%d %H:%M"))
}

pub fn quote(body: &str) -> String {
    body.lines()
        .map(|l| if l.is_empty() { ">".to_string() } else { format!("> {l}") })
        .collect::<Vec<_>>()
        .join("\n")
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(60)
        .collect()
}

/// Splits a user-typed recipient line. Quoted display names may contain commas,
/// so a naive `split(',')` mangles `"Doe, Jane" <jane@example.org>`.
pub fn parse_address_list(input: &str) -> Vec<Addr> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut in_angle = false;

    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            '<' if !in_quotes => {
                in_angle = true;
                cur.push(ch);
            }
            '>' if !in_quotes => {
                in_angle = false;
                cur.push(ch);
            }
            ',' | ';' if !in_quotes && !in_angle => {
                if let Some(a) = parse_one(&cur) {
                    out.push(a);
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if let Some(a) = parse_one(&cur) {
        out.push(a);
    }
    out
}

fn parse_one(s: &str) -> Option<Addr> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Some(open) = s.rfind('<') {
        let close = s[open..].find('>').map(|i| open + i)?;
        let email = s[open + 1..close].trim().to_string();
        let name = s[..open].trim().trim_matches('"').trim().to_string();
        if email.is_empty() {
            return None;
        }
        return Some(Addr { name: (!name.is_empty()).then_some(name), email });
    }
    s.contains('@').then(|| Addr::new(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_display_names() {
        let v = parse_address_list(r#""Doe, Jane" <jane@example.org>, bob@example.org"#);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name.as_deref(), Some("Doe, Jane"));
        assert_eq!(v[0].email, "jane@example.org");
        assert_eq!(v[1].email, "bob@example.org");
    }

    #[test]
    fn does_not_double_prefix_subject() {
        assert_eq!(prefix_subject("Re: ", "Re: hello"), "Re: hello");
        assert_eq!(prefix_subject("Re: ", "hello"), "Re: hello");
    }
}
