use chrono::{DateTime, NaiveDate, TimeZone, Utc};

use crate::store::model::{CryptoState, Envelope, Flags};

#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    All,
    And(Vec<Node>),
    Or(Vec<Node>),
    Not(Box<Node>),
    Field { field: Field, term: String },
    Is(Is),
    Before(DateTime<Utc>),
    After(DateTime<Utc>),
    Larger(u64),
    Smaller(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Any,
    From,
    To,
    Cc,
    Bcc,
    Subject,
    Body,
    List,
    Tag,
    Attachment,
    Folder,
    Account,
}

impl Field {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "from" | "f" => Field::From,
            "to" | "t" => Field::To,
            "cc" => Field::Cc,
            "bcc" => Field::Bcc,
            "subject" | "subj" | "s" => Field::Subject,
            "body" | "b" => Field::Body,
            "list" => Field::List,
            "tag" | "label" | "keyword" => Field::Tag,
            "attachment" | "file" => Field::Attachment,
            "in" | "folder" | "mailbox" => Field::Folder,
            "account" | "acct" => Field::Account,
            _ => return None,
        })
    }

    pub fn index_name(self) -> &'static str {
        match self {
            Field::Any => "any",
            Field::From => "from",
            Field::To | Field::Cc | Field::Bcc => "to",
            Field::Subject => "subject",
            Field::Body => "body",
            Field::List => "list",
            Field::Tag => "tag",
            Field::Attachment => "attachment",
            Field::Folder | Field::Account => "any",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Is {
    Unread,
    Read,
    Flagged,
    Answered,
    Draft,
    Deleted,
    Forwarded,
    Junk,
    Attachment,
    Encrypted,
    Signed,
    Unsigned,
}

impl Is {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "unread" | "new" => Is::Unread,
            "read" | "seen" => Is::Read,
            "flagged" | "starred" => Is::Flagged,
            "answered" | "replied" => Is::Answered,
            "draft" => Is::Draft,
            "deleted" => Is::Deleted,
            "forwarded" => Is::Forwarded,
            "junk" | "spam" => Is::Junk,
            "attachment" | "attached" => Is::Attachment,
            "encrypted" => Is::Encrypted,
            "signed" => Is::Signed,
            "unsigned" => Is::Unsigned,
            _ => return None,
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum QueryError {
    #[error("unbalanced parenthesis")]
    Unbalanced,
    #[error("`{0}` is not a recognised search term")]
    UnknownTerm(String),
    #[error("`{0}` is not a date; try 2026-01-31, today, yesterday, or 7d")]
    BadDate(String),
    #[error("`{0}` is not a size; try 5M, 200k, or 1048576")]
    BadSize(String),
    #[error("query is empty")]
    Empty,
}

pub fn parse(input: &str) -> Result<Node, QueryError> {
    let tokens = lex(input);
    if tokens.is_empty() {
        return Err(QueryError::Empty);
    }
    let mut p = Parser { tokens, pos: 0 };
    let node = p.parse_or()?;
    if p.pos < p.tokens.len() {
        return Err(QueryError::Unbalanced);
    }
    Ok(node)
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Word(String),
    Or,
    Not,
    LParen,
    RParen,
}

fn lex(input: &str) -> Vec<Tok> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = input.chars().peekable();

    let flush = |cur: &mut String, out: &mut Vec<Tok>| {
        if !cur.is_empty() {
            let w = std::mem::take(cur);
            match w.to_ascii_lowercase().as_str() {
                "or" | "|" => out.push(Tok::Or),
                "and" | "&" => {}
                "not" => out.push(Tok::Not),
                _ => out.push(Tok::Word(w)),
            }
        }
    };

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                if !quoted {
                    out.push(Tok::Word(std::mem::take(&mut cur)));
                }
            }
            _ if quoted => cur.push(c),
            '(' => {
                flush(&mut cur, &mut out);
                out.push(Tok::LParen);
            }
            ')' => {
                flush(&mut cur, &mut out);
                out.push(Tok::RParen);
            }
            '-' if cur.is_empty() => out.push(Tok::Not),
            c if c.is_whitespace() => flush(&mut cur, &mut out),
            _ => cur.push(c),
        }
    }
    flush(&mut cur, &mut out);
    out
}

struct Parser {
    tokens: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn parse_or(&mut self) -> Result<Node, QueryError> {
        let mut terms = vec![self.parse_and()?];
        while matches!(self.peek(), Some(Tok::Or)) {
            self.pos += 1;
            terms.push(self.parse_and()?);
        }
        Ok(if terms.len() == 1 { terms.pop().unwrap() } else { Node::Or(terms) })
    }

    fn parse_and(&mut self) -> Result<Node, QueryError> {
        let mut terms = Vec::new();
        while let Some(t) = self.peek() {
            if matches!(t, Tok::Or | Tok::RParen) {
                break;
            }
            terms.push(self.parse_unary()?);
        }
        if terms.is_empty() {
            return Err(QueryError::Empty);
        }
        Ok(if terms.len() == 1 { terms.pop().unwrap() } else { Node::And(terms) })
    }

    fn parse_unary(&mut self) -> Result<Node, QueryError> {
        match self.peek().cloned() {
            Some(Tok::Not) => {
                self.pos += 1;
                Ok(Node::Not(Box::new(self.parse_unary()?)))
            }
            Some(Tok::LParen) => {
                self.pos += 1;
                let inner = self.parse_or()?;
                match self.peek() {
                    Some(Tok::RParen) => {
                        self.pos += 1;
                        Ok(inner)
                    }
                    _ => Err(QueryError::Unbalanced),
                }
            }
            Some(Tok::Word(w)) => {
                self.pos += 1;
                atom(&w)
            }
            Some(Tok::RParen) | None => Err(QueryError::Unbalanced),
            Some(Tok::Or) => Err(QueryError::Empty),
        }
    }
}

fn atom(word: &str) -> Result<Node, QueryError> {
    let Some((key, value)) = word.split_once(':') else {
        return Ok(Node::Field { field: Field::Any, term: word.to_lowercase() });
    };
    let key = key.to_ascii_lowercase();
    let value = value.trim();

    if let Some(f) = Field::parse(&key) {
        return Ok(Node::Field { field: f, term: value.to_lowercase() });
    }

    match key.as_str() {
        "is" | "has" => Is::parse(&value.to_ascii_lowercase())
            .map(Node::Is)
            .ok_or_else(|| QueryError::UnknownTerm(word.to_string())),
        "before" | "until" => parse_date(value).map(Node::Before),
        "after" | "since" | "newer" => parse_date(value).map(Node::After),
        "on" => {
            let d = parse_date(value)?;
            Ok(Node::And(vec![
                Node::After(d),
                Node::Before(d + chrono::Duration::days(1)),
            ]))
        }
        "larger" | "bigger" => parse_size(value).map(Node::Larger),
        "smaller" => parse_size(value).map(Node::Smaller),
        _ => Err(QueryError::UnknownTerm(word.to_string())),
    }
}

fn parse_date(s: &str) -> Result<DateTime<Utc>, QueryError> {
    let now = Utc::now();
    let err = || QueryError::BadDate(s.to_string());

    match s.to_ascii_lowercase().as_str() {
        "today" => return Ok(now.date_naive().and_hms_opt(0, 0, 0).map(|d| Utc.from_utc_datetime(&d)).ok_or_else(err)?),
        "yesterday" => {
            let d = (now - chrono::Duration::days(1)).date_naive();
            return d.and_hms_opt(0, 0, 0).map(|d| Utc.from_utc_datetime(&d)).ok_or_else(err);
        }
        _ => {}
    }

    if let Some(n) = s.strip_suffix(['d', 'D']).and_then(|n| n.parse::<i64>().ok()) {
        return Ok(now - chrono::Duration::days(n));
    }
    if let Some(n) = s.strip_suffix(['w', 'W']).and_then(|n| n.parse::<i64>().ok()) {
        return Ok(now - chrono::Duration::weeks(n));
    }
    if let Some(n) = s.strip_suffix(['h', 'H']).and_then(|n| n.parse::<i64>().ok()) {
        return Ok(now - chrono::Duration::hours(n));
    }

    for fmt in ["%Y-%m-%d", "%Y/%m/%d", "%d.%m.%Y", "%d/%m/%Y"] {
        if let Ok(d) = NaiveDate::parse_from_str(s, fmt) {
            return d.and_hms_opt(0, 0, 0).map(|d| Utc.from_utc_datetime(&d)).ok_or_else(err);
        }
    }
    Err(err())
}

fn parse_size(s: &str) -> Result<u64, QueryError> {
    let s = s.trim();
    let err = || QueryError::BadSize(s.to_string());
    let (num, mult) = match s.chars().last() {
        Some('k') | Some('K') => (&s[..s.len() - 1], 1024),
        Some('m') | Some('M') => (&s[..s.len() - 1], 1024 * 1024),
        Some('g') | Some('G') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.trim().parse::<u64>().map(|n| n * mult).map_err(|_| err())
}

impl Node {
    pub fn matches(&self, e: &Envelope) -> bool {
        match self {
            Node::All => true,
            Node::And(v) => v.iter().all(|n| n.matches(e)),
            Node::Or(v) => v.iter().any(|n| n.matches(e)),
            Node::Not(n) => !n.matches(e),
            Node::Before(d) => e.date < *d,
            Node::After(d) => e.date >= *d,
            Node::Larger(n) => e.size > *n,
            Node::Smaller(n) => e.size < *n,
            Node::Is(i) => match_is(*i, e),
            Node::Field { field, term } => match_field(*field, term, e),
        }
    }

    /// Terms that can be answered from the blind index. Anything not covered
    /// here (negation, ranges, folder scoping) is applied afterwards by
    /// `matches`, so the index is only ever used to narrow the candidate set.
    pub fn index_terms(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        self.collect_index_terms(&mut out, true);
        out
    }

    fn collect_index_terms(&self, out: &mut Vec<(&'static str, String)>, positive: bool) {
        match self {
            Node::And(v) => {
                for n in v {
                    n.collect_index_terms(out, positive);
                }
            }
            Node::Field { field, term } if positive && !term.is_empty() => {
                if !matches!(field, Field::Folder | Field::Account) {
                    for t in crate::crypto::blind::tokenize(term) {
                        out.push((field.index_name(), t));
                    }
                }
            }
            _ => {}
        }
    }
}

fn match_is(i: Is, e: &Envelope) -> bool {
    match i {
        Is::Unread => !e.flags.contains(Flags::SEEN),
        Is::Read => e.flags.contains(Flags::SEEN),
        Is::Flagged => e.flags.contains(Flags::FLAGGED),
        Is::Answered => e.flags.contains(Flags::ANSWERED),
        Is::Draft => e.flags.contains(Flags::DRAFT),
        Is::Deleted => e.flags.contains(Flags::DELETED),
        Is::Forwarded => e.flags.contains(Flags::FORWARDED),
        Is::Junk => e.flags.contains(Flags::JUNK),
        Is::Attachment => e.attachments.iter().any(|a| !a.inline),
        Is::Encrypted => matches!(
            e.crypto,
            CryptoState::Encrypted | CryptoState::EncryptedAndSigned | CryptoState::DecryptFailed
        ),
        Is::Signed => matches!(
            e.crypto,
            CryptoState::SignedValid | CryptoState::SignedInvalid | CryptoState::SignedUnknownKey
                | CryptoState::EncryptedAndSigned
        ),
        Is::Unsigned => matches!(e.crypto, CryptoState::None | CryptoState::Encrypted),
    }
}

fn match_field(field: Field, term: &str, e: &Envelope) -> bool {
    let hit = |s: &str| s.to_lowercase().contains(term);
    let any_addr = |list: &[crate::store::model::Addr]| {
        list.iter()
            .any(|a| hit(&a.email) || a.name.as_deref().is_some_and(hit))
    };

    match field {
        Field::From => any_addr(&e.from) || any_addr(&e.reply_to),
        Field::To => any_addr(&e.to),
        Field::Cc => any_addr(&e.cc),
        Field::Bcc => any_addr(&e.bcc),
        Field::Subject => hit(&e.subject),
        Field::Body => hit(&e.preview),
        Field::List => e.list_id.as_deref().is_some_and(hit),
        Field::Tag => e.tags.iter().chain(&e.keywords).any(|t| hit(t)),
        Field::Attachment => e.attachments.iter().any(|a| hit(&a.name)),
        Field::Folder => hit(&e.folder),
        Field::Account => hit(&e.account),
        Field::Any => {
            hit(&e.subject)
                || hit(&e.preview)
                || any_addr(&e.from)
                || any_addr(&e.to)
                || any_addr(&e.cc)
                || e.attachments.iter().any(|a| hit(&a.name))
                || e.tags.iter().any(|t| hit(t))
        }
    }
}

/// Translates the parts of a query that IMAP can evaluate server-side, so a
/// remote search does not have to download every envelope first.
pub fn to_imap(node: &Node) -> Option<String> {
    Some(match node {
        Node::All => "ALL".into(),
        Node::And(v) => v.iter().map(to_imap).collect::<Option<Vec<_>>>()?.join(" "),
        Node::Or(v) => {
            let mut it = v.iter().map(to_imap).collect::<Option<Vec<_>>>()?.into_iter();
            let mut acc = it.next()?;
            for next in it {
                acc = format!("OR ({acc}) ({next})");
            }
            acc
        }
        Node::Not(n) => format!("NOT ({})", to_imap(n)?),
        Node::Before(d) => format!("BEFORE {}", d.format("%d-%b-%Y")),
        Node::After(d) => format!("SINCE {}", d.format("%d-%b-%Y")),
        Node::Larger(n) => format!("LARGER {n}"),
        Node::Smaller(n) => format!("SMALLER {n}"),
        Node::Is(i) => match i {
            Is::Unread => "UNSEEN".into(),
            Is::Read => "SEEN".into(),
            Is::Flagged => "FLAGGED".into(),
            Is::Answered => "ANSWERED".into(),
            Is::Draft => "DRAFT".into(),
            Is::Deleted => "DELETED".into(),
            Is::Forwarded => "KEYWORD $Forwarded".into(),
            Is::Junk => "KEYWORD $Junk".into(),
            _ => return None,
        },
        Node::Field { field, term } => {
            let t = imap_quote(term);
            match field {
                Field::From => format!("FROM {t}"),
                Field::To => format!("TO {t}"),
                Field::Cc => format!("CC {t}"),
                Field::Bcc => format!("BCC {t}"),
                Field::Subject => format!("SUBJECT {t}"),
                Field::Body => format!("BODY {t}"),
                Field::Tag => format!("KEYWORD {t}"),
                Field::Any => format!("TEXT {t}"),
                Field::List => format!("HEADER List-Id {t}"),
                Field::Attachment | Field::Folder | Field::Account => return None,
            }
        }
    })
}

fn imap_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_implicit_and() {
        let q = parse("from:alice is:unread").unwrap();
        assert!(matches!(q, Node::And(ref v) if v.len() == 2));
    }

    #[test]
    fn parses_negation_and_or() {
        let q = parse("-in:spam (from:alice OR from:bob)").unwrap();
        let Node::And(v) = q else { panic!("expected AND") };
        assert!(matches!(v[0], Node::Not(_)));
        assert!(matches!(v[1], Node::Or(_)));
    }

    #[test]
    fn quoted_phrase_stays_one_term() {
        let q = parse(r#"subject:"weekly report""#).unwrap();
        assert_eq!(q, Node::Field { field: Field::Subject, term: "weekly report".into() });
    }

    #[test]
    fn rejects_unknown_term() {
        assert!(matches!(parse("nope:1"), Err(QueryError::UnknownTerm(_))));
    }
}
