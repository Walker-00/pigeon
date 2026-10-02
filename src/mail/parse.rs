use chrono::{DateTime, TimeZone, Utc};
use mail_parser::{Address as MpAddress, Addr as MpAddr, Message, MessageParser, MimeHeaders, PartType};

use crate::store::model::{Addr, AttachmentMeta, CryptoState, Envelope, Flags};

pub const PREVIEW_LEN: usize = 240;

#[derive(Debug, Clone)]
pub struct ParseOutput {
    pub envelope: Envelope,
    pub text: Option<String>,
    pub html: Option<String>,
    pub raw_len: usize,
}

pub fn parse_message(
    account: &str,
    folder: &str,
    uid: u32,
    raw: &[u8],
    flags: Flags,
    keywords: std::collections::BTreeSet<String>,
) -> Option<ParseOutput> {
    let msg = MessageParser::default().parse(raw)?;
    Some(build(account, folder, uid, raw, flags, keywords, &msg))
}

fn build(
    account: &str,
    folder: &str,
    uid: u32,
    raw: &[u8],
    flags: Flags,
    keywords: std::collections::BTreeSet<String>,
    msg: &Message<'_>,
) -> ParseOutput {
    // A header-only fetch still parses, and mail_parser reports an empty body
    // for it. Treating that as "this message has html" would put a preview and
    // an html flag on every message that has neither.
    let text = msg.body_text(0).map(|c| c.into_owned()).filter(|t| !t.trim().is_empty());
    let html = msg.body_html(0).map(|c| c.into_owned()).filter(|h| !h.trim().is_empty());

    let preview = match (&text, &html) {
        (Some(t), _) => snippet(t),
        (None, Some(h)) => snippet(&super::html::to_text(h, 100)),
        _ => String::new(),
    };

    let attachments = collect_attachments(msg);

    let envelope = Envelope {
        account: account.to_string(),
        folder: folder.to_string(),
        uid,
        modseq: 0,
        message_id: msg.message_id().map(normalize_msgid),
        in_reply_to: first_msgid(msg.in_reply_to()),
        references: msgid_list(msg.references()),
        thread_id: None,
        subject: msg.subject().unwrap_or_default().to_string(),
        from: addrs(msg.from()),
        sender: addrs(msg.sender()),
        reply_to: addrs(msg.reply_to()),
        to: addrs(msg.to()),
        cc: addrs(msg.cc()),
        bcc: addrs(msg.bcc()),
        list_id: msg.list_id().as_text().map(|s| s.trim().to_string()),
        date: msg.date().map(to_chrono).unwrap_or_else(Utc::now),
        received: msg.received().and_then(|r| r.date()).map(|d| to_chrono(&d)),
        size: raw.len() as u64,
        flags,
        keywords,
        tags: Default::default(),
        preview,
        has_html: html.is_some(),
        crypto: detect_crypto(msg),
        attachments,
        body_blob: None,
    };

    ParseOutput { envelope, text, html, raw_len: raw.len() }
}

fn collect_attachments(msg: &Message<'_>) -> Vec<AttachmentMeta> {
    let mut out = Vec::new();
    for (idx, part) in msg.parts.iter().enumerate() {
        let is_body = matches!(part.body, PartType::Text(_) | PartType::Html(_))
            && part.attachment_name().is_none();
        if is_body || matches!(part.body, PartType::Multipart(_)) {
            continue;
        }

        let mime = part
            .content_type()
            .map(|c| match c.subtype() {
                Some(s) => format!("{}/{}", c.ctype(), s),
                None => c.ctype().to_string(),
            })
            .unwrap_or_else(|| "application/octet-stream".into());

        let name = part
            .attachment_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| default_name(idx, &mime));

        out.push(AttachmentMeta {
            name,
            mime,
            size: part.len() as u64,
            part_id: idx.to_string(),
            inline: is_inline(part),
            content_id: part.content_id().map(|s| s.to_string()),
            blob: None,
        });
    }
    out
}

fn default_name(idx: usize, mime: &str) -> String {
    let ext = mime_guess::get_mime_extensions_str(mime)
        .and_then(|e| e.first())
        .copied()
        .unwrap_or("bin");
    format!("part-{idx}.{ext}")
}

/// Recognises the two OpenPGP MIME layouts from RFC 3156 plus the older inline
/// ("PGP/INLINE") convention that many mailing lists still emit.
fn detect_crypto(msg: &Message<'_>) -> CryptoState {
    let ctype = msg.content_type().map(|c| {
        (
            c.ctype().to_ascii_lowercase(),
            c.subtype().unwrap_or_default().to_ascii_lowercase(),
            c.attribute("protocol").unwrap_or_default().to_ascii_lowercase(),
        )
    });

    if let Some((ct, st, proto)) = ctype {
        if ct == "multipart" && st == "encrypted" && proto.contains("pgp-encrypted") {
            return CryptoState::Encrypted;
        }
        if ct == "multipart" && st == "signed" && proto.contains("pgp-signature") {
            return CryptoState::SignedUnknownKey;
        }
    }

    if let Some(t) = msg.body_text(0) {
        if t.contains("-----BEGIN PGP MESSAGE-----") {
            return CryptoState::Encrypted;
        }
        if t.contains("-----BEGIN PGP SIGNED MESSAGE-----") {
            return CryptoState::SignedUnknownKey;
        }
    }
    CryptoState::None
}

pub fn addrs(a: Option<&MpAddress<'_>>) -> Vec<Addr> {
    let Some(a) = a else { return Vec::new() };
    a.iter().filter_map(convert_addr).collect()
}

fn convert_addr(a: &MpAddr<'_>) -> Option<Addr> {
    let email = a.address.as_ref()?.trim().to_string();
    if email.is_empty() {
        return None;
    }
    Some(Addr {
        name: a.name.as_ref().map(|n| n.trim().to_string()).filter(|n| !n.is_empty()),
        email,
    })
}

pub fn to_chrono(d: &mail_parser::DateTime) -> DateTime<Utc> {
    let offset_secs = (d.tz_hour as i32 * 3600 + d.tz_minute as i32 * 60)
        * if d.tz_before_gmt { -1 } else { 1 };
    chrono::FixedOffset::east_opt(offset_secs)
        .and_then(|tz| {
            tz.with_ymd_and_hms(
                d.year as i32,
                d.month as u32,
                d.day as u32,
                d.hour as u32,
                d.minute as u32,
                d.second as u32,
            )
            .single()
        })
        .map(|t| t.with_timezone(&Utc))
        .unwrap_or_else(Utc::now)
}

pub fn normalize_msgid(id: &str) -> String {
    id.trim().trim_start_matches('<').trim_end_matches('>').to_string()
}

fn first_msgid(v: &mail_parser::HeaderValue<'_>) -> Option<String> {
    msgid_list(v).into_iter().next()
}

fn msgid_list(v: &mail_parser::HeaderValue<'_>) -> Vec<String> {
    match v {
        mail_parser::HeaderValue::Text(t) => vec![normalize_msgid(t)],
        mail_parser::HeaderValue::TextList(l) => l.iter().map(|t| normalize_msgid(t)).collect(),
        _ => Vec::new(),
    }
}

/// True when a stored preview would render as nothing: empty, or the zero-width
/// padding that older builds copied straight out of a preheader.
pub fn is_blank_preview(preview: &str) -> bool {
    preview.chars().all(|c| is_invisible(c) || c.is_whitespace())
}

/// Marketing mail opens with a run of zero-width characters, so that the
/// preheader a mail client shows is whatever the sender chose. Counting them as
/// text fills the preview with nothing visible.
fn is_invisible(ch: char) -> bool {
    matches!(ch, '\u{200b}'..='\u{200f}' | '\u{2060}'..='\u{2064}' | '\u{feff}' | '\u{00ad}')
        || ch.is_control()
}

fn snippet(text: &str) -> String {
    let mut out = String::with_capacity(PREVIEW_LEN);
    let mut last_space = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('>') || line.starts_with("--") {
            continue;
        }
        for ch in line.chars() {
            if out.chars().count() >= PREVIEW_LEN {
                return out;
            }
            if is_invisible(ch) {
                continue;
            }
            if ch.is_whitespace() {
                if !last_space && !out.is_empty() {
                    out.push(' ');
                    last_space = true;
                }
            } else {
                out.push(ch);
                last_space = false;
            }
        }
        if !out.is_empty() && !last_space {
            out.push(' ');
            last_space = true;
        }
    }
    out.trim_end().to_string()
}

pub fn is_inline(part: &mail_parser::MessagePart<'_>) -> bool {
    part.content_disposition().is_some_and(|d| d.is_inline())
        || matches!(part.body, PartType::InlineBinary(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_skips_preheader_padding() {
        let padded = "\u{200c}\u{a0}".repeat(60) + "Higher open rates, no extra cost.";
        assert_eq!(snippet(&padded), "Higher open rates, no extra cost.");
    }

    #[test]
    fn preview_collapses_runs_of_whitespace() {
        assert_eq!(snippet("  one\n\n   two  \tthree "), "one two three");
    }
}
