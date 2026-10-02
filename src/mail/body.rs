use mail_parser::{Message, MessageParser, MimeHeaders, PartType};

use super::parse::is_inline;

use crate::store::model::AttachmentMeta;

#[derive(Debug, Clone)]
pub struct RenderOptions {
    pub width: usize,
    pub prefer_html: bool,
    pub allow_remote: bool,
    pub show_quoted: bool,
    pub show_headers: bool,
}

impl Default for RenderOptions {
    fn default() -> Self {
        Self {
            width: 100,
            prefer_html: false,
            allow_remote: false,
            show_quoted: true,
            show_headers: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Body,
    Quote(u8),
    Signature,
    Header,
    Separator,
}

#[derive(Debug, Clone)]
pub struct BodyLine {
    pub text: String,
    pub kind: LineKind,
}

#[derive(Debug, Clone, Default)]
pub struct RenderedBody {
    pub lines: Vec<BodyLine>,
    pub links: Vec<String>,
    pub attachments: Vec<AttachmentMeta>,
    pub used_html: bool,
    pub remote_blocked: usize,
    pub trackers_stripped: usize,
}

impl RenderedBody {
    pub fn plain_text(&self) -> String {
        self.lines
            .iter()
            .map(|l| l.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn visible_lines(&self, show_quoted: bool) -> impl Iterator<Item = &BodyLine> {
        self.lines
            .iter()
            .filter(move |l| show_quoted || !matches!(l.kind, LineKind::Quote(_)))
    }
}

pub fn render(raw: &[u8], opts: &RenderOptions) -> RenderedBody {
    let Some(msg) = MessageParser::default().parse(raw) else {
        return RenderedBody {
            lines: vec![BodyLine {
                text: "(this message could not be parsed)".into(),
                kind: LineKind::Body,
            }],
            ..Default::default()
        };
    };
    render_message(&msg, opts)
}

pub fn render_message(msg: &Message<'_>, opts: &RenderOptions) -> RenderedBody {
    let mut out = RenderedBody::default();

    let text = msg.body_text(0).map(|c| c.into_owned());
    let html = msg.body_html(0).map(|c| c.into_owned());

    let body = match (&text, &html, opts.prefer_html) {
        (_, Some(h), true) | (None, Some(h), _) => {
            let (rendered, report) = super::html::render_safe(h, opts.width, opts.allow_remote);
            out.used_html = true;
            out.links = report.links;
            out.remote_blocked = if opts.allow_remote { 0 } else { report.remote_resources };
            out.trackers_stripped = report.trackers_stripped;
            rendered
        }
        (Some(t), _, _) => t.clone(),
        (None, None, _) => String::new(),
    };

    out.lines = classify(&body);
    out.attachments = list_attachments(msg);
    out
}

fn list_attachments(msg: &Message<'_>) -> Vec<AttachmentMeta> {
    let mut out = Vec::new();
    for (idx, part) in msg.parts.iter().enumerate() {
        if matches!(part.body, PartType::Multipart(_)) {
            continue;
        }
        let named = part.attachment_name().map(|s| s.to_string());
        let is_body = matches!(part.body, PartType::Text(_) | PartType::Html(_)) && named.is_none();
        if is_body {
            continue;
        }
        let mime = part
            .content_type()
            .map(|c| match c.subtype() {
                Some(s) => format!("{}/{}", c.ctype(), s),
                None => c.ctype().to_string(),
            })
            .unwrap_or_else(|| "application/octet-stream".into());
        out.push(AttachmentMeta {
            name: named.unwrap_or_else(|| format!("part-{idx}")),
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

/// The filename the sender gave a part, read from the message itself because the
/// stored envelope of a header-only sync carries no attachment list.
pub fn part_name(raw: &[u8], part_id: &str) -> Option<String> {
    let idx: usize = part_id.parse().ok()?;
    let msg = MessageParser::default().parse(raw)?;
    msg.parts.get(idx)?.attachment_name().map(str::to_string)
}

pub fn extract_part(raw: &[u8], part_id: &str) -> Option<Vec<u8>> {
    let idx: usize = part_id.parse().ok()?;
    let msg = MessageParser::default().parse(raw)?;
    let part = msg.parts.get(idx)?;
    Some(match &part.body {
        PartType::Text(t) | PartType::Html(t) => t.as_bytes().to_vec(),
        PartType::Binary(b) | PartType::InlineBinary(b) => b.to_vec(),
        PartType::Message(m) => m.raw_message().to_vec(),
        PartType::Multipart(_) => return None,
    })
}

fn classify(body: &str) -> Vec<BodyLine> {
    let mut out = Vec::new();
    let mut in_signature = false;

    for line in body.lines() {
        if line.trim_end() == "--" || line.trim_end() == "-- " {
            in_signature = true;
            out.push(BodyLine { text: line.to_string(), kind: LineKind::Separator });
            continue;
        }
        if in_signature {
            out.push(BodyLine { text: line.to_string(), kind: LineKind::Signature });
            continue;
        }
        let depth = quote_depth(line);
        out.push(BodyLine {
            text: line.to_string(),
            kind: if depth > 0 { LineKind::Quote(depth) } else { LineKind::Body },
        });
    }

    while out.last().is_some_and(|l| l.text.trim().is_empty()) {
        out.pop();
    }
    out
}

fn quote_depth(line: &str) -> u8 {
    let mut depth = 0u8;
    for ch in line.chars() {
        match ch {
            '>' => depth = depth.saturating_add(1),
            ' ' | '\t' => {}
            _ => break,
        }
    }
    depth
}
