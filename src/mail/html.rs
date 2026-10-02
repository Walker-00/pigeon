use std::collections::BTreeSet;

use regex::Regex;
use std::sync::LazyLock;

static TRACKER_IMG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<img[^>]*?(?:width|height)\s*=\s*["']?[01]["']?[^>]*?>"#).unwrap()
});
static SCRIPT_OR_STYLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<(script|style)\b.*?</\1\s*>").unwrap());
static REMOTE_SRC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(<[^>]*\b(?:src|background)\s*=\s*["']?)(https?://[^"'\s>]+)"#).unwrap());
static LINK_HREF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)href\s*=\s*["']?(https?://[^"'\s>]+)"#).unwrap());

#[derive(Debug, Clone, Default)]
pub struct HtmlReport {
    pub remote_resources: usize,
    pub trackers_stripped: usize,
    pub links: Vec<String>,
}

pub fn to_text(html: &str, width: usize) -> String {
    html2text::from_read(html.as_bytes(), width.max(20))
        .unwrap_or_else(|_| strip_tags(html))
}

/// Renders HTML with remote content neutralised. Mail is hostile input: loading
/// a remote image confirms the address to the sender, so nothing is fetched and
/// 1x1 tracking pixels are removed outright rather than shown as empty boxes.
pub fn render_safe(html: &str, width: usize, allow_remote: bool) -> (String, HtmlReport) {
    let mut report = HtmlReport::default();

    let cleaned = SCRIPT_OR_STYLE.replace_all(html, "");

    let before = cleaned.matches("<img").count();
    let cleaned = TRACKER_IMG.replace_all(&cleaned, "");
    report.trackers_stripped = before.saturating_sub(cleaned.matches("<img").count());

    report.remote_resources = REMOTE_SRC.find_iter(&cleaned).count();
    let cleaned = if allow_remote {
        cleaned
    } else {
        REMOTE_SRC.replace_all(&cleaned, "${1}blocked:")
    };

    let mut seen = BTreeSet::new();
    for c in LINK_HREF.captures_iter(&cleaned) {
        let url = c[1].to_string();
        if seen.insert(url.clone()) {
            report.links.push(url);
        }
    }

    (to_text(&cleaned, width), report)
}

fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}
