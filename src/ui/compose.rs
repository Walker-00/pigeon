use std::io::Write;
use std::path::{Path, PathBuf};

use crate::mail::compose::{Draft, ForwardMode, ReplyMode, parse_address_list};
use crate::store::model::Addr;
use crate::sync::Command;

use super::app::App;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposeKind {
    New,
    Reply { all: bool },
    Forward { attached: bool },
    EditAsNew,
}

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("no account is configured to send from")]
    NoAccount,
    #[error("select a message first")]
    NoMessage,
    #[error("the message body has not been downloaded yet; wait a moment and try again")]
    NoBody,
    #[error("could not write the draft file: {0}")]
    Io(#[from] std::io::Error),
    #[error("the editor exited with {0}")]
    EditorFailed(String),
    #[error("no editor found; set $EDITOR or general.editor")]
    NoEditor,
    #[error(transparent)]
    Build(#[from] crate::mail::compose::ComposeError),
}

/// Suspends the TUI, hands the draft to the user's editor, and queues the
/// result. Editing happens in a real editor rather than an in-app text widget
/// so that existing muscle memory, spell-checking and templates all keep
/// working.
pub fn compose_and_queue(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    kind: ComposeKind,
) -> Result<Option<String>, ComposeError> {
    let mut draft = seed_draft(app, kind)?;
    let path = write_draft_file(&draft)?;

    ratatui::restore();
    let status = launch_editor(app, &path);
    let _ = terminal.clear();
    app.redraw = true;

    status?;

    let edited = std::fs::read_to_string(&path)?;
    let _ = std::fs::remove_file(&path);

    if !apply_edits(&mut draft, &edited) {
        return Ok(None);
    }
    if draft.to.is_empty() && draft.cc.is_empty() && draft.bcc.is_empty() {
        return Ok(None);
    }

    let recipients = draft.all_recipients().len();
    app.send(Command::Send(Box::new(draft)));
    Ok(Some(format!(
        "queued for {recipients} recipient{}",
        if recipients == 1 { "" } else { "s" }
    )))
}

fn seed_draft(app: &App, kind: ComposeKind) -> Result<Draft, ComposeError> {
    let account = app
        .current_folder()
        .and_then(|f| app.config.account(&f.account))
        .or_else(|| app.config.primary_account())
        .ok_or(ComposeError::NoAccount)?;

    let from = Addr {
        name: account.display_name.clone(),
        email: account.address.clone(),
    };
    let mut draft = Draft::new(&account.name, from);
    draft.sign = account.pgp.enabled && account.pgp.sign_by_default;

    if let Some(sig) = account.signature_text() {
        draft.body = format!("\n\n-- \n{}", sig.trim_end());
    }

    let own: Vec<String> = std::iter::once(account.address.clone())
        .chain(account.aliases.iter().cloned())
        .collect();

    match kind {
        ComposeKind::New => {}
        ComposeKind::Reply { all } => {
            let msg = app.selected_message().ok_or(ComposeError::NoMessage)?;
            let body = app
                .body
                .as_ref()
                .map(|b| b.plain_text())
                .ok_or(ComposeError::NoBody)?;
            let signature = draft.body.clone();
            draft.reply_to_envelope(
                msg,
                &body,
                if all { ReplyMode::All } else { ReplyMode::Sender },
                &own,
            );
            draft.body = format!("\n\n{}{signature}", draft.body);
        }
        ComposeKind::Forward { attached } => {
            let msg = app.selected_message().ok_or(ComposeError::NoMessage)?;
            let raw = app.body_raw.clone().ok_or(ComposeError::NoBody)?;
            let body = app.body.as_ref().map(|b| b.plain_text()).unwrap_or_default();
            let signature = draft.body.clone();
            draft.forward_envelope(
                msg,
                &body,
                if attached { ForwardMode::Attached } else { ForwardMode::Inline },
                &raw,
            );
            draft.body = format!("{}{signature}", draft.body);
        }
        ComposeKind::EditAsNew => {
            let msg = app.selected_message().ok_or(ComposeError::NoMessage)?;
            let body = app.body.as_ref().map(|b| b.plain_text()).unwrap_or_default();
            draft.to = msg.to.clone();
            draft.cc = msg.cc.clone();
            draft.subject = msg.subject.clone();
            draft.body = body;
        }
    }

    Ok(draft)
}

const SEPARATOR: &str = "--- write your message below this line ---";

fn write_draft_file(draft: &Draft) -> Result<PathBuf, ComposeError> {
    let dir = std::env::temp_dir().join(format!("pigeon-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    let path = dir.join(format!("draft-{}.eml", uuid::Uuid::new_v4()));
    let mut f = std::fs::File::create(&path)?;

    let list = |v: &[Addr]| v.iter().map(|a| a.encoded()).collect::<Vec<_>>().join(", ");

    writeln!(f, "To: {}", list(&draft.to))?;
    writeln!(f, "Cc: {}", list(&draft.cc))?;
    writeln!(f, "Bcc: {}", list(&draft.bcc))?;
    writeln!(f, "Subject: {}", draft.subject)?;
    writeln!(f, "Attach:")?;
    writeln!(f, "Sign: {}", yes_no(draft.sign))?;
    writeln!(f, "Encrypt: {}", yes_no(draft.encrypt))?;
    writeln!(f, "{SEPARATOR}")?;
    write!(f, "{}", draft.body)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

fn truthy(s: &str) -> bool {
    matches!(s.trim().to_ascii_lowercase().as_str(), "yes" | "y" | "true" | "1" | "on")
}

/// Returns false when the user left the draft untouched or emptied the body,
/// which is the conventional way to abort a message from an editor.
fn apply_edits(draft: &mut Draft, text: &str) -> bool {
    let Some((head, body)) = text.split_once(SEPARATOR) else {
        return false;
    };

    draft.to.clear();
    draft.cc.clear();
    draft.bcc.clear();
    draft.attachments.clear();

    for line in head.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "to" => draft.to = parse_address_list(value),
            "cc" => draft.cc = parse_address_list(value),
            "bcc" => draft.bcc = parse_address_list(value),
            "subject" => draft.subject = value.to_string(),
            "sign" => draft.sign = truthy(value),
            "encrypt" => draft.encrypt = truthy(value),
            "attach" => {
                for p in value.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    if let Some(a) = load_attachment(Path::new(p)) {
                        draft.attachments.push(a);
                    }
                }
            }
            _ => {}
        }
    }

    draft.body = body.trim_start_matches('\n').to_string();
    !draft.body.trim().is_empty()
}

fn load_attachment(path: &Path) -> Option<crate::mail::compose::DraftAttachment> {
    let expanded = PathBuf::from(shellexpand::tilde(&path.to_string_lossy()).into_owned());
    let data = std::fs::read(&expanded).ok()?;
    let name = expanded.file_name()?.to_string_lossy().into_owned();
    let mime = mime_guess::from_path(&expanded)
        .first_or_octet_stream()
        .to_string();
    Some(crate::mail::compose::DraftAttachment { name, mime, data, inline_cid: None })
}

fn launch_editor(app: &App, path: &Path) -> Result<(), ComposeError> {
    let editor = app
        .config
        .general
        .editor
        .clone()
        .or_else(|| std::env::var("VISUAL").ok())
        .or_else(|| std::env::var("EDITOR").ok())
        .ok_or(ComposeError::NoEditor)?;

    let mut parts = editor.split_whitespace();
    let program = parts.next().ok_or(ComposeError::NoEditor)?;

    let status = std::process::Command::new(program)
        .args(parts)
        .arg(path)
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(ComposeError::EditorFailed(status.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_edited_headers_and_body() {
        let mut d = Draft::default();
        let text = format!(
            "To: a@example.org, B <b@example.org>\nCc:\nBcc:\nSubject: hi\nSign: yes\nEncrypt: no\n{SEPARATOR}\n\nhello there\n"
        );
        assert!(apply_edits(&mut d, &text));
        assert_eq!(d.to.len(), 2);
        assert_eq!(d.subject, "hi");
        assert!(d.sign);
        assert!(!d.encrypt);
        assert_eq!(d.body.trim(), "hello there");
    }

    #[test]
    fn empty_body_cancels() {
        let mut d = Draft::default();
        let text = format!("To: a@example.org\nSubject: x\n{SEPARATOR}\n\n   \n");
        assert!(!apply_edits(&mut d, &text));
    }
}
