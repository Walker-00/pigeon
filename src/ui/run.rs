use std::io::Write;
use std::time::Duration;

use ratatui::crossterm::event::{
    self, Event as TermEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEventKind,
};
use tokio::sync::mpsc::{self, UnboundedReceiver};

use crate::store::model::Flags;
use crate::sync::{Command, Event as SyncEvent};

use super::app::{App, ConfirmAction, InputMode, ListRow, Overlay, Pane};
use super::draw;
use super::keys::Action;

const TICK: Duration = Duration::from_millis(250);

pub async fn run(app: App, events: UnboundedReceiver<SyncEvent>) -> anyhow::Result<()> {
    let mut terminal = ratatui::try_init()?;
    let result = run_on(&mut terminal, app, events).await;
    ratatui::restore();
    result
}

/// Runs the reader on a terminal the caller already owns, so first-run setup and
/// the reader share one screen instead of tearing it down in between.
pub async fn run_on(
    terminal: &mut ratatui::DefaultTerminal,
    mut app: App,
    mut events: UnboundedReceiver<SyncEvent>,
) -> anyhow::Result<()> {
    if app.config.ui.mouse {
        let _ = ratatui::crossterm::execute!(
            std::io::stdout(),
            ratatui::crossterm::event::EnableMouseCapture
        );
    }

    let keys = spawn_input_reader();
    let result = event_loop(terminal, &mut app, &mut events, keys).await;

    if app.config.ui.mouse {
        let _ = ratatui::crossterm::execute!(
            std::io::stdout(),
            ratatui::crossterm::event::DisableMouseCapture
        );
    }
    result
}

/// crossterm's reader is blocking, so it lives on its own thread and feeds the
/// async loop through a channel. This keeps redraws responsive to sync events
/// even while no key is pressed.
pub(crate) fn spawn_input_reader() -> UnboundedReceiver<TermEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        loop {
            match event::poll(Duration::from_millis(200)) {
                Ok(true) => match event::read() {
                    Ok(e) => {
                        if tx.send(e).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                Ok(false) => {
                    if tx.is_closed() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    events: &mut UnboundedReceiver<SyncEvent>,
    mut keys: UnboundedReceiver<TermEvent>,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(TICK);

    loop {
        if app.redraw {
            terminal.draw(|f| draw::draw(f, app))?;
            app.redraw = false;
        }
        if app.should_quit {
            return Ok(());
        }

        tokio::select! {
            Some(term) = keys.recv() => {
                match term {
                    TermEvent::Key(k) if k.kind == KeyEventKind::Press => {
                        handle_key(terminal, app, k)?;
                    }
                    TermEvent::Mouse(m) => handle_mouse(app, m.kind),
                    TermEvent::Resize(..) => app.redraw = true,
                    _ => {}
                }
            }
            Some(evt) = events.recv() => apply_sync_event(app, evt),
            _ = ticker.tick() => app.expire_notice(),
        }
    }
}

fn handle_mouse(app: &mut App, kind: MouseEventKind) {
    match kind {
        MouseEventKind::ScrollDown => match app.pane {
            Pane::Preview => {
                app.body_scroll = app.body_scroll.saturating_add(3);
                app.redraw = true;
            }
            _ => app.move_list(1),
        },
        MouseEventKind::ScrollUp => match app.pane {
            Pane::Preview => {
                app.body_scroll = app.body_scroll.saturating_sub(3);
                app.redraw = true;
            }
            _ => app.move_list(-1),
        },
        _ => {}
    }
}

fn apply_sync_event(app: &mut App, evt: SyncEvent) {
    match evt {
        SyncEvent::Status { account, status } => {
            app.status.insert(account, status);
        }
        SyncEvent::Folders { .. } => app.reload_folders(),
        SyncEvent::Envelopes { account, folder, .. } | SyncEvent::Removed { account, folder, .. } => {
            if app
                .current_folder()
                .is_some_and(|f| f.account == account && f.name == folder)
            {
                let sel = app.list_sel;
                app.reload_messages();
                app.list_sel = sel.min(app.rows.len().saturating_sub(1));
            }
            app.reload_folders();
        }
        SyncEvent::FlagsChanged { key, .. } => {
            if let Some(m) = app
                .messages
                .iter_mut()
                .find(|m| m.account == key.account && m.folder == key.folder && m.uid == key.uid)
                && let Ok(Some(fresh)) = app.store.envelope(&key.account, &key.folder, key.uid)
            {
                *m = fresh;
            }
            app.rebuild_rows();
        }
        SyncEvent::Body { key, raw } => app.set_body(key, raw),
        SyncEvent::NewMail { account, folder, envelopes } => {
            let n = envelopes.len();
            app.notify(format!("{n} new message{} in {account}/{folder}", if n == 1 { "" } else { "s" }));
            if app.config.general.notify {
                crate::notify::desktop_new_mail(&envelopes);
            }
            app.reload_folders();
        }
        SyncEvent::OutboxChanged { pending } => {
            app.outbox_len = pending.len();
            app.redraw = true;
        }
        SyncEvent::Sent { .. } => app.notify("message sent"),
        SyncEvent::SendFailed { message, .. } => app.notify(&format!("send failed: {message}")),
        SyncEvent::Notice(m) => app.notify(m),
        SyncEvent::Error { account, message } => match account {
            Some(a) => app.warn(format!("{a}: {message}")),
            None => app.warn(message),
        },
    }
    app.redraw = true;
}

fn handle_key(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    k: KeyEvent,
) -> anyhow::Result<()> {
    if app.input_mode != InputMode::None {
        return handle_input_key(app, k);
    }
    if app.overlay != Overlay::None {
        return handle_overlay_key(app, k);
    }
    let Some(action) = app.keymap.get(k) else {
        return Ok(());
    };
    dispatch(terminal, app, action)
}

fn handle_input_key(app: &mut App, k: KeyEvent) -> anyhow::Result<()> {
    match k.code {
        KeyCode::Esc => {
            app.end_input();
            app.overlay = Overlay::None;
        }
        KeyCode::Enter => {
            let text = app.input.clone();
            let mode = app.input_mode;
            let pending = app.pending_secret.clone();
            app.end_input();
            match mode {
                InputMode::Search => app.apply_search(&text),
                InputMode::ExCommand => run_ex_command(app, &text),
                InputMode::Secret => {
                    if let Some((account, purpose)) = pending {
                        app.save_password(account, purpose, text);
                    }
                }
                InputMode::Filter | InputMode::None => {}
            }
        }
        KeyCode::Backspace => app.input_backspace(),
        KeyCode::Left => {
            app.input_cursor = app.input_cursor.saturating_sub(1);
            app.redraw = true;
        }
        KeyCode::Right => {
            app.input_cursor = (app.input_cursor + 1).min(app.input.chars().count());
            app.redraw = true;
        }
        KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => {
            app.input.clear();
            app.input_cursor = 0;
            app.redraw = true;
        }
        KeyCode::Char(c) => app.input_insert(c),
        _ => {}
    }
    Ok(())
}

fn handle_overlay_key(app: &mut App, k: KeyEvent) -> anyhow::Result<()> {
    let overlay = app.overlay.clone();

    if let Overlay::Confirm { action, .. } = overlay {
        match k.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                app.overlay = Overlay::None;
                confirm(app, action);
            }
            _ => app.overlay = Overlay::None,
        }
        app.redraw = true;
        return Ok(());
    }

    match k.code {
        KeyCode::Esc | KeyCode::Char('q') => {
            app.overlay = Overlay::None;
            app.overlay_sel = 0;
            app.end_input();
        }
        KeyCode::Down | KeyCode::Char('j') => app.overlay_sel = app.overlay_sel.saturating_add(1),
        KeyCode::Up | KeyCode::Char('k') => app.overlay_sel = app.overlay_sel.saturating_sub(1),
        KeyCode::Enter => return activate_overlay(app),
        KeyCode::Backspace => app.input_backspace(),
        KeyCode::Char(c)
            if matches!(overlay, Overlay::Palette | Overlay::FolderPicker { .. }) =>
        {
            app.input_insert(c);
            app.overlay_sel = 0;
        }
        KeyCode::Char('w') if overlay == Overlay::Attachments => save_attachment(app),
        KeyCode::Char('O') if overlay == Overlay::Attachments => open_attachment(app),
        _ => {}
    }
    app.redraw = true;
    Ok(())
}

fn activate_overlay(app: &mut App) -> anyhow::Result<()> {
    match app.overlay.clone() {
        Overlay::Palette => {
            let matches = draw::palette_matches(app);
            let picked = matches.get(app.overlay_sel).map(|(_, a)| *a);
            app.overlay = Overlay::None;
            app.overlay_sel = 0;
            app.end_input();
            if let Some(a) = picked {
                return dispatch_no_terminal(app, a);
            }
        }
        Overlay::FolderPicker { copy } => {
            let choices = draw::picker_folders(app);
            let target = choices.get(app.overlay_sel).cloned();
            app.overlay = Overlay::None;
            app.overlay_sel = 0;
            app.end_input();
            if let Some(to) = target {
                let keys = app.target_keys();
                if keys.is_empty() {
                    return Ok(());
                }
                let n = keys.len();
                app.send(if copy {
                    Command::Copy { keys, to: to.clone() }
                } else {
                    Command::Move { keys, to: to.clone() }
                });
                app.marked.clear();
                app.notify(format!(
                    "{} message{} queued to {to}",
                    n,
                    if n == 1 { "" } else { "s" }
                ));
                app.reload_messages();
            }
        }
        Overlay::Links => {
            let links = app.links();
            if let Some(url) = links.get(app.overlay_sel) {
                match open::that_detached(url) {
                    Ok(()) => app.notify(format!("opened {}", draw::truncate(url, 50))),
                    Err(e) => app.warn(format!("could not open link: {e}")),
                }
            }
        }
        Overlay::Attachments => open_attachment(app),
        _ => app.overlay = Overlay::None,
    }
    Ok(())
}

fn confirm(app: &mut App, action: ConfirmAction) {
    match action {
        ConfirmAction::Quit => app.should_quit = true,
        ConfirmAction::DeletePermanent(keys) => {
            let n = keys.len();
            app.send(Command::Delete { keys, permanent: true });
            app.marked.clear();
            app.notify(format!("{n} message{} deleted", if n == 1 { "" } else { "s" }));
            app.reload_messages();
        }
        ConfirmAction::MarkAllRead => {
            let keys: Vec<_> = app
                .messages
                .iter()
                .filter(|m| m.is_unread())
                .map(|m| m.key())
                .collect();
            let n = keys.len();
            if !keys.is_empty() {
                app.send(Command::SetFlags {
                    keys,
                    add: Flags::SEEN,
                    remove: Flags::EMPTY,
                });
            }
            app.notify(format!("{n} message{} marked read", if n == 1 { "" } else { "s" }));
        }
    }
}

fn dispatch_no_terminal(app: &mut App, action: Action) -> anyhow::Result<()> {
    match action {
        Action::Compose | Action::Reply | Action::ReplyAll | Action::Forward
        | Action::ForwardAttached | Action::EditAsNew => {
            app.warn("start that from the main view, not the palette");
            Ok(())
        }
        other => dispatch_inner(app, other),
    }
}

fn dispatch(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    action: Action,
) -> anyhow::Result<()> {
    use super::compose::{ComposeKind, compose_and_queue};

    let kind = match action {
        Action::Compose => Some(ComposeKind::New),
        Action::Reply => Some(ComposeKind::Reply { all: false }),
        Action::ReplyAll => Some(ComposeKind::Reply { all: true }),
        Action::Forward => Some(ComposeKind::Forward { attached: false }),
        Action::ForwardAttached => Some(ComposeKind::Forward { attached: true }),
        Action::EditAsNew => Some(ComposeKind::EditAsNew),
        _ => None,
    };

    if let Some(kind) = kind {
        match compose_and_queue(terminal, app, kind) {
            Ok(Some(msg)) => app.notify(msg),
            Ok(None) => app.notify("compose cancelled"),
            Err(e) => app.warn(e.to_string()),
        }
        app.redraw = true;
        return Ok(());
    }

    dispatch_inner(app, action)
}

fn dispatch_inner(app: &mut App, action: Action) -> anyhow::Result<()> {
    let page = 10;

    match action {
        Action::Quit => {
            if app.config.ui.confirm_quit {
                app.overlay = Overlay::Confirm {
                    prompt: "Quit pigeon?".into(),
                    action: ConfirmAction::Quit,
                };
            } else {
                app.should_quit = true;
            }
        }
        Action::ForceQuit => app.should_quit = true,
        Action::Help => {
            app.overlay = if app.overlay == Overlay::Help { Overlay::None } else { Overlay::Help };
            app.overlay_sel = 0;
        }
        Action::CommandPalette => {
            app.overlay = Overlay::Palette;
            app.overlay_sel = 0;
            app.begin_input(InputMode::None, "");
            app.input.clear();
        }
        Action::ExCommand => app.begin_input(InputMode::ExCommand, ""),

        Action::NextPane => app.pane = app.pane.next(),
        Action::PrevPane => app.pane = app.pane.prev(),
        Action::FocusFolders => app.pane = Pane::Folders,
        Action::FocusList => app.pane = Pane::List,
        Action::FocusPreview => app.pane = Pane::Preview,

        Action::Down => move_in_pane(app, 1),
        Action::Up => move_in_pane(app, -1),
        Action::PageDown => move_in_pane(app, page),
        Action::PageUp => move_in_pane(app, -page),
        Action::Top => match app.pane {
            Pane::Preview => app.body_scroll = 0,
            Pane::Folders => {
                app.folder_sel = 0;
                app.reload_messages();
            }
            Pane::List => app.jump_list(0),
        },
        Action::Bottom => match app.pane {
            Pane::Preview => app.body_scroll = app.body_scroll.saturating_add(1000),
            Pane::Folders => {
                app.folder_sel = app.folders.len().saturating_sub(1);
                app.reload_messages();
            }
            Pane::List => app.jump_list(usize::MAX),
        },
        Action::NextUnread => app.next_unread(true),
        Action::PrevUnread => app.next_unread(false),
        Action::NextThread => jump_thread(app, 1),
        Action::PrevThread => jump_thread(app, -1),

        Action::Open => match app.pane {
            Pane::Folders => {
                app.pane = Pane::List;
                app.reload_messages();
            }
            _ => {
                app.pane = Pane::Preview;
                app.on_selection_changed();
            }
        },
        Action::Back => {
            if app.query.is_some() {
                app.query = None;
                app.query_text.clear();
                app.reload_messages();
            } else {
                app.pane = Pane::List;
            }
        }
        Action::ToggleThread => app.toggle_thread(),
        Action::ToggleSelect => {
            app.toggle_mark();
            app.move_list(1);
        }
        Action::SelectAll => {
            app.marked = app.messages.iter().map(|m| m.key()).collect();
            app.notify(format!("{} marked", app.marked.len()));
        }
        Action::ClearSelection => {
            app.marked.clear();
            app.notify("selection cleared");
        }
        Action::InvertSelection => {
            let all: std::collections::BTreeSet<_> =
                app.messages.iter().map(|m| m.key()).collect();
            app.marked = all.difference(&app.marked).cloned().collect();
            app.notify(format!("{} marked", app.marked.len()));
        }

        Action::ToggleRead => {
            let keys = app.target_keys();
            let currently_read = app
                .selected_message()
                .is_some_and(|m| m.flags.contains(Flags::SEEN));
            if !keys.is_empty() {
                app.send(Command::SetFlags {
                    keys,
                    add: if currently_read { Flags::EMPTY } else { Flags::SEEN },
                    remove: if currently_read { Flags::SEEN } else { Flags::EMPTY },
                });
            }
        }
        Action::ToggleFlag => {
            let keys = app.target_keys();
            let flagged = app
                .selected_message()
                .is_some_and(|m| m.flags.contains(Flags::FLAGGED));
            if !keys.is_empty() {
                app.send(Command::SetFlags {
                    keys,
                    add: if flagged { Flags::EMPTY } else { Flags::FLAGGED },
                    remove: if flagged { Flags::FLAGGED } else { Flags::EMPTY },
                });
            }
        }
        Action::MarkAllRead => {
            app.overlay = Overlay::Confirm {
                prompt: "Mark every message in this folder as read?".into(),
                action: ConfirmAction::MarkAllRead,
            };
        }
        Action::Delete => {
            let keys = app.target_keys();
            if !keys.is_empty() {
                let n = keys.len();
                app.send(Command::Delete { keys, permanent: false });
                app.marked.clear();
                app.notify(format!("{n} message{} moved to trash", if n == 1 { "" } else { "s" }));
                app.reload_messages();
            }
        }
        Action::DeletePermanent => {
            let keys = app.target_keys();
            if !keys.is_empty() {
                app.overlay = Overlay::Confirm {
                    prompt: format!(
                        "Permanently delete {} message{}? This cannot be undone.",
                        keys.len(),
                        if keys.len() == 1 { "" } else { "s" }
                    ),
                    action: ConfirmAction::DeletePermanent(keys),
                };
            }
        }
        Action::Archive => move_to_role(app, crate::store::model::FolderRole::Archive),
        Action::Junk => move_to_role(app, crate::store::model::FolderRole::Spam),
        Action::Move => {
            app.overlay = Overlay::FolderPicker { copy: false };
            app.overlay_sel = 0;
            app.input.clear();
        }
        Action::Copy => {
            app.overlay = Overlay::FolderPicker { copy: true };
            app.overlay_sel = 0;
            app.input.clear();
        }

        Action::Search => app.begin_input(InputMode::Search, &app.query_text.clone()),
        Action::SearchServer => {
            app.warn("server-side search is only available while an account is connected")
        }
        Action::ClearSearch => {
            app.query = None;
            app.query_text.clear();
            app.reload_messages();
            app.notify("search cleared");
        }
        Action::NextMatch => app.next_unread(true),
        Action::PrevMatch => app.next_unread(false),

        Action::Sync => {
            if let Some(f) = app.current_folder().cloned() {
                app.send(Command::SyncFolder { account: f.account, folder: f.name });
                app.notify("syncing this folder");
            }
        }
        Action::SyncAll => {
            app.send(Command::SyncAll);
            app.notify("syncing all accounts");
        }
        Action::ToggleHtml => {
            app.render.prefer_html = !app.render.prefer_html;
            rerender_body(app);
        }
        Action::ToggleQuoted => {
            app.render.show_quoted = !app.render.show_quoted;
            app.redraw = true;
        }
        Action::ToggleHeaders => {
            app.render.show_headers = !app.render.show_headers;
            app.redraw = true;
        }
        Action::ToggleRemoteImages => {
            app.render.allow_remote = !app.render.allow_remote;
            let on = app.render.allow_remote;
            rerender_body(app);
            app.notify(if on {
                "remote images allowed for this message"
            } else {
                "remote images blocked"
            });
        }
        Action::ToggleThreading => {
            app.threading = !app.threading;
            app.rebuild_rows();
        }
        Action::ToggleSidebar => {
            app.sidebar = !app.sidebar;
            app.redraw = true;
        }
        Action::ToggleOrder => {
            app.sort = app.sort.cycle();
            let label = app.sort.label();
            app.reload_messages();
            app.notify(format!("sorted by {label}"));
        }

        Action::Attachments => {
            app.overlay = Overlay::Attachments;
            app.overlay_sel = 0;
        }
        Action::SaveAttachment => save_attachment(app),
        Action::OpenAttachment => open_attachment(app),
        Action::OpenLink => {
            app.overlay = Overlay::Links;
            app.overlay_sel = 0;
        }
        Action::CopyAddress => {
            if let Some(addr) = app.selected_message().and_then(|m| m.from.first().cloned()) {
                copy_to_clipboard(&addr.email);
                app.notify(format!("copied {}", addr.email));
            }
        }
        Action::ViewSource => {
            app.overlay = Overlay::Source;
            app.overlay_sel = 0;
        }

        Action::DecryptMessage | Action::VerifySignature => {
            app.warn("configure [account.pgp] with a secret key to use OpenPGP")
        }
        Action::ToggleSign | Action::ToggleEncrypt | Action::ImportKey => {
            app.warn("OpenPGP is not configured for this account")
        }

        Action::Outbox => {
            app.overlay = Overlay::Outbox;
            app.overlay_sel = 0;
        }
        Action::FlushOutbox => {
            app.send(Command::FlushOutbox);
            app.notify("retrying queued mail");
        }
        Action::CycleTheme => app.cycle_theme(),
        Action::Refresh => app.redraw = true,

        // Handled in `dispatch`, which has the terminal handle needed to
        // suspend the TUI while the external editor runs.
        Action::Compose
        | Action::Reply
        | Action::ReplyAll
        | Action::Forward
        | Action::ForwardAttached
        | Action::EditAsNew
        | Action::SaveDraft => app.warn("compose is only available from the message list"),
    }

    app.redraw = true;
    Ok(())
}

fn move_in_pane(app: &mut App, delta: isize) {
    match app.pane {
        Pane::Folders => app.select_folder(delta.signum()),
        Pane::List => app.move_list(delta),
        Pane::Preview => {
            app.body_scroll = if delta < 0 {
                app.body_scroll.saturating_sub(delta.unsigned_abs() as u16)
            } else {
                app.body_scroll.saturating_add(delta as u16)
            };
        }
    }
}

fn jump_thread(app: &mut App, dir: isize) {
    let len = app.rows.len();
    if len == 0 {
        return;
    }
    let mut i = app.list_sel as isize;
    loop {
        i += dir;
        if i < 0 || i as usize >= len {
            return;
        }
        if matches!(app.rows[i as usize], ListRow::Thread { .. }) {
            app.jump_list(i as usize);
            return;
        }
    }
}

fn move_to_role(app: &mut App, role: crate::store::model::FolderRole) {
    let Some(current) = app.current_folder().cloned() else { return };
    let target = app
        .folders
        .iter()
        .find(|f| f.account == current.account && f.role == Some(role))
        .map(|f| f.name.clone());

    let Some(to) = target else {
        app.warn(format!("this account has no {role:?} folder"));
        return;
    };

    let keys = app.target_keys();
    if keys.is_empty() {
        return;
    }
    let n = keys.len();
    app.send(Command::Move { keys, to: to.clone() });
    app.marked.clear();
    app.notify(format!("{n} message{} → {to}", if n == 1 { "" } else { "s" }));
    app.reload_messages();
}

fn rerender_body(app: &mut App) {
    if let Some(raw) = app.body_raw.clone() {
        app.body = Some(crate::mail::body::render(&raw, &app.render));
    }
    app.redraw = true;
}

fn attachment_dir() -> std::path::PathBuf {
    directories::UserDirs::new()
        .and_then(|d| d.download_dir().map(|p| p.to_path_buf()))
        .unwrap_or_else(std::env::temp_dir)
}

fn save_attachment(app: &mut App) {
    let atts = app.attachments();
    let Some(att) = atts.get(app.overlay_sel).or_else(|| atts.first()) else {
        app.warn("this message has no attachments");
        return;
    };
    let Some(raw) = app.body_raw.clone() else {
        app.warn("the message body has not been downloaded yet");
        return;
    };
    let Some(data) = crate::mail::body::extract_part(&raw, &att.part_id) else {
        app.warn("that part could not be extracted");
        return;
    };

    let dir = attachment_dir();
    let path = unique_path(&dir, &sanitize_filename(&att.name));
    match std::fs::write(&path, &data) {
        Ok(()) => app.notify(format!("saved to {}", path.display())),
        Err(e) => app.warn(format!("could not save: {e}")),
    }
}

fn open_attachment(app: &mut App) {
    let atts = app.attachments();
    let Some(att) = atts.get(app.overlay_sel).or_else(|| atts.first()) else {
        app.warn("this message has no attachments");
        return;
    };
    let Some(raw) = app.body_raw.clone() else {
        app.warn("the message body has not been downloaded yet");
        return;
    };
    let Some(data) = crate::mail::body::extract_part(&raw, &att.part_id) else {
        app.warn("that part could not be extracted");
        return;
    };

    // Attachments are written to a private per-run directory rather than a
    // shared /tmp path, so another local user cannot read or swap the file.
    let dir = std::env::temp_dir().join(format!("pigeon-{}", std::process::id()));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        app.warn(format!("could not create a temporary directory: {e}"));
        return;
    }
    restrict(&dir);

    let path = unique_path(&dir, &sanitize_filename(&att.name));
    if let Err(e) = std::fs::write(&path, &data) {
        app.warn(format!("could not write the attachment: {e}"));
        return;
    }
    restrict(&path);

    match open::that_detached(&path) {
        Ok(()) => app.notify(format!("opened {}", att.name)),
        Err(e) => app.warn(format!("could not open: {e}")),
    }
}

#[cfg(unix)]
fn restrict(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn restrict(_path: &std::path::Path) {}

pub fn sanitize_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = cleaned.trim().trim_start_matches('.').to_string();
    if trimmed.is_empty() { "attachment".into() } else { trimmed }
}

fn unique_path(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let mut path = dir.join(name);
    let mut n = 1;
    while path.exists() {
        let stem = std::path::Path::new(name)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into());
        let ext = std::path::Path::new(name)
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        path = dir.join(format!("{stem}-{n}{ext}"));
        n += 1;
    }
    path
}

/// OSC 52 puts the text on the system clipboard through the terminal itself,
/// which avoids a dependency on an X11/Wayland client library and works over
/// ssh where a local clipboard helper would not.
fn copy_to_clipboard(text: &str) {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let mut out = std::io::stdout();
    let _ = write!(out, "\x1b]52;c;{encoded}\x07");
    let _ = out.flush();
}

fn run_ex_command(app: &mut App, line: &str) {
    let line = line.trim();
    let (cmd, rest) = line.split_once(' ').unwrap_or((line, ""));
    let rest = rest.trim();

    match cmd {
        "q" | "quit" => app.should_quit = true,
        "w" | "save" => app.send(Command::FlushOutbox),
        "sync" => {
            app.send(Command::SyncAll);
            app.notify("syncing");
        }
        "search" | "s" => app.apply_search(rest),
        "theme" => {
            if super::theme::Theme::all().contains(&rest) {
                app.theme = super::theme::Theme::by_name(rest);
                app.notify(format!("theme: {rest}"));
            } else {
                app.warn(format!("themes: {}", super::theme::Theme::all().join(", ")));
            }
        }
        "sort" => {
            app.sort = match rest {
                "date" | "date-desc" => super::app::Sort::DateDesc,
                "date-asc" | "oldest" => super::app::Sort::DateAsc,
                "subject" => super::app::Sort::SubjectAsc,
                "sender" | "from" => super::app::Sort::SenderAsc,
                "size" => super::app::Sort::SizeDesc,
                "unread" => super::app::Sort::UnreadFirst,
                _ => {
                    app.warn("sort: date | date-asc | subject | sender | size | unread");
                    return;
                }
            };
            app.reload_messages();
        }
        "mkdir" => {
            if rest.is_empty() {
                app.warn("usage: :mkdir <folder>");
                return;
            }
            if let Some(f) = app.current_folder().cloned() {
                app.send(Command::CreateFolder { account: f.account, name: rest.to_string() });
                app.notify(format!("creating {rest}"));
            }
        }
        "rmdir" => {
            if let Some(f) = app.current_folder().cloned() {
                let name = if rest.is_empty() { f.name.clone() } else { rest.to_string() };
                app.send(Command::DeleteFolder { account: f.account, name: name.clone() });
                app.notify(format!("deleting {name}"));
            }
        }
        "outbox" => {
            app.overlay = Overlay::Outbox;
            app.overlay_sel = 0;
        }
        "passwd" | "password" => start_password_prompt(app, rest, "imap"),
        "smtp-passwd" => start_password_prompt(app, rest, "smtp"),
        "accounts" => {
            let names = app.accounts();
            if names.is_empty() {
                app.warn("no accounts are configured");
            } else {
                app.notify(format!("accounts: {}", names.join(", ")));
            }
        }
        "help" => app.overlay = Overlay::Help,
        "" => {}
        other => app.warn(format!("unknown command `{other}` — try :help")),
    }
}

/// `:passwd [account]` — sets or replaces a stored password without leaving the
/// reader. The value is echoed as dots and never reaches the notice line.
fn start_password_prompt(app: &mut App, account: &str, purpose: &str) {
    let names = app.accounts();
    let chosen = if account.trim().is_empty() {
        app.current_folder()
            .map(|f| f.account.clone())
            .or_else(|| names.first().cloned())
    } else {
        names.iter().find(|n| *n == account.trim()).cloned()
    };

    let Some(chosen) = chosen else {
        if account.trim().is_empty() {
            app.warn("no accounts are configured");
        } else {
            app.warn(format!(
                "no account named `{}` — try one of: {}",
                account.trim(),
                names.join(", ")
            ));
        }
        return;
    };

    app.pending_secret = Some((chosen.clone(), purpose.to_string()));
    app.begin_input(InputMode::Secret, "");
    app.notify(format!("enter the {purpose} password for {chosen}"));
}
