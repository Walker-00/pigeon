use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Margin, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Wrap,
};
use unicode_width::UnicodeWidthStr;

use crate::mail::body::LineKind;
use crate::store::model::{CryptoState, Envelope, Flags};

use super::app::{App, InputMode, ListRow, Overlay, Pane};
use super::keys::Action;

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    let input_active = app.input_mode != InputMode::None;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(u16::from(input_active)),
        ])
        .split(area);

    draw_header(f, app, chunks[0]);
    draw_main(f, app, chunks[1]);
    draw_status(f, app, chunks[2]);
    if input_active {
        draw_input(f, app, chunks[3]);
    }

    match app.overlay.clone() {
        Overlay::None => {}
        Overlay::Help => draw_help(f, app, area),
        Overlay::Palette => draw_palette(f, app, area),
        Overlay::Attachments => draw_attachments(f, app, area),
        Overlay::Links => draw_links(f, app, area),
        Overlay::Outbox => draw_outbox(f, app, area),
        Overlay::Source => draw_source(f, app, area),
        Overlay::FolderPicker { copy } => draw_folder_picker(f, app, area, copy),
        Overlay::Confirm { prompt, .. } => draw_confirm(f, app, area, &prompt),
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let folder = app
        .current_folder()
        .map(|f| format!("{}/{}", f.account, f.name))
        .unwrap_or_else(|| "no folder".into());

    let mut spans = vec![
        Span::styled(" pigeon ", Style::default().fg(t.accent).add_modifier(Modifier::BOLD)),
        Span::styled("│ ", t.dimmed()),
        Span::styled(folder, Style::default().fg(t.fg)),
    ];

    let unread = app.unread_total();
    if unread > 0 {
        spans.push(Span::styled(
            format!("  {unread} unread"),
            Style::default().fg(t.accent_alt),
        ));
    }
    if !app.query_text.is_empty() {
        spans.push(Span::styled(
            format!("  search: {}", truncate(&app.query_text, 40)),
            Style::default().fg(t.warning),
        ));
    }
    if !app.marked.is_empty() {
        spans.push(Span::styled(
            format!("  {} marked", app.marked.len()),
            Style::default().fg(t.success),
        ));
    }

    f.render_widget(Paragraph::new(Line::from(spans)).style(t.base()), area);
}

fn draw_main(f: &mut Frame, app: &mut App, area: Rect) {
    let sidebar_width = if app.sidebar {
        app.config.ui.sidebar_width.clamp(12, area.width / 2)
    } else {
        0
    };

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(sidebar_width), Constraint::Min(20)])
        .split(area);

    if app.sidebar {
        draw_folders(f, app, cols[0]);
    }

    if app.config.ui.preview {
        let pct = app.config.ui.list_height_pct.clamp(20, 80);
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(pct), Constraint::Min(5)])
            .split(cols[1]);
        draw_list(f, app, rows[0]);
        draw_preview(f, app, rows[1]);
    } else {
        draw_list(f, app, cols[1]);
    }
}

fn pane_block<'a>(app: &App, title: &'a str, pane: Pane) -> Block<'a> {
    let focused = app.pane == pane;
    Block::default()
        .borders(Borders::ALL)
        .border_type(if focused { BorderType::Thick } else { BorderType::Rounded })
        .border_style(app.theme.border_style(focused))
        .title(Span::styled(format!(" {title} "), app.theme.title(focused)))
}

fn draw_folders(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let items: Vec<ListItem> = app
        .folders
        .iter()
        .map(|row| {
            if row.is_account_header {
                return ListItem::new(Line::from(Span::styled(
                    row.label.clone(),
                    Style::default().fg(t.accent_alt).add_modifier(Modifier::BOLD),
                )));
            }

            let indent = "  ".repeat(row.depth);
            let icon = match row.role {
                Some(crate::store::model::FolderRole::Inbox) => "▸",
                Some(crate::store::model::FolderRole::Sent) => "↗",
                Some(crate::store::model::FolderRole::Drafts) => "✎",
                Some(crate::store::model::FolderRole::Trash) => "␡",
                Some(crate::store::model::FolderRole::Archive) => "⌸",
                Some(crate::store::model::FolderRole::Spam) => "⚠",
                _ => "·",
            };

            let name_style = if row.unread > 0 {
                t.unread_style()
            } else {
                Style::default().fg(t.fg)
            };

            let mut spans = vec![
                Span::raw(indent),
                Span::styled(format!("{icon} "), t.dimmed()),
                Span::styled(row.label.clone(), name_style),
            ];
            if row.unread > 0 {
                spans.push(Span::styled(
                    format!(" {}", row.unread),
                    Style::default().fg(t.accent),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.folder_sel));

    let list = List::new(items)
        .block(pane_block(app, "folders", Pane::Folders))
        .highlight_style(t.selected())
        .highlight_symbol("");

    f.render_stateful_widget(list, area, &mut state);
}

fn draw_list(f: &mut Frame, app: &mut App, area: Rect) {
    let t = &app.theme;
    let inner_width = area.width.saturating_sub(2) as usize;

    let items: Vec<ListItem> = app
        .rows
        .iter()
        .map(|row| match row {
            ListRow::Thread { index, collapsed } => {
                let Some(th) = app.threads.get(*index) else {
                    return ListItem::new("");
                };
                let marker = if *collapsed { "▸" } else { "▾" };
                let count = th.members.len();
                let style = if th.unread > 0 {
                    t.unread_style()
                } else {
                    Style::default().fg(t.dim)
                };
                let mut spans = vec![
                    Span::styled(format!("{marker} "), Style::default().fg(t.accent)),
                    Span::styled(truncate(&th.subject, inner_width.saturating_sub(24)), style),
                ];
                if count > 1 {
                    spans.push(Span::styled(format!("  ({count})"), t.dimmed()));
                }
                if th.unread > 0 {
                    spans.push(Span::styled(
                        format!("  {} new", th.unread),
                        Style::default().fg(t.accent),
                    ));
                }
                if th.flagged {
                    spans.push(Span::styled("  ★", Style::default().fg(t.flagged)));
                }
                if th.has_attachments {
                    spans.push(Span::styled("  @", t.dimmed()));
                }
                ListItem::new(Line::from(spans))
            }
            ListRow::Message { msg, depth } => {
                let Some(e) = app.messages.get(*msg) else {
                    return ListItem::new("");
                };
                ListItem::new(message_line(app, e, *depth, inner_width))
            }
        })
        .collect();

    let title = format!(
        "messages · {} · {}",
        app.messages.len(),
        app.sort.label()
    );

    let mut state = ListState::default();
    state.select(Some(app.list_sel));

    let list = List::new(items)
        .block(pane_block(app, &title, Pane::List))
        .highlight_style(t.selected());

    f.render_stateful_widget(list, area, &mut state);
    app.list_offset = state.offset();

    if app.rows.len() > area.height.saturating_sub(2) as usize {
        let mut sb = ScrollbarState::new(app.rows.len()).position(app.list_sel);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight).style(t.dimmed()),
            area.inner(Margin { vertical: 1, horizontal: 0 }),
            &mut sb,
        );
    }
}

fn message_line<'a>(app: &App, e: &'a Envelope, depth: u16, width: usize) -> Line<'a> {
    let t = &app.theme;
    let marked = app.marked.contains(&e.key());

    let base = if e.is_unread() {
        t.unread_style()
    } else {
        Style::default().fg(t.fg)
    };

    let date = if app.config.ui.relative_dates {
        relative_date(e.date)
    } else {
        e.date.format(&app.config.ui.date_format).to_string()
    };

    let flags = flag_glyphs(e, t);
    let indent = "  ".repeat(depth as usize);

    let from = truncate(&e.display_from(), 22);
    let reserved = 10 + 24 + flags.len() + indent.len() + 4;
    let subject = truncate(e.subject_or_placeholder(), width.saturating_sub(reserved).max(10));

    let mut spans = vec![
        Span::styled(
            if marked { "▪ " } else { "  " },
            Style::default().fg(t.success),
        ),
        Span::styled(format!("{date:>9} "), t.dimmed()),
        Span::styled(format!("{from:<22} "), Style::default().fg(if e.is_unread() { t.fg } else { t.dim })),
        Span::raw(indent),
        Span::styled(subject, base),
    ];
    spans.extend(flags);
    Line::from(spans)
}

fn flag_glyphs<'a>(e: &Envelope, t: &super::theme::Theme) -> Vec<Span<'a>> {
    let mut out = Vec::new();
    if e.flags.contains(Flags::FLAGGED) {
        out.push(Span::styled(" ★", Style::default().fg(t.flagged)));
    }
    if e.flags.contains(Flags::ANSWERED) {
        out.push(Span::styled(" ↩", t.dimmed()));
    }
    if e.flags.contains(Flags::FORWARDED) {
        out.push(Span::styled(" ↪", t.dimmed()));
    }
    if e.attachments.iter().any(|a| !a.inline) {
        out.push(Span::styled(" @", t.dimmed()));
    }
    match e.crypto {
        CryptoState::None => {}
        CryptoState::SignedValid => out.push(Span::styled(" ✔", Style::default().fg(t.success))),
        CryptoState::SignedInvalid => out.push(Span::styled(" ✘", Style::default().fg(t.danger))),
        CryptoState::SignedUnknownKey => out.push(Span::styled(" ?", t.dimmed())),
        CryptoState::Encrypted | CryptoState::EncryptedAndSigned => {
            out.push(Span::styled(" 🔒", Style::default().fg(t.accent)))
        }
        CryptoState::DecryptFailed => out.push(Span::styled(" 🔒!", Style::default().fg(t.danger))),
    }
    out
}

fn draw_preview(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let block = pane_block(app, "message", Pane::Preview);

    let Some(msg) = app.selected_message() else {
        f.render_widget(
            Paragraph::new("No message selected.").style(t.dimmed()).block(block),
            area,
        );
        return;
    };

    let mut lines: Vec<Line> = Vec::new();
    let label = |s: &str| Span::styled(format!("{s:<9}"), Style::default().fg(t.dim));

    lines.push(Line::from(vec![
        label("From"),
        Span::styled(
            msg.from.iter().map(|a| a.encoded()).collect::<Vec<_>>().join(", "),
            Style::default().fg(t.fg).add_modifier(Modifier::BOLD),
        ),
    ]));
    if !msg.to.is_empty() {
        lines.push(Line::from(vec![
            label("To"),
            Span::raw(msg.to.iter().map(|a| a.encoded()).collect::<Vec<_>>().join(", ")),
        ]));
    }
    if !msg.cc.is_empty() {
        lines.push(Line::from(vec![
            label("Cc"),
            Span::raw(msg.cc.iter().map(|a| a.encoded()).collect::<Vec<_>>().join(", ")),
        ]));
    }
    lines.push(Line::from(vec![
        label("Date"),
        Span::raw(msg.date.format("%a, %d %b %Y %H:%M %z").to_string()),
    ]));
    lines.push(Line::from(vec![
        label("Subject"),
        Span::styled(
            msg.subject_or_placeholder().to_string(),
            Style::default().fg(t.accent),
        ),
    ]));

    if app.render.show_headers && !msg.references.is_empty() {
        lines.push(Line::from(vec![
            label("Refs"),
            Span::styled(msg.references.join(" "), t.dimmed()),
        ]));
    }

    let mut badges = Vec::new();
    if msg.crypto != CryptoState::None {
        badges.push(Span::styled(
            format!(" [{}] ", msg.crypto.badge()),
            match msg.crypto {
                CryptoState::SignedValid => Style::default().fg(t.success),
                CryptoState::SignedInvalid | CryptoState::DecryptFailed => {
                    Style::default().fg(t.danger)
                }
                _ => Style::default().fg(t.accent),
            },
        ));
    }
    if let Some(b) = &app.body {
        if b.remote_blocked > 0 {
            badges.push(Span::styled(
                format!(" [{} remote images blocked — I to allow] ", b.remote_blocked),
                Style::default().fg(t.warning),
            ));
        }
        if b.trackers_stripped > 0 {
            badges.push(Span::styled(
                format!(" [{} trackers removed] ", b.trackers_stripped),
                Style::default().fg(t.warning),
            ));
        }
        if !b.attachments.is_empty() {
            badges.push(Span::styled(
                format!(" [{} attachments — a to list] ", b.attachments.len()),
                t.dimmed(),
            ));
        }
    }
    if !badges.is_empty() {
        lines.push(Line::from(badges));
    }

    lines.push(Line::from(Span::styled(
        "─".repeat(area.width.saturating_sub(2) as usize),
        t.dimmed(),
    )));

    match &app.body {
        None => lines.push(Line::from(Span::styled("Loading…", t.dimmed()))),
        Some(body) => {
            for l in body.visible_lines(app.render.show_quoted) {
                let style = match l.kind {
                    LineKind::Body => Style::default().fg(t.fg),
                    LineKind::Quote(d) => t.quote_style(d),
                    LineKind::Signature => Style::default().fg(t.signature),
                    LineKind::Separator => t.dimmed(),
                    LineKind::Header => Style::default().fg(t.dim),
                };
                lines.push(Line::from(Span::styled(l.text.clone(), style)));
            }
        }
    }

    let total = lines.len();
    let para = Paragraph::new(Text::from(lines))
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.body_scroll, 0));
    f.render_widget(para, area);

    let viewport = area.height.saturating_sub(2) as usize;
    if total > viewport {
        let mut sb = ScrollbarState::new(total.saturating_sub(viewport))
            .position(app.body_scroll as usize);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight).style(t.dimmed()),
            area.inner(Margin { vertical: 1, horizontal: 0 }),
            &mut sb,
        );
    }
}

fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;

    if let Some((msg, _, is_error)) = &app.notice {
        let style = if *is_error {
            Style::default().fg(t.danger).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(t.success)
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(format!(" {msg}"), style))),
            area,
        );
        return;
    }

    let mut spans = vec![
        Span::styled(format!(" {} ", app.status_summary()), Style::default().fg(t.accent)),
        Span::styled("│", t.dimmed()),
    ];
    if app.outbox_len > 0 {
        spans.push(Span::styled(
            format!(" outbox {} ", app.outbox_len),
            Style::default().fg(t.warning),
        ));
        spans.push(Span::styled("│", t.dimmed()));
    }
    spans.push(Span::styled(
        format!(
            " {}/{} ",
            (app.list_sel + 1).min(app.rows.len().max(1)),
            app.rows.len()
        ),
        t.dimmed(),
    ));
    spans.push(Span::styled("│", t.dimmed()));
    spans.push(Span::styled(
        format!(
            " {} · {} ",
            if app.threading { "threads" } else { "flat" },
            if app.render.prefer_html { "html" } else { "text" }
        ),
        t.dimmed(),
    ));
    spans.push(Span::styled("│ ? help ", t.dimmed()));

    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn draw_input(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let prefix = match app.input_mode {
        InputMode::Search => "/",
        InputMode::ExCommand => ":",
        InputMode::Filter => "filter> ",
        InputMode::Secret => "password: ",
        InputMode::None => "",
    };
    let shown = if app.input_mode == InputMode::Secret {
        "•".repeat(app.input.chars().count())
    } else {
        app.input.clone()
    };
    let line = Line::from(vec![
        Span::styled(prefix, Style::default().fg(t.accent)),
        Span::styled(shown, Style::default().fg(t.fg)),
    ]);
    f.render_widget(Paragraph::new(line), area);
    f.set_cursor_position((
        area.x + prefix.width() as u16 + app.input_cursor as u16,
        area.y,
    ));
}

// ---- overlays ----

fn overlay_area(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
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

fn overlay_block<'a>(app: &App, title: &'a str) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(app.theme.border_focus))
        .title(Span::styled(
            format!(" {title} "),
            Style::default()
                .fg(app.theme.accent)
                .add_modifier(Modifier::BOLD),
        ))
}

fn draw_help(f: &mut Frame, app: &App, area: Rect) {
    let area = overlay_area(area, 76, 82);
    f.render_widget(Clear, area);

    let t = &app.theme;
    let mut lines = vec![
        Line::from(Span::styled(
            "Search syntax: from:alice subject:\"weekly report\" is:unread has:attachment after:7d -in:spam",
            t.dimmed(),
        )),
        Line::from(Span::styled(
            "Commands (:) — :q :sync :search :sort :theme :mkdir :rmdir :outbox :accounts",
            t.dimmed(),
        )),
        Line::from(Span::styled(
            "Accounts     — :passwd [account] sets the IMAP password, :smtp-passwd the SMTP one",
            t.dimmed(),
        )),
        Line::from(""),
    ];

    for (chord, action) in app.keymap.entries() {
        lines.push(Line::from(vec![
            Span::styled(format!("  {chord:<10}"), Style::default().fg(t.accent)),
            Span::styled(action.describe().to_string(), Style::default().fg(t.fg)),
        ]));
    }

    let para = Paragraph::new(Text::from(lines))
        .block(overlay_block(app, "keys — esc to close"))
        .scroll((app.overlay_sel as u16, 0));
    f.render_widget(para, area);
}

fn draw_palette(f: &mut Frame, app: &App, area: Rect) {
    let area = overlay_area(area, 60, 60);
    f.render_widget(Clear, area);

    let t = &app.theme;
    let matches = palette_matches(app);
    let items: Vec<ListItem> = matches
        .iter()
        .map(|(chord, action)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{chord:<10}"), t.dimmed()),
                Span::styled(action.describe().to_string(), Style::default().fg(t.fg)),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.overlay_sel.min(matches.len().saturating_sub(1))));

    let title = format!("run › {}", app.input);
    let list = List::new(items)
        .block(overlay_block(app, &title))
        .highlight_style(t.selected());
    f.render_stateful_widget(list, area, &mut state);
}

pub fn palette_matches(app: &App) -> Vec<(String, Action)> {
    let needle = app.input.to_lowercase();
    let mut v: Vec<(String, Action)> = app
        .keymap
        .entries()
        .into_iter()
        .filter(|(_, a)| {
            needle.is_empty() || a.describe().to_lowercase().contains(&needle)
        })
        .collect();
    v.dedup_by(|a, b| a.1 == b.1);
    v
}

fn draw_attachments(f: &mut Frame, app: &App, area: Rect) {
    let area = overlay_area(area, 62, 50);
    f.render_widget(Clear, area);

    let t = &app.theme;
    let atts = app.attachments();
    let items: Vec<ListItem> = if atts.is_empty() {
        vec![ListItem::new(Span::styled("(no attachments)", t.dimmed()))]
    } else {
        atts.iter()
            .map(|a| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{:<34}", truncate(&a.name, 34)), Style::default().fg(t.fg)),
                    Span::styled(format!("{:<24}", truncate(&a.mime, 24)), t.dimmed()),
                    Span::styled(human_size(a.size), Style::default().fg(t.accent)),
                ]))
            })
            .collect()
    };

    let mut state = ListState::default();
    state.select(Some(app.overlay_sel.min(items.len().saturating_sub(1))));
    let list = List::new(items)
        .block(overlay_block(app, "attachments — w save · O open · esc close"))
        .highlight_style(t.selected());
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_links(f: &mut Frame, app: &App, area: Rect) {
    let area = overlay_area(area, 70, 50);
    f.render_widget(Clear, area);

    let t = &app.theme;
    let links = app.links();
    let items: Vec<ListItem> = if links.is_empty() {
        vec![ListItem::new(Span::styled("(no links in this message)", t.dimmed()))]
    } else {
        links
            .iter()
            .map(|l| ListItem::new(Span::styled(truncate(l, 100), Style::default().fg(t.link))))
            .collect()
    };

    let mut state = ListState::default();
    state.select(Some(app.overlay_sel.min(items.len().saturating_sub(1))));
    let list = List::new(items)
        .block(overlay_block(app, "links — enter to open · esc close"))
        .highlight_style(t.selected());
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_outbox(f: &mut Frame, app: &App, area: Rect) {
    let area = overlay_area(area, 70, 50);
    f.render_widget(Clear, area);

    let t = &app.theme;
    let items: Vec<ListItem> = match app.store.outbox() {
        Ok(items) if !items.is_empty() => items
            .iter()
            .map(|i| {
                let mut spans = vec![
                    Span::styled(format!("{:<20}", truncate(&i.subject, 20)), Style::default().fg(t.fg)),
                    Span::styled(
                        format!("→ {:<26}", truncate(&i.to.iter().map(|a| a.email.clone()).collect::<Vec<_>>().join(", "), 26)),
                        t.dimmed(),
                    ),
                ];
                if let Some(e) = &i.last_error {
                    spans.push(Span::styled(
                        format!("  {} ({})", truncate(e, 40), i.attempts),
                        Style::default().fg(t.danger),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect(),
        _ => vec![ListItem::new(Span::styled("(outbox is empty)", t.dimmed()))],
    };

    let list = List::new(items).block(overlay_block(app, "outbox — C-o to retry · esc close"));
    f.render_widget(list, area);
}

fn draw_source(f: &mut Frame, app: &App, area: Rect) {
    let area = overlay_area(area, 86, 86);
    f.render_widget(Clear, area);

    let text = match &app.body_raw {
        Some(raw) => String::from_utf8_lossy(raw).into_owned(),
        None => "(the raw message has not been downloaded yet)".to_string(),
    };

    let para = Paragraph::new(text)
        .style(app.theme.dimmed())
        .block(overlay_block(app, "raw source — esc close"))
        .scroll((app.overlay_sel as u16, 0));
    f.render_widget(para, area);
}

fn draw_folder_picker(f: &mut Frame, app: &App, area: Rect, copy: bool) {
    let area = overlay_area(area, 50, 60);
    f.render_widget(Clear, area);

    let t = &app.theme;
    let choices = picker_folders(app);
    let items: Vec<ListItem> = choices
        .iter()
        .map(|n| ListItem::new(Span::styled(n.clone(), Style::default().fg(t.fg))))
        .collect();

    let mut state = ListState::default();
    state.select(Some(app.overlay_sel.min(items.len().saturating_sub(1))));
    let verb = if copy { "copy to" } else { "move to" };
    let title = format!("{verb} › {}", app.input);
    let list = List::new(items)
        .block(overlay_block(app, &title))
        .highlight_style(t.selected());
    f.render_stateful_widget(list, area, &mut state);
}

pub fn picker_folders(app: &App) -> Vec<String> {
    let account = app.current_folder().map(|f| f.account.clone());
    let needle = app.input.to_lowercase();
    app.folders
        .iter()
        .filter(|f| !f.is_account_header)
        .filter(|f| account.as_ref().is_none_or(|a| &f.account == a))
        .filter(|f| needle.is_empty() || f.name.to_lowercase().contains(&needle))
        .map(|f| f.name.clone())
        .collect()
}

fn draw_confirm(f: &mut Frame, app: &App, area: Rect, prompt: &str) {
    let area = overlay_area(area, 50, 20);
    f.render_widget(Clear, area);

    let t = &app.theme;
    let text = Text::from(vec![
        Line::from(Span::styled(prompt.to_string(), Style::default().fg(t.fg))),
        Line::from(""),
        Line::from(Span::styled(
            "y = yes    n / esc = no",
            Style::default().fg(t.warning),
        )),
    ]);

    f.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Center)
            .block(overlay_block(app, "confirm")),
        area,
    );
}

// ---- helpers ----

pub fn truncate(s: &str, max: usize) -> String {
    if max == 0 {
        return String::new();
    }
    if s.width() <= max {
        return s.to_string();
    }
    let mut out = String::new();
    let mut w = 0;
    for ch in s.chars() {
        let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if w + cw > max.saturating_sub(1) {
            break;
        }
        out.push(ch);
        w += cw;
    }
    out.push('…');
    out
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1}{}", UNITS[i])
    }
}

pub fn relative_date(d: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let delta = now.signed_duration_since(d);

    if delta.num_seconds() < 0 {
        return d.format("%Y-%m-%d").to_string();
    }
    if delta.num_minutes() < 60 {
        return format!("{}m", delta.num_minutes().max(0));
    }
    if delta.num_hours() < 24 {
        return format!("{}h", delta.num_hours());
    }
    if delta.num_days() < 7 {
        return d.format("%a %H:%M").to_string();
    }
    if d.format("%Y").to_string() == now.format("%Y").to_string() {
        return d.format("%d %b").to_string();
    }
    d.format("%Y-%m-%d").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_on_display_width() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world", 6), "hello…");
        assert_eq!(truncate("abc", 0), "");
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0K");
        assert_eq!(human_size(5 * 1024 * 1024), "5.0M");
    }
}
