use std::collections::HashMap;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    Quit,
    ForceQuit,
    Help,
    CommandPalette,
    ExCommand,

    NextPane,
    PrevPane,
    FocusFolders,
    FocusList,
    FocusPreview,

    Down,
    Up,
    PageDown,
    PageUp,
    Top,
    Bottom,
    NextUnread,
    PrevUnread,
    NextThread,
    PrevThread,

    Open,
    Back,
    ToggleThread,
    ToggleSelect,
    SelectAll,
    ClearSelection,
    InvertSelection,

    ToggleRead,
    ToggleFlag,
    MarkAllRead,
    Delete,
    DeletePermanent,
    Archive,
    Junk,
    Move,
    Copy,

    Compose,
    Reply,
    ReplyAll,
    Forward,
    ForwardAttached,
    EditAsNew,
    SaveDraft,

    Search,
    SearchServer,
    ClearSearch,
    NextMatch,
    PrevMatch,

    Sync,
    SyncAll,
    ToggleHtml,
    ToggleQuoted,
    ToggleHeaders,
    ToggleRemoteImages,
    ToggleThreading,
    ToggleSidebar,
    ToggleOrder,

    Attachments,
    SaveAttachment,
    OpenAttachment,
    OpenLink,
    CopyAddress,
    ViewSource,

    DecryptMessage,
    VerifySignature,
    ToggleSign,
    ToggleEncrypt,
    ImportKey,

    Outbox,
    FlushOutbox,
    CycleTheme,
    Refresh,
}

impl Action {
    pub fn describe(self) -> &'static str {
        match self {
            Action::Quit => "quit",
            Action::ForceQuit => "quit without confirming",
            Action::Help => "toggle this help",
            Action::CommandPalette => "command palette",
            Action::ExCommand => "command line",
            Action::NextPane => "focus next pane",
            Action::PrevPane => "focus previous pane",
            Action::FocusFolders => "focus folder list",
            Action::FocusList => "focus message list",
            Action::FocusPreview => "focus message body",
            Action::Down => "move down",
            Action::Up => "move up",
            Action::PageDown => "page down",
            Action::PageUp => "page up",
            Action::Top => "go to first",
            Action::Bottom => "go to last",
            Action::NextUnread => "next unread",
            Action::PrevUnread => "previous unread",
            Action::NextThread => "next thread",
            Action::PrevThread => "previous thread",
            Action::Open => "open selection",
            Action::Back => "close / go back",
            Action::ToggleThread => "expand or collapse thread",
            Action::ToggleSelect => "select or deselect message",
            Action::SelectAll => "select all",
            Action::ClearSelection => "clear selection",
            Action::InvertSelection => "invert selection",
            Action::ToggleRead => "toggle read",
            Action::ToggleFlag => "toggle flag",
            Action::MarkAllRead => "mark folder read",
            Action::Delete => "move to trash",
            Action::DeletePermanent => "delete permanently",
            Action::Archive => "archive",
            Action::Junk => "mark as junk",
            Action::Move => "move to folder",
            Action::Copy => "copy to folder",
            Action::Compose => "compose",
            Action::Reply => "reply",
            Action::ReplyAll => "reply to all",
            Action::Forward => "forward inline",
            Action::ForwardAttached => "forward as attachment",
            Action::EditAsNew => "edit as new message",
            Action::SaveDraft => "save draft",
            Action::Search => "search locally",
            Action::SearchServer => "search on the server",
            Action::ClearSearch => "clear search",
            Action::NextMatch => "next match",
            Action::PrevMatch => "previous match",
            Action::Sync => "sync this folder",
            Action::SyncAll => "sync everything",
            Action::ToggleHtml => "prefer HTML or plain text",
            Action::ToggleQuoted => "show or hide quoted text",
            Action::ToggleHeaders => "show or hide full headers",
            Action::ToggleRemoteImages => "allow or block remote images",
            Action::ToggleThreading => "toggle threading",
            Action::ToggleSidebar => "toggle the folder sidebar",
            Action::ToggleOrder => "reverse sort order",
            Action::Attachments => "list attachments",
            Action::SaveAttachment => "save attachment",
            Action::OpenAttachment => "open attachment",
            Action::OpenLink => "open a link from the message",
            Action::CopyAddress => "copy sender address",
            Action::ViewSource => "view raw source",
            Action::DecryptMessage => "decrypt message",
            Action::VerifySignature => "verify signature",
            Action::ToggleSign => "toggle signing for this message",
            Action::ToggleEncrypt => "toggle encryption for this message",
            Action::ImportKey => "import an OpenPGP key from this message",
            Action::Outbox => "show the outbox",
            Action::FlushOutbox => "try sending queued mail now",
            Action::CycleTheme => "cycle theme",
            Action::Refresh => "redraw",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Chord {
    pub code: KeyCode,
    pub mods: KeyModifiers,
}

impl Chord {
    pub fn new(code: KeyCode, mods: KeyModifiers) -> Self {
        Self { code, mods }
    }

    pub fn from_event(e: KeyEvent) -> Self {
        // Shift is already reflected in the character itself, so folding it in
        // would make 'G' and 'g' impossible to distinguish from each other.
        let mods = match e.code {
            KeyCode::Char(_) => e.modifiers - KeyModifiers::SHIFT,
            _ => e.modifiers,
        };
        Self { code: e.code, mods }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let mut mods = KeyModifiers::NONE;
        let mut rest = s;
        loop {
            let lower = rest.to_ascii_lowercase();
            if let Some(r) = lower.strip_prefix("ctrl-").or(lower.strip_prefix("c-")) {
                mods |= KeyModifiers::CONTROL;
                rest = &rest[rest.len() - r.len()..];
            } else if let Some(r) = lower.strip_prefix("alt-").or(lower.strip_prefix("m-")) {
                mods |= KeyModifiers::ALT;
                rest = &rest[rest.len() - r.len()..];
            } else if let Some(r) = lower.strip_prefix("shift-") {
                mods |= KeyModifiers::SHIFT;
                rest = &rest[rest.len() - r.len()..];
            } else {
                break;
            }
        }

        let code = match rest.to_ascii_lowercase().as_str() {
            "enter" | "return" => KeyCode::Enter,
            "esc" | "escape" => KeyCode::Esc,
            "tab" => KeyCode::Tab,
            "backtab" | "shift-tab" => KeyCode::BackTab,
            "space" => KeyCode::Char(' '),
            "backspace" => KeyCode::Backspace,
            "delete" | "del" => KeyCode::Delete,
            "insert" => KeyCode::Insert,
            "home" => KeyCode::Home,
            "end" => KeyCode::End,
            "pageup" | "pgup" => KeyCode::PageUp,
            "pagedown" | "pgdn" => KeyCode::PageDown,
            "up" => KeyCode::Up,
            "down" => KeyCode::Down,
            "left" => KeyCode::Left,
            "right" => KeyCode::Right,
            f if f.starts_with('f') && f[1..].parse::<u8>().is_ok() => {
                KeyCode::F(f[1..].parse().unwrap())
            }
            _ => {
                let mut chars = rest.chars();
                let c = chars.next()?;
                if chars.next().is_some() {
                    return None;
                }
                KeyCode::Char(c)
            }
        };
        Some(Self { code, mods })
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        if self.mods.contains(KeyModifiers::CONTROL) {
            s.push_str("C-");
        }
        if self.mods.contains(KeyModifiers::ALT) {
            s.push_str("M-");
        }
        s.push_str(&match self.code {
            KeyCode::Char(' ') => "space".into(),
            KeyCode::Char(c) => c.to_string(),
            KeyCode::Enter => "enter".into(),
            KeyCode::Esc => "esc".into(),
            KeyCode::Tab => "tab".into(),
            KeyCode::BackTab => "S-tab".into(),
            KeyCode::Backspace => "bksp".into(),
            KeyCode::Delete => "del".into(),
            KeyCode::Home => "home".into(),
            KeyCode::End => "end".into(),
            KeyCode::PageUp => "pgup".into(),
            KeyCode::PageDown => "pgdn".into(),
            KeyCode::Up => "up".into(),
            KeyCode::Down => "down".into(),
            KeyCode::Left => "left".into(),
            KeyCode::Right => "right".into(),
            KeyCode::F(n) => format!("F{n}"),
            other => format!("{other:?}").to_lowercase(),
        });
        s
    }
}

pub struct Keymap {
    map: HashMap<Chord, Action>,
}

impl Keymap {
    pub fn get(&self, e: KeyEvent) -> Option<Action> {
        self.map.get(&Chord::from_event(e)).copied()
    }

    pub fn chords_for(&self, action: Action) -> Vec<String> {
        let mut v: Vec<String> = self
            .map
            .iter()
            .filter(|(_, a)| **a == action)
            .map(|(c, _)| c.render())
            .collect();
        v.sort();
        v
    }

    pub fn entries(&self) -> Vec<(String, Action)> {
        let mut v: Vec<(String, Action)> =
            self.map.iter().map(|(c, a)| (c.render(), *a)).collect();
        v.sort_by(|a, b| a.1.describe().cmp(b.1.describe()).then(a.0.cmp(&b.0)));
        v
    }

    pub fn build(vim: bool, overrides: &std::collections::BTreeMap<String, String>) -> Self {
        let mut map = HashMap::new();
        let mut bind = |s: &str, a: Action| {
            if let Some(c) = Chord::parse(s) {
                map.insert(c, a);
            }
        };

        bind("q", Action::Quit);
        bind("C-c", Action::ForceQuit);
        bind("?", Action::Help);
        bind("F1", Action::Help);
        bind("C-p", Action::CommandPalette);
        bind(":", Action::ExCommand);

        bind("tab", Action::NextPane);
        bind("backtab", Action::PrevPane);
        bind("1", Action::FocusFolders);
        bind("2", Action::FocusList);
        bind("3", Action::FocusPreview);

        bind("down", Action::Down);
        bind("up", Action::Up);
        bind("pagedown", Action::PageDown);
        bind("pageup", Action::PageUp);
        bind("home", Action::Top);
        bind("end", Action::Bottom);
        bind("C-d", Action::PageDown);
        bind("C-u", Action::PageUp);
        bind("n", Action::NextUnread);
        bind("p", Action::PrevUnread);
        bind("}", Action::NextThread);
        bind("{", Action::PrevThread);

        bind("enter", Action::Open);
        bind("esc", Action::Back);
        bind("space", Action::ToggleThread);
        bind("v", Action::ToggleSelect);
        bind("C-a", Action::SelectAll);
        bind("C-n", Action::ClearSelection);
        bind("C-i", Action::InvertSelection);

        bind("t", Action::ToggleRead);
        bind("f", Action::ToggleFlag);
        bind("A", Action::MarkAllRead);
        bind("d", Action::Delete);
        bind("D", Action::DeletePermanent);
        bind("e", Action::Archive);
        bind("!", Action::Junk);
        bind("m", Action::Move);
        bind("y", Action::Copy);

        bind("c", Action::Compose);
        bind("r", Action::Reply);
        bind("R", Action::ReplyAll);
        bind("F", Action::Forward);
        bind("M-f", Action::ForwardAttached);
        bind("E", Action::EditAsNew);
        bind("C-s", Action::SaveDraft);

        bind("/", Action::Search);
        bind("C-f", Action::SearchServer);
        bind("M-/", Action::ClearSearch);

        bind("s", Action::Sync);
        bind("S", Action::SyncAll);
        bind("h", Action::ToggleHtml);
        bind("Q", Action::ToggleQuoted);
        bind("H", Action::ToggleHeaders);
        bind("I", Action::ToggleRemoteImages);
        bind("T", Action::ToggleThreading);
        bind("b", Action::ToggleSidebar);
        bind("o", Action::ToggleOrder);

        bind("a", Action::Attachments);
        bind("w", Action::SaveAttachment);
        bind("O", Action::OpenAttachment);
        bind("L", Action::OpenLink);
        bind("C", Action::CopyAddress);
        bind("u", Action::ViewSource);

        bind("X", Action::DecryptMessage);
        bind("V", Action::VerifySignature);
        bind("C-g", Action::ToggleSign);
        bind("C-e", Action::ToggleEncrypt);
        bind("K", Action::ImportKey);

        bind("B", Action::Outbox);
        bind("C-o", Action::FlushOutbox);
        bind("M-t", Action::CycleTheme);
        bind("C-l", Action::Refresh);

        if vim {
            bind("j", Action::Down);
            bind("k", Action::Up);
            bind("g", Action::Top);
            bind("G", Action::Bottom);
            bind("l", Action::Open);
            bind("N", Action::PrevMatch);
        }

        for (chord, name) in overrides {
            let Some(c) = Chord::parse(chord) else { continue };
            match action_by_name(name) {
                Some(a) => {
                    map.insert(c, a);
                }
                None if name.is_empty() || name == "none" => {
                    map.remove(&c);
                }
                None => {}
            }
        }

        Self { map }
    }
}

pub fn action_by_name(name: &str) -> Option<Action> {
    let n = name.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    ALL_ACTIONS
        .iter()
        .copied()
        .find(|a| format!("{a:?}").to_ascii_lowercase() == n)
}

pub const ALL_ACTIONS: &[Action] = &[
    Action::Quit,
    Action::ForceQuit,
    Action::Help,
    Action::CommandPalette,
    Action::ExCommand,
    Action::NextPane,
    Action::PrevPane,
    Action::FocusFolders,
    Action::FocusList,
    Action::FocusPreview,
    Action::Down,
    Action::Up,
    Action::PageDown,
    Action::PageUp,
    Action::Top,
    Action::Bottom,
    Action::NextUnread,
    Action::PrevUnread,
    Action::NextThread,
    Action::PrevThread,
    Action::Open,
    Action::Back,
    Action::ToggleThread,
    Action::ToggleSelect,
    Action::SelectAll,
    Action::ClearSelection,
    Action::InvertSelection,
    Action::ToggleRead,
    Action::ToggleFlag,
    Action::MarkAllRead,
    Action::Delete,
    Action::DeletePermanent,
    Action::Archive,
    Action::Junk,
    Action::Move,
    Action::Copy,
    Action::Compose,
    Action::Reply,
    Action::ReplyAll,
    Action::Forward,
    Action::ForwardAttached,
    Action::EditAsNew,
    Action::SaveDraft,
    Action::Search,
    Action::SearchServer,
    Action::ClearSearch,
    Action::NextMatch,
    Action::PrevMatch,
    Action::Sync,
    Action::SyncAll,
    Action::ToggleHtml,
    Action::ToggleQuoted,
    Action::ToggleHeaders,
    Action::ToggleRemoteImages,
    Action::ToggleThreading,
    Action::ToggleSidebar,
    Action::ToggleOrder,
    Action::Attachments,
    Action::SaveAttachment,
    Action::OpenAttachment,
    Action::OpenLink,
    Action::CopyAddress,
    Action::ViewSource,
    Action::DecryptMessage,
    Action::VerifySignature,
    Action::ToggleSign,
    Action::ToggleEncrypt,
    Action::ImportKey,
    Action::Outbox,
    Action::FlushOutbox,
    Action::CycleTheme,
    Action::Refresh,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modifier_chords() {
        assert_eq!(
            Chord::parse("C-a"),
            Some(Chord::new(KeyCode::Char('a'), KeyModifiers::CONTROL))
        );
        assert_eq!(
            Chord::parse("alt-enter"),
            Some(Chord::new(KeyCode::Enter, KeyModifiers::ALT))
        );
        assert_eq!(Chord::parse("F5"), Some(Chord::new(KeyCode::F(5), KeyModifiers::NONE)));
    }

    #[test]
    fn overrides_replace_default_bindings() {
        let mut o = std::collections::BTreeMap::new();
        o.insert("x".to_string(), "archive".to_string());
        let km = Keymap::build(true, &o);
        assert_eq!(
            km.get(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)),
            Some(Action::Archive)
        );
    }

    #[test]
    fn case_distinguishes_bindings() {
        let km = Keymap::build(true, &Default::default());
        assert_eq!(
            km.get(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
            Some(Action::Reply)
        );
        assert_eq!(
            km.get(KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT)),
            Some(Action::ReplyAll)
        );
    }
}
