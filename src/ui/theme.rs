use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone)]
pub struct Theme {
    pub name: &'static str,
    pub bg: Color,
    pub fg: Color,
    pub dim: Color,
    pub accent: Color,
    pub accent_alt: Color,
    pub selection_bg: Color,
    pub selection_fg: Color,
    pub border: Color,
    pub border_focus: Color,
    pub unread: Color,
    pub flagged: Color,
    pub danger: Color,
    pub success: Color,
    pub warning: Color,
    pub quote: [Color; 3],
    pub signature: Color,
    pub link: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

impl Theme {
    pub fn by_name(name: &str) -> Self {
        match name {
            "default-light" | "light" => Self::light(),
            "gruvbox-dark" => Self::gruvbox_dark(),
            "nord" => Self::nord(),
            "mono" => Self::mono(),
            _ => Self::dark(),
        }
    }

    pub fn all() -> &'static [&'static str] {
        &["default-dark", "default-light", "gruvbox-dark", "nord", "mono"]
    }

    pub fn dark() -> Self {
        Self {
            name: "default-dark",
            bg: Color::Reset,
            fg: Color::Rgb(0xd0, 0xd0, 0xd0),
            dim: Color::Rgb(0x80, 0x80, 0x88),
            accent: Color::Rgb(0x7a, 0xa2, 0xf7),
            accent_alt: Color::Rgb(0xbb, 0x9a, 0xf7),
            selection_bg: Color::Rgb(0x2a, 0x2f, 0x41),
            selection_fg: Color::Rgb(0xf0, 0xf0, 0xf5),
            border: Color::Rgb(0x3b, 0x40, 0x52),
            border_focus: Color::Rgb(0x7a, 0xa2, 0xf7),
            unread: Color::Rgb(0xff, 0xff, 0xff),
            flagged: Color::Rgb(0xe0, 0xaf, 0x68),
            danger: Color::Rgb(0xf7, 0x76, 0x8e),
            success: Color::Rgb(0x9e, 0xce, 0x6a),
            warning: Color::Rgb(0xe0, 0xaf, 0x68),
            quote: [
                Color::Rgb(0x7d, 0xcf, 0xff),
                Color::Rgb(0x9e, 0xce, 0x6a),
                Color::Rgb(0xbb, 0x9a, 0xf7),
            ],
            signature: Color::Rgb(0x70, 0x70, 0x78),
            link: Color::Rgb(0x7d, 0xcf, 0xff),
        }
    }

    pub fn light() -> Self {
        Self {
            name: "default-light",
            bg: Color::Reset,
            fg: Color::Rgb(0x24, 0x28, 0x30),
            dim: Color::Rgb(0x6a, 0x70, 0x7c),
            accent: Color::Rgb(0x24, 0x5b, 0xc4),
            accent_alt: Color::Rgb(0x7a, 0x3e, 0xb0),
            selection_bg: Color::Rgb(0xdc, 0xe4, 0xf7),
            selection_fg: Color::Rgb(0x10, 0x14, 0x1c),
            border: Color::Rgb(0xc4, 0xc8, 0xd0),
            border_focus: Color::Rgb(0x24, 0x5b, 0xc4),
            unread: Color::Rgb(0x00, 0x00, 0x00),
            flagged: Color::Rgb(0xb0, 0x6c, 0x00),
            danger: Color::Rgb(0xc0, 0x26, 0x3c),
            success: Color::Rgb(0x2a, 0x7a, 0x2a),
            warning: Color::Rgb(0xb0, 0x6c, 0x00),
            quote: [
                Color::Rgb(0x1c, 0x6a, 0x96),
                Color::Rgb(0x2a, 0x7a, 0x2a),
                Color::Rgb(0x7a, 0x3e, 0xb0),
            ],
            signature: Color::Rgb(0x8a, 0x90, 0x9c),
            link: Color::Rgb(0x1c, 0x6a, 0x96),
        }
    }

    pub fn gruvbox_dark() -> Self {
        Self {
            name: "gruvbox-dark",
            fg: Color::Rgb(0xeb, 0xdb, 0xb2),
            dim: Color::Rgb(0x92, 0x83, 0x74),
            accent: Color::Rgb(0x83, 0xa5, 0x98),
            accent_alt: Color::Rgb(0xd3, 0x86, 0x9b),
            selection_bg: Color::Rgb(0x3c, 0x38, 0x36),
            selection_fg: Color::Rgb(0xfb, 0xf1, 0xc7),
            border: Color::Rgb(0x50, 0x49, 0x45),
            border_focus: Color::Rgb(0xfa, 0xbd, 0x2f),
            unread: Color::Rgb(0xfb, 0xf1, 0xc7),
            flagged: Color::Rgb(0xfa, 0xbd, 0x2f),
            danger: Color::Rgb(0xfb, 0x49, 0x34),
            success: Color::Rgb(0xb8, 0xbb, 0x26),
            warning: Color::Rgb(0xfe, 0x80, 0x19),
            quote: [
                Color::Rgb(0x83, 0xa5, 0x98),
                Color::Rgb(0xb8, 0xbb, 0x26),
                Color::Rgb(0xd3, 0x86, 0x9b),
            ],
            signature: Color::Rgb(0x7c, 0x6f, 0x64),
            link: Color::Rgb(0x83, 0xa5, 0x98),
            ..Self::dark()
        }
    }

    pub fn nord() -> Self {
        Self {
            name: "nord",
            fg: Color::Rgb(0xd8, 0xde, 0xe9),
            dim: Color::Rgb(0x4c, 0x56, 0x6a),
            accent: Color::Rgb(0x88, 0xc0, 0xd0),
            accent_alt: Color::Rgb(0xb4, 0x8e, 0xad),
            selection_bg: Color::Rgb(0x3b, 0x42, 0x52),
            selection_fg: Color::Rgb(0xec, 0xef, 0xf4),
            border: Color::Rgb(0x43, 0x4c, 0x5e),
            border_focus: Color::Rgb(0x88, 0xc0, 0xd0),
            unread: Color::Rgb(0xec, 0xef, 0xf4),
            flagged: Color::Rgb(0xeb, 0xcb, 0x8b),
            danger: Color::Rgb(0xbf, 0x61, 0x6a),
            success: Color::Rgb(0xa3, 0xbe, 0x8c),
            warning: Color::Rgb(0xd0, 0x87, 0x70),
            quote: [
                Color::Rgb(0x81, 0xa1, 0xc1),
                Color::Rgb(0xa3, 0xbe, 0x8c),
                Color::Rgb(0xb4, 0x8e, 0xad),
            ],
            signature: Color::Rgb(0x4c, 0x56, 0x6a),
            link: Color::Rgb(0x88, 0xc0, 0xd0),
            ..Self::dark()
        }
    }

    pub fn mono() -> Self {
        Self {
            name: "mono",
            bg: Color::Reset,
            fg: Color::Reset,
            dim: Color::DarkGray,
            accent: Color::White,
            accent_alt: Color::Gray,
            selection_bg: Color::DarkGray,
            selection_fg: Color::White,
            border: Color::DarkGray,
            border_focus: Color::White,
            unread: Color::White,
            flagged: Color::White,
            danger: Color::Red,
            success: Color::Green,
            warning: Color::Yellow,
            quote: [Color::DarkGray, Color::DarkGray, Color::DarkGray],
            signature: Color::DarkGray,
            link: Color::Gray,
        }
    }

    pub fn base(&self) -> Style {
        Style::default().fg(self.fg).bg(self.bg)
    }

    pub fn dimmed(&self) -> Style {
        Style::default().fg(self.dim)
    }

    pub fn selected(&self) -> Style {
        Style::default()
            .fg(self.selection_fg)
            .bg(self.selection_bg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn unread_style(&self) -> Style {
        Style::default().fg(self.unread).add_modifier(Modifier::BOLD)
    }

    pub fn title(&self, focused: bool) -> Style {
        if focused {
            Style::default().fg(self.border_focus).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(self.dim)
        }
    }

    pub fn border_style(&self, focused: bool) -> Style {
        Style::default().fg(if focused { self.border_focus } else { self.border })
    }

    pub fn quote_style(&self, depth: u8) -> Style {
        Style::default().fg(self.quote[(depth.saturating_sub(1) as usize) % self.quote.len()])
    }
}
