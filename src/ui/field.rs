use ratatui::style::Style;
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Text,
    Secret,
    Number,
    Choice,
    Toggle,
}

#[derive(Debug, Clone)]
pub struct Field {
    pub label: &'static str,
    pub help: &'static str,
    pub kind: FieldKind,
    pub value: String,
    pub cursor: usize,
    pub choices: Vec<String>,
    pub error: Option<String>,
}

impl Field {
    pub fn text(label: &'static str, help: &'static str, value: impl Into<String>) -> Self {
        let value = value.into();
        Self {
            label,
            help,
            kind: FieldKind::Text,
            cursor: value.chars().count(),
            value,
            choices: Vec::new(),
            error: None,
        }
    }

    pub fn secret(label: &'static str, help: &'static str) -> Self {
        Self { kind: FieldKind::Secret, ..Self::text(label, help, "") }
    }

    pub fn number(label: &'static str, help: &'static str, value: u16) -> Self {
        Self { kind: FieldKind::Number, ..Self::text(label, help, value.to_string()) }
    }

    pub fn choice(
        label: &'static str,
        help: &'static str,
        choices: &[&str],
        selected: &str,
    ) -> Self {
        Self {
            kind: FieldKind::Choice,
            choices: choices.iter().map(|c| c.to_string()).collect(),
            ..Self::text(label, help, selected)
        }
    }

    pub fn toggle(label: &'static str, help: &'static str, on: bool) -> Self {
        Self {
            kind: FieldKind::Toggle,
            choices: vec!["no".into(), "yes".into()],
            ..Self::text(label, help, if on { "yes" } else { "no" })
        }
    }

    pub fn is_on(&self) -> bool {
        self.value == "yes"
    }

    pub fn set(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.cursor = self.value.chars().count();
    }

    pub fn number_value(&self) -> u16 {
        self.value.trim().parse().unwrap_or(0)
    }

    pub fn insert(&mut self, c: char) {
        if self.kind == FieldKind::Number && !c.is_ascii_digit() {
            return;
        }
        if matches!(self.kind, FieldKind::Choice | FieldKind::Toggle) {
            return;
        }
        let idx = self.byte_index(self.cursor);
        self.value.insert(idx, c);
        self.cursor += 1;
        self.error = None;
    }

    pub fn backspace(&mut self) {
        if matches!(self.kind, FieldKind::Choice | FieldKind::Toggle) || self.cursor == 0 {
            return;
        }
        let start = self.byte_index(self.cursor - 1);
        let end = self.byte_index(self.cursor);
        self.value.replace_range(start..end, "");
        self.cursor -= 1;
        self.error = None;
    }

    pub fn delete_forward(&mut self) {
        if matches!(self.kind, FieldKind::Choice | FieldKind::Toggle) {
            return;
        }
        let len = self.value.chars().count();
        if self.cursor >= len {
            return;
        }
        let start = self.byte_index(self.cursor);
        let end = self.byte_index(self.cursor + 1);
        self.value.replace_range(start..end, "");
        self.error = None;
    }

    pub fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
        self.error = None;
    }

    pub fn left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.cursor = (self.cursor + 1).min(self.value.chars().count());
    }

    pub fn home(&mut self) {
        self.cursor = 0;
    }

    pub fn end(&mut self) {
        self.cursor = self.value.chars().count();
    }

    pub fn cycle(&mut self, forward: bool) {
        if self.choices.is_empty() {
            return;
        }
        let i = self.choices.iter().position(|c| *c == self.value).unwrap_or(0);
        let n = self.choices.len();
        let next = if forward { (i + 1) % n } else { (i + n - 1) % n };
        self.value = self.choices[next].clone();
        self.error = None;
    }

    fn byte_index(&self, char_index: usize) -> usize {
        self.value
            .char_indices()
            .nth(char_index)
            .map(|(i, _)| i)
            .unwrap_or(self.value.len())
    }

    pub fn display(&self) -> String {
        match self.kind {
            FieldKind::Secret => "•".repeat(self.value.chars().count()),
            _ => self.value.clone(),
        }
    }

    /// Column offset of the caret within the rendered value, so a masked field
    /// still places the cursor correctly.
    pub fn cursor_column(&self) -> u16 {
        match self.kind {
            FieldKind::Secret => self.cursor as u16,
            _ => {
                let upto: String = self.value.chars().take(self.cursor).collect();
                upto.width() as u16
            }
        }
    }

    pub fn render(&self, focused: bool, width: usize, style: Style, hint: Style) -> Line<'static> {
        let label = format!("{:<14}", self.label);
        let mut value = self.display();
        if matches!(self.kind, FieldKind::Choice | FieldKind::Toggle) {
            value = format!("‹ {value} ›");
        }
        if value.is_empty() && !focused {
            value = "—".into();
        }

        let room = width.saturating_sub(label.width() + 2);
        if value.width() > room {
            value = super::draw::truncate(&value, room);
        }

        Line::from(vec![
            Span::styled(label, hint),
            Span::styled(value, style),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_fields_reject_letters() {
        let mut f = Field::number("Port", "", 993);
        f.clear();
        for c in "9a9b3".chars() {
            f.insert(c);
        }
        assert_eq!(f.value, "993");
    }

    #[test]
    fn secret_fields_mask_their_value() {
        let mut f = Field::secret("Password", "");
        for c in "hunter2".chars() {
            f.insert(c);
        }
        assert_eq!(f.display(), "•••••••");
        assert_eq!(f.value, "hunter2");
        assert_eq!(f.cursor_column(), 7);
    }

    #[test]
    fn choice_fields_wrap_around() {
        let mut f = Field::choice("Security", "", &["tls", "starttls", "none"], "tls");
        f.cycle(true);
        assert_eq!(f.value, "starttls");
        f.cycle(false);
        assert_eq!(f.value, "tls");
        f.cycle(false);
        assert_eq!(f.value, "none");
    }

    #[test]
    fn editing_respects_character_boundaries() {
        let mut f = Field::text("Name", "", "naïve");
        f.end();
        f.backspace();
        assert_eq!(f.value, "naïv");
        f.home();
        f.delete_forward();
        assert_eq!(f.value, "aïv");
    }
}
