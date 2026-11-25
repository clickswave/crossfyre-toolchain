//! The frame around every screen: the rounded panels, the line of keys under
//! them, and the small formatting they share.

use crate::theme::{self, Tone};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph, Wrap},
};
use std::time::Duration;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// A rounded panel with `left` and `right` set into its top border.
pub(crate) fn panel<'a>(left: Line<'a>, right: Line<'a>) -> Block<'a> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(theme::border())
        .title_top(own_colours(left))
        .title_top(own_colours(right).right_aligned())
}

/// A line set into a border is drawn over the border's style, so a span that
/// names no colour of its own would take the border's grey. This gives every
/// span the terminal's own text colour to start from.
fn own_colours(mut line: Line<'_>) -> Line<'_> {
    let ordinary = Style::default()
        .fg(Color::Reset)
        .remove_modifier(Modifier::DIM);
    for span in &mut line.spans {
        span.style = ordinary.patch(span.style);
    }
    line
}

/// The left of a panel's border: the tool's name, then what follows it.
pub(crate) fn heading<'a>(name: &'a str, rest: Vec<Span<'a>>) -> Line<'a> {
    let mut spans = vec![
        Span::styled("─ ", theme::border()),
        Span::styled(name, theme::title()),
    ];
    if !rest.is_empty() {
        spans.push(Span::styled(" ─ ", theme::border()));
        spans.extend(rest);
    }
    spans.push(Span::raw(" "));
    Line::from(spans)
}

/// The right of a panel's border.
pub(crate) fn trailing<'a>(mut spans: Vec<Span<'a>>) -> Line<'a> {
    spans.insert(0, Span::raw(" "));
    spans.push(Span::styled(" ─", theme::border()));
    Line::from(spans)
}

/// A panel's inside, with a column of air against each border.
pub(crate) fn pad(inside: Rect) -> Rect {
    Rect {
        x: inside.x + 1,
        width: inside.width.saturating_sub(2),
        ..inside
    }
}

/// Draw `text` along the bottom of a panel's inside and return what is left
/// above it for the rows.
///
/// Two lines at most: a note that runs longer is cut, not left to push the
/// rows off the screen.
pub(crate) fn note(frame: &mut Frame, inside: Rect, text: &str, tone: Tone) -> Rect {
    let padded = pad(inside);
    let needs = (text.width() as u16)
        .div_ceil(padded.width.max(1))
        .clamp(1, 2)
        .min(inside.height);
    let rows = Rect {
        height: inside.height - needs,
        ..inside
    };
    frame.render_widget(
        Paragraph::new(Span::styled(text.to_string(), theme::tone(tone))).wrap(Wrap { trim: true }),
        Rect {
            y: inside.y + rows.height,
            height: needs,
            ..padded
        },
    );
    rows
}

/// A key and what it does. `rank` orders what is given up on a narrow
/// terminal: the highest goes first, and zero is never dropped.
pub(crate) struct Hint {
    pub key: String,
    pub does: &'static str,
    pub rank: u8,
}

impl Hint {
    pub fn new(key: impl Into<String>, does: &'static str, rank: u8) -> Self {
        Self {
            key: key.into(),
            does,
            rank,
        }
    }

    fn width(&self) -> usize {
        // " key " as a cap, a space, the word, and two spaces to the next.
        self.key.width() + self.does.width() + 5
    }
}

/// The hints that fit in `room` columns, in the order given.
pub(crate) fn fitting(mut hints: Vec<Hint>, room: usize) -> Vec<Hint> {
    while hints.iter().map(Hint::width).sum::<usize>() + 1 > room {
        let Some(drop) = hints
            .iter()
            .enumerate()
            .filter(|(_, hint)| hint.rank > 0)
            .max_by_key(|(_, hint)| hint.rank)
            .map(|(i, _)| i)
        else {
            break;
        };
        hints.remove(drop);
    }
    hints
}

/// The line of keys under the panels.
pub(crate) fn footer(frame: &mut Frame, area: Rect, hints: Vec<Hint>) {
    let mut spans = vec![Span::raw(" ")];
    for hint in fitting(hints, area.width as usize) {
        spans.push(Span::styled(format!(" {} ", hint.key), theme::cap()));
        spans.push(Span::styled(format!(" {}  ", hint.does), theme::label()));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// A line said in place of the keys.
pub(crate) fn said(frame: &mut Frame, area: Rect, line: &str) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(format!(" {line}"), theme::label()))),
        area,
    );
}

/// A duration as a clock: `01:42`, or `1:01:42` past the hour.
pub(crate) fn clock(elapsed: Duration) -> String {
    let secs = elapsed.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

/// `text` cut to `room` columns, ending in an ellipsis where it was cut.
///
/// Columns, not letters: a CJK letter or an emoji takes two.
pub(crate) fn shorten(text: &str, room: usize) -> String {
    if text.width() <= room {
        return text.to_string();
    }
    if room == 0 {
        return String::new();
    }
    let mut cut = String::new();
    let mut used = 0;
    for letter in text.chars() {
        let takes = letter.width().unwrap_or(0);
        if used + takes > room - 1 {
            break;
        }
        cut.push(letter);
        used += takes;
    }
    cut.push('…');
    cut
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_in_a_border_keeps_the_terminals_colour_and_the_border_keeps_its_own() {
        let line = own_colours(Line::from(vec![
            Span::raw("running"),
            Span::styled("─", theme::border()),
        ]));
        assert_eq!(line.spans[0].style.fg, Some(Color::Reset));
        assert_eq!(line.spans[1].style.fg, theme::border().fg);
    }

    #[test]
    fn a_clock_grows_an_hour_only_when_it_has_one() {
        assert_eq!(clock(Duration::from_secs(41)), "00:41");
        assert_eq!(clock(Duration::from_secs(102)), "01:42");
        assert_eq!(clock(Duration::from_secs(3_702)), "1:01:42");
    }

    #[test]
    fn text_too_long_for_its_room_ends_in_an_ellipsis() {
        assert_eq!(shorten("orbital.example", 20), "orbital.example");
        assert_eq!(shorten("orbital.example", 8), "orbital…");
        assert_eq!(shorten("orbital.example", 0), "");
    }

    #[test]
    fn wide_letters_are_cut_by_the_columns_they_take() {
        // Each of these takes two columns, so five columns hold two and the
        // ellipsis.
        assert_eq!(shorten("日本語テスト", 5), "日本…");
        assert_eq!(shorten("日本語", 6), "日本語");
        // A cut never leaves a column over that a wide letter would cross.
        assert_eq!(shorten("日本語テスト", 4), "日…");
    }

    #[test]
    fn a_narrow_terminal_gives_up_the_least_needed_keys_and_never_quit() {
        let hints = || {
            vec![
                Hint::new("f l", "views", 1),
                Hint::new("↑↓", "scroll", 2),
                Hint::new("g/G", "ends", 5),
                Hint::new("/", "filter", 3),
                Hint::new("y", "copy", 4),
                Hint::new("q", "quit", 0),
            ]
        };
        let kept =
            |room| -> Vec<&'static str> { fitting(hints(), room).iter().map(|h| h.does).collect() };
        assert_eq!(
            kept(80),
            ["views", "scroll", "ends", "filter", "copy", "quit"]
        );
        assert_eq!(kept(50), ["views", "scroll", "filter", "quit"]);
        assert_eq!(kept(5), ["quit"]);
    }
}
