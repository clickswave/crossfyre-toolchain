//! The table every view is drawn as: columns, rows of toned cells, and the
//! place in it the user has scrolled to.
//!
//! A tool hands over text and what the text means. Where the rows sit on
//! screen, which one is selected and which ones a filter hides are kept here,
//! so every tool scrolls, follows and filters the same way.

use crate::theme::{self, Tone};
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Constraint, Rect},
    text::{Line, Span, Text},
    widgets::{HighlightSpacing, Paragraph, Row, Table, TableState},
};

/// A column: its heading, and how wide it is.
pub struct Column {
    pub title: &'static str,
    /// In terminal cells. Zero takes whatever the other columns leave.
    pub width: u16,
}

impl Column {
    pub const fn new(title: &'static str, width: u16) -> Self {
        Self { title, width }
    }

    /// The column that takes the room the others leave. Conventionally the
    /// last one, and the one whose text can run long.
    pub const fn rest(title: &'static str) -> Self {
        Self { title, width: 0 }
    }
}

/// One cell: its text and what the text means.
pub struct Cell {
    pub text: String,
    pub tone: Tone,
    /// Drawn on a filled background, for a severity.
    pub chip: bool,
}

/// What a cell may show of `text`: none of what a terminal would act on or hide,
/// and on one line. A line break in a copied row goes wherever it is pasted, a
/// shell prompt included.
fn shown(text: &str) -> String {
    cfx_untrusted::strip(text).replace(['\n', '\t'], " ")
}

impl Cell {
    pub fn toned(text: impl Into<String>, tone: Tone) -> Self {
        Self {
            text: shown(&text.into()),
            tone,
            chip: false,
        }
    }

    pub fn plain(text: impl Into<String>) -> Self {
        Self::toned(text, Tone::Plain)
    }

    pub fn muted(text: impl Into<String>) -> Self {
        Self::toned(text, Tone::Muted)
    }

    /// A severity, in its tone. Low and above are chips, so they stand out of a
    /// list that is mostly informational, which is left as quiet text.
    pub fn severity(severity: impl Into<String>) -> Self {
        let text = shown(&severity.into());
        Self {
            tone: theme::severity(&text),
            chip: matches!(text.as_str(), "critical" | "high" | "medium" | "low"),
            text,
        }
    }

    /// An HTTP status, toned by its class.
    pub fn status_code(code: impl Into<String>) -> Self {
        let text = shown(&code.into());
        Self {
            tone: theme::status_code(&text),
            text,
            chip: false,
        }
    }

    fn draw(self) -> Text<'static> {
        if self.chip && !self.text.is_empty() {
            Text::from(Span::styled(
                format!(" {} ", self.text),
                theme::chip(self.tone),
            ))
        } else {
            Text::from(Span::styled(self.text, theme::tone(self.tone)))
        }
    }
}

/// Where the user is in one view.
pub struct Scroll {
    /// The selected row, counted among the rows the filter lets through.
    at: usize,
    /// The first row on screen, counted the same way.
    top: usize,
    /// Whether this view may follow its newest row at all. A list kept in
    /// arrival order does; one kept worst-first does not, since its newest row
    /// can land anywhere.
    follows: bool,
    /// Whether it is following right now.
    following: bool,
    filter: String,
    /// The rows the filter lets through, and how many rows there were when
    /// they were worked out.
    matches: Option<(usize, Vec<usize>)>,
    /// Rows that fitted on screen at the last draw: how far a page is.
    page: usize,
}

impl Scroll {
    pub fn new(follows: bool) -> Self {
        Self {
            at: 0,
            top: 0,
            follows,
            following: follows,
            filter: String::new(),
            matches: None,
            page: 1,
        }
    }

    /// A view drawn once with `at` selected, for a list whose owner keeps the
    /// selection itself.
    pub(crate) fn at(at: usize) -> Self {
        Self {
            at,
            ..Self::new(false)
        }
    }

    /// Move as `code` asks, among `shown` rows. False if the key is not one
    /// that moves.
    pub fn moved(&mut self, code: KeyCode, shown: usize) -> bool {
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.up(1),
            KeyCode::Down | KeyCode::Char('j') => self.down(1, shown),
            KeyCode::PageUp => self.up(self.page),
            KeyCode::PageDown => self.down(self.page, shown),
            KeyCode::Home | KeyCode::Char('g') => {
                self.at = 0;
                self.following = false;
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.at = shown.saturating_sub(1);
                self.following = self.follows;
            }
            _ => return false,
        }
        true
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    pub fn following(&self) -> bool {
        self.following
    }

    /// The selected row's place, from one, for "12 of 37".
    pub fn place(&self) -> usize {
        self.at + 1
    }

    /// Something arrived, so the rows the filter let through may no longer be
    /// the ones it would. A list can change without changing its length: a
    /// capped log drops a line for every one it takes, and a row can be
    /// rewritten where it stands.
    pub fn forget(&mut self) {
        self.matches = None;
    }

    pub fn set_filter(&mut self, filter: String) {
        self.filter = filter;
        self.matches = None;
        self.at = 0;
        self.top = 0;
        self.following = self.follows;
    }

    /// Work out which rows the filter lets through and say how many.
    ///
    /// Kept until something arrives, the list changes length or the filter
    /// changes: a finished run can hold tens of thousands of rows and is drawn
    /// many times a second.
    pub fn shown(&mut self, len: usize, row: &dyn Fn(usize) -> Vec<Cell>) -> usize {
        if self.filter.is_empty() {
            self.matches = None;
            return len;
        }
        if !matches!(&self.matches, Some((seen, _)) if *seen == len) {
            let wanted = self.filter.to_lowercase();
            let kept = (0..len)
                .filter(|&i| {
                    row(i)
                        .iter()
                        .any(|cell| cell.text.to_lowercase().contains(&wanted))
                })
                .collect();
            self.matches = Some((len, kept));
        }
        self.matches.as_ref().map_or(0, |(_, kept)| kept.len())
    }

    /// The row a place among the shown rows stands for.
    fn index(&self, place: usize) -> usize {
        match &self.matches {
            Some((_, kept)) => kept[place],
            None => place,
        }
    }

    /// The selected row, if there is one.
    pub fn selected(&self, shown: usize) -> Option<usize> {
        (self.at < shown).then(|| self.index(self.at))
    }

    fn up(&mut self, by: usize) {
        self.at = self.at.saturating_sub(by);
        self.following = false;
    }

    /// Move down. Arriving at the last row takes following up again.
    fn down(&mut self, by: usize, shown: usize) {
        let last = shown.saturating_sub(1);
        self.at = (self.at + by).min(last);
        self.following = self.follows && self.at == last;
    }

    /// Bring the selection and the window into line with `shown` rows on a
    /// screen that fits `height` of them.
    fn settle(&mut self, shown: usize, height: usize) {
        // A table with room only for its headings still has a selection, and
        // the window around it is worked out as though one row fitted.
        let height = height.max(1);
        self.page = height;
        if shown == 0 {
            self.at = 0;
            self.top = 0;
            return;
        }
        if self.following {
            self.at = shown - 1;
        }
        self.at = self.at.min(shown - 1);
        if self.at < self.top {
            self.top = self.at;
        }
        if self.at >= self.top + height {
            self.top = self.at + 1 - height;
        }
        // Never leave the bottom of the screen empty while rows wait above it.
        self.top = self.top.min(shown.saturating_sub(height));
    }
}

/// Draw a view: the headings, then as many rows as fit, around the selection.
///
/// `shown` is what [`Scroll::shown`] answered for the same `len` and `row`.
/// Only the rows on screen are asked for. `empty` is said where there are none.
pub fn draw(
    frame: &mut Frame,
    area: Rect,
    columns: &[Column],
    shown: usize,
    row: &dyn Fn(usize) -> Vec<Cell>,
    scroll: &mut Scroll,
    empty: &str,
) {
    if area.height == 0 {
        return;
    }
    let height = area.height.saturating_sub(1) as usize;
    scroll.settle(shown, height);

    let widths = columns.iter().map(|column| match column.width {
        0 => Constraint::Fill(1),
        width => Constraint::Length(width),
    });
    let headings =
        Row::new(columns.iter().map(|column| column.title.to_uppercase())).style(theme::label());
    let rows = (scroll.top..shown.min(scroll.top + height))
        .map(|place| Row::new(row(scroll.index(place)).into_iter().map(Cell::draw)));

    let table = Table::new(rows, widths)
        .header(headings)
        .column_spacing(1)
        .row_highlight_style(theme::selected())
        .highlight_symbol(Span::styled("▌", theme::tone(Tone::Accent)))
        // The marker's column is kept on every row, so the selected one does
        // not shift right of the others.
        .highlight_spacing(HighlightSpacing::Always);
    let mut state =
        TableState::default().with_selected((shown > 0).then(|| scroll.at - scroll.top));
    frame.render_stateful_widget(table, area, &mut state);

    if shown == 0 && area.height > 1 {
        let said = if scroll.filter.is_empty() {
            empty.to_string()
        } else {
            format!("Nothing matches \"{}\".", scroll.filter)
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(said, theme::label()))),
            Rect {
                x: area.x + 1,
                y: area.y + 1,
                width: area.width.saturating_sub(1),
                height: 1,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cell's text is mostly what a scanned target wrote: a title, a banner, a
    /// server header. What a terminal would act on or hide goes before it is drawn
    /// or copied, and so does a line break, which a copied row would take with it
    /// into wherever it is pasted.
    #[test]
    fn a_cell_keeps_only_what_shows() {
        let raw = "a\x1b[31mred\x1b[0m\x1b]8;;http://x.test\x07link\u{202E}b\u{200B}c\r\nd\te";
        for cell in [
            Cell::plain(raw),
            Cell::muted(raw),
            Cell::severity(raw),
            Cell::status_code(raw),
        ] {
            assert_eq!(cell.text, "aredlinkbc d e");
        }
    }

    fn rows(names: &'static [&'static str]) -> impl Fn(usize) -> Vec<Cell> {
        move |i| vec![Cell::plain(names[i])]
    }

    #[test]
    fn a_severity_is_a_chip_from_low_up_and_quiet_text_below() {
        for (severity, tone, chip) in [
            ("critical", Tone::Bad, true),
            ("high", Tone::Bad, true),
            ("medium", Tone::Warn, true),
            ("low", Tone::Muted, true),
            ("info", Tone::Muted, false),
            ("", Tone::Muted, false),
        ] {
            let cell = Cell::severity(severity);
            assert_eq!((cell.tone, cell.chip), (tone, chip), "{severity}");
        }
    }

    #[test]
    fn a_view_follows_its_newest_row_until_the_user_moves_up() {
        let mut scroll = Scroll::new(true);
        scroll.settle(40, 10);
        assert_eq!((scroll.at, scroll.top), (39, 30));
        scroll.moved(KeyCode::Up, 40);
        // More rows arrive: the selection stays where the user put it.
        scroll.settle(60, 10);
        assert_eq!((scroll.at, scroll.top), (38, 30));
        assert!(!scroll.following());
    }

    #[test]
    fn reaching_the_last_row_takes_following_up_again() {
        let mut scroll = Scroll::new(true);
        scroll.settle(40, 10);
        for _ in 0..5 {
            scroll.moved(KeyCode::Char('k'), 40);
        }
        assert!(!scroll.following());
        for _ in 0..5 {
            scroll.moved(KeyCode::Char('j'), 40);
        }
        assert!(scroll.following());
        scroll.settle(41, 10);
        assert_eq!(scroll.at, 40);
    }

    #[test]
    fn a_view_kept_worst_first_starts_at_the_top_and_never_follows() {
        let mut scroll = Scroll::new(false);
        scroll.settle(40, 10);
        assert_eq!((scroll.at, scroll.top), (0, 0));
        scroll.moved(KeyCode::End, 40);
        scroll.settle(45, 10);
        assert_eq!(scroll.at, 39);
        assert!(!scroll.following());
    }

    #[test]
    fn a_page_is_what_fitted_on_screen() {
        let mut scroll = Scroll::new(false);
        scroll.settle(100, 12);
        scroll.moved(KeyCode::PageDown, 100);
        scroll.settle(100, 12);
        assert_eq!((scroll.at, scroll.top), (12, 1));
        scroll.moved(KeyCode::PageUp, 100);
        assert_eq!(scroll.at, 0);
        assert!(
            !scroll.moved(KeyCode::Char('x'), 100),
            "not a key that moves"
        );
    }

    #[test]
    fn the_bottom_of_the_screen_is_not_left_empty_while_rows_wait_above() {
        let mut scroll = Scroll::new(true);
        scroll.settle(30, 5);
        assert_eq!(scroll.top, 25);
        // The screen grows: the window slides up to stay full.
        scroll.settle(30, 20);
        assert_eq!(scroll.top, 10);
    }

    #[test]
    fn a_filter_keeps_the_rows_that_hold_it_in_any_letter_case() {
        let names = &["api.app.test", "mail.app.test", "API-2.app.test"];
        let mut scroll = Scroll::new(true);
        scroll.set_filter("api".into());
        let shown = scroll.shown(3, &rows(names));
        assert_eq!(shown, 2);
        scroll.settle(shown, 10);
        assert_eq!(scroll.selected(shown), Some(2));
        scroll.moved(KeyCode::Up, shown);
        assert_eq!(scroll.selected(shown), Some(0));
    }

    #[test]
    fn a_filter_is_worked_out_again_when_the_list_grows() {
        let names = &["api.app.test", "mail.app.test", "api-2.app.test"];
        let mut scroll = Scroll::new(true);
        scroll.set_filter("api".into());
        assert_eq!(scroll.shown(2, &rows(names)), 1);
        assert_eq!(scroll.shown(3, &rows(names)), 2);
    }

    #[test]
    fn clearing_the_filter_shows_every_row_again() {
        let names = &["api.app.test", "mail.app.test"];
        let mut scroll = Scroll::new(true);
        scroll.set_filter("zzz".into());
        assert_eq!(scroll.shown(2, &rows(names)), 0);
        assert_eq!(scroll.selected(0), None);
        scroll.set_filter(String::new());
        assert_eq!(scroll.shown(2, &rows(names)), 2);
    }

    #[test]
    fn a_filter_is_worked_out_again_when_rows_change_in_place() {
        let mut scroll = Scroll::new(false);
        scroll.set_filter("waiting".into());
        assert_eq!(scroll.shown(2, &rows(&["a waiting", "b waiting"])), 2);
        // The same two rows, one of them answered since: the count is the
        // same, so only being told that something arrived can catch it.
        scroll.forget();
        assert_eq!(scroll.shown(2, &rows(&["a confirmed", "b waiting"])), 1);
        assert_eq!(scroll.selected(1), Some(1));
    }

    #[test]
    fn a_table_with_room_only_for_its_headings_still_draws() {
        use ratatui::{Terminal, backend::TestBackend};
        const COLUMNS: &[Column] = &[Column::rest("Host")];
        let names: &'static [&'static str] = &["a", "b", "c"];
        for height in 1..4 {
            let mut terminal = Terminal::new(TestBackend::new(20, height)).unwrap();
            for follows in [true, false] {
                let mut scroll = Scroll::new(follows);
                scroll.moved(KeyCode::End, 3);
                terminal
                    .draw(|f| draw(f, f.area(), COLUMNS, 3, &rows(names), &mut scroll, ""))
                    .unwrap();
            }
        }
    }
}
