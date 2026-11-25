//! A read-only list an engine keeps, shown as a table: toolmark's inventory of what it
//! found running where.

use crate::chrome::{self, Hint};
use crate::sheet::{self, Cell, Column, Scroll};
use crate::theme::{self, Tone};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    text::Span,
};
use std::io;

/// One table to show: engine `name`'s list `title`, a line saying how much it holds, and
/// `rows` under `columns`.
pub struct List {
    pub name: &'static str,
    pub title: &'static str,
    pub summary: String,
    pub columns: &'static [Column],
    pub rows: Vec<Vec<String>>,
}

/// Show `list` until the user leaves with q or Esc, moving through it with the arrows.
///
/// Blocking, and expects to own the terminal. Under tokio, wrap the call in
/// `spawn_blocking`.
pub fn show(list: &List) -> io::Result<()> {
    let mut terminal = crate::enter()?;
    // The terminal is given back even if drawing panics, as the dashboard's is.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut scroll = Scroll::new(false);
        loop {
            terminal.draw(|f| paint(f, list, &mut scroll))?;
            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    // Raw mode keeps Ctrl-C from the shell, so it is honoured here.
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    code => {
                        scroll.moved(code, list.rows.len());
                    }
                }
            }
        }
    }));
    crate::leave(&mut terminal)?;
    match result {
        Ok(r) => r,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn paint(frame: &mut Frame, list: &List, scroll: &mut Scroll) {
    let [panel, keys] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(frame.area());
    let place = if list.rows.is_empty() {
        Vec::new()
    } else {
        vec![Span::styled(
            format!("{} of {}", scroll.place(), list.rows.len()),
            theme::label(),
        )]
    };
    let block = chrome::panel(
        chrome::heading(list.name, vec![Span::styled(list.title, theme::value())]),
        chrome::trailing(place),
    );
    let inside = block.inner(panel);
    frame.render_widget(block, panel);
    let rows = chrome::note(frame, inside, &list.summary, Tone::Muted);
    let row = |i: usize| list.rows[i].iter().map(Cell::plain).collect();
    sheet::draw(
        frame,
        rows,
        list.columns,
        list.rows.len(),
        &row,
        scroll,
        "Nothing kept yet.",
    );
    chrome::footer(
        frame,
        keys,
        vec![
            Hint::new("↑↓", "scroll", 1),
            Hint::new("g/G", "ends", 2),
            Hint::new("q", "quit", 0),
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    const COLUMNS: &[Column] = &[
        Column::new("Host", 20),
        Column::new("Product", 16),
        Column::rest("Version"),
    ];

    #[test]
    fn a_list_shows_its_header_and_rows() {
        let list = List {
            name: "TOOLMARK",
            title: "Inventory",
            summary: "2 products on 1 host".into(),
            columns: COLUMNS,
            rows: vec![
                vec!["app.test:443".into(), "Nginx".into(), "1.24.0".into()],
                vec!["app.test:443".into(), "WordPress".into(), ">= 5.0".into()],
            ],
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
        let mut scroll = Scroll::new(false);
        scroll.moved(KeyCode::Down, 2);
        terminal.draw(|f| paint(f, &list, &mut scroll)).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        for shown in [
            "TOOLMARK",
            "Inventory",
            "2 of 2",
            "2 products on 1 host",
            "PRODUCT",
            "Nginx",
            "WordPress",
            ">= 5.0",
        ] {
            assert!(screen.contains(shown), "{shown} missing from:\n{screen}");
        }
    }
}
