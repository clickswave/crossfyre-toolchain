//! A read-only list an engine keeps, shown as a table: toolmark's inventory of what it
//! found running where.

use crate::theme;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState},
};
use std::io;

/// One table to show: engine `name`'s view `title`, a line saying how much it holds, and
/// `rows` under `header`, each column at least as wide as `widths` says.
pub struct List<'a> {
    pub name: &'a str,
    pub title: &'a str,
    pub summary: String,
    pub header: &'a [&'a str],
    pub widths: &'a [u16],
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
        let mut at = 0usize;
        loop {
            terminal.draw(|f| paint(f, list, at))?;
            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Down => at = (at + 1).min(list.rows.len().saturating_sub(1)),
                    KeyCode::Up => at = at.saturating_sub(1),
                    _ => {}
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

fn paint(frame: &mut Frame, list: &List, at: usize) {
    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());
    let header = Line::from(vec![
        Span::styled(format!("  {}  ", list.name), theme::title()),
        Span::styled(list.title.to_string(), theme::value()),
        Span::styled(format!("    {}", list.summary), theme::label()),
    ]);
    frame.render_widget(
        Paragraph::new(header).block(Block::default().borders(Borders::ALL)),
        areas[0],
    );
    if list.rows.is_empty() {
        frame.render_widget(
            Paragraph::new("  Nothing kept yet.").style(theme::label()),
            areas[1],
        );
    } else {
        let rows = list.rows.iter().map(|r| Row::new(r.clone()));
        let table = Table::new(rows, crate::widgets::table_constraints(list.widths))
            .header(Row::new(list.header.to_vec()).style(theme::label()))
            .block(Block::default().borders(Borders::ALL))
            .row_highlight_style(theme::selected());
        let mut state = TableState::default().with_selected(Some(at));
        frame.render_stateful_widget(table, areas[1], &mut state);
    }
    frame.render_widget(
        Paragraph::new("  Up and down to move, q to exit.").style(theme::label()),
        areas[2],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn a_list_shows_its_header_and_rows() {
        let list = List {
            name: "TOOLMARK",
            title: "INVENTORY",
            summary: "2 products on 1 host".into(),
            header: &["HOST", "PRODUCT", "VERSION"],
            widths: &[20, 16, 10],
            rows: vec![
                vec!["app.test:443".into(), "Nginx".into(), "1.24.0".into()],
                vec!["app.test:443".into(), "WordPress".into(), ">= 5.0".into()],
            ],
        };
        let mut terminal = Terminal::new(TestBackend::new(80, 12)).unwrap();
        terminal.draw(|f| paint(f, &list, 1)).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        for shown in [
            "INVENTORY",
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
