//! The Scans view: the scans an engine's daemon keeps, the latest first, as its `scans`
//! operation lists them, and a stopped one to take up again.

use crate::theme;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
};
use serde_json::Value;
use std::io;

/// What a key did.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Stay,
    Quit,
    /// Take up the scan at this place in the list again.
    TakeUp(usize),
}

/// Where the view is: which scan is chosen, and what it last said about it.
struct Picker<'a> {
    scans: &'a [Value],
    chosen: usize,
    said: Option<String>,
}

impl<'a> Picker<'a> {
    fn new(scans: &'a [Value]) -> Self {
        Self {
            scans,
            chosen: 0,
            said: None,
        }
    }

    fn key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Step {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => return Step::Quit,
            // Ctrl-C in raw mode is ours to handle, as on the dashboard.
            KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                return Step::Quit;
            }
            KeyCode::Up | KeyCode::Char('k') => self.chosen = self.chosen.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.chosen = (self.chosen + 1).min(self.scans.len().saturating_sub(1));
            }
            KeyCode::Enter => match self.scans.get(self.chosen) {
                Some(scan) if scan["resumable"] == true => return Step::TakeUp(self.chosen),
                Some(scan) => {
                    self.said = Some(format!(
                        "This scan cannot be taken up again: {}.",
                        text(&scan["why_not"])
                    ));
                    return Step::Stay;
                }
                None => return Step::Stay,
            },
            _ => return Step::Stay,
        }
        self.said = None;
        Step::Stay
    }
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

/// `scans`, those engine `name` keeps, as its `scans` command shows them: in the Scans
/// view when `tui`, until the user leaves or chooses a stopped scan to take up again,
/// which this gives, and otherwise written out a JSON object a line.
///
/// Blocking, and expects to own the terminal when `tui`. Under tokio, wrap the call in
/// `spawn_blocking`.
pub fn show(name: &str, scans: &[Value], tui: bool) -> io::Result<Option<Value>> {
    if !tui {
        use std::io::Write;
        let mut out = io::stdout().lock();
        for scan in scans {
            writeln!(out, "{scan}")?;
        }
        return Ok(None);
    }
    Ok(pick(name, scans)?.map(|chosen| scans[chosen].clone()))
}

/// Show `scans` until the user leaves, or chooses a stopped scan to take up again, whose
/// place in the list this gives.
fn pick(name: &str, scans: &[Value]) -> io::Result<Option<usize>> {
    let mut terminal = crate::enter()?;
    // The terminal is given back even if drawing panics, as the dashboard's is.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut picker = Picker::new(scans);
        loop {
            terminal.draw(|f| paint(f, name, &picker))?;
            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match picker.key(key.code, key.modifiers) {
                    Step::Stay => {}
                    Step::Quit => return Ok(None),
                    Step::TakeUp(chosen) => return Ok(Some(chosen)),
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

fn paint(frame: &mut Frame, name: &str, picker: &Picker) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());
    let header = Line::from(vec![
        Span::styled(format!("  {name}  "), theme::title()),
        Span::styled("SCANS", theme::value()),
        Span::styled(format!("    {} kept", picker.scans.len()), theme::label()),
    ]);
    frame.render_widget(
        Paragraph::new(header).block(Block::default().borders(Borders::ALL)),
        rows[0],
    );
    body(frame, picker, rows[1]);
    let footer = picker.said.clone().unwrap_or_else(|| {
        "  Up and down to choose, Enter takes a stopped scan up again, q to exit.".to_string()
    });
    frame.render_widget(Paragraph::new(footer).style(theme::label()), rows[2]);
}

fn body(frame: &mut Frame, picker: &Picker, area: Rect) {
    if picker.scans.is_empty() {
        frame.render_widget(
            Paragraph::new("  No scans kept yet.").style(theme::label()),
            area,
        );
        return;
    }
    let rows = picker.scans.iter().map(|scan| {
        let status = text(&scan["status"]);
        let colour = match status {
            "stopped" => theme::WARN,
            "completed" => theme::GOOD,
            "failed" => theme::BAD,
            _ => theme::ACCENT,
        };
        Row::new(vec![
            Cell::from(status.to_string()).style(ratatui::style::Style::default().fg(colour)),
            Cell::from(when(text(&scan["updated_at"]))),
            Cell::from(text(&scan["target"]).to_string()),
            Cell::from(text(&scan["id"]).chars().take(8).collect::<String>()),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(20),
            Constraint::Min(20),
            Constraint::Length(8),
        ],
    )
    .header(Row::new(["STATUS", "LAST CHANGED", "TARGET", "ID"]).style(theme::label()))
    .block(Block::default().borders(Borders::ALL))
    .row_highlight_style(theme::selected());
    let mut state = TableState::default().with_selected(Some(picker.chosen));
    frame.render_stateful_widget(table, area, &mut state);
}

/// `stamp`, an RFC 3339 time in UTC, to the minute.
fn when(stamp: &str) -> String {
    match stamp.get(..16) {
        Some(minute) => format!("{} UTC", minute.replace('T', " ")),
        None => stamp.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};
    use serde_json::json;

    fn scans() -> Vec<Value> {
        vec![
            json!({"id": "11111111-aaaa", "target": "app.example", "status": "stopped",
                   "updated_at": "2026-11-19T16:39:51Z", "resumable": true, "why_not": null}),
            json!({"id": "22222222-bbbb", "target": "old.example", "status": "completed",
                   "updated_at": "2026-11-18T09:05:00Z", "resumable": false,
                   "why_not": "it is completed"}),
        ]
    }

    #[test]
    fn enter_takes_a_stopped_scan_up_and_says_why_another_cannot_be() {
        let scans = scans();
        let mut picker = Picker::new(&scans);
        let none = KeyModifiers::NONE;
        assert_eq!(picker.key(KeyCode::Up, none), Step::Stay);
        assert_eq!(picker.chosen, 0, "nothing above the first");
        assert_eq!(picker.key(KeyCode::Down, none), Step::Stay);
        assert_eq!(picker.key(KeyCode::Down, none), Step::Stay);
        assert_eq!(picker.chosen, 1, "nothing below the last");
        assert_eq!(picker.key(KeyCode::Enter, none), Step::Stay);
        assert_eq!(
            picker.said.as_deref(),
            Some("This scan cannot be taken up again: it is completed.")
        );
        assert_eq!(picker.key(KeyCode::Char('k'), none), Step::Stay);
        assert_eq!(picker.said, None, "moving on clears it");
        assert_eq!(picker.key(KeyCode::Enter, none), Step::TakeUp(0));
        assert_eq!(picker.key(KeyCode::Char('q'), none), Step::Quit);
        assert_eq!(
            picker.key(KeyCode::Char('c'), KeyModifiers::CONTROL),
            Step::Quit
        );
        assert_eq!(
            Picker::new(&[]).key(KeyCode::Enter, none),
            Step::Stay,
            "with nothing kept"
        );
    }

    #[test]
    fn each_scan_shows_its_status_when_it_last_changed_its_target_and_id() {
        let scans = scans();
        let picker = Picker::new(&scans);
        let mut terminal = Terminal::new(TestBackend::new(100, 10)).unwrap();
        terminal.draw(|f| paint(f, "VOYAGE", &picker)).unwrap();
        let screen: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        for shown in [
            "VOYAGE",
            "SCANS",
            "2 kept",
            "stopped",
            "2026-11-19 16:39 UTC",
            "app.example",
            "11111111",
            "completed",
            "old.example",
            "Enter takes a stopped scan up again",
        ] {
            assert!(screen.contains(shown), "{shown} is not on the screen");
        }
        assert!(!screen.contains("aaaa"), "the id is cut to its first eight");
    }
}
