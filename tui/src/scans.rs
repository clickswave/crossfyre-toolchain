//! The Scans view: the scans an engine's daemon keeps, the latest first, as its `scans`
//! operation lists them, and a stopped one to take up again.

use crate::chrome::{self, Hint};
use crate::sheet::{self, Cell, Column, Scroll};
use crate::theme::{self, Tone};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    text::Span,
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

const COLUMNS: &[Column] = &[
    Column::new("Status", 10),
    Column::new("Last changed", 20),
    Column::rest("Target"),
    Column::new("ID", 8),
];

fn paint(frame: &mut Frame, name: &str, picker: &Picker) {
    let [panel, keys] =
        Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(frame.area());
    let block = chrome::panel(
        chrome::heading(name, vec![Span::styled("Scans", theme::value())]),
        chrome::trailing(vec![Span::styled(
            format!("{} kept", picker.scans.len()),
            theme::label(),
        )]),
    );
    let inside = block.inner(panel);
    frame.render_widget(block, panel);

    let row = |i: usize| {
        let scan = &picker.scans[i];
        let status = text(&scan["status"]);
        let tone = match status {
            "stopped" => Tone::Warn,
            "completed" => Tone::Good,
            "failed" => Tone::Bad,
            _ => Tone::Accent,
        };
        vec![
            Cell::toned(status, tone),
            Cell::plain(when(text(&scan["updated_at"]))),
            Cell::plain(text(&scan["target"])),
            Cell::muted(text(&scan["id"]).chars().take(8).collect::<String>()),
        ]
    };
    sheet::draw(
        frame,
        inside,
        COLUMNS,
        picker.scans.len(),
        &row,
        &mut Scroll::at(picker.chosen),
        "No scans kept yet.",
    );

    match &picker.said {
        Some(line) => chrome::said(frame, keys, line),
        None => chrome::footer(
            frame,
            keys,
            vec![
                Hint::new("↑↓", "choose", 2),
                Hint::new("Enter", "take a stopped scan up again", 1),
                Hint::new("q", "quit", 0),
            ],
        ),
    }
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
            "Scans",
            "2 kept",
            "stopped",
            "2026-11-19 16:39 UTC",
            "app.example",
            "11111111",
            "completed",
            "old.example",
            "take a stopped scan up again",
        ] {
            assert!(screen.contains(shown), "{shown} is not on the screen");
        }
        assert!(!screen.contains("aaaa"), "the id is cut to its first eight");
    }
}
