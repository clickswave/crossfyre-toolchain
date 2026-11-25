//! Shared terminal dashboard for the crossfyre tools.
//!
//! Every tool used to carry its own copy of the same three hundred lines, and
//! they had already drifted: different keys, different colours, different
//! wording for the same idea. This crate owns the whole screen, so a tool only
//! says what it is counting and what its rows are.
//!
//! A tool implements [`Dashboard`] and hands it to [`run`]. It supplies its
//! name and target, its progress and counters, and for each view the columns
//! and the rows. It gets the two panels, the tabs, the logs view, scrolling,
//! filtering, copying, the clock, the rate and the terminal's lifecycle.
//!
//! Nothing here depends on any engine crate. It takes numbers and strings, so
//! it cannot become a path for internals to reach the screen by accident.

mod chrome;
pub mod scans;
pub mod sheet;
pub mod table;
pub mod theme;
pub mod widgets;

#[cfg(feature = "tuning")]
pub mod tuning;

use chrome::Hint;
use crossterm::{
    clipboard::CopyToClipboard,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::Modifier,
    text::{Line, Span},
    widgets::Paragraph,
};
use sheet::Scroll;
use std::collections::VecDeque;
use std::io::{self, IsTerminal};
use std::time::{Duration, Instant};
use unicode_width::UnicodeWidthStr;

pub use sheet::{Cell, Column};
pub use theme::Tone;
pub use widgets::{Level, Logs, Progress, Stat};

/// A view the user can switch to. `key` is what they press, `label` is what
/// its tab says. The key is a letter of the label, which the tab underlines.
pub struct View {
    pub key: char,
    pub label: &'static str,
    /// Whether the view follows its newest row. See [`View::from_top`].
    pub follows: bool,
}

impl View {
    pub const fn new(key: char, label: &'static str) -> Self {
        Self {
            key,
            label,
            follows: true,
        }
    }

    /// A view that opens at its first row and stays where the user leaves it,
    /// for a list that is not kept in arrival order.
    pub const fn from_top(self) -> Self {
        Self {
            key: self.key,
            label: self.label,
            follows: false,
        }
    }
}

/// The logs view every tool gets for free. Reserved so no tool binds it to
/// something else and breaks the muscle memory.
pub const LOGS_KEY: char = 'l';

/// Keys the driver keeps for itself, which no view may take.
const RESERVED: &[char] = &[LOGS_KEY, 'q', 'j', 'k', 'g', 'G', 'y', '/'];

/// What a tool must tell the driver.
pub trait Dashboard {
    /// Shown in the border, conventionally the tool name in capitals.
    fn name(&self) -> &str;

    /// What the run is pointed at: a domain, a range, a URL.
    fn target(&self) -> &str {
        ""
    }

    /// The word beside the clock while the work goes on.
    fn doing(&self) -> &'static str {
        "running"
    }

    /// True once the work is over. The clock stops and the driver stops
    /// pumping, but the screen stays up so the results can be read.
    fn finished(&self) -> bool;

    /// How far the run is.
    fn progress(&self) -> Progress;

    /// The counters under the progress bar.
    fn stats(&self) -> Vec<Stat>;

    /// Views beyond logs. Order is the tab order.
    fn views(&self) -> &'static [View];

    /// A view's columns. `view` is always a key this tool declared.
    fn columns(&self, view: char) -> &'static [Column];

    /// How many rows a view holds.
    fn len(&self, view: char) -> usize;

    /// One row of a view, a cell per column. Only rows on screen are asked for,
    /// unless a filter is on.
    fn row(&self, view: char, index: usize) -> Vec<Cell>;

    /// A line kept under a view's rows: what the list is, or a caution about
    /// reading it.
    fn note(&self, _view: char) -> Option<Cell> {
        None
    }

    /// Shared log scrollback.
    fn logs(&mut self) -> &mut Logs;

    /// Current pacing, if the tool tracks it.
    #[cfg(feature = "tuning")]
    fn tuning(&self) -> tuning::Snapshot {
        tuning::Snapshot::default()
    }
}

/// Whether a dashboard can be shown at all.
///
/// Worth checking before asking for one: these tools run under the node with
/// stdout piped, and taking over a terminal that is really a pipe produces
/// escape sequences in somebody's log file.
pub fn available() -> bool {
    io::stdout().is_terminal()
}

/// Whether to draw a dashboard: in a terminal, unless `--no-tui` asks for JSON. A
/// stdout that is not a terminal never gets one: no caller who piped us wanted escape
/// sequences, and the engines used to draw anyway.
pub fn wanted(no_tui: bool) -> bool {
    wanted_from(no_tui, available())
}

/// The decision, without asking the terminal. See [`wanted`].
///
/// Split out so the policy is testable: under a test harness stdout is never a
/// terminal, so [`available`] would answer the question before the flag did.
pub fn wanted_from(no_tui: bool, available: bool) -> bool {
    !no_tui && available
}

/// Drive a dashboard until the user quits.
///
/// `pump` is called every tick to drain whatever the tool is receiving into
/// its own state, and says whether anything came. The driver never sees the
/// events, only the effect.
///
/// Blocking, and expects to own the terminal. Under tokio, wrap the call in
/// `spawn_blocking`.
pub fn run<D: Dashboard>(
    dashboard: &mut D,
    tick_ms: u64,
    mut pump: impl FnMut(&mut D) -> bool,
) -> io::Result<()> {
    debug_assert!(
        dashboard
            .views()
            .iter()
            .all(|view| !RESERVED.contains(&view.key)),
        "a view took a key the driver keeps for itself"
    );
    let mut terminal = enter()?;

    // Restore the terminal even if rendering panics. Without this a panic
    // leaves raw mode on and the alternate screen up, and the user is left
    // with a shell that no longer echoes what they type.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drive(&mut terminal, dashboard, tick_ms, &mut pump)
    }));

    leave(&mut terminal)?;

    match result {
        Ok(r) => r,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

type Term = Terminal<CrosstermBackend<io::Stdout>>;

fn enter() -> io::Result<Term> {
    // Before the screen is taken over: settling the palette may mean asking
    // the terminal for its colours and reading the reply.
    theme::init();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    Terminal::new(CrosstermBackend::new(stdout))
}

fn leave(terminal: &mut Term) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()
}

/// How long a line said in place of the keys stays up.
const SAID_FOR: Duration = Duration::from_secs(2);

/// What the driver keeps between frames: where the user is, and the clock.
struct Ui {
    active: char,
    scrolls: Vec<(char, Scroll)>,
    /// A filter is being typed, so letters go to it and not to the keys.
    typing: bool,
    said: Option<(&'static str, Instant)>,
    started: Instant,
    finished: Option<Instant>,
    pace: Pace,
}

impl Ui {
    fn new<D: Dashboard>(dashboard: &D, now: Instant) -> Self {
        let views = dashboard.views();
        let mut scrolls: Vec<(char, Scroll)> = views
            .iter()
            .map(|view| (view.key, Scroll::new(view.follows)))
            .collect();
        scrolls.push((LOGS_KEY, Scroll::new(true)));
        Self {
            active: views.first().map(|view| view.key).unwrap_or(LOGS_KEY),
            scrolls,
            typing: false,
            said: None,
            started: now,
            finished: None,
            pace: Pace::default(),
        }
    }

    /// Rows arrived: every view works its filter out again.
    fn forget(&mut self) {
        for (_, scroll) in &mut self.scrolls {
            scroll.forget();
        }
    }

    fn scroll(&mut self) -> &mut Scroll {
        let active = self.active;
        let at = self
            .scrolls
            .iter()
            .position(|(key, _)| *key == active)
            .expect("the active view is one of the views");
        &mut self.scrolls[at].1
    }

    fn elapsed(&self, now: Instant) -> Duration {
        self.finished.unwrap_or(now).duration_since(self.started)
    }
}

/// How fast the count is moving, from the last few seconds of it.
#[derive(Default)]
struct Pace {
    samples: VecDeque<(Instant, usize)>,
}

impl Pace {
    const EVERY: Duration = Duration::from_millis(250);
    const WINDOW: Duration = Duration::from_secs(5);

    fn note(&mut self, now: Instant, done: usize) {
        if self
            .samples
            .back()
            .is_none_or(|(at, _)| now.duration_since(*at) >= Self::EVERY)
        {
            self.samples.push_back((now, done));
        }
        // Keep one sample from before the window, as the point to measure from.
        while self.samples.len() > 2 && now.duration_since(self.samples[1].0) >= Self::WINDOW {
            self.samples.pop_front();
        }
    }

    /// Counts a second, once there is a second of counting to go by.
    fn per_second(&self) -> Option<f64> {
        let (first, last) = (self.samples.front()?, self.samples.back()?);
        let over = last.0.duration_since(first.0);
        (over >= Duration::from_secs(1))
            .then(|| last.1.saturating_sub(first.1) as f64 / over.as_secs_f64())
    }
}

/// The active view's columns, how many rows it has, and its rows.
fn with_view<D: Dashboard, R>(
    dashboard: &mut D,
    view: char,
    then: impl FnOnce(&[Column], usize, &dyn Fn(usize) -> Vec<Cell>) -> R,
) -> R {
    if view == LOGS_KEY {
        let logs = &*dashboard.logs();
        then(Logs::COLUMNS, logs.len(), &|i| logs.row(i))
    } else {
        let dashboard = &*dashboard;
        then(dashboard.columns(view), dashboard.len(view), &|i| {
            dashboard.row(view, i)
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Step {
    Stay,
    Quit,
    /// Put this on the clipboard.
    Copy(String),
}

fn key<D: Dashboard>(
    ui: &mut Ui,
    dashboard: &mut D,
    code: KeyCode,
    modifiers: KeyModifiers,
) -> Step {
    // Ctrl-C in raw mode is ours to handle: the terminal will not deliver
    // SIGINT, so without this the only way out is to kill the process from
    // another shell.
    if code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL) {
        return Step::Quit;
    }
    let view = ui.active;
    if ui.typing {
        let mut filter = ui.scroll().filter().to_string();
        match code {
            KeyCode::Enter => ui.typing = false,
            KeyCode::Esc => {
                ui.typing = false;
                ui.scroll().set_filter(String::new());
            }
            KeyCode::Backspace => {
                filter.pop();
                ui.scroll().set_filter(filter);
            }
            KeyCode::Char(c) => {
                filter.push(c);
                ui.scroll().set_filter(filter);
            }
            _ => {}
        }
        return Step::Stay;
    }
    let scroll = ui.scroll();
    let shown = with_view(dashboard, view, |_, len, row| scroll.shown(len, row));
    match code {
        KeyCode::Char('q') => return Step::Quit,
        // Esc backs out of one thing at a time: the filter first, then the run.
        KeyCode::Esc if !scroll.filter().is_empty() => scroll.set_filter(String::new()),
        KeyCode::Esc => return Step::Quit,
        KeyCode::Char('/') => ui.typing = true,
        code if scroll.moved(code, shown) => {}
        KeyCode::Char('y') => {
            let Some(index) = scroll.selected(shown) else {
                return Step::Stay;
            };
            let cells = with_view(dashboard, view, |_, _, row| row(index));
            let line: Vec<String> = cells.into_iter().map(|cell| cell.text).collect();
            return Step::Copy(line.join("\t"));
        }
        KeyCode::Char(c) if c == LOGS_KEY || dashboard.views().iter().any(|view| view.key == c) => {
            ui.active = c;
        }
        _ => {}
    }
    Step::Stay
}

fn drive<D: Dashboard>(
    terminal: &mut Term,
    dashboard: &mut D,
    tick_ms: u64,
    pump: &mut impl FnMut(&mut D) -> bool,
) -> io::Result<()> {
    let mut ui = Ui::new(dashboard, Instant::now());
    // Cap the tick so the UI stays responsive to keys even when a tool asks
    // for a slow poll.
    let tick = Duration::from_millis(tick_ms.clamp(16, 100));

    loop {
        let now = Instant::now();
        if !dashboard.finished() {
            if pump(dashboard) {
                ui.forget();
            }
        } else if ui.finished.is_none() {
            ui.finished = Some(now);
            // Say so once, in the logs, so the reason the numbers stopped
            // moving is on screen rather than inferred.
            dashboard.logs().info("Run complete. Press q to exit.");
        }
        if let Progress::Counted { done, .. } | Progress::Open { done, .. } = dashboard.progress() {
            ui.pace.note(now, done);
        }

        terminal.draw(|f| paint(f, dashboard, &mut ui, now))?;

        if event::poll(tick)?
            && let Event::Key(pressed) = event::read()?
            && pressed.kind == KeyEventKind::Press
        {
            match key(&mut ui, dashboard, pressed.code, pressed.modifiers) {
                Step::Stay => {}
                Step::Quit => return Ok(()),
                Step::Copy(line) => {
                    execute!(
                        terminal.backend_mut(),
                        CopyToClipboard::to_clipboard_from(line)
                    )?;
                    // The terminal decides whether a program may set the
                    // clipboard and does not say which way it went, so this
                    // says what was done and no more.
                    ui.said = Some(("Row sent to the terminal's clipboard.", now));
                }
            }
        }
    }
}

#[cfg(feature = "tuning")]
fn pacing<D: Dashboard>(dashboard: &D) -> Option<Line<'static>> {
    let snapshot = dashboard.tuning();
    (!snapshot.is_empty()).then(|| tuning::line(&snapshot))
}

/// Without the tuning feature there is no pacing line and no room kept for one.
#[cfg(not(feature = "tuning"))]
fn pacing<D: Dashboard>(_dashboard: &D) -> Option<Line<'static>> {
    None
}

fn paint<D: Dashboard>(frame: &mut Frame, dashboard: &mut D, ui: &mut Ui, now: Instant) {
    let mut lines = Vec::new();
    let finished = dashboard.finished();
    // Once the run is over the rate is the whole run's, which is the figure
    // worth reading afterwards; the last few seconds of it would read zero.
    let elapsed = ui.elapsed(now);
    let rate = match (finished, dashboard.progress()) {
        (true, Progress::Counted { done, .. }) if elapsed.as_secs() > 0 => {
            Some(done as f64 / elapsed.as_secs_f64())
        }
        _ => ui.pace.per_second(),
    };
    let width = frame.area().width.saturating_sub(4) as usize;
    if let Some(line) = progress_line(&dashboard.progress(), width, rate, finished, elapsed) {
        lines.push(line);
    }
    lines.push(stats_line(&dashboard.stats()));
    lines.extend(pacing(dashboard));

    let [run, results, keys] = Layout::vertical([
        Constraint::Length(lines.len() as u16 + 2),
        Constraint::Min(0),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    run_panel(frame, run, dashboard, lines, elapsed);
    results_panel(frame, results, dashboard, ui);
    footer(frame, keys, dashboard, ui, now);
}

/// The top panel: the tool and its target in the border, the state and the
/// clock opposite, and inside it the progress, the counters and the pacing.
fn run_panel<D: Dashboard>(
    frame: &mut Frame,
    area: Rect,
    dashboard: &D,
    lines: Vec<Line<'static>>,
    elapsed: Duration,
) {
    let state = if dashboard.finished() {
        vec![
            Span::styled("✓", theme::tone(Tone::Good)),
            Span::styled(" done", theme::value()),
        ]
    } else {
        vec![
            Span::styled("●", theme::tone(Tone::Good)),
            Span::raw(format!(" {}", dashboard.doing())),
        ]
    };
    let mut right = state;
    right.push(Span::styled(
        format!("  {}", chrome::clock(elapsed)),
        theme::label(),
    ));
    let right = chrome::trailing(right);

    // The target gives way before anything else does: its start is what
    // identifies it, and the state and the clock are short.
    let name = dashboard.name();
    let taken = right.width() + name.width() + 8;
    let target = chrome::shorten(
        dashboard.target(),
        (area.width as usize).saturating_sub(taken),
    );
    let rest = if target.is_empty() {
        Vec::new()
    } else {
        vec![Span::styled(target, theme::value())]
    };

    let block = chrome::panel(chrome::heading(name, rest), right);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    frame.render_widget(Paragraph::new(lines), chrome::pad(inner));
}

/// The bar and the figures beside it, or nothing for a tool that is not a run.
fn progress_line(
    progress: &Progress,
    width: usize,
    rate: Option<f64>,
    finished: bool,
    elapsed: Duration,
) -> Option<Line<'static>> {
    // The figures need about 46 columns. The bar takes what is left, up to 40.
    let bar = width.saturating_sub(46).clamp(8, 40);
    let filled = |cells: usize| Span::styled("━".repeat(cells), theme::tone(Tone::Accent));
    let empty = |cells: usize| Span::styled("─".repeat(cells), theme::label());

    match *progress {
        Progress::None => None,
        Progress::Counted { done, total } => {
            let ratio = if total > 0 {
                (done as f64 / total as f64).min(1.0)
            } else {
                0.0
            };
            let cells = (ratio * bar as f64).round() as usize;
            let mut spans = vec![filled(cells), empty(bar - cells)];
            // A run can start before its work is counted. Until then there is
            // a count and no total to set it against.
            if total > 0 {
                spans.push(Span::styled(
                    format!("  {} / {}", widgets::grouped(done), widgets::grouped(total)),
                    theme::value(),
                ));
                spans.push(Span::styled(
                    format!("  {}%", (ratio * 100.0).round() as usize),
                    theme::label(),
                ));
            } else {
                spans.push(Span::styled(
                    format!("  {}", widgets::grouped(done)),
                    theme::value(),
                ));
            }
            if let Some(rate) = rate {
                spans.push(Span::raw(format!("   {}/s", per_second(rate))));
                if !finished && rate > 0.0 && total > done {
                    // Rounded up: a run with half a second left is not done.
                    let left = Duration::from_secs(((total - done) as f64 / rate).ceil() as u64);
                    spans.push(Span::styled(
                        format!("   eta {}", chrome::clock(left)),
                        theme::label(),
                    ));
                }
            }
            Some(Line::from(spans))
        }
        Progress::Open { done, unit } => {
            // No total, so nothing to fill: a short mark travels the bar while
            // the work goes on, and the bar is whole once it is over.
            let mut spans = if finished {
                vec![filled(bar)]
            } else {
                let mark = (bar / 4).max(2);
                let reach = bar - mark;
                let step = (elapsed.as_millis() / 90) as usize % (reach * 2).max(1);
                let at = if step <= reach {
                    step
                } else {
                    reach * 2 - step
                };
                vec![empty(at), filled(mark), empty(reach - at)]
            };
            spans.push(Span::styled(
                format!("  {} {unit}", widgets::grouped(done)),
                theme::value(),
            ));
            Some(Line::from(spans))
        }
    }
}

/// A rate, with a decimal only where it would otherwise round to nothing.
fn per_second(rate: f64) -> String {
    if rate < 10.0 {
        format!("{rate:.1}")
    } else {
        widgets::grouped(rate.round() as usize)
    }
}

fn stats_line(stats: &[Stat]) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, stat) in stats.iter().enumerate() {
        if i > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(
            format!("{} ", stat.label.to_lowercase()),
            theme::label(),
        ));
        spans.push(Span::styled(
            stat.value.clone(),
            theme::tone(stat.tone).add_modifier(Modifier::BOLD),
        ));
    }
    Line::from(spans)
}

/// A tab: its label with the key underlined, then how many rows it holds.
fn tab(view_key: char, label: &'static str, count: usize, active: bool) -> Vec<Span<'static>> {
    let style = theme::tab(active);
    let hot = label
        .char_indices()
        .find(|(_, c)| c.eq_ignore_ascii_case(&view_key));
    let mut spans = match hot {
        Some((at, c)) => vec![
            Span::styled(&label[..at], style),
            Span::styled(
                &label[at..at + c.len_utf8()],
                style.add_modifier(Modifier::UNDERLINED),
            ),
            Span::styled(&label[at + c.len_utf8()..], style),
        ],
        None => vec![Span::styled(label, style)],
    };
    let count_style = if active {
        theme::tone(Tone::Accent)
    } else {
        theme::label()
    };
    spans.push(Span::styled(
        format!(" {}", widgets::grouped(count)),
        count_style,
    ));
    spans
}

/// The bottom panel: the tabs in its border, where the user is opposite, and
/// inside it the active view's rows over its note.
fn results_panel<D: Dashboard>(frame: &mut Frame, area: Rect, dashboard: &mut D, ui: &mut Ui) {
    let view = ui.active;
    let typing = ui.typing;

    let mut tabs = vec![Span::styled("─ ", theme::border())];
    for (i, declared) in dashboard.views().iter().enumerate() {
        if i > 0 {
            tabs.push(Span::styled(" ── ", theme::border()));
        }
        let count = dashboard.len(declared.key);
        tabs.extend(tab(
            declared.key,
            declared.label,
            count,
            declared.key == view,
        ));
    }
    if !dashboard.views().is_empty() {
        tabs.push(Span::styled(" ── ", theme::border()));
    }
    let lines = dashboard.logs().len();
    tabs.extend(tab(LOGS_KEY, "Logs", lines, view == LOGS_KEY));
    tabs.push(Span::raw(" "));

    let note = if view == LOGS_KEY {
        None
    } else {
        dashboard.note(view)
    };
    let scroll = ui.scroll();
    with_view(dashboard, view, |columns, len, row| {
        let shown = scroll.shown(len, row);

        let place = if typing || !scroll.filter().is_empty() {
            let caret = if typing { "▏" } else { "" };
            vec![
                Span::styled(format!("/{}{caret}", scroll.filter()), theme::title()),
                Span::styled(
                    format!("  {} of {}", widgets::grouped(shown), widgets::grouped(len)),
                    theme::label(),
                ),
            ]
        } else if scroll.following() || shown == 0 {
            vec![Span::styled("following", theme::label())]
        } else {
            vec![Span::styled(
                format!(
                    "{} of {}",
                    widgets::grouped(scroll.place().min(shown)),
                    widgets::grouped(shown)
                ),
                theme::label(),
            )]
        };

        let block = chrome::panel(Line::from(tabs), chrome::trailing(place));
        let inside = block.inner(area);
        frame.render_widget(block, area);

        let rows = match note {
            Some(note) => chrome::note(frame, inside, &note.text, note.tone),
            None => inside,
        };
        sheet::draw(frame, rows, columns, shown, row, scroll, "Nothing yet.");
    });
}

fn footer<D: Dashboard>(frame: &mut Frame, area: Rect, dashboard: &D, ui: &mut Ui, now: Instant) {
    if ui.typing {
        return chrome::footer(
            frame,
            area,
            vec![
                Hint::new("Enter", "keep the filter", 0),
                Hint::new("Esc", "clear it", 0),
            ],
        );
    }
    if let Some((line, at)) = ui.said {
        if now.duration_since(at) < SAID_FOR {
            return chrome::said(frame, area, line);
        }
        ui.said = None;
    }
    let mut view_keys: Vec<String> = dashboard
        .views()
        .iter()
        .map(|view| view.key.to_string())
        .collect();
    view_keys.push(LOGS_KEY.to_string());
    let filtered = !ui.scroll().filter().is_empty();
    let mut hints = vec![
        Hint::new(view_keys.join(" "), "views", 1),
        Hint::new("↑↓", "scroll", 2),
        Hint::new("g/G", "ends", 5),
        Hint::new("/", "filter", 3),
        Hint::new("y", "copy", 4),
    ];
    if filtered {
        hints.push(Hint::new("Esc", "clear the filter", 0));
    }
    hints.push(Hint::new("q", "quit", 0));
    chrome::footer(frame, area, hints);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    const FOUND: char = 'f';
    const HELD: char = 'h';
    const VIEWS: &[View] = &[
        View::new(FOUND, "Found"),
        View::new(HELD, "Held back").from_top(),
    ];
    const COLUMNS: &[Column] = &[Column::new("Source", 10), Column::rest("Name")];
    const NONE: KeyModifiers = KeyModifiers::NONE;

    /// A run over 12,000 names that has found 37 of them, four with "api" in.
    struct Fake {
        names: Vec<String>,
        done: usize,
        total: usize,
        finished: bool,
        progress: fn(&Fake) -> Progress,
        logs: Logs,
    }

    fn fake() -> Fake {
        let mut logs = Logs::new();
        logs.info("started");
        Fake {
            names: (0..37)
                .map(|i| match i % 10 {
                    3 => format!("api-{i}.app.test"),
                    _ => format!("host-{i}.app.test"),
                })
                .collect(),
            done: 4_812,
            total: 12_000,
            finished: false,
            progress: |fake| Progress::Counted {
                done: fake.done,
                total: fake.total,
            },
            logs,
        }
    }

    impl Dashboard for Fake {
        fn name(&self) -> &str {
            "VOYAGE"
        }
        fn target(&self) -> &str {
            "orbital.example"
        }
        fn finished(&self) -> bool {
            self.finished
        }
        fn progress(&self) -> Progress {
            (self.progress)(self)
        }
        fn stats(&self) -> Vec<Stat> {
            vec![
                Stat::count("Found", self.names.len()).good(),
                Stat::count("Not found", 4_775),
            ]
        }
        fn views(&self) -> &'static [View] {
            VIEWS
        }
        fn columns(&self, _view: char) -> &'static [Column] {
            COLUMNS
        }
        fn len(&self, view: char) -> usize {
            if view == HELD { 2 } else { self.names.len() }
        }
        fn row(&self, view: char, index: usize) -> Vec<Cell> {
            if view == HELD {
                vec![Cell::muted("policy"), Cell::plain(format!("held-{index}"))]
            } else {
                vec![Cell::muted("dns"), Cell::plain(&self.names[index])]
            }
        }
        fn note(&self, view: char) -> Option<Cell> {
            (view == HELD).then(|| Cell::muted("Not run, so not tested."))
        }
        fn logs(&mut self) -> &mut Logs {
            &mut self.logs
        }
    }

    /// The screen as text, a line per row.
    fn screen(fake: &mut Fake, ui: &mut Ui, now: Instant, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| paint(f, fake, ui, now)).unwrap();
        let buffer = terminal.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn press(ui: &mut Ui, fake: &mut Fake, code: KeyCode) -> Step {
        key(ui, fake, code, NONE)
    }

    #[track_caller]
    fn has(screen: &str, wanted: &[&str]) {
        for text in wanted {
            assert!(screen.contains(text), "{text:?} is not on:\n{screen}");
        }
    }

    #[test]
    fn the_run_panel_names_the_tool_its_target_and_how_far_it_is() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        let shown = screen(&mut fake, &mut ui, start + Duration::from_secs(41), 92, 24);
        has(
            &shown,
            &[
                "╭─ VOYAGE ─ orbital.example ",
                "● running  00:41 ─╮",
                "4,812 / 12,000  40%",
                "found 37   not found 4,775",
            ],
        );
        assert!(
            !shown.contains("/s"),
            "no rate before there is a second to go by"
        );
    }

    #[test]
    fn the_rate_and_the_time_left_come_from_the_last_few_seconds() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        ui.pace.note(start, 4_412);
        ui.pace.note(start + Duration::from_secs(2), 4_812);
        let shown = screen(&mut fake, &mut ui, start + Duration::from_secs(2), 92, 24);
        // 400 in two seconds, and 7,188 still to do.
        has(&shown, &["200/s", "eta 00:36"]);
    }

    #[test]
    fn a_rate_forgets_what_happened_before_its_window() {
        let start = Instant::now();
        let mut pace = Pace::default();
        // Fast for ten seconds, then one a second.
        for second in 0..=10 {
            pace.note(start + Duration::from_secs(second), second as usize * 1_000);
        }
        for second in 11..=20 {
            pace.note(
                start + Duration::from_secs(second),
                10_000 + second as usize - 10,
            );
        }
        let rate = pace.per_second().unwrap();
        assert!((0.9..=1.1).contains(&rate), "{rate} a second");
    }

    #[test]
    fn tabs_say_how_many_rows_each_view_holds_and_the_rows_follow_the_newest() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        let shown = screen(&mut fake, &mut ui, start, 92, 24);
        has(
            &shown,
            &[
                "╭─ Found 37 ── Held back 2 ── Logs 1 ",
                " following ─╮",
                "SOURCE",
                "NAME",
                "▌dns        host-36.app.test",
            ],
        );
        assert!(!shown.contains("host-0.app.test"), "the oldest are above");
    }

    #[test]
    fn moving_up_stops_following_and_says_where_the_selection_is() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        screen(&mut fake, &mut ui, start, 92, 24);
        assert_eq!(press(&mut ui, &mut fake, KeyCode::Up), Step::Stay);
        let shown = screen(&mut fake, &mut ui, start, 92, 24);
        has(&shown, &[" 36 of 37 ─╮", "▌dns        host-35.app.test"]);
        // g goes to the first row, and G back to the last and to following.
        press(&mut ui, &mut fake, KeyCode::Char('g'));
        has(
            &screen(&mut fake, &mut ui, start, 92, 24),
            &[" 1 of 37 ─╮", "▌dns        host-0.app.test"],
        );
        press(&mut ui, &mut fake, KeyCode::Char('G'));
        has(
            &screen(&mut fake, &mut ui, start, 92, 24),
            &[" following ─╮"],
        );
    }

    #[test]
    fn a_filter_is_typed_narrows_the_rows_and_esc_clears_it() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        press(&mut ui, &mut fake, KeyCode::Char('/'));
        // While typing, letters are the filter's: q does not quit and l does not
        // switch to the logs.
        for letter in "aql".chars() {
            assert_eq!(press(&mut ui, &mut fake, KeyCode::Char(letter)), Step::Stay);
        }
        press(&mut ui, &mut fake, KeyCode::Backspace);
        press(&mut ui, &mut fake, KeyCode::Backspace);
        for letter in "PI".chars() {
            press(&mut ui, &mut fake, KeyCode::Char(letter));
        }
        let shown = screen(&mut fake, &mut ui, start, 92, 24);
        has(
            &shown,
            &[
                "/aPI▏  4 of 37 ─╮",
                "api-3.app.test",
                "▌dns        api-33.app.test",
                "keep the filter",
            ],
        );
        assert!(!shown.contains("host-"), "rows without it are gone");

        press(&mut ui, &mut fake, KeyCode::Enter);
        has(
            &screen(&mut fake, &mut ui, start, 92, 24),
            &["/aPI  4 of 37 ─╮", "clear the filter"],
        );
        // Esc clears the filter first, and only then leaves.
        assert_eq!(press(&mut ui, &mut fake, KeyCode::Esc), Step::Stay);
        has(
            &screen(&mut fake, &mut ui, start, 92, 24),
            &["host-36.app.test"],
        );
        assert_eq!(press(&mut ui, &mut fake, KeyCode::Esc), Step::Quit);
    }

    #[test]
    fn a_filter_that_matches_nothing_says_so() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        for code in [KeyCode::Char('/'), KeyCode::Char('z'), KeyCode::Enter] {
            press(&mut ui, &mut fake, code);
        }
        has(
            &screen(&mut fake, &mut ui, start, 92, 24),
            &["Nothing matches \"z\".", "/z  0 of 37"],
        );
        assert_eq!(press(&mut ui, &mut fake, KeyCode::Char('y')), Step::Stay);
    }

    #[test]
    fn y_copies_the_selected_row_with_a_tab_between_its_cells() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        screen(&mut fake, &mut ui, start, 92, 24);
        press(&mut ui, &mut fake, KeyCode::Up);
        assert_eq!(
            press(&mut ui, &mut fake, KeyCode::Char('y')),
            Step::Copy("dns\thost-35.app.test".into())
        );
    }

    #[test]
    fn a_view_key_switches_views_and_each_view_keeps_its_own_place() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        screen(&mut fake, &mut ui, start, 92, 24);
        press(&mut ui, &mut fake, KeyCode::Up);
        press(&mut ui, &mut fake, KeyCode::Char(HELD));
        let shown = screen(&mut fake, &mut ui, start, 92, 24);
        // A view that does not follow opens on its first row, over its note.
        has(
            &shown,
            &[
                "▌policy     held-0",
                " 1 of 2 ─╮",
                "Not run, so not tested.",
            ],
        );
        press(&mut ui, &mut fake, KeyCode::Char(LOGS_KEY));
        has(
            &screen(&mut fake, &mut ui, start, 92, 24),
            &["LEVEL", "▌info   started"],
        );
        // A key no view has does nothing.
        assert_eq!(press(&mut ui, &mut fake, KeyCode::Char('x')), Step::Stay);
        press(&mut ui, &mut fake, KeyCode::Char(FOUND));
        has(
            &screen(&mut fake, &mut ui, start, 92, 24),
            &[" 36 of 37 ─╮"],
        );
    }

    #[test]
    fn q_and_ctrl_c_quit_and_ctrl_c_does_so_even_while_a_filter_is_typed() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        assert_eq!(press(&mut ui, &mut fake, KeyCode::Char('q')), Step::Quit);
        press(&mut ui, &mut fake, KeyCode::Char('/'));
        assert_eq!(
            key(
                &mut ui,
                &mut fake,
                KeyCode::Char('c'),
                KeyModifiers::CONTROL
            ),
            Step::Quit
        );
    }

    #[test]
    fn once_the_run_is_over_the_clock_stops_and_the_rate_is_the_whole_runs() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        fake.finished = true;
        fake.done = 12_000;
        ui.finished = Some(start + Duration::from_secs(100));
        let shown = screen(&mut fake, &mut ui, start + Duration::from_secs(900), 92, 24);
        has(
            &shown,
            &["✓ done  01:40 ─╮", "12,000 / 12,000  100%   120/s"],
        );
        assert!(!shown.contains("eta"), "nothing is left to wait for");
    }

    #[test]
    fn a_run_with_no_total_has_a_count_and_no_percentage() {
        let (mut fake, start) = (fake(), Instant::now());
        fake.progress = |fake| Progress::Open {
            done: fake.names.len(),
            unit: "findings",
        };
        let mut ui = Ui::new(&fake, start);
        let shown = screen(&mut fake, &mut ui, start, 92, 24);
        has(&shown, &["  37 findings"]);
        assert!(!shown.contains('%'));
    }

    #[test]
    fn a_tool_that_is_not_a_run_has_no_bar_and_gives_the_rows_its_line() {
        let (mut fake, start) = (fake(), Instant::now());
        fake.progress = |_| Progress::None;
        let mut ui = Ui::new(&fake, start);
        let shown = screen(&mut fake, &mut ui, start, 92, 24);
        let lines: Vec<&str> = shown.lines().collect();
        assert!(lines[1].contains("found 37"), "{shown}");
        assert!(lines[2].starts_with('╰'), "{shown}");
        assert!(lines[3].starts_with("╭─ Found 37"), "{shown}");
    }

    #[test]
    fn a_long_target_is_cut_before_the_state_and_the_clock_are() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        let shown = screen(&mut fake, &mut ui, start, 40, 12);
        has(&shown, &["╭─ VOYAGE ─ orbita… ", "● running  00:00 ─╮"]);
    }

    #[test]
    fn what_was_said_gives_the_keys_back_after_two_seconds() {
        let (mut fake, start) = (fake(), Instant::now());
        let mut ui = Ui::new(&fake, start);
        ui.said = Some(("Row sent to the terminal's clipboard.", start));
        let shown = screen(&mut fake, &mut ui, start + Duration::from_secs(1), 92, 24);
        has(&shown, &["Row sent to the terminal's clipboard."]);
        assert!(!shown.contains("quit"));
        let shown = screen(&mut fake, &mut ui, start + Duration::from_secs(3), 92, 24);
        has(
            &shown,
            &[" f h l  views", " ↑↓  scroll", " /  filter", " q  quit"],
        );
    }

    #[test]
    fn a_rate_keeps_a_decimal_only_below_ten() {
        assert_eq!(per_second(0.44), "0.4");
        assert_eq!(per_second(9.96), "10.0");
        assert_eq!(per_second(118.4), "118");
        assert_eq!(per_second(1_234.0), "1,234");
    }

    #[test]
    fn no_view_of_the_fake_takes_a_reserved_key() {
        assert!(VIEWS.iter().all(|view| !RESERVED.contains(&view.key)));
    }
}

#[cfg(test)]
mod wanted_tests {
    use super::wanted_from;

    #[test]
    fn a_pipe_never_gets_a_dashboard() {
        assert!(!wanted_from(false, false));
        assert!(!wanted_from(true, false));
    }

    #[test]
    fn a_terminal_gets_one_unless_no_tui_asks_for_json() {
        assert!(wanted_from(false, true));
        assert!(!wanted_from(true, true));
    }
}
