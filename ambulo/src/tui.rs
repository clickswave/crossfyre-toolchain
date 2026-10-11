use crate::libs::cli_args::Args;
use crate::scanner::{Limit, Logs, Offset, ScanResults};
use crossterm::event;
use crossterm::event::{Event, KeyCode};
use ratatui::buffer::Buffer;
use ratatui::prelude::{Color, Constraint, Line, Rect, Style, Stylize, Widget};
use ratatui::symbols::border::THICK;
use ratatui::widgets::{Block, BorderType, Cell, Gauge, HighlightSpacing, Row, Table};
use std::io;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Home,
    Logs,
}

pub struct Tui {
    config: Arc<Args>,
    scan_results: Arc<Mutex<ScanResults>>,
    scan_results_limit: Arc<Mutex<Limit>>,
    scan_results_offset: Arc<Mutex<Offset>>,
    logs: Arc<Mutex<Logs>>,
    logs_limit: Arc<Mutex<Limit>>,
    logs_offset: Arc<Mutex<Offset>>,
    halt: bool,
    paused: Arc<core::sync::atomic::AtomicBool>,
    current_tab: Tab,
    log_level: String,
    status: String,
    probe_status_filter: String,
    scan_id: i64,
    output_written: bool,
    db: crate::libs::ambulo_db::AmbuloDb,
}

impl Tui {
    pub fn set_limit(&mut self, limit: usize) {
        self.scan_results_limit.lock().unwrap().set(limit);
        self.logs_limit.lock().unwrap().set(limit);
    }

    pub fn set_limit_from_terminal(
        &mut self,
        terminal: &ratatui::DefaultTerminal,
    ) -> Result<(), io::Error> {
        // Dynamically update the limit based on terminal height
        let terminal_size = terminal.size()?;
        let buffer_size = 0;
        let available_rows = terminal_size.height.saturating_sub(6) + buffer_size;
        self.set_limit(available_rows as usize);
        self.logs_limit.lock().unwrap().set(available_rows as usize);

        Ok(())
    }

    // Constructor taking the full initial render state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Args>,
        scan_results: Arc<Mutex<ScanResults>>,
        pause_notifier: Arc<core::sync::atomic::AtomicBool>,
        scan_results_limit: Arc<Mutex<Limit>>,
        scan_results_offset: Arc<Mutex<Offset>>,
        logs: Arc<Mutex<Logs>>,
        logs_limit: Arc<Mutex<Limit>>,
        logs_offset: Arc<Mutex<Offset>>,
        scan_id: i64,
        db: crate::libs::ambulo_db::AmbuloDb,
    ) -> Self {
        Tui {
            config,
            scan_results,
            scan_results_limit,
            scan_results_offset,
            logs,
            logs_limit,
            logs_offset,
            halt: false,
            paused: pause_notifier,
            current_tab: Tab::Home,
            log_level: "debug".to_string(),
            status: "Running".to_string(),
            probe_status_filter: "found".to_string(),
            output_written: false,
            scan_id,
            db,
        }
    }
    pub async fn run(&mut self, mut terminal: ratatui::DefaultTerminal) -> Result<(), sqlx::Error> {
        while !self.halt {
            if !self.config.output_path.is_empty()
                && !self.output_written
                && self.status == "Completed"
            {
                self.status = "Writing Output".to_string();
                let export_results = crate::exporter::Exporter::new(
                    self.scan_id,
                    &self.db,
                    &self.config.output_path,
                )
                .export(&self.config.output_format.to_string())
                .await;
                match export_results {
                    Ok(_) => {
                        self.output_written = true;
                    }
                    Err(e) => {
                        return Err(sqlx::Error::Io(io::Error::other(format!(
                            "Failed to export results: {e}"
                        ))));
                    }
                }
            }
            // limit the MutexGuard's lifetime to this block
            {
                let scan_results = self.scan_results.lock().unwrap();

                let found = scan_results.totals.found;
                let not_found = scan_results.totals.not_found;
                let error = scan_results.totals.error;
                let complete = found + not_found + error;
                let total = scan_results.totals.entries;

                self.status = if complete >= total {
                    "Completed".to_string()
                } else if self.paused.load(core::sync::atomic::Ordering::Relaxed) {
                    "Paused".to_string()
                } else {
                    "Running".to_string()
                };
            } // <-- MutexGuard dropped here before mutable borrow

            if self.config.enable_offset_pagination {
                self.set_limit_from_terminal(&terminal)?;
            }

            terminal.draw(|frame| {
                self.render(frame);
            })?;

            self.handle_events().await?;
        }
        ratatui::restore();

        if !self.config.no_exit_banner {
            crate::libs::banner::exit_banner();
        };

        exit(0);
    }

    fn render(&self, frame: &mut ratatui::Frame) {
        frame.render_widget(self, frame.area());
    }

    fn render_home(&self, area: Rect, buf: &mut Buffer) {
        let visible_items = area.height - 4;
        let scan_results = { self.scan_results.lock().unwrap() };
        let mut displayed_list = vec![];

        let scan_results_offset = self.scan_results_offset.lock().unwrap().value;

        let (results, style_color, label) = match self.probe_status_filter.as_str() {
            "found" => (&scan_results.found, Color::Green, "Found"),
            "not_found" => (&scan_results.not_found, Color::Gray, "Not Found"),
            "error" => (&scan_results.error, Color::Red, "Error"),
            _ => (&Vec::new(), Color::White, ""), // default empty
        };

        let style = Style::default().fg(style_color);

        for (index, result) in results.iter().enumerate() {
            if self.config.enable_offset_pagination {
                let real_index = scan_results_offset + index + 1;

                let index_cell = Cell::from(format!("{real_index}"));
                let url_cell = Cell::from(result.url.clone());
                let status_cell = Cell::from(format!("{} [{}]", label, result.request_status));
                let headers_length_cell = Cell::from(format!("{}", result.headers_length));
                let body_length_cell = Cell::from(format!("{}", result.body_length));

                let row = Row::new(vec![
                    index_cell,
                    url_cell,
                    status_cell.style(style),
                    headers_length_cell,
                    body_length_cell,
                ]);

                displayed_list.push(row);
            } else if index >= scan_results_offset
                && index < scan_results_offset + visible_items as usize
            {
                let real_index = index + 1;

                let index_cell = Cell::from(format!("{real_index}"));
                let url_cell = Cell::from(result.url.clone());
                let status_cell = Cell::from(format!("{} [{}]", label, result.request_status));
                let headers_length_cell = Cell::from(format!("{}", result.headers_length));
                let body_length_cell = Cell::from(format!("{}", result.body_length));

                let row = Row::new(vec![
                    index_cell,
                    url_cell,
                    status_cell.style(style),
                    headers_length_cell,
                    body_length_cell,
                ]);

                displayed_list.push(row);
            }
        }

        let header_style = Style::default().fg(Color::Indexed(1));
        let header = ["No.", "URL", "Status", "Headers", "Body Size"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(header_style)
            .height(1);

        // Create a separator row with dashes spanning all columns
        let separator = Row::new(vec![
            "-".repeat(area.width as usize), // Adjust width for "No."
            "-".repeat(area.width as usize), // Adjust width for "URL"
            "-".repeat(area.width as usize), // Adjust width for "Status"
            "-".repeat(area.width as usize), // Adjust width for "Body Length"
            "-".repeat(area.width as usize), // Adjust width for "Headers Length"
        ])
        .style(Style::default().fg(Color::White));

        let instructions = Line::from(" <Up/Down> Navigate | <Left/Right> Cycle Filter ".bold());
        let cell_sizes = [
            Constraint::Length(5),
            Constraint::Fill(2),
            Constraint::Length(16),
            Constraint::Length(10),
            Constraint::Length(18),
        ];

        let table = Table::new(
            // Insert separator row after header
            std::iter::once(header.clone())
                .chain(std::iter::once(separator))
                .chain(displayed_list),
            cell_sizes,
        )
        .block(
            Block::default()
                .title(format!(" Filter Results: {} ", self.probe_status_filter).bold())
                .title_bottom(instructions.left_aligned())
                .borders(ratatui::widgets::Borders::all())
                .border_type(BorderType::Rounded),
        )
        .widths(cell_sizes)
        .highlight_spacing(HighlightSpacing::Always);

        let table_area = Rect::new(area.x + 1, area.y + 3, area.width - 2, area.height - 4);
        table.render(table_area, buf);
    }

    fn render_logs(&self, area: Rect, buf: &mut Buffer) {
        let visible_items = area.height - 4;
        let logs = { self.logs.lock().unwrap() };
        let mut displayed_list = vec![];
        let log_levels = ["debug", "info", "warn", "error"];
        let min_log_level_index = log_levels
            .iter()
            .position(|&x| x == self.log_level)
            .unwrap_or(0);

        let logs_offset = self.logs_offset.lock().unwrap().value;

        for (index, log) in logs
            .logs
            .iter()
            .filter(|l| {
                let log_level_index = log_levels.iter().position(|&x| x == l.level).unwrap_or(0);
                log_level_index >= min_log_level_index
            })
            .enumerate()
        {
            if self.config.enable_offset_pagination {
                let real_index = logs_offset + index + 1;
                let index_cell = Cell::from(format!("{real_index}"));
                let level_cell = Cell::from(log.level.clone());
                let message_cell = Cell::from(log.description.clone());
                let timestamp_cell = Cell::from(log.created_at.to_string());
                let row = Row::new(vec![index_cell, level_cell, message_cell, timestamp_cell]);
                displayed_list.push(row);
            } else if index >= logs_offset && index < logs_offset + visible_items as usize {
                let real_index = index + 1;
                let index_cell = Cell::from(format!("{real_index}"));
                let level_cell = Cell::from(log.level.clone());
                let message_cell = Cell::from(log.description.clone());
                let timestamp_cell = Cell::from(log.created_at.to_string());

                let row = Row::new(vec![index_cell, level_cell, message_cell, timestamp_cell]);

                displayed_list.push(row);
            }
        }

        let header_style = Style::default().fg(Color::Indexed(1));
        let header = ["No.", "Level", "Message", "Timestamp"]
            .into_iter()
            .map(Cell::from)
            .collect::<Row>()
            .style(header_style)
            .height(1);
        // Create a separator row with dashes spanning all columns
        let separator = Row::new(vec![
            "-".repeat(area.width as usize),
            "-".repeat(area.width as usize),
            "-".repeat(area.width as usize),
            "-".repeat(area.width as usize),
        ])
        .style(Style::default().fg(Color::White));
        let instructions = Line::from(" <Up/Down> Navigate | <Left/Right> Cycle Log Level ".bold());
        let cell_sizes = [
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Fill(1),
            Constraint::Length(20),
        ];
        let table = Table::new(
            // Insert separator row after header
            std::iter::once(header.clone())
                .chain(std::iter::once(separator))
                .chain(displayed_list),
            cell_sizes,
        )
        .block(
            Block::default()
                .title(format!(" Log Level: {} ", self.log_level).bold())
                .title_bottom(instructions.left_aligned())
                .borders(ratatui::widgets::Borders::all())
                .border_type(BorderType::Rounded),
        )
        .widths(cell_sizes)
        .highlight_spacing(HighlightSpacing::Always);

        let table_area = Rect::new(area.x + 1, area.y + 3, area.width - 2, area.height - 4);
        table.render(table_area, buf);
    }

    async fn handle_events(&mut self) -> io::Result<()> {
        if event::poll(Duration::from_millis(self.config.event_poll_timeout))?
            && let Event::Key(key_event) = event::read()?
        {
            match key_event.code {
                KeyCode::Char('q') | KeyCode::Char('Q') => self.halt = true,
                KeyCode::Char('p') | KeyCode::Char('P') => {
                    // allow pausing only if status is not "Completed"
                    if &self.status != "Completed" {
                        self.paused.store(
                            !self.paused.load(core::sync::atomic::Ordering::Relaxed),
                            core::sync::atomic::Ordering::Relaxed,
                        );
                    }
                }
                KeyCode::Char('h') | KeyCode::Char('H') => self.current_tab = Tab::Home,
                KeyCode::Char('l') | KeyCode::Char('L') => self.current_tab = Tab::Logs,
                KeyCode::Up => match self.current_tab {
                    Tab::Home => {
                        // update scan results offset
                        let scan_results_offset =
                            { self.scan_results_offset.lock().unwrap().value };
                        if scan_results_offset > 0 {
                            self.scan_results_offset
                                .lock()
                                .unwrap()
                                .set(scan_results_offset - 1)
                        }
                    }
                    Tab::Logs => {
                        // update logs offset
                        let logs_offset = { self.logs_offset.lock().unwrap().value };
                        if logs_offset > 0 {
                            self.logs_offset.lock().unwrap().set(logs_offset - 1);
                        }
                    }
                },
                KeyCode::Down => match self.current_tab {
                    Tab::Home => {
                        let scan_results_offset =
                            { self.scan_results_offset.lock().unwrap().value };

                        let results_length = {
                            match self.probe_status_filter.as_str() {
                                "found" => self.scan_results.lock().unwrap().found.len(),
                                "not_found" => self.scan_results.lock().unwrap().not_found.len(),
                                "error" => self.scan_results.lock().unwrap().error.len(),
                                _ => 0,
                            }
                        };

                        if self.config.enable_offset_pagination {
                            if results_length > 1 {
                                self.scan_results_offset
                                    .lock()
                                    .unwrap()
                                    .set(scan_results_offset + 1);
                            }
                        } else if scan_results_offset + 1 < results_length {
                            self.scan_results_offset
                                .lock()
                                .unwrap()
                                .set(scan_results_offset + 1);
                        }
                    }
                    Tab::Logs => {
                        let logs_offset = { self.logs_offset.lock().unwrap().value };

                        let logs_length = self.logs.lock().unwrap().logs.len();

                        if self.config.enable_offset_pagination {
                            if logs_length > 1 {
                                self.logs_offset.lock().unwrap().set(logs_offset + 1);
                            }
                        } else if logs_offset + 1 < logs_length {
                            self.logs_offset.lock().unwrap().set(logs_offset + 1);
                        }
                    }
                },

                KeyCode::Left => match self.current_tab {
                    Tab::Home => {
                        self.probe_status_filter = match self.probe_status_filter.as_str() {
                            "error" => "not_found".to_string(),
                            "not_found" => "found".to_string(),
                            _ => "found".to_string(),
                        };
                    }
                    Tab::Logs => {
                        self.log_level = match self.log_level.as_str() {
                            "debug" => "info".to_string(),
                            "info" => "warn".to_string(),
                            "warn" => "error".to_string(),
                            _ => "error".to_string(),
                        };
                    }
                },
                KeyCode::Right => match self.current_tab {
                    Tab::Home => {
                        self.probe_status_filter = match self.probe_status_filter.as_str() {
                            "found" => "not_found".to_string(),
                            "not_found" => "error".to_string(),
                            _ => "error".to_string(),
                        };
                    }
                    Tab::Logs => {
                        self.log_level = match self.log_level.as_str() {
                            "error" => "warn".to_string(),
                            "warn" => "info".to_string(),
                            "info" => "debug".to_string(),
                            _ => "debug".to_string(),
                        };
                    }
                },
                _ => {}
            }
        }
        Ok(())
    }
}

impl Widget for &Tui {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let title = Line::from("[ M A C H ]".bold());
        let status = Line::from(format!(" Status: {} ", self.status).bold());
        let tab = Line::from(match self.current_tab {
            Tab::Home => " Home ",
            Tab::Logs => " Logs ",
        });
        let instructions = Line::from(" <Q> Quit | <P> Toggle Pause | <H/L> Home/Logs ".bold());
        let version = Line::from(format!(" v{} ", env!("CARGO_PKG_VERSION")).bold());
        let block = Block::bordered()
            .title(title.centered())
            .title_top(status.right_aligned())
            .title_top(tab.left_aligned())
            .title_bottom(instructions.left_aligned())
            .title_bottom(version.right_aligned())
            .border_set(THICK)
            .border_type(BorderType::Rounded);
        block.render(area, buf);

        let totals = {
            let scan_results = self.scan_results.lock().unwrap();
            scan_results.totals.clone()
        }; // lock is dropped here

        let completed = totals.found + totals.not_found + totals.error;
        let total = totals.entries;

        let progress_percentage = if total == 0 {
            0
        } else {
            (completed as f64 / total as f64 * 100.0).round() as u8
        };

        let progress_text = format!(
            "Progress: {}% | Found: {} | Scanned: {} | Total: {}",
            &progress_percentage, &totals.found, &completed, &total,
        );

        let progress_area = Rect::new(1, 1, area.width - 2, 1);
        let progress_ratio = if total == 0 {
            0.0
        } else {
            let ratio = completed as f64 / total as f64;
            ratio.clamp(0.0, 1.0) // neat way to bound between 0.0 and 1.0
        };

        Gauge::default()
            .gauge_style(Style::default().fg(Color::Indexed(2)).bg(Color::Indexed(0)))
            .ratio(progress_ratio)
            .label(progress_text)
            .render(progress_area, buf);

        match self.current_tab {
            Tab::Home => self.render_home(area, buf),
            Tab::Logs => self.render_logs(area, buf),
        }
    }
}
