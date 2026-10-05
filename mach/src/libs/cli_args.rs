use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use dialoguer::{Confirm, Input, Select, theme::ColorfulTheme};
use reqwest::Url;

#[derive(Clone, Debug, ValueEnum)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Clone, Debug, ValueEnum, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                HttpMethod::Get => "get",
                HttpMethod::Post => "post",
                HttpMethod::Put => "put",
                HttpMethod::Delete => "delete",
                HttpMethod::Head => "head",
            }
        )
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                LogLevel::Debug => "debug",
                LogLevel::Info => "info",
                LogLevel::Warn => "warn",
                LogLevel::Error => "error",
            }
        )
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Text,
    Csv,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                OutputFormat::Text => "text",
                OutputFormat::Csv => "csv",
            }
        )
    }
}

// ---------------------------------------------------------------------------
// Top-level CLI
// ---------------------------------------------------------------------------

/// {n}
/// |-------------------------------------------------|{n}
/// |                     M A C H                     |{n}
/// |-------------------------------------------------|{n}
/// |          Stateful asset discovery tool          |{n}
/// |                                                 |{n}
/// |                 clickswave.org                  |{n}
/// |-------------------------------------------------|{n}
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Run as a background TCP daemon service
    #[arg(long, default_value_t = false)]
    pub daemon: bool,

    /// Port for daemon mode
    #[arg(long, default_value_t = 4441)]
    pub port: u16,

    /// Show the live dashboard instead of streaming JSON. Ignored when stdout is
    /// not a terminal, so piping still produces parseable output.
    #[arg(long, default_value_t = false)]
    pub tui: bool,

    /// Never draw the dashboard; stream newline-delimited JSON instead.
    #[arg(long, default_value_t = false)]
    pub no_tui: bool,
}

#[derive(Subcommand, Debug)]
// clap subcommand enum: the large variant is the fully-populated scan config,
// constructed once per process. Boxing it would only move an allocation that
// never happens in a hot path.
#[allow(clippy::large_enum_variant)]
pub enum Commands {
    /// Scan URLs using a wordlist
    Scan(ScanArgs),
    /// Send a JSON op to the daemon and print the reply. `operation` defaults to
    /// `probe`, which checks a single URL with no wordlist and no dashboard.
    #[command(alias = "scan-exec")]
    Exec(ExecArgs),
    /// Database management
    Db(DbArgs),
}

#[derive(ClapArgs, Clone, Debug)]
pub struct ExecArgs {
    /// JSON payload: {"operation_id":"<uuid>","url":"<url>","success_codes":[200],"method":"get"}
    pub json: String,
}

#[derive(ClapArgs, Clone, Debug)]
pub struct DbArgs {
    /// Remove all rows from every table (keeps schema intact)
    #[arg(long, default_value_t = false)]
    pub full_reset: bool,
}

// ---------------------------------------------------------------------------
// Fuzz subcommand args
// ---------------------------------------------------------------------------

#[derive(ClapArgs, Clone, Debug)]
pub struct ScanArgs {
    /// Specify the URL(s) to target
    #[arg(short, long)]
    pub url: Vec<String>,

    /// Specify the wordlist path
    #[arg(short, long, default_value_t = format!(""))]
    pub wordlist_path: String,

    /// Specify what point of the URL should be replaced with words
    #[arg(long, default_value_t = format!("::FUZZ::"))]
    pub fuzz_marker: String,

    /// Cookies to use. Format: "Name: Value"
    #[arg(long)]
    pub cookies: Vec<String>,

    /// Headers to use. Format: "Name: Value"
    #[arg(long)]
    pub headers: Vec<String>,

    /// Basic auth credentials. Format: "username:password"
    #[arg(long, default_value_t = format!(""))]
    pub basic_auth: String,

    /// Store cookies received from the server
    #[arg(long, default_value_t = false)]
    pub store_cookies: bool,

    /// Success status codes (comma-separated)
    #[arg(long, value_delimiter = ',', default_values_t = vec![200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,306,307,308])]
    pub success_status_codes: Vec<u16>,

    /// Follow redirects
    #[arg(long, default_value_t = true)]
    pub follow_redirects: bool,

    /// Redirect follow depth
    #[arg(long, default_value_t = 5)]
    pub follow_redirects_depth: u64,

    /// HTTP method to use
    #[arg(long, value_enum, default_value_t = HttpMethod::Get)]
    pub http_method: HttpMethod,

    /// Interval in ms between requests per task
    #[arg(short, long, default_value_t = 0)]
    pub interval: u64,

    /// Number of concurrent tasks (threads)
    #[arg(short, long, default_value_t = 2)]
    pub tasks: usize,

    /// Start from scratch, ignoring any saved state
    #[arg(long, default_value_t = false)]
    pub fresh_start: bool,

    /// Use a random user agent for the whole scan
    #[arg(long, default_value_t = false)]
    pub random_user_agent_scan: bool,

    /// Use a different random user agent per request
    #[arg(long, default_value_t = false)]
    pub random_user_agent_request: bool,

    /// Append trailing slash to URLs
    #[arg(long, default_value_t = true)]
    pub append_slash: bool,

    /// Save response body for each request
    #[arg(long, default_value_t = false)]
    pub save_response_body: bool,

    /// Save response headers for each request
    #[arg(long, default_value_t = true)]
    pub save_response_headers: bool,

    /// User agent string
    #[arg(long, default_value_t = adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, None).user_agent)]
    pub user_agent: String,

    /// Present as a real browser (evasive, default) vs a neutral honest client.
    #[arg(long, default_value_t = true)]
    pub evasive: bool,

    /// Attribution token for authorized programs (sent as X-Bug-Bounty).
    #[arg(long)]
    pub identify: Option<String>,

    /// Suppress exit banner
    #[arg(long, default_value_t = false)]
    pub no_exit_banner: bool,

    /// Drop and recreate the database before scanning
    #[arg(long, default_value_t = false)]
    pub recreate_db: bool,

    /// Delay in seconds before starting
    #[arg(long, default_value_t = 0)]
    pub launch_delay: i64,

    /// Minimum log level
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub output_format: OutputFormat,

    /// Output file path
    #[arg(short, long, default_value_t = format!(""))]
    pub output_path: String,

    /// TUI event polling timeout in ms
    #[arg(long, default_value_t = 1000)]
    pub event_poll_timeout: u64,

    /// [UNSTABLE] Enable TUI offset pagination
    #[arg(long, default_value_t = false)]
    pub enable_offset_pagination: bool,

    /// Interactive mode - prompts for required options
    #[arg(long, default_value_t = false)]
    pub interactive: bool,

    /// Adaptive rate limiting: a controller sets concurrency + inter-probe delay
    /// live from the target's health instead of the fixed `tasks`/`interval`.
    #[arg(long, default_value_t = false)]
    pub adaptive_rate: bool,

    /// Adaptive resilience: retry policy follows the same live health signal.
    #[arg(long, default_value_t = false)]
    pub adaptive_resilience: bool,

    /// Controller posture when adaptive is on: stealth | balanced | throughput.
    #[arg(long, default_value_t = format!("balanced"))]
    pub posture: String,
}

// Re-export FuzzArgs as Args so the rest of the codebase is unchanged.
pub type Args = ScanArgs;

impl ScanArgs {
    /// Validate and normalise URLs. Called after interactive fill (if any).
    pub fn validate_urls(&mut self) -> Result<(), String> {
        if self.fuzz_marker.is_empty() {
            return Err("Fuzz marker cannot be empty".to_string());
        }

        let mut valid_urls = vec![];
        for mut url in self.url.drain(..) {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                url = format!("http://{url}");
            }

            let mut parsed = match Url::parse(&url) {
                Ok(u) => u.to_string(),
                Err(e) => return Err(format!("Invalid URL `{url}`: {e}")),
            };

            if !parsed.as_str().contains(&self.fuzz_marker) {
                if parsed.ends_with('/') {
                    parsed.push_str(&self.fuzz_marker);
                } else {
                    parsed.push_str(&format!("/{}", self.fuzz_marker));
                }
            }

            if !parsed.ends_with('/') && self.append_slash {
                parsed.push('/');
            }

            valid_urls.push(parsed);
        }
        self.url = valid_urls;
        Ok(())
    }

    /// Fill in required fields interactively, pre-filling with any values already set.
    pub fn interactive_fill(&mut self) -> Result<(), String> {
        let theme = ColorfulTheme::default();

        // --- URL ---
        let url_prefill = self.url.first().cloned().unwrap_or_default();
        let url_input: String = Input::with_theme(&theme)
            .with_prompt("URL to fuzz")
            .with_initial_text(&url_prefill)
            .validate_with(|input: &String| {
                if input.trim().is_empty() {
                    Err("URL cannot be empty")
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .map_err(|e| e.to_string())?;

        self.url = vec![url_input];

        // --- Wordlist ---
        let wordlist_input: String = Input::with_theme(&theme)
            .with_prompt("Wordlist path")
            .with_initial_text(&self.wordlist_path)
            .validate_with(|input: &String| {
                if input.trim().is_empty() {
                    Err("Wordlist path cannot be empty")
                } else if !std::path::Path::new(input.trim()).exists() {
                    Err("File not found")
                } else {
                    Ok(())
                }
            })
            .interact_text()
            .map_err(|e| e.to_string())?;

        self.wordlist_path = wordlist_input;

        // --- HTTP Method ---
        let methods = ["GET", "POST", "PUT", "DELETE", "HEAD"];
        let current_method_idx = match self.http_method {
            HttpMethod::Get => 0,
            HttpMethod::Post => 1,
            HttpMethod::Put => 2,
            HttpMethod::Delete => 3,
            HttpMethod::Head => 4,
        };
        let method_idx = Select::with_theme(&theme)
            .with_prompt("HTTP method")
            .items(&methods)
            .default(current_method_idx)
            .interact()
            .map_err(|e| e.to_string())?;

        self.http_method = match method_idx {
            1 => HttpMethod::Post,
            2 => HttpMethod::Put,
            3 => HttpMethod::Delete,
            4 => HttpMethod::Head,
            _ => HttpMethod::Get,
        };

        // --- Tasks ---
        let tasks_input: String = Input::with_theme(&theme)
            .with_prompt("Number of concurrent tasks")
            .with_initial_text(self.tasks.to_string())
            .validate_with(|input: &String| {
                input
                    .trim()
                    .parse::<usize>()
                    .map(|_| ())
                    .map_err(|_| "Must be a number")
            })
            .interact_text()
            .map_err(|e| e.to_string())?;

        self.tasks = tasks_input.trim().parse::<usize>().unwrap_or(self.tasks);

        // --- Follow redirects ---
        self.follow_redirects = Confirm::with_theme(&theme)
            .with_prompt("Follow redirects?")
            .default(self.follow_redirects)
            .interact()
            .map_err(|e| e.to_string())?;

        // --- Fresh start ---
        self.fresh_start = Confirm::with_theme(&theme)
            .with_prompt("Fresh start (ignore saved scan state)?")
            .default(self.fresh_start)
            .interact()
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}
