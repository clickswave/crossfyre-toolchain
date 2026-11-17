use crate::scanners::{active_scan, passive_scan};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueEnum};
use dialoguer::{Confirm, Input, theme::ColorfulTheme};

#[derive(Clone, Debug, ValueEnum)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
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

// ---------------------------------------------------------------------------
// Top-level CLI
// ---------------------------------------------------------------------------

/// {n}
/// |---------------------------------------------------|{n}
/// |                  V O Y A G E                     |{n}
/// |---------------------------------------------------|{n}
/// |       Stateful subdomain enumeration toolkit      |{n}
/// |                                                   |{n}
/// |                  clickswave.org                   |{n}
/// |---------------------------------------------------|{n}
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Run as a background TCP daemon service
    #[arg(long, default_value_t = false)]
    pub daemon: bool,

    /// Port for daemon mode
    #[arg(long, default_value_t = 4442)]
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
pub enum Commands {
    /// Scan for subdomains with a live TUI
    Scan(ScanArgs),
    /// Send a JSON op to the daemon and print the reply. `operation` defaults to
    /// `probe`, which checks a single subdomain with no dashboard.
    #[command(alias = "scan-exec")]
    Exec(ExecArgs),
    /// Database management
    Db(DbArgs),
    /// Discover a target's real origin IP behind a CDN/WAF
    Origin(OriginArgs),
    /// Try a DNS zone transfer (AXFR) and print every name the zone gives up
    Axfr(AxfrArgs),
    /// Print a shell completion script to stdout, for example:
    ///   voyage completions bash > ~/.local/share/bash-completion/completions/voyage
    Completions {
        /// The shell to generate completions for
        shell: clap_complete::Shell,
    },
}

#[derive(ClapArgs, Clone, Debug)]
pub struct AxfrArgs {
    /// Zone to request (e.g. example.com)
    #[arg(short, long)]
    pub domain: String,

    /// Nameserver to ask, as `ip` or `ip:port`. Omit to ask the zone's own
    /// authoritative servers.
    #[arg(long, default_value = "")]
    pub dns_server: String,

    /// Per-step timeout in ms
    #[arg(long, default_value_t = 8000)]
    pub timeout: u64,
}

#[derive(ClapArgs, Clone, Debug)]
pub struct OriginArgs {
    /// Target apex domain (e.g. example.com)
    #[arg(short, long)]
    pub domain: String,

    /// Per-request timeout in ms
    #[arg(long, default_value_t = 12000)]
    pub timeout: u64,

    /// Disable browser impersonation for the origin probes
    #[arg(long, default_value_t = false)]
    pub no_evasive: bool,

    /// Emit findings as JSON instead of human-readable text
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(ClapArgs, Clone, Debug)]
pub struct ExecArgs {
    /// JSON payload: {"domain":"sub.example.com","volatility":0}
    pub json: String,
}

#[derive(ClapArgs, Clone, Debug)]
pub struct DbArgs {
    /// Remove all rows from every table (keeps schema intact)
    #[arg(long, default_value_t = false)]
    pub full_reset: bool,
}

// ---------------------------------------------------------------------------
// Scan subcommand args
// ---------------------------------------------------------------------------

#[derive(ClapArgs, Clone, Debug)]
pub struct ScanArgs {
    /// Target domain(s) to enumerate
    #[arg(short, long)]
    pub domain: Vec<String>,

    /// Wordlist path for active enumeration
    #[arg(short, long, default_value_t = String::new())]
    pub wordlist_path: String,

    /// Number of concurrent tasks
    #[arg(short, long, default_value_t = 4)]
    pub tasks: usize,

    /// Interval in ms between requests per task
    #[arg(short, long, default_value_t = 0)]
    pub interval: u64,

    /// Start from scratch, ignoring any saved scan state
    #[arg(long, default_value_t = false)]
    pub fresh_start: bool,

    /// Disable passive subdomain enumeration
    #[arg(long, default_value_t = false)]
    pub disable_passive_enum: bool,

    /// Disable active subdomain enumeration (wordlist-based)
    #[arg(long, default_value_t = false)]
    pub disable_active_enum: bool,

    /// Passive sources to exclude; an unknown name is an error
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(passive_scan::SOURCES))]
    pub exclude_passive_source: Vec<String>,

    /// Active techniques to exclude; an unknown name is an error
    #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(active_scan::TECHNIQUES))]
    pub exclude_active_technique: Vec<String>,

    /// Ports to probe over HTTP
    #[arg(long, value_delimiter = ',', default_values_t = vec![80u16])]
    pub http_probing_port: Vec<u16>,

    /// Ports to probe over HTTPS
    #[arg(long, value_delimiter = ',', default_values_t = vec![443u16])]
    pub https_probing_port: Vec<u16>,

    /// User agent for active enumeration requests
    #[arg(long, default_value_t = adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, None).user_agent)]
    pub active_user_agent: String,

    /// User agent for passive enumeration requests
    #[arg(long, default_value_t = adaptive::identity::resolve(&adaptive::identity::Mode::Evasive, None).user_agent)]
    pub passive_user_agent: String,

    /// Randomize user agent per active request
    #[arg(long, default_value_t = false)]
    pub active_random_user_agent: bool,

    /// Randomize user agent per passive request
    #[arg(long, default_value_t = false)]
    pub passive_random_user_agent: bool,

    /// Minimum log level
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// TUI event polling timeout in ms
    #[arg(long, default_value_t = 1000)]
    pub event_poll_timeout: u64,

    /// Interactive mode - prompts for required options
    #[arg(long, default_value_t = false)]
    pub interactive: bool,
}

impl ScanArgs {
    pub fn interactive_fill(&mut self) -> Result<(), String> {
        let theme = ColorfulTheme::default();

        // --- Domain ---
        if self.domain.is_empty() {
            let domain_input: String = Input::with_theme(&theme)
                .with_prompt("Target domain (e.g. example.com)")
                .validate_with(|input: &String| {
                    if input.trim().is_empty() {
                        Err("Domain cannot be empty")
                    } else {
                        Ok(())
                    }
                })
                .interact_text()
                .map_err(|e| e.to_string())?;
            self.domain = vec![domain_input.trim().to_string()];
        }

        // --- Wordlist ---
        let wordlist_input: String = Input::with_theme(&theme)
            .with_prompt("Wordlist path (leave empty to skip active enum)")
            .with_initial_text(&self.wordlist_path)
            .allow_empty(true)
            .interact_text()
            .map_err(|e| e.to_string())?;

        if wordlist_input.trim().is_empty() {
            self.disable_active_enum = true;
        } else {
            if !std::path::Path::new(wordlist_input.trim()).exists() {
                return Err(format!("Wordlist not found: {}", wordlist_input.trim()));
            }
            self.wordlist_path = wordlist_input.trim().to_string();
        }

        // --- Tasks ---
        let tasks_input: String = Input::with_theme(&theme)
            .with_prompt("Concurrent tasks")
            .with_initial_text(self.tasks.to_string())
            .validate_with(|input: &String| {
                input
                    .trim()
                    .parse::<usize>()
                    .map(|_| ())
                    .map_err(|_| "Must be a positive number")
            })
            .interact_text()
            .map_err(|e| e.to_string())?;
        self.tasks = tasks_input.trim().parse::<usize>().unwrap_or(self.tasks);

        // --- Passive enum ---
        self.disable_passive_enum = !Confirm::with_theme(&theme)
            .with_prompt(format!(
                "Run passive enumeration? ({})",
                passive_scan::SOURCES.join(", ")
            ))
            .default(!self.disable_passive_enum)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_args(argv: &[&str]) -> Result<ScanArgs, clap::Error> {
        Cli::try_parse_from(argv).map(|cli| match cli.command {
            Some(Commands::Scan(args)) => args,
            other => panic!("not a scan: {other:?}"),
        })
    }

    #[test]
    fn the_exclusions_take_the_names_the_scanners_use() {
        let args = scan_args(&[
            "voyage",
            "scan",
            "--domain",
            "example.com",
            "--exclude-passive-source",
            passive_scan::CRT_SH,
            "--exclude-active-technique",
            active_scan::HTTP_PROBING,
        ])
        .expect("a known name parses");
        assert_eq!(args.exclude_passive_source, [passive_scan::CRT_SH]);
        assert_eq!(args.exclude_active_technique, [active_scan::HTTP_PROBING]);
    }

    fn refused(flag: &str, typo: &str, valid: &[&str]) {
        let err = scan_args(&["voyage", "scan", "--domain", "example.com", flag, typo])
            .expect_err("an unknown name is refused");
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
        let text = err.to_string();
        assert!(text.contains(typo), "{text}");
        for name in valid {
            assert!(text.contains(name), "{name} missing from: {text}");
        }
    }

    #[test]
    fn an_unknown_exclusion_is_refused_and_the_error_names_the_valid_ones() {
        // A misspelt name used to be accepted and ignored, so the source the
        // operator meant to switch off ran anyway and nothing said so.
        refused("--exclude-passive-source", "crtsh", &passive_scan::SOURCES);
        refused(
            "--exclude-active-technique",
            "http_probe",
            &active_scan::TECHNIQUES,
        );
    }
}
