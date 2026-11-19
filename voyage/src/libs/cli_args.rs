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

    /// The port the daemon listens on, and the one the commands here reach it on
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        default_value_t = 4442
    )]
    pub port: u16,

    /// Never draw the dashboard; stream newline-delimited JSON instead, as piped or
    /// redirected output always gets
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        default_value_t = false
    )]
    pub no_tui: bool,

    /// Never start the daemon: when it is not running, say so and stop. Setting
    /// CFX_NO_AUTOSTART=1 does the same.
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        default_value_t = false
    )]
    pub no_autostart: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan for subdomains with a live TUI
    Scan(ScanArgs),
    /// Send a JSON op to the daemon and print the reply. `operation` defaults to
    /// `probe`, which checks a single subdomain with no dashboard.
    Exec(ExecArgs),
    /// Database management
    Db(DbArgs),
    /// Discover a target's real origin IP behind a CDN/WAF
    Origin(OriginArgs),
    /// Try a DNS zone transfer (AXFR) and print every name the zone gives up
    Axfr(AxfrArgs),
    /// Run as this engine's daemon, which the commands here and the node talk to on
    /// --port
    Daemon,
    /// Print a shell completion script to stdout, for example:
    ///   voyage completions bash > ~/.local/share/bash-completion/completions/voyage
    Completions {
        /// The shell to generate completions for
        shell: clap_complete::Shell,
    },
}

#[derive(ClapArgs, Clone, Debug)]
pub struct AxfrArgs {
    /// The zone to request (e.g. example.com)
    #[arg(value_name = "DOMAIN")]
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
    /// The apex domain to look behind (e.g. example.com)
    #[arg(value_name = "DOMAIN")]
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
    /// The domains to enumerate, one after another
    #[arg(value_name = "DOMAIN", required_unless_present = "interactive")]
    pub domain: Vec<String>,

    /// A wordlist of names to try under each domain. Without one, only passive sources
    /// run
    #[arg(short, long, default_value_t = String::new(), hide_default_value = true)]
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

        self.wordlist_path = wordlist_input.trim().to_string();
        if !self.wordlist_path.is_empty() && !std::path::Path::new(&self.wordlist_path).exists() {
            return Err(format!("Wordlist not found: {}", self.wordlist_path));
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

    /// What runs without a wordlist: the line that says only the passive sources do,
    /// or why nothing would. None with a wordlist, when both halves run.
    pub fn passive_only(&self) -> Result<Option<&'static str>, &'static str> {
        if !self.wordlist_path.is_empty() {
            return Ok(None);
        }
        if self.disable_passive_enum {
            return Err(
                "there is nothing to run: the passive sources are off, and active \
                 enumeration needs -w <wordlist>",
            );
        }
        Ok(Some(
            "voyage: active enumeration needs -w <wordlist>, so only passive sources run",
        ))
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
        let err = scan_args(&["voyage", "scan", "example.com", flag, typo])
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

    #[test]
    fn no_autostart_goes_before_or_after_the_command() {
        let parsed = |argv: &[&str]| Cli::try_parse_from(argv).expect("parses").no_autostart;
        assert!(parsed(&["voyage", "--no-autostart", "db", "--full-reset"]));
        assert!(parsed(&["voyage", "db", "--full-reset", "--no-autostart"]));
        assert!(!parsed(&["voyage", "db", "--full-reset"]));
    }

    #[test]
    fn the_daemon_is_a_command_with_its_port_after_it() {
        let argv: Vec<String> = std::iter::once("voyage".to_string())
            .chain(dguard::daemon_args(5000))
            .collect();
        let cli = Cli::try_parse_from(&argv).expect("parses");
        assert!(matches!(cli.command, Some(Commands::Daemon)), "{argv:?}");
        assert_eq!(cli.port, 5000);
        assert!(
            Cli::try_parse_from(["voyage", "--daemon"]).is_err(),
            "the old flag"
        );
    }

    #[test]
    fn the_domains_follow_scan_and_the_old_names_are_gone() {
        let args = scan_args(&["voyage", "scan", "example.com", "example.org"]).expect("parses");
        assert_eq!(args.domain, ["example.com", "example.org"]);
        assert!(
            scan_args(&["voyage", "scan", "--interactive"]).is_ok(),
            "asked for"
        );
        for old in [
            &["voyage", "scan"][..],
            &["voyage", "scan", "-d", "example.com"],
            &["voyage", "scan", "--domain", "example.com"],
            &["voyage", "scan", "example.com", "--disable-active-enum"],
            &["voyage", "scan-exec", "{}"],
        ] {
            assert!(Cli::try_parse_from(old).is_err(), "{old:?}");
        }
    }

    #[test]
    fn without_a_wordlist_only_the_passive_sources_run() {
        let args = scan_args(&["voyage", "scan", "example.com"]).unwrap();
        assert_eq!(
            args.passive_only(),
            Ok(Some(
                "voyage: active enumeration needs -w <wordlist>, so only passive sources run"
            ))
        );
        let args = scan_args(&["voyage", "scan", "example.com", "-w", "subs.txt"]).unwrap();
        assert_eq!(args.passive_only(), Ok(None));
        let args = scan_args(&["voyage", "scan", "example.com", "--disable-passive-enum"]).unwrap();
        assert!(args.passive_only().is_err());
    }

    #[test]
    fn no_tui_goes_before_or_after_the_command_and_tui_is_gone() {
        let parsed = |argv: &[&str]| Cli::try_parse_from(argv).expect("parses").no_tui;
        assert!(parsed(&["voyage", "--no-tui", "scan", "example.com"]));
        assert!(parsed(&["voyage", "scan", "example.com", "--no-tui"]));
        assert!(!parsed(&["voyage", "scan", "example.com"]));
        assert!(Cli::try_parse_from(["voyage", "--tui", "scan", "example.com"]).is_err());
    }
    #[test]
    fn origin_and_axfr_take_the_domain_as_scan_does() {
        let cli = Cli::try_parse_from(["voyage", "origin", "example.com"]).expect("parses");
        let Some(Commands::Origin(args)) = cli.command else {
            panic!("not origin")
        };
        assert_eq!(args.domain, "example.com");
        let cli =
            Cli::try_parse_from(["voyage", "axfr", "example.com", "--dns-server", "10.0.0.53"])
                .expect("parses");
        let Some(Commands::Axfr(args)) = cli.command else {
            panic!("not axfr")
        };
        assert_eq!(args.domain, "example.com");
        for old in [
            &["voyage", "origin"][..],
            &["voyage", "origin", "-d", "example.com"],
            &["voyage", "origin", "--domain", "example.com"],
            &["voyage", "axfr", "-d", "example.com"],
            &["voyage", "axfr", "--domain", "example.com"],
        ] {
            assert!(Cli::try_parse_from(old).is_err(), "{old:?}");
        }
    }
}
