use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "plessor",
    about = "Vulnerability detection engine daemon",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// The port the daemon listens on, and the one the commands here reach it on
    #[arg(
        long,
        global = true,
        help_heading = "Global options",
        default_value_t = 4445
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

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// Scan a single target through the running daemon
    Scan(ScanArgs),
    /// Test the parameters of URLs for injection: SQL, command, template and
    /// XSS among them. URLs come from the arguments, or one per line on stdin.
    Inject(InjectArgs),
    /// Send a JSON op to the daemon and print the streamed events. `operation` is
    /// required: this is the raw interface the node uses.
    Exec(ExecArgs),
    /// The scans this engine keeps, the latest first, and a stopped template scan to take
    /// up again
    Scans,
    /// What this engine keeps: delete one scan, old scans, or everything
    Db {
        #[command(subcommand)]
        action: dguard::DbAction,
    },
    /// Run as this engine's daemon, which the commands here and the node talk to on
    /// --port
    Daemon,
    /// Print a shell completion script to stdout, for example:
    ///   plessor completions bash > ~/.local/share/bash-completion/completions/plessor
    Completions {
        /// The shell to generate completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Parser, Clone)]
pub struct ScanArgs {
    /// Target URL or host[:port]
    pub target: String,

    /// A directory of nuclei-format templates to run as well as the built-in
    /// checks and the starter pack. A template here replaces a pack template
    /// with the same id.
    #[arg(long, value_name = "DIR")]
    pub templates: Option<String>,
}

#[derive(Parser, Clone)]
pub struct InjectArgs {
    /// URLs to test. Every query parameter in each is tried. With none given,
    /// they are read from stdin, one per line, so another engine's output can be
    /// piped in.
    pub urls: Vec<String>,

    /// Cookie header to send with every request, for testing behind a login
    #[arg(long, value_name = "COOKIES")]
    pub cookie: Option<String>,

    /// Extra header to send with every request, as "Name: value". Repeatable.
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    pub headers: Vec<String>,

    /// Form body, as name=value pairs joined by &. Sends each URL as a POST and
    /// tests these fields as well as the query.
    #[arg(short = 'd', long, value_name = "FORM")]
    pub data: Option<String>,
}

#[derive(Parser, Clone)]
pub struct ExecArgs {
    /// Raw JSON payload to send to the daemon
    pub json: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_autostart_goes_before_or_after_the_command() {
        let parsed = |argv: &[&str]| Cli::try_parse_from(argv).expect("parses").no_autostart;
        assert!(parsed(&[
            "plessor",
            "--no-autostart",
            "scan",
            "example.com"
        ]));
        assert!(parsed(&[
            "plessor",
            "scan",
            "example.com",
            "--no-autostart"
        ]));
        assert!(!parsed(&["plessor", "scan", "example.com"]));
    }

    #[test]
    fn the_daemon_is_a_command_with_its_port_after_it() {
        let argv: Vec<String> = std::iter::once("plessor".to_string())
            .chain(dguard::daemon_args(5000))
            .collect();
        let cli = Cli::try_parse_from(&argv).expect("parses");
        assert!(matches!(cli.command, Some(Commands::Daemon)), "{argv:?}");
        assert_eq!(cli.port, 5000);
        assert!(
            Cli::try_parse_from(["plessor", "--daemon"]).is_err(),
            "the old flag"
        );
    }

    #[test]
    fn no_tui_goes_before_or_after_the_command_and_tui_is_gone() {
        let parsed = |argv: &[&str]| Cli::try_parse_from(argv).expect("parses").no_tui;
        assert!(parsed(&["plessor", "--no-tui", "scan", "example.com"]));
        assert!(parsed(&["plessor", "scan", "example.com", "--no-tui"]));
        assert!(!parsed(&["plessor", "scan", "example.com"]));
        assert!(Cli::try_parse_from(["plessor", "--tui", "scan", "example.com"]).is_err());
    }
}
