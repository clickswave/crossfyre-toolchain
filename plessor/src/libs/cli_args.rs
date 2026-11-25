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
        default_value_t = dguard::ports::PLESSOR
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
    /// What this engine kept of what its scans found, oldest first: each finding's id,
    /// check, severity and where, and whether it has a proof to verify it by
    Findings(FindingsArgs),
    /// Check one kept finding again by its proof, running nothing else of its scan, and say
    /// whether it is reproduced, changed, not reproduced or unreachable
    Verify(VerifyArgs),
    /// Check a folder of templates as plessor reads them: each parses, has a request, runs
    /// only matchers plessor has and patterns that compile, has an id of its own, and names
    /// a product toolmark names, when it names one
    Check(CheckArgs),
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
    /// Print the plessor man page (roff) to stdout, for example:
    ///   plessor man > plessor.1
    #[command(hide = true)]
    Man,
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

    /// What runs on the target, as toolmark names it (part:vendor:product, comma
    /// separated): a template about one product then runs only on the products named,
    /// and those held back are listed. Without it, toolmark's daemon is asked what it saw
    /// there in the last week, and with nothing fresh every template runs
    #[arg(long, value_name = "NAMES", value_delimiter = ',')]
    pub products: Option<Vec<String>>,

    /// Run every template, whatever --products says
    #[arg(long)]
    pub all_templates: bool,

    /// The port of toolmark's daemon, which the scan asks what it saw on the target
    /// lately: the products that choose the templates and the CVE leads to answer.
    /// Without it, the toolchain's config.toml names the port, as for every engine. With
    /// --products, toolmark is not asked
    #[arg(long, value_name = "PORT")]
    pub toolmark_port: Option<u16>,
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
pub struct FindingsArgs {
    /// Only what this scan found
    #[arg(long, value_name = "ID")]
    pub scan: Option<String>,

    /// The most to list
    #[arg(long, default_value_t = 200)]
    pub limit: i64,
}

#[derive(Parser, Clone)]
pub struct VerifyArgs {
    /// The finding's id, as `plessor findings` lists it
    pub id: i64,

    /// Cookie header for a finding of a scan behind a login: the proof names the slot,
    /// never the value
    #[arg(long, value_name = "COOKIES")]
    pub cookie: Option<String>,

    /// A header the proof needs, as "Name: value". Repeatable.
    #[arg(short = 'H', long = "header", value_name = "HEADER")]
    pub headers: Vec<String>,

    /// Send again what changes the target, which is not sent otherwise
    #[arg(long)]
    pub test_writes: bool,
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

#[derive(Parser, Clone)]
pub struct CheckArgs {
    /// The folder of templates
    pub dir: std::path::PathBuf,
    /// The products toolmark names, one vendor:product a line, as `toolmark check --names`
    /// writes them. Without it, the products templates name are not checked
    #[arg(long)]
    pub known: Option<std::path::PathBuf>,
}
