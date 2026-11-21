use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "toolmark",
    about = "Service enumeration and web fingerprinting daemon",
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
        default_value_t = 4444
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
    /// Scan a single target through the running daemon: fingerprint its web
    /// stack and report what it is running
    Scan(ScanArgs),
    /// Send a JSON op to the daemon and print the streamed events. `operation` is
    /// required: this is the raw interface the node uses.
    Exec(ExecArgs),
    /// Identify non-HTTP services on host:port targets, and whether they let
    /// anyone in
    Services(SvcArgs),
    /// The scans this engine keeps, the latest first. toolmark keeps nothing a stopped
    /// scan could carry on from, so a scan is run again rather than taken up
    Scans,
    /// What toolmark knows runs where: each host and port it scanned, the products and
    /// versions it found there, and the CVE leads each has in the CVE data it has now
    Inventory,
    /// Run the signatures toolmark has now over the pages it kept from earlier scans, and
    /// its CVE data over the products it holds, and report only what is new: products,
    /// versions and CVE leads. Nothing is sent to any host
    Rematch,
    /// Check a folder of signatures, and the mappings beside them, as toolmark reads them,
    /// and write the products they name for plessor's check of its templates
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
    ///   toolmark completions bash > ~/.local/share/bash-completion/completions/toolmark
    Completions {
        /// The shell to generate completions for
        shell: clap_complete::Shell,
    },
}

#[derive(Parser, Clone)]
pub struct ScanArgs {
    /// Target URL or host[:port] (e.g. https://example.com, example.com:8443)
    pub target: String,

    /// How far the scan goes: passive (the landing page only), quiet (and the
    /// favicon), standard (and the paths signatures ask for), aggressive, or rendered
    /// (and the landing page built in a browser, which needs Chrome or Chromium). 0 to 4
    /// work too
    #[arg(long, default_value = "standard", value_parser = depth)]
    pub depth: u8,
}

impl ScanArgs {
    /// The operation the daemon is sent for this scan.
    pub fn request(&self) -> serde_json::Value {
        serde_json::json!({
            "operation": "fingerprint",
            "response": "stream",
            "target": self.target,
            "depth_tier": self.depth,
        })
    }
}

/// A depth tier, by its number or its name.
fn depth(given: &str) -> Result<u8, String> {
    match given.to_ascii_lowercase().as_str() {
        "0" | "passive" => Ok(0),
        "1" | "quiet" => Ok(1),
        "2" | "standard" => Ok(2),
        "3" | "aggressive" => Ok(3),
        "4" | "rendered" => Ok(4),
        _ => Err("a depth is passive, quiet, standard, aggressive or rendered, or 0 to 4".into()),
    }
}

#[derive(Parser, Clone)]
pub struct SvcArgs {
    /// One or more `host:port` targets
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Skip the single anonymous/default-account check per service
    #[arg(long, default_value_t = false)]
    pub no_auth_checks: bool,

    /// Per-operation timeout in milliseconds
    #[arg(long, default_value_t = 5000)]
    pub timeout_ms: u64,
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
            "toolmark",
            "--no-autostart",
            "scan",
            "example.com"
        ]));
        assert!(parsed(&[
            "toolmark",
            "scan",
            "example.com",
            "--no-autostart"
        ]));
        assert!(!parsed(&["toolmark", "scan", "example.com"]));
    }

    #[test]
    fn the_daemon_is_a_command_with_its_port_after_it() {
        let argv: Vec<String> = std::iter::once("toolmark".to_string())
            .chain(dguard::daemon_args(5000))
            .collect();
        let cli = Cli::try_parse_from(&argv).expect("parses");
        assert!(matches!(cli.command, Some(Commands::Daemon)), "{argv:?}");
        assert_eq!(cli.port, 5000);
        assert!(
            Cli::try_parse_from(["toolmark", "--daemon"]).is_err(),
            "the old flag"
        );
    }

    #[test]
    fn a_scan_takes_its_depth_by_number_or_name() {
        let depth = |args: &[&str]| match Cli::try_parse_from(args).ok()?.command? {
            Commands::Scan(scan) => Some(scan.depth),
            _ => None,
        };
        let scan = ["toolmark", "scan", "example.com"];
        assert_eq!(depth(&scan), Some(2));
        for (given, tier) in [("rendered", 4), ("4", 4), ("passive", 0), ("Aggressive", 3)] {
            assert_eq!(
                depth(&[&scan[..], &["--depth", given]].concat()),
                Some(tier)
            );
        }
        for wrong in ["5", "loud", "-1"] {
            assert!(Cli::try_parse_from([&scan[..], &["--depth", wrong]].concat()).is_err());
        }
        let Some(Commands::Scan(args)) =
            Cli::try_parse_from([&scan[..], &["--depth", "rendered"]].concat())
                .unwrap()
                .command
        else {
            panic!("not a scan");
        };
        assert_eq!(args.request()["depth_tier"], 4);
    }

    #[test]
    fn fingerprint_is_no_longer_a_name_for_scan() {
        assert!(Cli::try_parse_from(["toolmark", "scan", "example.com"]).is_ok());
        assert!(Cli::try_parse_from(["toolmark", "fingerprint", "example.com"]).is_err());
    }

    #[test]
    fn no_tui_goes_before_or_after_the_command_and_tui_is_gone() {
        let parsed = |argv: &[&str]| Cli::try_parse_from(argv).expect("parses").no_tui;
        assert!(parsed(&["toolmark", "--no-tui", "scan", "example.com"]));
        assert!(parsed(&["toolmark", "scan", "example.com", "--no-tui"]));
        assert!(!parsed(&["toolmark", "scan", "example.com"]));
        assert!(Cli::try_parse_from(["toolmark", "--tui", "scan", "example.com"]).is_err());
    }
}

#[derive(Parser, Clone)]
pub struct CheckArgs {
    /// The folder of signatures
    pub dir: std::path::PathBuf,
    /// The folder of mappings: aliases.yaml, versions.yaml and each table a stamp leaf
    /// names, <name>-stamps.csv
    #[arg(long)]
    pub mappings: std::path::PathBuf,
    /// Write the products the signatures name, and their aliases, one vendor:product a
    /// line, to this file
    #[arg(long)]
    pub names: Option<std::path::PathBuf>,
}
