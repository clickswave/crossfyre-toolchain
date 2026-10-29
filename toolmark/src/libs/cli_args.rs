use clap::{Parser, Subcommand};

#[derive(Parser)]
// `bin_name` is fixed so help names the engine as it is now called, even when it
// is started through the link its old name left behind.
#[command(
    name = "toolmark",
    bin_name = "toolmark",
    about = "Service enumeration and web fingerprinting daemon",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Run as a background daemon (TCP server on the given port)
    #[arg(long, default_value_t = false)]
    pub daemon: bool,

    /// TCP port to bind (daemon) or connect to (client)
    #[arg(long, default_value_t = 4444)]
    pub port: u16,

    /// Show a live dashboard instead of streaming JSON. Ignored when stdout is
    /// not a terminal, so piping still produces parseable output.
    #[arg(long, default_value_t = false)]
    pub tui: bool,

    /// Never draw the dashboard; stream newline-delimited JSON instead.
    #[arg(long, default_value_t = false)]
    pub no_tui: bool,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// Scan a single target through the running daemon: fingerprint its web
    /// stack and report what it is running
    #[command(alias = "fingerprint")]
    Scan(ScanArgs),
    /// Send a JSON op to the daemon and print the streamed events. `operation` is
    /// required: this is the raw interface the node uses.
    Exec(ExecArgs),
    /// Identify non-HTTP services on host:port targets, and whether they let
    /// anyone in
    Services(SvcArgs),
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
