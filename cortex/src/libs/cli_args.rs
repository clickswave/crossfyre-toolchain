use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cortex",
    about = "Vulnerability detection engine daemon",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Run as a background daemon (TCP server on the given port)
    #[arg(long, default_value_t = false)]
    pub daemon: bool,

    /// TCP port to bind (daemon) or connect to (client)
    #[arg(long, default_value_t = 4445)]
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
    /// Scan a single target through the running daemon
    Scan(ScanArgs),
    /// Send a JSON op to the daemon and print the streamed events. `operation` is
    /// required: this is the raw interface the node uses.
    Exec(ExecArgs),
}

#[derive(Parser, Clone)]
pub struct ScanArgs {
    /// Target URL or host[:port]
    pub target: String,
}

#[derive(Parser, Clone)]
pub struct ExecArgs {
    /// Raw JSON payload to send to the daemon
    pub json: String,
}
