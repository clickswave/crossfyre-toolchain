use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "scout",
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
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// Fingerprint a single target through the running daemon
    Fingerprint(FpArgs),
    /// Identify non-HTTP services on host:port targets, and whether they let
    /// anyone in
    Services(SvcArgs),
    /// Send a raw JSON op to the daemon and print the streamed events
    Exec(ExecArgs),
}

#[derive(Parser, Clone)]
pub struct FpArgs {
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
