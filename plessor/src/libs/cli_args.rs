use clap::{Parser, Subcommand};

#[derive(Parser)]
// `bin_name` is fixed so help names the engine as it is now called, even when it
// is started through the link its old name left behind.
#[command(
    name = "plessor",
    bin_name = "plessor",
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
    /// Test the parameters of URLs for injection: SQL, command, template and
    /// XSS among them. URLs come from the arguments, or one per line on stdin.
    Inject(InjectArgs),
    /// Send a JSON op to the daemon and print the streamed events. `operation` is
    /// required: this is the raw interface the node uses.
    Exec(ExecArgs),
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
