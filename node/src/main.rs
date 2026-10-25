//! The Crossfyre node worker. This binary is not run directly by users; the
//! `crossfyre` CLI starts it (via the OS service, which execs `node supervise`,
//! and the supervisor in turn spawns `node daemon <id>` per registered node).
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "node",
    about = "Crossfyre node worker (managed by the crossfyre CLI)",
    version
)]
struct Cli {
    /// Override the crossfyre config root (matches `crossfyre --data-dir`).
    #[arg(long, global = true, value_name = "PATH")]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Supervise every registered node and keep them online (the OS service runs this).
    Supervise {
        /// Force-disconnect already-running instances and take over.
        #[arg(long)]
        force: bool,
    },
    /// Run a single registered node daemon (normally spawned by `supervise`).
    Daemon {
        /// Node id whose `nodes.d/<node-id>.toml` should be loaded.
        node_id: String,
        /// Force-disconnect an already-running instance and take over.
        #[arg(long)]
        force: bool,
    },
    /// Run `supervise` as the Windows service (the service manager runs this).
    #[cfg(windows)]
    #[command(hide = true)]
    Service {
        /// The crossfyre CLI that registered the service.
        #[arg(long, value_name = "PATH")]
        cli: PathBuf,
        /// The account that registered it, which the engines' tasks run as.
        #[arg(long, value_name = "DOMAIN\\USER")]
        operator: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    // The service manager calls back on a thread of its own, which makes its own runtime.
    #[cfg(windows)]
    if let Cmd::Service {
        cli: ref path,
        ref operator,
    } = cli.command
    {
        let base = cfx_core::resolve_data_dir(cli.data_dir.as_deref())?;
        return cfx_core::toolchain::win::scm::run_node_service(
            base,
            path.clone(),
            operator.clone(),
        );
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(cli))
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    // The node unit names the CLI that set it up. The node takes that CLI's packaging,
    // because a packaged CLI and the node it fetched live in different directories.
    if let Some(path) =
        std::env::var_os(cfx_core::toolchain::packaging::CLI_ENV).filter(|p| !p.is_empty())
    {
        cfx_core::toolchain::packaging::set_cli(PathBuf::from(path));
    }
    let base = cfx_core::resolve_data_dir(cli.data_dir.as_deref())?;
    // Off Linux the toolchain directory is the data directory, as it is for the CLI. On
    // Windows the service runs as LocalSystem, whose own profile is not the operator's;
    // on macOS it keeps `--data-dir` meaning the same thing to the node as to the CLI.
    // Linux keeps finding it through SUDO_USER, as it always has.
    if !cfg!(target_os = "linux") {
        cfx_core::toolchain::config::set_toolchain_dir(base.clone());
    }
    match cli.command {
        Cmd::Supervise { force } => cfx_core::run_boot(force, &base).await?,
        Cmd::Daemon { node_id, force } => {
            let paths = cfx_core::NodePaths::new(&base, &node_id);
            cfx_core::run_daemon(force, &paths, env!("CARGO_PKG_VERSION")).await?;
        }
        #[cfg(windows)]
        Cmd::Service { .. } => unreachable!("handled before the runtime starts"),
    }
    Ok(())
}
