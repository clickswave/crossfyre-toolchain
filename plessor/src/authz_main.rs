//! The `plessor-authz` command: plessor's authorization testing as a daemon of its own,
//! on its own port. It runs `authz` and nothing else.

use clap::{CommandFactory, FromArgMatches};
use plessor::libs::cli_args::Cli;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Before anything asks the adaptive crate, clap's defaults included.
    cfx_pacing::load();
    // plessor's arguments, with this daemon's name and port. Made once, so it is kept.
    let port: &'static str = Box::leak(dguard::ports::PLESSOR_AUTHZ.to_string().into_boxed_str());
    let matches = Cli::command()
        .name("plessor-authz")
        .bin_name("plessor-authz")
        .mut_arg("port", |a| a.default_value(port))
        .get_matches();
    let ran = match Cli::from_arg_matches(&matches) {
        Ok(cli) => plessor::run_authz(cli).await,
        Err(e) => e.exit(),
    };
    match ran {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
