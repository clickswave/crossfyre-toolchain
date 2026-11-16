//! The `plessor` command.
//!
//! Deliberately thin: everything it does lives in the library beside it, so other
//! crates in this product can call the engine without shelling out to a binary.

use clap::Parser;
use plessor::libs::cli_args::Cli;

// An error is printed as the sentence it is. Returned from `main`, Rust prints it in
// debug form: in quotes, with a line break shown as a backslash and an n.
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match plessor::run(Cli::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
