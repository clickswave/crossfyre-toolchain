//! The `plessor` command.
//!
//! Deliberately thin: everything it does lives in the library beside it, so other
//! crates in this product can call the engine without shelling out to a binary.

use clap::Parser;
use plessor::libs::cli_args::Cli;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    plessor::run(Cli::parse()).await
}
