//! The `cortex` command.
//!
//! Deliberately thin: everything it does lives in the library beside it, so other
//! crates in this product can call the engine without shelling out to a binary.

use clap::Parser;
use cortex::libs::cli_args::Cli;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    cortex::run(Cli::parse()).await
}
