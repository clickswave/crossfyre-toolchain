//! The `db` subcommand every engine has, which works on what the engine's daemon keeps.

use crate::Daemon;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// What `<engine> db` does.
#[derive(clap::Subcommand, Clone, Debug, PartialEq, Eq)]
pub enum DbAction {
    /// Delete everything this engine keeps: every scan, and what each one found
    Reset,
    /// Delete one scan with what it found, or every scan made more than a number of days
    /// ago. A running scan is left alone
    Purge(PurgeArgs),
}

/// Which scans a purge deletes: one, or the old ones. `crossfyre db purge` takes the same.
#[derive(clap::Args, Clone, Debug, PartialEq, Eq)]
pub struct PurgeArgs {
    /// The id of the scan to delete
    #[arg(
        long,
        value_name = "ID",
        conflicts_with = "older_than",
        required_unless_present = "older_than"
    )]
    pub scan: Option<String>,
    /// Delete every scan made more than this many days ago
    #[arg(long, value_name = "DAYS")]
    pub older_than: Option<u32>,
}

impl DbAction {
    /// The request the daemon is sent for this.
    pub fn request(&self) -> serde_json::Value {
        match self {
            DbAction::Reset => json!({ "operation": "db_reset", "response": "instant" }),
            DbAction::Purge(PurgeArgs { scan: Some(id), .. }) => {
                json!({ "operation": "purge", "response": "instant", "scan": id })
            }
            DbAction::Purge(PurgeArgs { older_than, .. }) => json!({
                "operation": "purge",
                "response": "instant",
                "older_than_days": older_than,
            }),
        }
    }
}

/// Send `action` to the engine's daemon and print what it says. An answer other than
/// done is an error, in the daemon's words.
pub async fn run_db(daemon: &Daemon, action: &DbAction) -> Result<(), Box<dyn std::error::Error>> {
    let stream = daemon.connect().await?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut line = crate::encode(&action.request());
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    let answer = BufReader::new(reader)
        .lines()
        .next_line()
        .await?
        .ok_or("the daemon closed the connection without answering")?;
    let answer: serde_json::Value = serde_json::from_str(&answer)?;
    let message = answer["message"].as_str().unwrap_or_default().to_string();
    match answer["status"].as_str() {
        Some("completed") => {
            println!("{message}");
            Ok(())
        }
        _ => Err(message.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Engine {
        #[command(subcommand)]
        db: DbAction,
    }

    fn parse(args: &[&str]) -> Result<DbAction, clap::Error> {
        Engine::try_parse_from(std::iter::once("engine").chain(args.iter().copied())).map(|e| e.db)
    }

    #[test]
    fn a_purge_names_one_scan_or_a_number_of_days() {
        assert_eq!(
            parse(&["purge", "--scan", "s-1"]).unwrap().request(),
            json!({ "operation": "purge", "response": "instant", "scan": "s-1" })
        );
        assert_eq!(
            parse(&["purge", "--older-than", "30"]).unwrap().request(),
            json!({ "operation": "purge", "response": "instant", "older_than_days": 30 })
        );
        assert!(parse(&["purge"]).is_err(), "one of the two is needed");
        assert!(
            parse(&["purge", "--scan", "s-1", "--older-than", "30"]).is_err(),
            "and not both"
        );
        assert_eq!(
            parse(&["reset"]).unwrap().request(),
            json!({ "operation": "db_reset", "response": "instant" })
        );
    }
}
