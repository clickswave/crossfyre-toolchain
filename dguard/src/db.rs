//! The `db` and `scans` subcommands every engine has, which work on what the engine's
//! daemon keeps.

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
    let answer = ask(daemon, &action.request()).await?;
    println!("{}", answer["message"].as_str().unwrap_or_default());
    Ok(())
}

/// The scans the engine's daemon keeps, the latest first, as its `scans` operation lists
/// them.
pub async fn list_scans(
    daemon: &Daemon,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let answer = ask(
        daemon,
        &json!({ "operation": "scans", "response": "instant" }),
    )
    .await?;
    match answer["scans"].as_array() {
        Some(scans) => Ok(scans.clone()),
        None => Err("the daemon listed no scans".into()),
    }
}

/// The request that takes stopped scan `id` up again, with the settings it was kept with.
/// Its events come as the scan's own did.
pub fn resume_request(id: &str) -> serde_json::Value {
    json!({ "operation": "resume", "response": "stream", "scan": id })
}

/// Send `request` to the engine's daemon, and give its answer when it is done. An answer
/// other than done is an error, in the daemon's words.
async fn ask(
    daemon: &Daemon,
    request: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let stream = daemon.connect().await?;
    let (reader, mut writer) = tokio::io::split(stream);
    let mut line = crate::encode(request);
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    let answer = BufReader::new(reader)
        .lines()
        .next_line()
        .await?
        .ok_or("the daemon closed the connection without answering")?;
    let answer: serde_json::Value = serde_json::from_str(&answer)?;
    match answer["status"].as_str() {
        Some("completed") => Ok(answer),
        _ => Err(answer["message"]
            .as_str()
            .unwrap_or("the daemon refused it")
            .into()),
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

    /// A daemon on a port of its own that answers one request with `answer`, and gives
    /// the request it was sent.
    async fn answering(answer: &'static str) -> (Daemon, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = tokio::io::split(stream);
            let line = BufReader::new(reader)
                .lines()
                .next_line()
                .await
                .unwrap()
                .unwrap();
            writer.write_all(answer.as_bytes()).await.unwrap();
            writer.write_all(b"\n").await.unwrap();
            line
        });
        (Daemon::new("voyage", port, false), asked)
    }

    #[tokio::test]
    async fn the_scans_are_asked_of_the_daemon_and_a_refusal_is_its_own_words() {
        let (daemon, asked) =
            answering(r#"{"status": "completed", "scans": [{"id": "s-1"}]}"#).await;
        assert_eq!(list_scans(&daemon).await.unwrap(), [json!({"id": "s-1"})]);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&asked.await.unwrap()).unwrap(),
            json!({"operation": "scans", "response": "instant"})
        );
        let (daemon, _) = answering(r#"{"status": "error", "message": "no database"}"#).await;
        assert_eq!(
            list_scans(&daemon).await.unwrap_err().to_string(),
            "no database"
        );
        assert_eq!(
            resume_request("s-1"),
            json!({"operation": "resume", "response": "stream", "scan": "s-1"})
        );
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
