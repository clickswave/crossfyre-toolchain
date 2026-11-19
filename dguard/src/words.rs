//! A wordlist sent over the connection a scan is asked on.
//!
//! The command line reads the wordlist the user names and sends its words after the
//! scan request, so the daemon opens no path for that scan, and any file the user can
//! read works while the daemon still cannot be made to read one. The request says the
//! words follow by naming the list in [`WORDS_FOLLOW`]. Each chunk of words is then one
//! line, `{"words":[...]}`, and an empty chunk ends the list. Neither end holds more
//! than one chunk of it, so a list of millions of lines costs no more memory than a
//! short one.

use crate::Gate;
use std::path::Path;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, Lines};

/// The scan request field that says the words follow on the connection. It holds the
/// list's name, which is how records show it.
pub const WORDS_FOLLOW: &str = "wordlist_follows";

/// How many words go in one chunk.
pub const CHUNK_WORDS: usize = 4096;

/// The name a list sent from `path` goes by: its file name.
pub fn list_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Send the words of the file at `path`, its lines that are not empty, to a daemon
/// on `writer`, in chunks of [`CHUNK_WORDS`] and then the empty one that ends them.
/// The file is read as it is sent, never whole.
pub async fn send_words<W: AsyncWrite + Unpin>(writer: &mut W, path: &Path) -> Result<(), String> {
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("cannot read the wordlist {}: {e}", path.display()))?;
    let mut lines = BufReader::new(file).lines();
    let mut chunk = Vec::with_capacity(CHUNK_WORDS);
    loop {
        let line = lines.next_line().await.map_err(|e| {
            format!(
                "cannot read the wordlist {}: {e}. A wordlist is one word to a line, \
                 in UTF-8",
                path.display()
            )
        })?;
        let end = line.is_none();
        if let Some(word) = line.filter(|l| !l.is_empty()) {
            chunk.push(word);
        }
        if chunk.len() == CHUNK_WORDS || (end && !chunk.is_empty()) {
            send_chunk(writer, &chunk).await?;
            chunk.clear();
        }
        if end {
            return send_chunk(writer, &[]).await;
        }
    }
}

async fn send_chunk<W: AsyncWrite + Unpin>(writer: &mut W, words: &[String]) -> Result<(), String> {
    let mut line = crate::encode(&serde_json::json!({ "words": words }));
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .await
        .map_err(|e| format!("the daemon stopped reading the wordlist: {e}"))
}

/// The chunks of words a client sends after a scan request with [`WORDS_FOLLOW`], read
/// from the connection's lines one chunk at a time.
pub struct WordChunks<'a, R> {
    lines: &'a mut Lines<R>,
    gate: &'a Gate,
    ended: bool,
}

impl<'a, R: AsyncBufRead + Unpin> WordChunks<'a, R> {
    /// The chunks on `lines`, each let through `gate` as a request line is.
    pub fn new(lines: &'a mut Lines<R>, gate: &'a Gate) -> Self {
        Self {
            lines,
            gate,
            ended: false,
        }
    }

    /// The next chunk, or None once the empty chunk that ends the list has come.
    pub async fn next(&mut self) -> Result<Option<Vec<String>>, String> {
        if self.ended {
            return Ok(None);
        }
        let line = self
            .lines
            .next_line()
            .await
            .map_err(|e| format!("reading the wordlist failed: {e}"))?
            .ok_or("the connection closed before the end of the wordlist")?;
        if let Some(refused) = self.gate.refusal(&line) {
            return Err(serde_json::from_str::<serde_json::Value>(refused)
                .ok()
                .and_then(|v| v["message"].as_str().map(str::to_string))
                .unwrap_or_else(|| "refused".to_string()));
        }
        let words = serde_json::from_str::<serde_json::Value>(&line)
            .ok()
            .and_then(|v| match v.get("words") {
                Some(serde_json::Value::Array(words)) => words
                    .iter()
                    .map(|w| w.as_str().map(str::to_string))
                    .collect::<Option<Vec<String>>>(),
                _ => None,
            })
            .ok_or("a line of the wordlist is not {\"words\":[...]} with words that are text")?;
        if words.is_empty() {
            self.ended = true;
            return Ok(None);
        }
        Ok(Some(words))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file of its own under the system's temporary directory, removed when dropped.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str, bytes: &[u8]) -> Self {
            let path =
                std::env::temp_dir().join(format!("dguard-words-{}-{name}", std::process::id()));
            std::fs::write(&path, bytes).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// What a daemon reads of the words sent from `file`, chunk by chunk.
    async fn round_trip(file: &Path, gate: &Gate) -> Result<Vec<Vec<String>>, String> {
        let (mut client, daemon) = tokio::io::duplex(1 << 16);
        let path = file.to_path_buf();
        let sending = tokio::spawn(async move { send_words(&mut client, &path).await });
        let mut lines = BufReader::new(daemon).lines();
        let mut chunks = WordChunks::new(&mut lines, gate);
        let mut got = Vec::new();
        while let Some(chunk) = chunks.next().await? {
            got.push(chunk);
        }
        sending.await.unwrap()?;
        Ok(got)
    }

    #[tokio::test]
    async fn the_words_arrive_in_order_a_chunk_at_a_time_and_empty_lines_do_not() {
        let mut text = String::from("admin\r\n\r\n  \nindex.html\n");
        for i in 0..CHUNK_WORDS {
            text.push_str(&format!("w{i}\n"));
        }
        let file = Scratch::new("order", text.as_bytes());
        let chunks = round_trip(&file.0, &Gate::default()).await.unwrap();
        assert_eq!(chunks.len(), 2, "one chunk of {CHUNK_WORDS}, then the rest");
        assert_eq!(chunks[0].len(), CHUNK_WORDS);
        assert_eq!(chunks[0][..3], ["admin", "  ", "index.html"]);
        let rest: Vec<String> = (CHUNK_WORDS - 3..CHUNK_WORDS)
            .map(|i| format!("w{i}"))
            .collect();
        assert_eq!(chunks[1], rest);
    }

    #[tokio::test]
    async fn an_empty_file_is_a_list_of_no_words() {
        let file = Scratch::new("empty", b"\n\n");
        assert!(
            round_trip(&file.0, &Gate::default())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_file_that_is_not_text_is_refused_by_the_client() {
        let file = Scratch::new("binary", b"admin\n\xff\xfe\n");
        let (mut client, _daemon) = tokio::io::duplex(1 << 16);
        let e = send_words(&mut client, &file.0).await.unwrap_err();
        assert!(e.contains("in UTF-8"), "{e}");
    }

    #[tokio::test]
    async fn chunks_need_the_token_a_request_needs() {
        let gate = Gate {
            secret: Some("s3cret".into()),
        };
        let line = format!(
            "{}\n",
            crate::encode_with(&serde_json::json!({"words": ["a"]}), Some("wrong"))
        );
        let mut lines = BufReader::new(line.as_bytes()).lines();
        let e = WordChunks::new(&mut lines, &gate).next().await.unwrap_err();
        assert_eq!(e, "unauthorized");
    }

    #[tokio::test]
    async fn a_list_cut_off_or_not_made_of_words_is_an_error() {
        let gate = Gate::default();
        let mut lines = BufReader::new(&b"{\"words\":[\"a\"]}\n"[..]).lines();
        let mut chunks = WordChunks::new(&mut lines, &gate);
        assert_eq!(chunks.next().await, Ok(Some(vec!["a".to_string()])));
        assert!(
            chunks
                .next()
                .await
                .unwrap_err()
                .contains("closed before the end")
        );

        let mut lines = BufReader::new(&b"{\"words\":[1,2]}\n"[..]).lines();
        let e = WordChunks::new(&mut lines, &gate).next().await.unwrap_err();
        assert!(e.contains("words that are text"), "{e}");
    }
}
