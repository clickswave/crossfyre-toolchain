//! The lines a daemon reads off a connection.
//!
//! Every request is one line, and the token that says whether its sender may
//! ask anything is inside that line, so a line has to be read before the
//! [`Gate`](crate::Gate) can judge it. Read without a limit, a connection that
//! never sends a newline is held in memory for as long as it keeps sending,
//! token or no token. Each line is therefore cut off at [`MAX_LINE`], and the
//! connection with it.

use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// The longest line a daemon reads. A request is a small JSON object, and the
/// largest line any client writes is a chunk of [`CHUNK_WORDS`](crate::CHUNK_WORDS)
/// words of a wordlist, which this leaves room for many times over.
pub const MAX_LINE: usize = 8 * 1024 * 1024;

/// Lines from `reader`, each at most [`MAX_LINE`] bytes. A longer one is an
/// error, which ends the connection the way a closed one does.
pub struct Lines<R> {
    reader: R,
    line: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin> Lines<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            line: Vec::new(),
        }
    }

    /// The next line without its `\n` or `\r\n`, or None at the end of the
    /// stream. Cancel safe, as tokio's `Lines::next_line` is: what has been read
    /// of a line is kept here, not in the future, so a `select!` may drop it.
    pub async fn next_line(&mut self) -> io::Result<Option<String>> {
        loop {
            let seen = self.reader.fill_buf().await?;
            if seen.is_empty() {
                if self.line.is_empty() {
                    return Ok(None);
                }
                return self.take().map(Some);
            }
            let (part, used, ends) = match seen.iter().position(|b| *b == b'\n') {
                Some(at) => (&seen[..at], at + 1, true),
                None => (seen, seen.len(), false),
            };
            if self.line.len() + part.len() > MAX_LINE {
                self.line = Vec::new();
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("a line longer than {MAX_LINE} bytes"),
                ));
            }
            self.line.extend_from_slice(part);
            self.reader.consume(used);
            if ends {
                return self.take().map(Some);
            }
        }
    }

    fn take(&mut self) -> io::Result<String> {
        let mut line = std::mem::take(&mut self.line);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        String::from_utf8(line).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "stream did not contain valid UTF-8",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn lines_read_as_tokio_reads_them() {
        let mut lines = Lines::new(BufReader::new(&b"one\r\ntwo\n\nthree"[..]));
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("one"));
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("two"));
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some(""));
        assert_eq!(lines.next_line().await.unwrap().as_deref(), Some("three"));
        assert_eq!(lines.next_line().await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_line_past_the_limit_is_an_error_before_it_is_held_whole() {
        let mut at_limit = vec![b'a'; MAX_LINE];
        at_limit.push(b'\n');
        let mut lines = Lines::new(BufReader::new(&at_limit[..]));
        assert_eq!(
            lines.next_line().await.unwrap().map(|l| l.len()),
            Some(MAX_LINE)
        );

        // No newline at all, and more of it than the limit.
        let endless = vec![b'a'; MAX_LINE + 1];
        let mut lines = Lines::new(BufReader::new(&endless[..]));
        let err = lines.next_line().await.expect_err("a line past the limit");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn invalid_utf8_is_an_error() {
        let mut lines = Lines::new(BufReader::new(&b"\xff\n"[..]));
        assert!(lines.next_line().await.is_err());
    }
}
