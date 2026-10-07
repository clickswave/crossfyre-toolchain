use std::io::BufRead;

/// Every line of a wordlist, in file order, without its `\n` or `\r\n`, empty
/// lines included.
///
/// The read happens on the blocking pool with std's buffered reader: one task for
/// the whole file rather than an await per line, and nothing kept but the lines.
/// A file that is not UTF-8 is an error, never a list cut short at the bad byte.
pub async fn read_lines(file_path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let path = file_path.to_owned();
    let lines = tokio::task::spawn_blocking(move || {
        std::io::BufReader::new(std::fs::File::open(path)?)
            .lines()
            .collect::<std::io::Result<Vec<String>>>()
    })
    .await??;
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::read_lines;

    fn file(name: &str, bytes: &[u8]) -> String {
        let path =
            std::env::temp_dir().join(format!("voyage-read-lines-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn keeps_order_and_empty_lines_and_drops_both_line_endings() {
        let p = file("endings", b"a\r\nb\n\nc");
        assert_eq!(read_lines(&p).await.unwrap(), ["a", "b", "", "c"]);
        std::fs::remove_file(p).unwrap();
    }

    #[tokio::test]
    async fn a_final_newline_adds_no_line() {
        let p = file("final", b"x\ny\n");
        assert_eq!(read_lines(&p).await.unwrap(), ["x", "y"]);
        std::fs::remove_file(p).unwrap();
    }

    #[tokio::test]
    async fn a_missing_file_is_an_error() {
        assert!(read_lines("/nonexistent/voyage-wordlist").await.is_err());
    }

    #[tokio::test]
    async fn bytes_that_are_not_utf8_are_an_error_not_a_short_list() {
        let p = file("utf8", b"ok\n\xff\xfe\n");
        assert!(read_lines(&p).await.is_err());
        std::fs::remove_file(p).unwrap();
    }
}
