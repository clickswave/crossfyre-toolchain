use std::io::BufRead;

/// The non-empty lines of a wordlist, in file order, without their `\n` or
/// `\r\n`. A line of spaces is not empty and is kept.
///
/// Read on the blocking pool with std's buffered reader, so the whole file is one
/// task rather than an await per line. A file that is not UTF-8 is an error, never
/// a list cut short at the bad byte.
pub async fn read_lines(file_path: &str) -> Result<Vec<String>, std::io::Error> {
    let path = file_path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut kept = Vec::new();
        for line in std::io::BufReader::new(std::fs::File::open(path)?).lines() {
            let line = line?;
            if !line.is_empty() {
                kept.push(line);
            }
        }
        Ok(kept)
    })
    .await
    .map_err(std::io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::read_lines;

    fn file(name: &str, bytes: &[u8]) -> String {
        let path =
            std::env::temp_dir().join(format!("mach-read-lines-{}-{name}", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn skips_empty_lines_including_bare_crlf_and_keeps_order() {
        let p = file("endings", b"a\r\n\r\nb\n\nc\n");
        assert_eq!(read_lines(&p).await.unwrap(), ["a", "b", "c"]);
        std::fs::remove_file(p).unwrap();
    }

    #[tokio::test]
    async fn a_line_of_spaces_is_not_empty() {
        let p = file("spaces", b" \nz");
        assert_eq!(read_lines(&p).await.unwrap(), [" ", "z"]);
        std::fs::remove_file(p).unwrap();
    }

    #[tokio::test]
    async fn a_missing_file_is_an_error() {
        assert!(read_lines("/nonexistent/mach-wordlist").await.is_err());
    }

    #[tokio::test]
    async fn bytes_that_are_not_utf8_are_an_error_not_a_short_list() {
        let p = file("utf8", b"ok\n\xff\xfe\n");
        assert!(read_lines(&p).await.is_err());
        std::fs::remove_file(p).unwrap();
    }
}
