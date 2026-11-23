//! Where a scan's words come from, a chunk at a time: a wordlist file the request names,
//! which the daemon opens only inside the permitted directories, or the connection the
//! client sends the words on after the request (see [`dguard::WordChunks`]). Neither is
//! ever read whole, so a list of millions of lines is held here one chunk at a time.

use sha2::Digest;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader, Lines};

/// A wordlist's words, a chunk at a time.
pub(crate) trait WordSource {
    /// The next chunk of words, or None at the end of the list.
    async fn next_chunk(&mut self) -> Result<Option<Vec<String>>, String>;
}

/// The words of a wordlist file a request names: its lines that are not empty, in
/// file order. The file is opened once, inside the permitted directories (see
/// [`dguard::open_wordlist`]), and read only through that handle, so the words are
/// those of the file that was checked, whatever its name points at later.
pub(crate) struct FileWords {
    /// The file's name, which is how records show the list.
    pub(crate) name: String,
    lines: Lines<BufReader<tokio::fs::File>>,
}

impl FileWords {
    pub(crate) fn open(path: &str) -> Result<Self, String> {
        if path.trim().is_empty() {
            return Err("no wordlist is given".to_string());
        }
        let (real, file) = dguard::open_wordlist(path)?;
        Ok(Self {
            name: dguard::list_name(&real),
            lines: BufReader::new(tokio::fs::File::from_std(file)).lines(),
        })
    }
}

impl WordSource for FileWords {
    async fn next_chunk(&mut self) -> Result<Option<Vec<String>>, String> {
        let mut chunk = Vec::new();
        while chunk.len() < dguard::CHUNK_WORDS {
            let line = self.lines.next_line().await.map_err(|e| {
                format!(
                    "the wordlist {} is not one word to a line in UTF-8: {e}",
                    self.name
                )
            })?;
            match line {
                Some(word) if word.is_empty() => {}
                Some(word) => chunk.push(word),
                None => break,
            }
        }
        Ok((!chunk.is_empty()).then_some(chunk))
    }
}

impl<R: AsyncBufRead + Unpin> WordSource for dguard::WordChunks<'_, R> {
    async fn next_chunk(&mut self) -> Result<Option<Vec<String>>, String> {
        self.next().await
    }
}

/// What a wordlist is known by: the SHA-512 of its words, each followed by a newline,
/// whichever way they came. A list stored before is found by it and used again.
#[derive(Default)]
pub(crate) struct ListDigest(sha2::Sha512);

impl ListDigest {
    pub(crate) fn update(&mut self, words: &[String]) {
        for word in words {
            self.0.update(word.as_bytes());
            self.0.update(b"\n");
        }
    }

    pub(crate) fn finish(self) -> String {
        format!("{:x}", self.0.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_is_known_by_its_words_however_they_were_cut_into_chunks() {
        let words: Vec<String> = ["admin", "  ", "index.html"].map(String::from).to_vec();
        let mut whole = ListDigest::default();
        whole.update(&words);
        let mut cut = ListDigest::default();
        cut.update(&words[..1]);
        cut.update(&words[1..]);
        let expected = format!("{:x}", sha2::Sha512::digest(b"admin\n  \nindex.html\n"));
        assert_eq!(whole.finish(), expected);
        assert_eq!(cut.finish(), expected);
    }

    #[cfg(unix)]
    mod files {
        use super::*;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        use std::path::PathBuf;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        /// A file the test process can read that is in none of the wordlist roots.
        const OUTSIDE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

        /// A fresh directory in the temp dir laid out as the node hands wordlists over,
        /// the only shape the default roots read there.
        fn scratch(tag: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!(
                "{}ambulo-{tag}-{}",
                dguard::HANDOFF_PREFIX,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            // Writable by its owner alone, whatever the umask.
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
            d
        }

        /// Put a symlink to [`OUTSIDE`] where `at` was, in one rename.
        fn point_at_outside(dir: &std::path::Path, at: &std::path::Path) {
            let link = dir.join("link");
            std::os::unix::fs::symlink(OUTSIDE, &link).unwrap();
            std::fs::rename(&link, at).unwrap();
        }

        /// Every word `source` gives, chunk by chunk.
        async fn chunks(mut source: impl WordSource) -> Result<Vec<Vec<String>>, String> {
            let mut got = Vec::new();
            while let Some(chunk) = source.next_chunk().await? {
                got.push(chunk);
            }
            Ok(got)
        }

        fn leaked(chunks: &[Vec<String>]) -> bool {
            chunks.iter().flatten().any(|l| l.contains("[package]"))
        }

        #[tokio::test]
        async fn the_words_are_the_file_s_lines_that_are_not_empty_in_chunks() {
            let dir = scratch("lines");
            let wl = dir.join("wl.txt");
            let mut text = String::from("a\r\n\r\n \nb\n");
            for i in 0..dguard::CHUNK_WORDS {
                text.push_str(&format!("w{i}\n"));
            }
            std::fs::write(&wl, text).unwrap();
            let words = FileWords::open(wl.to_str().unwrap()).unwrap();
            assert_eq!(words.name, "wl.txt");
            let got = chunks(words).await.unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            assert_eq!(got.len(), 2);
            assert_eq!(got[0].len(), dguard::CHUNK_WORDS);
            assert_eq!(got[0][..3], ["a", " ", "b"]);
        }

        #[tokio::test]
        async fn a_file_that_is_not_text_is_an_error_not_a_list_cut_short() {
            let dir = scratch("binary");
            let wl = dir.join("wl.txt");
            std::fs::write(&wl, b"a\n\xff\n").unwrap();
            let got = chunks(FileWords::open(wl.to_str().unwrap()).unwrap()).await;
            let _ = std::fs::remove_dir_all(&dir);
            assert!(got.unwrap_err().contains("UTF-8"));
        }

        #[tokio::test]
        async fn the_words_come_from_the_file_that_was_checked_not_from_its_name() {
            let dir = scratch("rename");
            let wl = dir.join("wl.txt");
            std::fs::write(&wl, "alpha\nbeta\n").unwrap();
            let words = FileWords::open(wl.to_str().unwrap()).unwrap();
            point_at_outside(&dir, &wl);
            let got = chunks(words).await.unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            assert!(!leaked(&got), "read a file outside the roots: {got:?}");
            assert_eq!(got, [["alpha", "beta"]]);
        }

        #[test]
        fn a_file_outside_the_permitted_directories_is_refused() {
            assert!(FileWords::open(OUTSIDE).is_err());
            assert!(FileWords::open("  ").is_err());
        }

        // A FIFO whose name is replaced by a symlink while it is being opened. Nothing
        // outside the roots may come back, whether the wordlist is refused or read.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_fifo_swapped_for_a_symlink_mid_read_reads_nothing_outside_the_roots() {
            use std::io::Write;
            let dir = scratch("fifo");
            let wl = dir.join("wl");
            let c = std::ffi::CString::new(wl.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

            let done = Arc::new(AtomicBool::new(false));
            let swapper = {
                let (dir, wl, done) = (dir.clone(), wl.clone(), done.clone());
                std::thread::spawn(move || {
                    while !done.load(Ordering::SeqCst) {
                        // Succeeds only once a reader has the FIFO open.
                        match std::fs::OpenOptions::new()
                            .write(true)
                            .custom_flags(libc::O_NONBLOCK)
                            .open(&wl)
                        {
                            Ok(mut f) => {
                                point_at_outside(&dir, &wl);
                                let _ = f.write_all(b"decoy\n");
                                return;
                            }
                            Err(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
                        }
                    }
                })
            };

            let path = wl.to_str().unwrap().to_string();
            let got = tokio::time::timeout(std::time::Duration::from_secs(20), async move {
                match tokio::task::spawn_blocking(move || FileWords::open(&path))
                    .await
                    .unwrap()
                {
                    Ok(words) => chunks(words).await.unwrap_or_default(),
                    Err(_) => Vec::new(),
                }
            })
            .await
            .expect("the reader was left waiting on the FIFO");
            done.store(true, Ordering::SeqCst);
            swapper.join().unwrap();
            let _ = std::fs::remove_dir_all(&dir);
            assert!(!leaked(&got), "read a file outside the roots: {got:?}");
        }
    }
}
