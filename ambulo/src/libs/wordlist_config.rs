use std::io::{Read, Seek};

/// The wordlist a scan reads: opened once, with the hash and the words both taken
/// from that one handle.
///
/// The path in a request is checked against the permitted directories, and a name
/// opened again after that check can by then be a different file. So nothing here
/// opens the wordlist by name: [`dguard::open_wordlist`] opens it, checks the open
/// file, and every read after that goes through the handle it returned.
#[derive(Debug)]
pub struct WordlistConfig {
    pub path: String,
    pub name: String,
    pub hash: String,
    file: std::fs::File,
}

impl WordlistConfig {
    pub async fn new(p: &str) -> Result<WordlistConfig, Box<dyn std::error::Error>> {
        if p.trim().is_empty() {
            return Err("[ERROR] No wordlist is specified".into());
        }

        let (real, file) = dguard::open_wordlist(p)?;

        let name = real
            .file_name()
            .ok_or("[ERROR] Invalid wordlist path")?
            .to_str()
            .ok_or("[ERROR] Invalid wordlist name")?
            .to_string();

        let hash = sha512_of(file.try_clone()?).await?;

        Ok(WordlistConfig {
            path: real.to_string_lossy().into_owned(),
            name,
            hash,
            file,
        })
    }

    /// The words, read from the handle the hash was taken from.
    pub async fn lines(&self) -> Result<Vec<String>, std::io::Error> {
        crate::libs::utils::read_lines_from(self.file.try_clone()?).await
    }
}

/// The SHA-512 of a whole file, from its start, on the blocking pool.
async fn sha512_of(mut file: std::fs::File) -> Result<String, std::io::Error> {
    use sha2::Digest;
    tokio::task::spawn_blocking(move || {
        file.rewind()?;
        let mut hasher = sha2::Sha512::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    })
    .await
    .map_err(std::io::Error::other)?
}

#[cfg(all(test, unix))]
mod tests {
    use super::WordlistConfig;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A file the test process can read that is in none of the wordlist roots.
    const OUTSIDE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

    /// A fresh directory in the temp dir, which is one of the default roots.
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ambulo-wl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Put a symlink to [`OUTSIDE`] where `at` was, in one rename.
    fn point_at_outside(dir: &std::path::Path, at: &std::path::Path) {
        let link = dir.join("link");
        std::os::unix::fs::symlink(OUTSIDE, &link).unwrap();
        std::fs::rename(&link, at).unwrap();
    }

    fn leaked(lines: &[String]) -> bool {
        lines.iter().any(|l| l.contains("[package]"))
    }

    #[tokio::test]
    async fn the_words_come_from_the_file_that_was_checked_not_from_its_name() {
        let dir = scratch("rename");
        let wl = dir.join("wl.txt");
        std::fs::write(&wl, "alpha\nbeta\n").unwrap();
        let cfg = WordlistConfig::new(wl.to_str().unwrap()).await.unwrap();
        point_at_outside(&dir, &wl);
        let lines = cfg.lines().await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!leaked(&lines), "read a file outside the roots: {lines:?}");
        assert_eq!(lines, ["alpha", "beta"]);
    }

    #[tokio::test]
    async fn the_hash_is_of_the_whole_file_and_reading_twice_gives_the_same_words() {
        use sha2::Digest;
        let dir = scratch("hash");
        let wl = dir.join("wl.txt");
        std::fs::write(&wl, "a\nb\n").unwrap();
        let cfg = WordlistConfig::new(wl.to_str().unwrap()).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(cfg.hash, format!("{:x}", sha2::Sha512::digest(b"a\nb\n")));
        assert_eq!(cfg.name, "wl.txt");
        assert_eq!(cfg.lines().await.unwrap(), ["a", "b"]);
        assert_eq!(cfg.lines().await.unwrap(), ["a", "b"]);
    }

    // The request names a FIFO in a directory the sender owns. The check passes, the
    // reader then waits on the FIFO, and while it waits the sender swaps the name
    // for a symlink to a file outside every root. Nothing outside the roots may come
    // back, whether the wordlist is refused or read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fifo_swapped_for_a_symlink_mid_read_reads_nothing_outside_the_roots() {
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

        let got = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            WordlistConfig::new(wl.to_str().unwrap()),
        )
        .await
        .expect("the reader was left waiting on the FIFO");
        let lines = match got {
            Ok(cfg) => cfg.lines().await.unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        done.store(true, Ordering::SeqCst);
        swapper.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!leaked(&lines), "read a file outside the roots: {lines:?}");
    }
}
