use std::io::Read;
use std::sync::Arc;

/// The wordlist a scan reads, read once: the hash and the words both come from the
/// same bytes.
///
/// [`dguard::open_wordlist`] opens the file inside the permitted directories and
/// checks the handle it returns. That handle is read to the end here and nothing
/// opens the wordlist again, so the words stored under a hash are always the words
/// that were hashed, even if the file is rewritten while the scan is set up.
#[derive(Debug)]
pub struct WordlistConfig {
    pub path: String,
    pub name: String,
    pub hash: String,
    bytes: Arc<Vec<u8>>,
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

        let (bytes, hash) = read_and_hash(file).await?;

        Ok(WordlistConfig {
            path: real.to_string_lossy().into_owned(),
            name,
            hash,
            bytes: Arc::new(bytes),
        })
    }

    /// The words, from the bytes the hash was taken of.
    pub async fn lines(&self) -> Result<Vec<String>, std::io::Error> {
        let bytes = self.bytes.clone();
        tokio::task::spawn_blocking(move || crate::libs::utils::split_lines(&bytes))
            .await
            .map_err(std::io::Error::other)?
    }
}

/// The whole of a file and its SHA-512, from one read on the blocking pool.
async fn read_and_hash(mut file: std::fs::File) -> Result<(Vec<u8>, String), std::io::Error> {
    use sha2::Digest;
    tokio::task::spawn_blocking(move || {
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let hash = format!("{:x}", sha2::Sha512::digest(&bytes));
        Ok((bytes, hash))
    })
    .await
    .map_err(std::io::Error::other)?
}

#[cfg(all(test, unix))]
mod tests {
    use super::WordlistConfig;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

    #[tokio::test]
    async fn the_words_are_the_bytes_that_were_hashed_even_if_the_file_is_rewritten() {
        use sha2::Digest;
        let dir = scratch("rewrite");
        let wl = dir.join("wl.txt");
        std::fs::write(&wl, "alpha\nbeta\n").unwrap();
        let cfg = WordlistConfig::new(wl.to_str().unwrap()).await.unwrap();
        // The same file, rewritten in place rather than replaced.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&wl)
            .unwrap();
        f.write_all(b"gamma\n").unwrap();
        drop(f);
        let lines = cfg.lines().await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            cfg.hash,
            format!("{:x}", sha2::Sha512::digest(b"alpha\nbeta\n"))
        );
        assert_eq!(lines, ["alpha", "beta"]);
    }

    // A FIFO whose name is replaced by a symlink while it is being opened. Nothing
    // outside the roots may come back, whether the wordlist is refused or read.
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
