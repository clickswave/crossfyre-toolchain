//! Out-of-line bodies: content-addressed files beside the database, reference counted.
//!
//! A 200 MB download must not land in a row. Above [`crate::INLINE_MAX`] a body is hashed,
//! written once under that hash, and the row keeps the hash instead of the bytes.
//!
//! Content addressing means identical bodies share one file, which on a real capture is
//! most of them: the same framework bundle, the same sprite sheet, the same empty `{}`
//! answered four hundred times. It also means a delete cannot simply unlink by hash, so
//! every blob carries a reference count and the file goes only when the last row holding
//! it does.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};

/// Hex sha256 of `bytes`, which is also the file name it is stored under.
pub fn hash(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Where a hash lives inside the blob directory.
///
/// Fanned out by the first two hex characters. A flat directory of a hundred thousand
/// files is slow to list on every platform and pathological on some, and a capture
/// reaches that in an afternoon.
pub fn path_for(root: &Path, hash: &str) -> PathBuf {
    root.join(&hash[..2]).join(hash)
}

/// Write `bytes` into the blob directory and take a reference to it.
///
/// Idempotent on content: a body already present is not rewritten, only referenced again.
/// The write goes to a temporary file and is renamed into place, so a reader never sees a
/// half-written blob under a hash that claims to describe it.
pub async fn put(
    conn: &mut SqliteConnection,
    root: &Path,
    bytes: &[u8],
) -> Result<String, crate::Error> {
    let h = hash(bytes);
    let dest = path_for(root, &h);

    if !tokio::fs::try_exists(&dest).await.unwrap_or(false) {
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // The temporary name carries the hash plus the pid, so two processes writing the
        // same body at once do not land on one another's partial file.
        let tmp = dest.with_extension(format!("{}.part", std::process::id()));
        tokio::fs::write(&tmp, bytes).await?;
        // A rename onto an existing file is fine: the content is identical by definition,
        // which is what makes a race here harmless rather than something to lock against.
        tokio::fs::rename(&tmp, &dest).await?;
    }

    sqlx::query(
        "INSERT INTO blob (hash, len, refs) VALUES (?1, ?2, 1)
         ON CONFLICT(hash) DO UPDATE SET refs = refs + 1",
    )
    .bind(&h)
    .bind(bytes.len() as i64)
    .execute(&mut *conn)
    .await?;

    Ok(h)
}

/// Read a blob back.
///
/// A missing file is an error rather than an empty body. A project whose blob directory
/// was partly deleted should say so, because the alternative is a response that renders as
/// empty and reads like the server sent nothing.
pub async fn get(root: &Path, hash: &str) -> Result<Vec<u8>, crate::Error> {
    let p = path_for(root, hash);
    match tokio::fs::read(&p).await {
        Ok(b) => Ok(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(crate::Error::MissingBlob {
            hash: hash.to_string(),
        }),
        Err(e) => Err(e.into()),
    }
}

/// Drop one reference, and unlink the file when it was the last.
///
/// Decrementing and reading back in one statement keeps the decision in the database
/// rather than in a read-modify-write that two evictions could interleave on.
pub async fn release(
    conn: &mut SqliteConnection,
    root: &Path,
    hash: &str,
) -> Result<(), crate::Error> {
    let remaining: Option<i64> =
        sqlx::query("UPDATE blob SET refs = refs - 1 WHERE hash = ?1 RETURNING refs")
            .bind(hash)
            .fetch_optional(&mut *conn)
            .await?
            .map(|r| r.try_get(0))
            .transpose()?;

    let Some(remaining) = remaining else {
        // No row means nothing claimed this hash, which is a bug upstream rather than a
        // condition to act on. Logged and not escalated: refusing here would fail a
        // delete that is otherwise correct.
        log::warn!("blob {hash}: released with no reference row");
        return Ok(());
    };

    if remaining > 0 {
        return Ok(());
    }

    sqlx::query("DELETE FROM blob WHERE hash = ?1")
        .bind(hash)
        .execute(&mut *conn)
        .await?;
    // A blob directory missing a file it was about to delete is the state being asked
    // for, so a NotFound here is success.
    match tokio::fs::remove_file(path_for(root, hash)).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Total bytes held out of line, counting each distinct body once.
///
/// Once, because that is what the directory occupies. A figure that counted a shared body
/// per referencing row would not match what the user sees on disk, and the cap exists to
/// describe the disk.
pub async fn bytes_on_disk(conn: &mut SqliteConnection) -> Result<i64, crate::Error> {
    let n: Option<i64> = sqlx::query("SELECT SUM(len) FROM blob")
        .fetch_one(&mut *conn)
        .await?
        .try_get(0)?;
    Ok(n.unwrap_or(0))
}
