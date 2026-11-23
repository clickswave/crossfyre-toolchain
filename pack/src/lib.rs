//! A pack: the templates, signatures and mappings the engines run, in one gzipped JSON
//! file.
//!
//! ```json
//! {
//!   "format": 1,
//!   "name": "crossfyre-templates",
//!   "sequence": 12,
//!   "made": "2026-11-21T06:30:00Z",
//!   "commit": "6820170e4b...",
//!   "files": {
//!     "plessor/cves/CVE-2021-41773-apache-path-traversal.yaml": "id: CVE-2021-41773\n...",
//!     "toolmark/apache-httpd.yaml": "id: apache-httpd\n...",
//!     "mappings/aliases.yaml": "..."
//!   }
//! }
//! ```
//!
//! `files` holds each file of the crossfyre-templates repo the engines read, by its path
//! there: plessor's templates under plessor/, toolmark's signatures under toolmark/, and
//! the mappings toolmark reads CVE leads with under mappings/. `sequence` is the number of
//! commits in the repo up to the one packed, so a later pack has a higher one; `commit`
//! names it and `made` is when it was made.
//!
//! Each release compiles in a copy of the same files, from the commit [`COMPILED`] names,
//! and a pack is used in its place only when it is later
//! ([`Pack::replaces_compiled`]). Engines never fetch a pack: they read the one in the
//! toolchain directory ([`installed`]).

mod compiled;

use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};

/// The pack format this crate reads.
pub const FORMAT: u32 = 1;

/// The name of the pack made from crossfyre-templates.
pub const NAME: &str = "crossfyre-templates";

/// The most a pack may hold unpacked. The first was about 1 MB.
pub const MAX_BYTES: u64 = 32 << 20;

/// The folders a pack's files are in.
pub const FOLDERS: &[&str] = &["plessor", "toolmark", "mappings"];

/// Where the pack is kept in the toolchain directory `dir`.
pub fn path_in(dir: &Path) -> PathBuf {
    dir.join("packs").join(format!("{NAME}.json.gz"))
}

/// The pack kept in the toolchain directory `dir`: none when there is no file, and why
/// when there is one that cannot be read.
pub fn installed(dir: &Path) -> Result<Option<Pack>, Error> {
    let path = path_in(dir);
    match std::fs::read(&path) {
        Ok(bytes) => Pack::from_bytes(&bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error(format!("{}: {e}", path.display()))),
    }
}

/// The pack the copies compiled into this build come from.
pub struct Compiled {
    pub sequence: u64,
    pub commit: &'static str,
}

/// The pack the copies compiled into this build come from.
pub const COMPILED: Compiled = Compiled {
    sequence: compiled::SEQUENCE,
    commit: compiled::COMMIT,
};

/// Why a pack cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// A pack, read.
#[derive(Debug, Clone)]
pub struct Pack {
    name: String,
    sequence: u64,
    made: String,
    commit: String,
    files: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    /// Read before the rest, by itself; here so that the file may hold it.
    #[serde(rename = "format")]
    _format: u32,
    name: String,
    sequence: u64,
    made: String,
    commit: String,
    files: BTreeMap<String, String>,
}

impl Pack {
    /// The pack in `bytes`, gzipped or not, or why it is not one this reads.
    pub fn from_bytes(bytes: &[u8]) -> Result<Pack, Error> {
        let mut text = Vec::new();
        let read = if bytes.starts_with(&[0x1f, 0x8b]) {
            flate2::read::GzDecoder::new(bytes)
                .take(MAX_BYTES + 1)
                .read_to_end(&mut text)
        } else {
            bytes.take(MAX_BYTES + 1).read_to_end(&mut text)
        };
        read.map_err(|e| Error(format!("the pack does not unpack: {e}")))?;
        if text.len() as u64 > MAX_BYTES {
            return Err(Error(format!(
                "the pack holds more than {} MB unpacked",
                MAX_BYTES >> 20
            )));
        }
        // The format is read first, so a pack in a later one says so rather than failing
        // on a field this does not know.
        #[derive(Deserialize)]
        struct Format {
            format: Option<u32>,
        }
        let unreadable =
            |e: serde_json::Error| Error(format!("the pack is not one this reads: {e}"));
        match serde_json::from_slice::<Format>(&text)
            .map_err(unreadable)?
            .format
        {
            Some(FORMAT) => {}
            Some(other) => {
                return Err(Error(format!(
                    "the pack is in format {other}, and this reads format {FORMAT}"
                )));
            }
            None => return Err(Error("the pack says no format".to_string())),
        }
        let file: File = serde_json::from_slice(&text).map_err(unreadable)?;
        for path in file.files.keys() {
            check_path(path).map_err(|why| Error(format!("the pack holds {path:?}, {why}")))?;
        }
        Ok(Pack {
            name: file.name,
            sequence: file.sequence,
            made: file.made,
            commit: file.commit,
            files: file.files,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn made(&self) -> &str {
        &self.made
    }

    pub fn commit(&self) -> &str {
        &self.commit
    }

    /// The files in `folder`, one of [`FOLDERS`], by their paths in it, in order.
    pub fn files_in<'a>(&'a self, folder: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.files.iter().filter_map(move |(path, text)| {
            let inside = path.strip_prefix(folder)?.strip_prefix('/')?;
            Some((inside, text.as_str()))
        })
    }

    /// Whether this pack is used in place of the copy compiled in: it is made from
    /// crossfyre-templates, and from a later commit.
    pub fn replaces_compiled(&self) -> bool {
        self.name == NAME && self.sequence > COMPILED.sequence
    }
}

/// Why `path` is not one a pack may hold: a file in one of [`FOLDERS`], by a plain
/// relative path, which nothing that reads it can be led out of the folder by.
fn check_path(path: &str) -> Result<(), &'static str> {
    let mut parts = path.split('/');
    if !parts.next().is_some_and(|first| FOLDERS.contains(&first)) {
        return Err("which is in none of plessor/, toolmark/ and mappings/");
    }
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        return Err("which is a folder, not a file in one");
    }
    if rest
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == ".." || p.contains(['\\', ':', '\0']))
    {
        return Err("which is not a plain path inside its folder");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn pack_value(files: &[(&str, &str)]) -> serde_json::Value {
        let files: BTreeMap<&str, &str> = files.iter().copied().collect();
        serde_json::json!({
            "format": 1,
            "name": NAME,
            "sequence": 7,
            "made": "2026-11-21T06:30:00Z",
            "commit": "6820170e",
            "files": files,
        })
    }

    fn pack_json(files: &[(&str, &str)]) -> String {
        pack_value(files).to_string()
    }

    /// The pack with `key` set to `value`, or taken out when it is null.
    fn with(key: &str, value: serde_json::Value) -> Vec<u8> {
        let mut pack = pack_value(&[]);
        let fields = pack.as_object_mut().unwrap();
        if value.is_null() {
            fields.remove(key);
        } else {
            fields.insert(key.to_string(), value);
        }
        pack.to_string().into_bytes()
    }

    fn gzip(text: &str) -> Vec<u8> {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(text.as_bytes()).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn a_pack_is_read_gzipped_or_not_and_gives_each_folders_files() {
        let text = pack_json(&[
            ("plessor/cves/a.yaml", "id: a\n"),
            ("plessor/panels/b.yaml", "id: b\n"),
            ("toolmark/nginx.yaml", "id: nginx\n"),
            ("mappings/aliases.yaml", "{}\n"),
        ]);
        for bytes in [gzip(&text), text.clone().into_bytes()] {
            let pack = Pack::from_bytes(&bytes).unwrap();
            assert_eq!(
                (pack.name(), pack.sequence(), pack.made(), pack.commit()),
                (NAME, 7, "2026-11-21T06:30:00Z", "6820170e")
            );
            let plessor: Vec<_> = pack.files_in("plessor").collect();
            assert_eq!(
                plessor,
                [("cves/a.yaml", "id: a\n"), ("panels/b.yaml", "id: b\n")]
            );
            assert_eq!(
                pack.files_in("toolmark").collect::<Vec<_>>(),
                [("nginx.yaml", "id: nginx\n")]
            );
            assert_eq!(pack.files_in("mappings").count(), 1);
        }
    }

    #[test]
    fn a_path_that_leaves_its_folder_or_is_in_none_is_refused() {
        for path in [
            "plessor/../etc/passwd",
            "plessor/./a.yaml",
            "plessor//a.yaml",
            "/plessor/a.yaml",
            "plessor/a\\..\\b.yaml",
            "plessor/C:a.yaml",
            "plessor",
            "plessor/",
            "README.md",
            "labs/run.py",
        ] {
            let err = Pack::from_bytes(pack_json(&[(path, "x")]).as_bytes()).unwrap_err();
            assert!(
                err.0.starts_with(&format!("the pack holds {path:?}, ")),
                "{path}: {err}"
            );
        }
    }

    #[test]
    fn a_pack_in_another_format_or_missing_a_field_says_so() {
        use serde_json::{Value, json};
        assert!(Pack::from_bytes(&with("format", json!(1))).is_ok());
        assert_eq!(
            Pack::from_bytes(&with("format", json!(2))).unwrap_err().0,
            "the pack is in format 2, and this reads format 1"
        );
        assert_eq!(
            Pack::from_bytes(&with("format", Value::Null))
                .unwrap_err()
                .0,
            "the pack says no format"
        );
        for key in ["name", "sequence", "made", "commit", "files"] {
            assert!(Pack::from_bytes(&with(key, Value::Null)).is_err(), "{key}");
        }
        assert!(Pack::from_bytes(&with("signed", json!(true))).is_err());
        assert!(Pack::from_bytes(&gzip("not json")).is_err());
        assert!(Pack::from_bytes(&[0x1f, 0x8b, 0, 1, 2]).is_err());
    }

    #[test]
    fn a_pack_larger_than_the_limit_unpacked_is_refused() {
        let big = "a".repeat(MAX_BYTES as usize);
        let err = Pack::from_bytes(&gzip(&pack_json(&[("plessor/a.yaml", &big)]))).unwrap_err();
        assert_eq!(err.0, "the pack holds more than 32 MB unpacked");
    }

    #[test]
    fn the_pack_in_a_toolchain_directory_is_read_from_its_packs_folder() {
        let dir = std::env::temp_dir().join(format!("cfx-pack-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(installed(&dir).unwrap().is_none(), "no file is no pack");
        let path = path_in(&dir);
        assert_eq!(path, dir.join("packs").join("crossfyre-templates.json.gz"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, gzip(&pack_json(&[("toolmark/a.yaml", "id: a\n")]))).unwrap();
        let pack = installed(&dir).unwrap().unwrap();
        assert_eq!(pack.files_in("toolmark").count(), 1);
        std::fs::write(&path, b"not a pack").unwrap();
        assert!(
            installed(&dir).is_err(),
            "a file that does not read says why"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_a_later_pack_of_this_name_replaces_the_compiled_copy() {
        let at = |name: &str, sequence: u64| {
            let mut pack = pack_value(&[]);
            pack["name"] = serde_json::json!(name);
            pack["sequence"] = serde_json::json!(sequence);
            Pack::from_bytes(pack.to_string().as_bytes()).unwrap()
        };
        assert!(at(NAME, COMPILED.sequence + 1).replaces_compiled());
        assert!(!at(NAME, COMPILED.sequence).replaces_compiled());
        assert!(!at(NAME, COMPILED.sequence.saturating_sub(1)).replaces_compiled());
        assert!(!at("someone-elses", COMPILED.sequence + 1).replaces_compiled());
    }
}
