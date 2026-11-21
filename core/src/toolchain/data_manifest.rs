//! The data manifest: the packs and the CVE dataset the engines read, as `crossfyre update`
//! brings them, signed with the data key (see `release_sig`).
//!
//! ```json
//! {
//!   "format": 1,
//!   "made": "2026-11-21T15:00:00Z",
//!   "packs": {
//!     "crossfyre-templates": {"sequence": 5, "file": "data/crossfyre-templates-5.json.gz",
//!                             "sha256": "...", "size": 27805}
//!   },
//!   "dataset": {"sequence": 42, "file": "data/cve-dataset-42.json.gz", "sha256": "...",
//!               "size": 9000000}
//! }
//! ```
//!
//! It is published at `data/manifest.json` on the bins origin, with `manifest.json.sig`
//! beside it, and each file it names is in `data/` there, named with its sequence, so a
//! manifest and the files it names never disagree while one replaces another. It names
//! data and nothing else: no component, no binary, and no file outside `data/`.

use serde::Deserialize;
use std::collections::BTreeMap;

/// Where the data manifest is on the bins origin.
pub const PATH: &str = "data/manifest.json";

/// The data manifest format this reads.
pub const FORMAT: u32 = 1;

/// The most a file the manifest names may be: the dataset is a few megabytes.
pub const MAX_FILE_BYTES: u64 = 256 << 20;

/// One file the manifest names: its sequence, where it is on the bins origin, its SHA-256
/// and its size.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub sequence: u64,
    pub file: String,
    pub sha256: String,
    pub size: u64,
}

/// A data manifest, read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataManifest {
    /// When it was made, in seconds since 1970.
    pub made: i64,
    /// Each pack by its name.
    pub packs: BTreeMap<String, Entry>,
    pub dataset: Option<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(rename = "format")]
    _format: u32,
    made: String,
    #[serde(default)]
    packs: BTreeMap<String, Entry>,
    dataset: Option<Entry>,
}

impl DataManifest {
    /// The manifest in `bytes`, or why it is not one this reads.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Format {
            format: Option<u32>,
        }
        let unreadable = |e: serde_json::Error| format!("the data manifest does not read: {e}");
        match serde_json::from_slice::<Format>(bytes)
            .map_err(unreadable)?
            .format
        {
            Some(FORMAT) => {}
            Some(other) => {
                return Err(format!(
                    "the data manifest is in format {other}, and this reads format {FORMAT}"
                ));
            }
            None => return Err("the data manifest says no format".to_string()),
        }
        let file: File = serde_json::from_slice(bytes).map_err(unreadable)?;
        let made = cfx_cve::unix_time(&file.made)
            .ok_or_else(|| format!("the data manifest's time {:?} is no time", file.made))?;
        for (name, entry) in &file.packs {
            let lawful = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
            if name.is_empty() || !name.chars().all(lawful) {
                return Err(format!("the data manifest names a pack {name:?}"));
            }
            check(&format!("pack {name}"), entry)?;
        }
        if let Some(entry) = &file.dataset {
            check("the dataset", entry)?;
        }
        Ok(Self {
            made,
            packs: file.packs,
            dataset: file.dataset,
        })
    }
}

/// Why `entry` is not a file the manifest may name: one in `data/` by a plain name, with
/// a SHA-256 and a size within [`MAX_FILE_BYTES`].
fn check(what: &str, entry: &Entry) -> Result<(), String> {
    let plain = |name: &str| {
        !name.is_empty()
            && !name.starts_with('.')
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    };
    if !entry.file.strip_prefix("data/").is_some_and(plain) {
        return Err(format!(
            "the data manifest names {:?} for {what}, which is not a file in data/",
            entry.file
        ));
    }
    let hex = |s: &str| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !hex(&entry.sha256) {
        return Err(format!("the data manifest gives {what} no SHA-256"));
    }
    if entry.size == 0 || entry.size > MAX_FILE_BYTES {
        return Err(format!(
            "the data manifest gives {what} a size of {} bytes",
            entry.size
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest() -> serde_json::Value {
        json!({
            "format": 1,
            "made": "2026-11-21T15:00:00Z",
            "packs": {"crossfyre-templates": {"sequence": 5,
                "file": "data/crossfyre-templates-5.json.gz", "sha256": "ab".repeat(32),
                "size": 27805}},
            "dataset": {"sequence": 42, "file": "data/cve-dataset-42.json.gz",
                "sha256": "cd".repeat(32), "size": 9_000_000},
        })
    }

    fn parse(v: &serde_json::Value) -> Result<DataManifest, String> {
        DataManifest::parse(v.to_string().as_bytes())
    }

    #[test]
    fn a_manifest_gives_its_packs_its_dataset_and_when_it_was_made() {
        let m = parse(&manifest()).unwrap();
        assert_eq!(m.made, 1_795_273_200);
        assert_eq!(m.packs["crossfyre-templates"].sequence, 5);
        assert_eq!(m.dataset.unwrap().file, "data/cve-dataset-42.json.gz");
        let mut bare = manifest();
        bare.as_object_mut().unwrap().remove("packs");
        bare.as_object_mut().unwrap().remove("dataset");
        let m = parse(&bare).unwrap();
        assert!(m.packs.is_empty() && m.dataset.is_none());
    }

    /// It names data and nothing else: a component, a field this does not know, a file
    /// outside data/ or one that climbs out of it, an entry with no SHA-256, and another
    /// format are each refused.
    #[test]
    fn a_manifest_that_names_anything_but_data_files_is_refused() {
        let with = |path: &[&str], value: serde_json::Value| {
            let mut m = manifest();
            let mut at = &mut m;
            for key in &path[..path.len() - 1] {
                at = &mut at[*key];
            }
            at[path[path.len() - 1]] = value;
            parse(&m)
        };
        for (path, value) in [
            (&["components"][..], json!({"crossfyre": {}})),
            (&["dataset", "file"][..], json!("cli/crossfyre-0.1.45.zip")),
            (&["dataset", "file"][..], json!("data/../manifest.json")),
            (&["dataset", "file"][..], json!("data/sub/x.json.gz")),
            (&["dataset", "file"][..], json!("data/.hidden")),
            (&["dataset", "sha256"][..], json!("")),
            (&["dataset", "sha256"][..], json!("AB".repeat(32))),
            (&["dataset", "size"][..], json!(0)),
            (&["dataset", "size"][..], json!(MAX_FILE_BYTES + 1)),
            (&["dataset", "binary"][..], json!(true)),
            (
                &["packs", "Crossfyre Templates"][..],
                manifest()["dataset"].clone(),
            ),
            (&["made"][..], json!("yesterday")),
            (&["format"][..], json!(2)),
        ] {
            assert!(with(path, value.clone()).is_err(), "{path:?} = {value}");
        }
        let mut none = manifest();
        none.as_object_mut().unwrap().remove("format");
        assert_eq!(
            parse(&none).unwrap_err(),
            "the data manifest says no format"
        );
    }
}
