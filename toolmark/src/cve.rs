//! CVE leads: the CVEs that may affect a technology toolmark found, from the CVE dataset
//! in toolmark's data folder or, with none there it can read, the known-exploited
//! snapshot compiled in. A lead is a version match, never a confirmed finding: a version
//! can be read wrong, and a build may carry a fix its version does not show.

use cfx_cve::{Cpe, Dataset, Lead};
use std::collections::HashSet;
use std::path::Path;
use std::sync::RwLock;

/// The known-exploited CVEs of the dataset, cut at the last release (toolmark/data).
const SNAPSHOT: &[u8] = include_bytes!("../data/cve-known-exploited.json.gz");

/// The dataset's file in toolmark's data folder.
pub const DATASET_FILE: &str = "cve-dataset.json.gz";

/// What a lead from the snapshot says of where it came from.
pub const SNAPSHOT_LABEL: &str = "built-in known-exploited snapshot";

/// Where leads come from, and what each says of it.
pub struct Cves {
    data: RwLock<(Dataset, String)>,
}

impl Cves {
    /// The dataset in `folder` when there is one this reads, else the snapshot, with only
    /// the products `names` name.
    pub fn load(folder: Option<&Path>, names: &HashSet<Cpe>) -> Self {
        let data = folder
            .and_then(|f| read(&f.join(DATASET_FILE), names))
            .unwrap_or_else(|| snapshot(names));
        Self {
            data: RwLock::new(data),
        }
    }

    /// The leads for `name` at `version`, built by the distribution `distro` names when
    /// one is known, and the data they come from.
    pub fn leads(&self, name: &Cpe, version: &str, distro: Option<&str>) -> (Vec<Lead>, String) {
        let data = self.data.read().unwrap_or_else(|e| e.into_inner());
        let leads = data.0.leads(std::slice::from_ref(name), version, distro);
        (leads, data.1.clone())
    }
}

/// The dataset at `path` and what its leads say of it, or none when there is no file or
/// it does not read, which is said.
fn read(path: &Path, names: &HashSet<Cpe>) -> Option<(Dataset, String)> {
    let bytes = std::fs::read(path).ok()?;
    match Dataset::from_bytes_for(&bytes, names) {
        Ok(d) => {
            let made = d.made().get(..10).unwrap_or(d.made());
            let label = format!("CVE dataset {} of {made}", d.sequence());
            Some((d, label))
        }
        Err(e) => {
            eprintln!(
                "[toolmark] the CVE dataset in {} is not used: {e}",
                path.display()
            );
            None
        }
    }
}

fn snapshot(names: &HashSet<Cpe>) -> (Dataset, String) {
    let d = Dataset::from_bytes_for(SNAPSHOT, names)
        .expect("the snapshot compiled into toolmark reads, as its test shows");
    (d, SNAPSHOT_LABEL.to_string())
}

/// The snapshot alone with every shipped signature's product, as a daemon with no dataset
/// answers: for the tests that fingerprint.
#[cfg(test)]
pub fn snapshot_for_tests() -> std::sync::Arc<Cves> {
    static ONE: std::sync::LazyLock<std::sync::Arc<Cves>> = std::sync::LazyLock::new(|| {
        let names = crate::signatures::Signatures::shipped().cpes();
        std::sync::Arc::new(Cves::load(None, &names))
    });
    ONE.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn apache() -> Cpe {
        Cpe::new("a", "apache", "http_server")
    }

    fn ids(leads: &[Lead]) -> Vec<&str> {
        leads.iter().map(|l| l.cve.as_str()).collect()
    }

    /// A dataset of one CVE on Apache 2.4.49, numbered `sequence`.
    fn dataset(sequence: u64) -> Vec<u8> {
        let json = format!(
            r#"{{"format": 1, "sequence": {sequence}, "made": "2026-11-21T15:00:00Z",
            "products": [{{"part": "a", "vendor": "apache", "product": "http_server",
              "affected": [{{"cve": "CVE-2099-0049", "ranges": [{{"eq": "2.4.49"}}]}}]}}],
            "cves": {{"CVE-2099-0049": {{"severity": "high", "score": 7.5}}}}}}"#
        );
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(json.as_bytes()).unwrap();
        gz.finish().unwrap()
    }

    /// With no dataset, the snapshot answers with the known-exploited CVEs, and says so.
    #[test]
    fn with_no_dataset_the_snapshot_answers() {
        let folder = tempfile::tempdir().unwrap();
        let names: HashSet<Cpe> = [apache()].into();
        for cves in [
            Cves::load(None, &names),
            Cves::load(Some(folder.path()), &names),
        ] {
            let (leads, from) = cves.leads(&apache(), "2.4.49", None);
            assert_eq!(from, SNAPSHOT_LABEL);
            for cve in ["CVE-2021-41773", "CVE-2021-42013"] {
                assert!(ids(&leads).contains(&cve), "{cve} in {:?}", ids(&leads));
            }
            assert!(leads.iter().all(|l| l.known.kev));
            let (later, _) = cves.leads(&apache(), "2.4.51", None);
            assert!(
                !ids(&later)
                    .iter()
                    .any(|c| *c == "CVE-2021-41773" || *c == "CVE-2021-42013")
            );
        }
    }

    /// The dataset in the data folder answers in place of the snapshot, and its leads say
    /// which dataset they come from.
    #[test]
    fn the_dataset_in_the_data_folder_answers_and_is_named() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join(DATASET_FILE), dataset(9)).unwrap();
        let cves = Cves::load(Some(folder.path()), &[apache()].into());
        let (leads, from) = cves.leads(&apache(), "2.4.49", Some("Ubuntu"));
        assert_eq!(from, "CVE dataset 9 of 2026-11-21");
        assert_eq!(ids(&leads), ["CVE-2099-0049"]);
        assert!(leads[0].backport);
    }

    /// A file there that does not read leaves the snapshot answering.
    #[test]
    fn a_dataset_that_does_not_read_leaves_the_snapshot() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join(DATASET_FILE), b"not a dataset").unwrap();
        let cves = Cves::load(Some(folder.path()), &[apache()].into());
        assert_eq!(cves.leads(&apache(), "2.4.49", None).1, SNAPSHOT_LABEL);
    }

    /// Every product a shipped signature names by CPE is one the snapshot can be asked
    /// about, and the snapshot reads.
    #[test]
    fn the_snapshot_reads_with_every_shipped_product() {
        let names = crate::signatures::Signatures::shipped().cpes();
        assert!(names.contains(&apache()), "{} products", names.len());
        let cves = Cves::load(None, &names);
        assert!(!cves.leads(&apache(), "2.4.49", None).0.is_empty());
    }
}
