//! CVE leads: the CVEs that may affect a technology toolmark found, from the CVE dataset
//! in toolmark's data folder or, with none there it can read, the known-exploited
//! snapshot compiled in. The daemon fetches the dataset from where it is published when
//! its copy is more than a day old. A lead is a version match, never a confirmed
//! finding: a version can be read wrong, and a build may carry a fix its version does
//! not show.

use cfx_cve::{Cpe, Dataset, Lead};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::Duration;

/// Where the dataset is published, with no login in front of it.
pub const DATASET_URL: &str = "https://bins.crossfyre.io/cve/cve-dataset.json.gz";

/// How old the copy in the data folder gets before the daemon fetches the dataset again.
pub const FRESH_FOR: Duration = Duration::from_secs(24 * 3600);

/// The most of a fetched dataset read; the published one is a few megabytes.
const MAX_DATASET_BYTES: usize = 64 * 1024 * 1024;

/// The known-exploited CVEs of the dataset, cut at the last release (toolmark/data).
const SNAPSHOT: &[u8] = include_bytes!("../data/cve-known-exploited.json.gz");

/// The dataset's file in toolmark's data folder.
pub const DATASET_FILE: &str = "cve-dataset.json.gz";

/// What a lead from the snapshot says of where it came from.
pub const SNAPSHOT_LABEL: &str = "built-in known-exploited snapshot";

/// Where leads come from, and what each says of it.
pub struct Cves {
    /// toolmark's data folder, where the dataset is kept; none for the snapshot alone.
    folder: Option<PathBuf>,
    /// Where the dataset is fetched from.
    url: String,
    names: HashSet<Cpe>,
    data: RwLock<(Dataset, String)>,
}

impl Cves {
    /// The dataset in `folder` when there is one this reads, else the snapshot, with only
    /// the products `names` name. A refresh fetches the dataset from `url`.
    pub fn load(folder: Option<&Path>, names: &HashSet<Cpe>, url: &str) -> Self {
        let data = folder
            .and_then(|f| read(&f.join(DATASET_FILE), names))
            .unwrap_or_else(|| snapshot(names));
        Self {
            folder: folder.map(Path::to_path_buf),
            url: url.to_string(),
            names: names.clone(),
            data: RwLock::new(data),
        }
    }

    /// Fetch the dataset into the data folder when the copy there is more than a day old,
    /// or whatever its age when `force` says so, and answer from it. What leads come from
    /// afterwards, or why nothing new was fetched: the data in use stays when the fetch
    /// fails or what came does not read.
    pub async fn refresh(&self, force: bool) -> Result<String, String> {
        let folder = self
            .folder
            .as_ref()
            .ok_or("toolmark has no data folder to keep a CVE dataset in")?;
        let path = folder.join(DATASET_FILE);
        if !force && fresh(&path) {
            return Ok(self.from());
        }
        let bytes = fetch(&self.url).await?;
        let dataset = Dataset::from_bytes_for(&bytes, &self.names)
            .map_err(|e| format!("the CVE dataset from {} is not used: {e}", self.url))?;
        let part = folder.join(format!("{DATASET_FILE}.part"));
        std::fs::create_dir_all(folder)
            .and_then(|()| std::fs::write(&part, &bytes))
            .and_then(|()| std::fs::rename(&part, &path))
            .map_err(|e| format!("cannot keep the CVE dataset in {}: {e}", folder.display()))?;
        let label = label(&dataset);
        *self.data.write().unwrap_or_else(|e| e.into_inner()) = (dataset, label.clone());
        Ok(label)
    }

    /// What leads come from now.
    pub fn from(&self) -> String {
        self.data
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .clone()
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
            let label = label(&d);
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

/// What a lead from `d` says of where it came from.
fn label(d: &Dataset) -> String {
    let made = d.made().get(..10).unwrap_or(d.made());
    format!("CVE dataset {} of {made}", d.sequence())
}

/// Whether the file at `path` was written less than a day ago.
fn fresh(path: &Path) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < FRESH_FOR)
}

/// The dataset at `url`, or why it could not be had.
async fn fetch(url: &str) -> Result<Vec<u8>, String> {
    let config = transport::ClientConfig {
        timeout: Some(Duration::from_secs(300)),
        ..Default::default()
    };
    let client = transport::build_client(config, &transport::Egress::Inherit)
        .map_err(|e| format!("no client to fetch the CVE dataset with: {e}"))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("the CVE dataset could not be fetched from {url}: {e}"))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(format!(
            "{url} answered {status}, so no CVE dataset was fetched"
        ));
    }
    Ok(crate::fingerprint::read_bytes_capped(response, MAX_DATASET_BYTES).await)
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
        std::sync::Arc::new(Cves::load(None, &names, DATASET_URL))
    });
    ONE.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

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
            Cves::load(None, &names, DATASET_URL),
            Cves::load(Some(folder.path()), &names, DATASET_URL),
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
        let cves = Cves::load(Some(folder.path()), &[apache()].into(), DATASET_URL);
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
        let cves = Cves::load(Some(folder.path()), &[apache()].into(), DATASET_URL);
        assert_eq!(cves.leads(&apache(), "2.4.49", None).1, SNAPSHOT_LABEL);
    }

    /// A server that answers every request with `status` and `body`, its URL, and how
    /// many requests it had.
    fn serving(status: u16, body: Vec<u8>) -> (String, std::sync::Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let count = asked.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                count.fetch_add(1, Ordering::SeqCst);
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        (format!("http://127.0.0.1:{port}/cve/{DATASET_FILE}"), asked)
    }

    /// With no copy, a refresh fetches the dataset into the data folder and answers from
    /// it; a copy less than a day old is not fetched again unless forced, as `toolmark cve
    /// update` forces it; and one a day old is.
    #[tokio::test]
    async fn a_refresh_fetches_the_dataset_only_when_its_copy_is_a_day_old() {
        let folder = tempfile::tempdir().unwrap();
        let (url, asked) = serving(200, dataset(7));
        let cves = Cves::load(Some(folder.path()), &[apache()].into(), &url);
        assert_eq!(cves.from(), SNAPSHOT_LABEL);
        assert_eq!(
            cves.refresh(false).await.unwrap(),
            "CVE dataset 7 of 2026-11-21"
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert!(folder.path().join(DATASET_FILE).is_file());
        assert_eq!(
            ids(&cves.leads(&apache(), "2.4.49", None).0),
            ["CVE-2099-0049"]
        );
        cves.refresh(false).await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 1, "a fresh copy is kept");
        cves.refresh(true).await.unwrap();
        assert_eq!(
            asked.load(Ordering::SeqCst),
            2,
            "update fetches whatever its age"
        );
        let day_ago = std::time::SystemTime::now() - FRESH_FOR - Duration::from_secs(60);
        std::fs::File::options()
            .write(true)
            .open(folder.path().join(DATASET_FILE))
            .unwrap()
            .set_modified(day_ago)
            .unwrap();
        cves.refresh(false).await.unwrap();
        assert_eq!(
            asked.load(Ordering::SeqCst),
            3,
            "a day-old copy is fetched again"
        );
        // A daemon started later reads the copy kept.
        let later = Cves::load(Some(folder.path()), &[apache()].into(), &url);
        assert_eq!(later.from(), "CVE dataset 7 of 2026-11-21");
    }

    /// What does not read, a refusal, or no data folder leaves the data in use as it is.
    #[tokio::test]
    async fn a_failed_refresh_leaves_the_data_in_use() {
        let folder = tempfile::tempdir().unwrap();
        let (garbage, _) = serving(200, b"not a dataset".to_vec());
        let cves = Cves::load(Some(folder.path()), &[apache()].into(), &garbage);
        let why = cves.refresh(true).await.unwrap_err();
        assert!(why.contains("is not used"), "{why}");
        assert_eq!(cves.from(), SNAPSHOT_LABEL);
        assert!(!folder.path().join(DATASET_FILE).exists());
        let (missing, _) = serving(404, Vec::new());
        let cves = Cves::load(Some(folder.path()), &[apache()].into(), &missing);
        let why = cves.refresh(true).await.unwrap_err();
        assert!(why.contains("answered 404"), "{why}");
        let (url, asked) = serving(200, dataset(7));
        let alone = Cves::load(None, &[apache()].into(), &url);
        assert!(
            alone
                .refresh(true)
                .await
                .unwrap_err()
                .contains("no data folder")
        );
        assert_eq!(asked.load(Ordering::SeqCst), 0);
    }

    /// Every product a shipped signature names by CPE is one the snapshot can be asked
    /// about, and the snapshot reads.
    #[test]
    fn the_snapshot_reads_with_every_shipped_product() {
        let names = crate::signatures::Signatures::shipped().cpes();
        assert!(names.contains(&apache()), "{} products", names.len());
        let cves = Cves::load(None, &names, DATASET_URL);
        assert!(!cves.leads(&apache(), "2.4.49", None).0.is_empty());
    }
}
