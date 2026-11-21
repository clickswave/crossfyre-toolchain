//! CVE leads: the CVEs that may affect a technology toolmark found, from the CVE dataset
//! in toolmark's data folder or, with none there it can read, the known-exploited
//! snapshot compiled in. The daemon fetches the dataset from where it is published when
//! its copy is more than a day old. A lead is a version match, never a confirmed
//! finding: a version can be read wrong, and a build may carry a fix its version does
//! not show.

use cfx_cve::{Asked, Cpe, Dataset, Lead, Version};
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

/// The other names the CVE data gives products the signatures name (toolmark/data).
const ALIASES: &str = include_str!("../data/aliases.yaml");

/// How the CVE data numbers the products whose CVEs are filed under other numbering than
/// toolmark reads (toolmark/data).
const VERSIONS: &str = include_str!("../data/versions.yaml");

/// The dataset's file in toolmark's data folder.
pub const DATASET_FILE: &str = "cve-dataset.json.gz";

/// What a lead from the snapshot says of where it came from.
pub const SNAPSHOT_LABEL: &str = "built-in known-exploited snapshot";

/// Each product's other names in the CVE data, from toolmark/data/aliases.yaml.
fn aliases() -> &'static std::collections::HashMap<Cpe, Vec<Cpe>> {
    static ALL: std::sync::LazyLock<std::collections::HashMap<Cpe, Vec<Cpe>>> =
        std::sync::LazyLock::new(|| {
            let read: std::collections::BTreeMap<String, Vec<String>> =
                serde_yaml::from_str(ALIASES).expect("toolmark/data/aliases.yaml reads");
            read.into_iter()
                .map(|(name, also)| (named(&name), also.iter().map(|a| named(a)).collect()))
                .collect()
        });
    &ALL
}

/// A name in toolmark/data/aliases.yaml, part:vendor:product.
fn named(text: &str) -> Cpe {
    Cpe::parse(text).unwrap_or_else(|| {
        panic!("{text} in toolmark/data/aliases.yaml is not part:vendor:product")
    })
}

/// One way a version toolmark reads maps to the one the CVE data files it under: an
/// exact version, or a range from one up to and not including another.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Filed {
    eq: Option<String>,
    from: Option<String>,
    below: Option<String>,
    #[serde(rename = "as")]
    filed: String,
}

impl Filed {
    fn holds(&self, v: &Version) -> bool {
        let at = |bound: &Option<String>| bound.as_deref().and_then(Version::parse);
        at(&self.eq).is_none_or(|b| *v == b)
            && at(&self.from).is_none_or(|b| *v >= b)
            && at(&self.below).is_none_or(|b| *v < b)
    }
}

/// Each product's map, from toolmark/data/versions.yaml.
fn version_maps() -> &'static std::collections::HashMap<Cpe, Vec<Filed>> {
    static ALL: std::sync::LazyLock<std::collections::HashMap<Cpe, Vec<Filed>>> =
        std::sync::LazyLock::new(|| {
            let read: std::collections::BTreeMap<String, Vec<Filed>> =
                serde_yaml::from_str(VERSIONS).expect("toolmark/data/versions.yaml reads");
            read.into_iter()
                .map(|(name, map)| (named(&name), map))
                .collect()
        });
    &ALL
}

/// `version` of `cpe` as the CVE data numbers it: itself, or for a product whose CVEs are
/// filed under other numbering, what its map gives, and none when the map has nothing
/// for it.
fn as_filed(cpe: &Cpe, version: &str) -> Option<String> {
    let Some(map) = version_maps().get(cpe) else {
        return Some(version.to_string());
    };
    let v = Version::parse(version)?;
    map.iter().find(|f| f.holds(&v)).map(|f| f.filed.clone())
}

/// `cpe` and its other names.
fn with_aliases(cpe: &Cpe) -> Vec<Cpe> {
    let mut names = vec![cpe.clone()];
    names.extend(aliases().get(cpe).into_iter().flatten().cloned());
    names
}

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
        let names: HashSet<Cpe> = names.iter().flat_map(with_aliases).collect();
        let data = folder
            .and_then(|f| read(&f.join(DATASET_FILE), &names))
            .unwrap_or_else(|| snapshot(&names));
        Self {
            folder: folder.map(Path::to_path_buf),
            url: url.to_string(),
            names,
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

    /// The leads at `version` for what `products` name, each under its own name and its
    /// aliases, built by the distribution `distro` names when one is known, and the data
    /// they come from. A lead that affects some of several products and not others is
    /// possible.
    pub fn leads(
        &self,
        products: &[Cpe],
        version: &str,
        distro: Option<&str>,
    ) -> (Vec<Lead>, String) {
        let asked: Vec<Asked> = products
            .iter()
            .filter_map(|p| Some(Asked::new(with_aliases(p), &as_filed(p, version)?)))
            .collect();
        let data = self.data.read().unwrap_or_else(|e| e.into_inner());
        (data.0.leads(&asked, distro), data.1.clone())
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
            let (leads, from) = cves.leads(&[apache()], "2.4.49", None);
            assert_eq!(from, SNAPSHOT_LABEL);
            for cve in ["CVE-2021-41773", "CVE-2021-42013"] {
                assert!(ids(&leads).contains(&cve), "{cve} in {:?}", ids(&leads));
            }
            assert!(leads.iter().all(|l| l.known.kev));
            let (later, _) = cves.leads(&[apache()], "2.4.51", None);
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
        let (leads, from) = cves.leads(&[apache()], "2.4.49", Some("Ubuntu"));
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
        assert_eq!(cves.leads(&[apache()], "2.4.49", None).1, SNAPSHOT_LABEL);
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
            ids(&cves.leads(&[apache()], "2.4.49", None).0),
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

    /// Exchange's build is asked for as the cumulative update NVD names, SharePoint's as its
    /// release, and Erlang/OTP's ssh version as the OTP release that shipped it; a build
    /// the map does not hold gives nothing.
    #[test]
    fn a_version_filed_under_other_numbering_is_asked_for_as_it_is_filed() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(
            folder.path().join(DATASET_FILE),
            r#"{"format": 1, "sequence": 3, "made": "2026-11-22T15:00:00Z", "products": [
              {"part": "a", "vendor": "microsoft", "product": "exchange_server",
               "affected": [{"cve": "CVE-2099-0040", "ranges": [{"eq": "2019cumulative_update_12"}]}]},
              {"part": "a", "vendor": "microsoft", "product": "sharepoint_server",
               "affected": [{"cve": "CVE-2099-0041", "ranges": [{"eq": "2019"}]}]},
              {"part": "a", "vendor": "erlang", "product": "erlang/otp",
               "affected": [{"cve": "CVE-2099-0042", "ranges": [{"ge": "27.0", "lt": "27.3.3"}]}]}],
             "cves": {"CVE-2099-0040": {}, "CVE-2099-0041": {}, "CVE-2099-0042": {}}}"#,
        )
        .unwrap();
        let exchange = Cpe::new("a", "microsoft", "exchange_server");
        let sharepoint = Cpe::new("a", "microsoft", "sharepoint_server");
        let otp = Cpe::new("a", "erlang", "erlang/otp");
        let names: HashSet<Cpe> = [exchange.clone(), sharepoint.clone(), otp.clone()].into();
        let cves = Cves::load(Some(folder.path()), &names, DATASET_URL);
        let ask = |cpe: &Cpe, version: &str| {
            ids(&cves.leads(&[cpe.clone()], version, None).0)
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(ask(&exchange, "15.2.1118.7"), ["CVE-2099-0040"]);
        assert_eq!(
            ask(&exchange, "15.2.1118.40"),
            ["CVE-2099-0040"],
            "any update of CU12"
        );
        assert!(ask(&exchange, "15.2.1258.12").is_empty(), "CU13");
        assert!(
            ask(&exchange, "15.2.2562.17").is_empty(),
            "Subscription Edition is not mapped"
        );
        assert_eq!(ask(&sharepoint, "16.0.0.10337"), ["CVE-2099-0041"]);
        assert_eq!(
            ask(&otp, "5.2.9"),
            ["CVE-2099-0042"],
            "ssh 5.2.9 shipped with OTP 27.3.1"
        );
        assert!(ask(&otp, "5.2.10").is_empty(), "ssh 5.2.10 is OTP 27.3.3's");
    }

    /// FortiOS, NetScaler and Exchange, each at a version with known-exploited CVEs, give
    /// them from the snapshot toolmark ships.
    #[test]
    fn the_snapshot_gives_fortios_netscaler_and_exchange_their_known_exploited_cves() {
        let cves = snapshot_for_tests();
        let kev = |products: &[Cpe], version: &str| {
            let (leads, from) = cves.leads(products, version, None);
            assert_eq!(from, SNAPSHOT_LABEL);
            leads
                .into_iter()
                .filter(|l| l.known.kev)
                .map(|l| l.cve)
                .collect::<Vec<_>>()
        };
        let fortios = kev(&[Cpe::new("o", "fortinet", "fortios")], "7.2.4");
        assert!(fortios.iter().any(|c| c == "CVE-2023-27997"), "{fortios:?}");
        let netscaler = kev(
            &[
                Cpe::new("a", "citrix", "netscaler_application_delivery_controller"),
                Cpe::new("a", "citrix", "netscaler_gateway"),
            ],
            "13.1-49.12",
        );
        assert!(
            netscaler.iter().any(|c| c == "CVE-2023-3519"),
            "{netscaler:?}"
        );
        let exchange = kev(
            &[Cpe::new("a", "microsoft", "exchange_server")],
            "15.2.1118.7",
        );
        assert!(
            exchange.iter().any(|c| c == "CVE-2022-41082"),
            "{exchange:?}"
        );
    }

    /// A product is looked up under its aliases too, and a lead that affects some of
    /// several products and not others is possible, whatever name each came under.
    #[test]
    fn products_are_looked_up_with_their_aliases_and_marked_possible() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(
            folder.path().join(DATASET_FILE),
            r#"{"format": 1, "sequence": 3, "made": "2026-11-22T15:00:00Z", "products": [
              {"part": "a", "vendor": "citrix", "product": "netscaler_application_delivery_controller",
               "affected": [{"cve": "CVE-2099-0010", "ranges": [{"lt": "13.1-49.13"}]},
                            {"cve": "CVE-2099-0011", "ranges": [{"lt": "13.1-49.13"}]}]},
              {"part": "o", "vendor": "citrix", "product": "netscaler_gateway_firmware",
               "affected": [{"cve": "CVE-2099-0010", "ranges": [{"lt": "13.1-49.13"}]}]},
              {"part": "a", "vendor": "synacor", "product": "zimbra_collaboration_suite",
               "affected": [{"cve": "CVE-2099-0020", "ranges": [{"lt": "9.0.0"}]}]},
              {"part": "o", "vendor": "fortinet", "product": "fortios",
               "affected": [{"cve": "CVE-2099-0030", "ranges": [{"le": "7.2.4"}]}]}],
             "cves": {"CVE-2099-0010": {}, "CVE-2099-0011": {}, "CVE-2099-0020": {},
                      "CVE-2099-0030": {"kev": true}}}"#,
        )
        .unwrap();
        let netscaler = [
            Cpe::new("a", "citrix", "netscaler_application_delivery_controller"),
            Cpe::new("a", "citrix", "netscaler_gateway"),
        ];
        let zimbra = [Cpe::new("a", "zimbra", "collaboration")];
        let fortinet = [
            Cpe::new("o", "fortinet", "fortios"),
            Cpe::new("a", "fortinet", "fortiproxy"),
        ];
        let names: HashSet<Cpe> = netscaler
            .iter()
            .chain(&zimbra)
            .chain(&fortinet)
            .cloned()
            .collect();
        let cves = Cves::load(Some(folder.path()), &names, DATASET_URL);
        let (leads, _) = cves.leads(&netscaler, "13.1-49.12", None);
        assert_eq!(ids(&leads), ["CVE-2099-0010", "CVE-2099-0011"]);
        assert!(
            !leads[0].possible,
            "the gateway has it as its firmware: both editions do"
        );
        assert!(leads[1].possible, "the ADC alone has it");
        let (leads, _) = cves.leads(&zimbra, "8.8.15", None);
        assert_eq!(
            ids(&leads),
            ["CVE-2099-0020"],
            "under the vendor's earlier name"
        );
        assert!(!leads[0].possible);
        let (leads, _) = cves.leads(&fortinet, "7.2.4", None);
        assert_eq!(ids(&leads), ["CVE-2099-0030"]);
        assert!(leads[0].possible, "FortiOS has it, FortiProxy does not");
    }

    /// Every product a shipped signature names by CPE is one the snapshot can be asked
    /// about, and the snapshot reads.
    #[test]
    fn the_snapshot_reads_with_every_shipped_product() {
        let names = crate::signatures::Signatures::shipped().cpes();
        assert!(names.contains(&apache()), "{} products", names.len());
        let cves = Cves::load(None, &names, DATASET_URL);
        assert!(!cves.leads(&[apache()], "2.4.49", None).0.is_empty());
    }
}
