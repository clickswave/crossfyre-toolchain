//! `crossfyre update` for the data the engines read: the crossfyre-templates pack and the
//! CVE dataset, as the data manifest on the bins origin names them (see `data_manifest`).
//!
//! The manifest's signature is checked against the data key when the build carries one.
//! Each file must have the size and SHA-256 the manifest gives it, and the pack must be
//! the one it names. A sequence lower than the last one accepted here is refused, so a
//! manifest kept from before cannot take a machine back. Each file goes where the engines
//! read it in the toolchain directory, under a temporary name and then renamed into
//! place, owned by the account the engines run as, and the engines' daemons that are
//! running are then told to read it again. The engines fetch none of it themselves.

use super::data_manifest::{DataManifest, Entry, PATH};
use super::release_http::{Purpose, http_client};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// The file in the toolchain directory that holds the sequence of what was last accepted.
pub const RECORD: &str = "data.json";

/// How many days old the published data gets before an update says so.
pub const STALE_AFTER_DAYS: i64 = 14;

/// The most of a data manifest or its signature read.
const MAX_MANIFEST_BYTES: u64 = 1 << 20;

/// The sequence of each piece of data last accepted here.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Accepted {
    #[serde(default)]
    packs: BTreeMap<String, u64>,
    #[serde(default)]
    dataset: Option<u64>,
}

/// What happened to one piece of data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Fetched, checked and put in place.
    Updated {
        from: Option<u64>,
        to: u64,
    },
    /// What is here is what is published.
    Current(u64),
    /// Published at a lower sequence than the one accepted here, and not used.
    Refused {
        offered: u64,
        accepted: u64,
    },
    Failed(String),
}

impl Outcome {
    fn updated(&self) -> bool {
        matches!(self, Outcome::Updated { .. })
    }
}

/// What an update of the data did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Report {
    /// False when the bins origin has published no data yet.
    pub published: bool,
    /// How many days ago the published data was made, when more than
    /// [`STALE_AFTER_DAYS`].
    pub stale_days: Option<i64>,
    pub pack: Option<Outcome>,
    pub dataset: Option<Outcome>,
}

impl Report {
    /// Whether the pack changed, which both engines read.
    pub fn pack_changed(&self) -> bool {
        self.pack.as_ref().is_some_and(Outcome::updated)
    }

    /// Whether the dataset changed, which toolmark reads.
    pub fn dataset_changed(&self) -> bool {
        self.dataset.as_ref().is_some_and(Outcome::updated)
    }
}

/// Check the manifest's signature, when this build demands one, against the data key.
pub type Verify<'a> = &'a (dyn Fn(&[u8], &str) -> Result<(), String> + Sync);

/// Fetch the data manifest from `base` and the data it names into the toolchain directory
/// `dir`, `now` being the time in seconds since 1970. `signed` says the manifest must carry
/// a signature, which `verify` checks. An error is one the whole update of the data stops
/// on: a manifest that cannot be had, does not verify or does not read.
pub async fn fetch(
    base: &str,
    dir: &Path,
    signed: bool,
    verify: Verify<'_>,
    now: i64,
) -> Result<Report, String> {
    let url = format!("{base}/{PATH}");
    let Some(body) = get(&url, Purpose::Check, MAX_MANIFEST_BYTES).await? else {
        return Ok(Report::default());
    };
    if signed {
        let sig_url = format!("{url}{}", super::release_sig::SIG_SUFFIX);
        let sig = get(&sig_url, Purpose::Check, MAX_MANIFEST_BYTES)
            .await?
            .ok_or_else(|| {
                format!(
                    "this build requires a signed data manifest and {sig_url} is not there, \
                     so no data was taken"
                )
            })?;
        verify(&body, &String::from_utf8_lossy(&sig))?;
    }
    let manifest = DataManifest::parse(&body)?;
    let age = (now - manifest.made).div_euclid(86_400);
    let mut accepted = read_record(dir);
    let mut report = Report {
        published: true,
        stale_days: (age > STALE_AFTER_DAYS).then_some(age),
        ..Report::default()
    };
    if let Some(entry) = manifest.packs.get(cfx_pack::NAME) {
        let had = accepted.packs.get(cfx_pack::NAME).copied();
        let outcome = take(base, entry, had, &cfx_pack::path_in(dir), check_pack).await;
        if let Outcome::Updated { to, .. } = outcome {
            accepted.packs.insert(cfx_pack::NAME.to_string(), to);
        }
        report.pack = Some(outcome);
    }
    if let Some(entry) = &manifest.dataset {
        let outcome = take(
            base,
            entry,
            accepted.dataset,
            &cfx_cve::path_in(dir),
            |_, _| Ok(()),
        )
        .await;
        if let Outcome::Updated { to, .. } = outcome {
            accepted.dataset = Some(to);
        }
        report.dataset = Some(outcome);
    }
    if report.pack_changed() || report.dataset_changed() {
        write_record(dir, &accepted)?;
    }
    Ok(report)
}

/// Fetch the file `entry` names to `path` unless what was accepted, `had`, is as late, or
/// later, which is refused. `check` looks at what came once its size and SHA-256 hold.
async fn take(
    base: &str,
    entry: &Entry,
    had: Option<u64>,
    path: &Path,
    check: fn(&[u8], &Entry) -> Result<(), String>,
) -> Outcome {
    if let Some(accepted) = had {
        if entry.sequence < accepted {
            return Outcome::Refused {
                offered: entry.sequence,
                accepted,
            };
        }
        if entry.sequence == accepted && path.is_file() {
            return Outcome::Current(accepted);
        }
    }
    let url = format!("{base}/{}", entry.file);
    let bytes = match get(&url, Purpose::Update, entry.size).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Outcome::Failed(format!("{url} is not there")),
        Err(e) => return Outcome::Failed(e),
    };
    if bytes.len() as u64 != entry.size {
        return Outcome::Failed(format!(
            "{url} is {} bytes, and the data manifest says {}",
            bytes.len(),
            entry.size
        ));
    }
    let got = format!("{:x}", Sha256::digest(&bytes));
    if got != entry.sha256 {
        return Outcome::Failed(format!(
            "{url} has the SHA-256 {got}, and the data manifest says {}",
            entry.sha256
        ));
    }
    if let Err(why) = check(&bytes, entry) {
        return Outcome::Failed(why);
    }
    if let Err(e) = super::sudo_user::replace_for_invoking_user(path, &bytes, 0o644) {
        return Outcome::Failed(format!("{}: {e}", path.display()));
    }
    Outcome::Updated {
        from: had,
        to: entry.sequence,
    }
}

/// Why `bytes` is not the pack `entry` names: it does not read, or it is another pack, or
/// another sequence of it.
fn check_pack(bytes: &[u8], entry: &Entry) -> Result<(), String> {
    let pack = cfx_pack::Pack::from_bytes(bytes).map_err(|e| e.to_string())?;
    if pack.name() != cfx_pack::NAME || pack.sequence() != entry.sequence {
        return Err(format!(
            "the file is {} {}, and the data manifest names {} {}",
            pack.name(),
            pack.sequence(),
            cfx_pack::NAME,
            entry.sequence
        ));
    }
    Ok(())
}

/// What was last accepted in `dir`; nothing when no record reads.
fn read_record(dir: &Path) -> Accepted {
    std::fs::read(dir.join(RECORD))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn write_record(dir: &Path, accepted: &Accepted) -> Result<(), String> {
    let path = dir.join(RECORD);
    let text = serde_json::to_vec_pretty(accepted).map_err(|e| e.to_string())?;
    super::sudo_user::replace_for_invoking_user(&path, &text, 0o644)
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// The body at `url`, none when the origin answers 404, and an error when it answers
/// anything else but success or sends more than `cap` bytes.
async fn get(url: &str, purpose: Purpose, cap: u64) -> Result<Option<Vec<u8>>, String> {
    let mut resp = http_client(purpose)
        .map_err(|e| e.to_string())?
        .get(url)
        .send()
        .await
        .map_err(|e| format!("could not fetch {url}: {e}"))?;
    if resp.status().as_u16() == 404 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("{url} answered {}", resp.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("could not read {url}: {e}"))?
    {
        body.extend_from_slice(&chunk);
        if body.len() as u64 > cap {
            return Err(format!("{url} sent more than the {cap} bytes expected"));
        }
    }
    Ok(Some(body))
}

/// Tell each engine that reads what changed, and whose daemon is running, to read it
/// again: toolmark the pack and the dataset, plessor the pack. Each engine with what its
/// daemon said, or none when it is not running and reads it as it starts.
pub async fn reload_engines(
    report: &Report,
) -> Vec<(&'static str, Option<Result<String, String>>)> {
    let mut asked = Vec::new();
    if report.pack_changed() || report.dataset_changed() {
        asked.push("toolmark");
    }
    if report.pack_changed() {
        asked.push("plessor");
    }
    let mut said = Vec::new();
    for engine in asked {
        if !super::config::is_extension_installed(engine) {
            continue;
        }
        let port = super::config::engine_port(engine);
        let running = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok();
        let answer = if running {
            let daemon = dguard::Daemon::new(engine, port, false);
            Some(
                dguard::answer(&daemon, "reload")
                    .await
                    .map(|a| a["message"].as_str().unwrap_or_default().to_string())
                    .map_err(|e| e.to_string()),
            )
        } else {
            None
        };
        said.push((engine, answer));
    }
    said
}

/// What a node last did with the data, for its log and its status to Cloud: when it
/// looked, the sequence of the pack and of the dataset in place, and what went wrong, if
/// anything did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    /// When it looked, in seconds since 1970.
    pub checked: i64,
    pub pack: Option<u64>,
    pub dataset: Option<u64>,
    pub problem: Option<String>,
}

impl Status {
    /// The status as the node's heartbeat carries it, in `toolchain_status.data`.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "checked": self.checked,
            "pack": self.pack,
            "dataset": self.dataset,
            "problem": self.problem,
        })
    }
}

/// Take the data as `crossfyre update data` does and say what is in place, with a line
/// for the log for each thing that happened, and what it did: the node's daily run and
/// its dashboard update, which [`refresh_here`] makes. What is refused or fails leaves the
/// data in place, and is said. The engines are told by `refresh_here`, never here, so a
/// test of this reaches no engine on the host.
pub async fn refresh(
    base: &str,
    dir: &Path,
    signed: bool,
    verify: Verify<'_>,
    now: i64,
) -> (Status, Vec<String>, Option<Report>) {
    let mut lines = Vec::new();
    let mut problems = Vec::new();
    let mut done = None;
    match fetch(base, dir, signed, verify, now).await {
        Err(why) => problems.push(why),
        Ok(report) if !report.published => lines.push("no data is published yet".to_string()),
        Ok(report) => {
            for (name, outcome) in [("templates", &report.pack), ("dataset", &report.dataset)] {
                match outcome {
                    None => {}
                    Some(Outcome::Updated {
                        from: Some(from),
                        to,
                    }) => lines.push(format!("{name} {from} -> {to}")),
                    Some(Outcome::Updated { from: None, to }) => lines.push(format!("{name} {to}")),
                    Some(Outcome::Current(at)) => lines.push(format!("{name} {at} is up to date")),
                    Some(Outcome::Refused { offered, accepted }) => problems.push(format!(
                        "{name} {offered} is published, older than the {accepted} accepted \
                         here, so it is not used"
                    )),
                    Some(Outcome::Failed(why)) => problems.push(format!("{name}: {why}")),
                }
            }
            if let Some(days) = report.stale_days {
                problems.push(format!(
                    "the published data was made {days} days ago, and nothing newer is published"
                ));
            }
            done = Some(report);
        }
    }
    lines.extend(problems.iter().cloned());
    let accepted = read_record(dir);
    let status = Status {
        checked: now,
        pack: accepted.packs.get(cfx_pack::NAME).copied(),
        dataset: accepted.dataset,
        problem: (!problems.is_empty()).then(|| problems.join("; ")),
    };
    (status, lines, done)
}

/// [`refresh`] from this build's bins origin into the toolchain directory, checked
/// against this build's data key, now, and then the engines that read what changed told
/// to read it again. Only the node calls this: no test does, as it reaches the bins
/// origin, the toolchain directory and the engines on this host.
pub async fn refresh_here() -> (Status, Vec<String>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let (status, mut lines, report) = refresh(
        super::install::bins_origin(),
        &super::config::get_toolchain_dir(),
        super::release_sig::data_required(),
        &super::release_sig::verify_data,
        now,
    )
    .await;
    if let Some(report) = report {
        for (engine, said) in reload_engines(&report).await {
            lines.push(match said {
                Some(Ok(_)) => format!("{engine} read it again"),
                Some(Err(why)) => format!("{engine} did not read it again: {why}"),
                None => format!("{engine} is not running, and reads it when it starts"),
            });
        }
    }
    (status, lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An origin on loopback serving `files` by path, 404 for anything else, and the paths
    /// it was asked for.
    async fn origin(files: BTreeMap<String, Vec<u8>>) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = asked.clone();
        let files = Arc::new(files);
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let (files, seen) = (files.clone(), seen.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let head = String::from_utf8_lossy(&buf);
                    let path = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .trim_start_matches('/');
                    seen.lock().unwrap().push(path.to_string());
                    let reply = match files.get(path) {
                        Some(body) => {
                            let mut r = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .into_bytes();
                            r.extend_from_slice(body);
                            r
                        }
                        None => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec(),
                    };
                    let _ = s.write_all(&reply).await;
                    let _ = s.shutdown().await;
                });
            }
        });
        (base, asked)
    }

    fn pack(sequence: u64, name: &str) -> Vec<u8> {
        serde_json::json!({"format": 1, "name": name, "sequence": sequence,
            "made": "2026-11-21T07:00:00Z", "commit": "abcdef0123456789",
            "files": {"toolmark/acme.yaml": "id: acme\n"}})
        .to_string()
        .into_bytes()
    }

    fn entry(sequence: u64, file: &str, body: &[u8]) -> serde_json::Value {
        serde_json::json!({"sequence": sequence, "file": file,
            "sha256": format!("{:x}", Sha256::digest(body)), "size": body.len()})
    }

    /// The data manifest naming `pack` at `pseq` and `dataset` at `dseq`, made `made`, and
    /// the files it names, as an origin serves them.
    fn published(
        pseq: u64,
        pack: &[u8],
        dseq: u64,
        dataset: &[u8],
        made: &str,
    ) -> BTreeMap<String, Vec<u8>> {
        let pfile = format!("data/crossfyre-templates-{pseq}.json.gz");
        let dfile = format!("data/cve-dataset-{dseq}.json.gz");
        let manifest = serde_json::json!({"format": 1, "made": made,
            "packs": {"crossfyre-templates": entry(pseq, &pfile, pack)},
            "dataset": entry(dseq, &dfile, dataset)});
        [
            (PATH.to_string(), manifest.to_string().into_bytes()),
            (pfile, pack.to_vec()),
            (dfile, dataset.to_vec()),
        ]
        .into_iter()
        .collect()
    }

    const NOW: i64 = 1_795_273_200; // 2026-11-21T15:00:00Z
    const MADE: &str = "2026-11-21T14:00:00Z";
    const DATASET: &[u8] = b"{\"format\":1,\"sequence\":42}";

    fn unsigned(_: &[u8], _: &str) -> Result<(), String> {
        Ok(())
    }

    async fn update(base: &str, dir: &Path) -> Report {
        fetch(base, dir, false, &unsigned, NOW).await.unwrap()
    }

    /// Later data is fetched, checked and put where the engines read it, with the record
    /// of what was accepted; asked again, nothing is fetched, as nothing is newer. The
    /// toolchain directory then holds those three files and nothing else.
    #[tokio::test]
    async fn later_data_is_put_where_the_engines_read_it_and_fetched_once() {
        let dir = tempfile::tempdir().unwrap();
        let (base, asked) = origin(published(5, &pack(5, cfx_pack::NAME), 42, DATASET, MADE)).await;
        let report = update(&base, dir.path()).await;
        assert!(report.published && report.stale_days.is_none());
        assert_eq!(report.pack, Some(Outcome::Updated { from: None, to: 5 }));
        assert_eq!(
            report.dataset,
            Some(Outcome::Updated { from: None, to: 42 })
        );
        assert_eq!(
            std::fs::read(cfx_pack::path_in(dir.path())).unwrap(),
            pack(5, cfx_pack::NAME)
        );
        assert_eq!(
            std::fs::read(cfx_cve::path_in(dir.path())).unwrap(),
            DATASET
        );
        assert_eq!(read_record(dir.path()).packs[cfx_pack::NAME], 5);
        let mut files: Vec<String> = walk(dir.path());
        files.sort();
        assert_eq!(
            files,
            [
                "data.json",
                "packs/crossfyre-templates.json.gz",
                "toolmark/cve-dataset.json.gz"
            ]
        );
        let before = asked.lock().unwrap().len();
        let again = update(&base, dir.path()).await;
        assert_eq!(
            (again.pack, again.dataset),
            (Some(Outcome::Current(5)), Some(Outcome::Current(42)))
        );
        assert_eq!(
            asked.lock().unwrap()[before..],
            [PATH.to_string()],
            "only the manifest"
        );
    }

    fn walk(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if p.is_dir() {
                out.extend(walk(&p).into_iter().map(|f| format!("{name}/{f}")));
            } else {
                out.push(name);
            }
        }
        out
    }

    /// A manifest offering a lower sequence than the one accepted here is refused, and
    /// what is here stays.
    #[tokio::test]
    async fn a_lower_sequence_than_the_one_accepted_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (later, _) = origin(published(5, &pack(5, cfx_pack::NAME), 42, DATASET, MADE)).await;
        update(&later, dir.path()).await;
        let (earlier, _) = origin(published(4, &pack(4, cfx_pack::NAME), 41, b"older", MADE)).await;
        let report = update(&earlier, dir.path()).await;
        assert_eq!(
            report.pack,
            Some(Outcome::Refused {
                offered: 4,
                accepted: 5
            })
        );
        assert_eq!(
            report.dataset,
            Some(Outcome::Refused {
                offered: 41,
                accepted: 42
            })
        );
        assert_eq!(
            std::fs::read(cfx_pack::path_in(dir.path())).unwrap(),
            pack(5, cfx_pack::NAME)
        );
        assert_eq!(
            std::fs::read(cfx_cve::path_in(dir.path())).unwrap(),
            DATASET
        );
    }

    /// A file that is not what the manifest says, by its hash, or a pack that is another
    /// pack or another sequence of it, is not put in place.
    #[tokio::test]
    async fn a_file_that_is_not_what_the_manifest_says_is_not_used() {
        for (served, why) in [
            (pack(6, cfx_pack::NAME), "another sequence"),
            (pack(5, "someone-elses"), "another pack"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let (base, _) = origin(published(5, &served, 42, DATASET, MADE)).await;
            let report = update(&base, dir.path()).await;
            assert!(
                matches!(report.pack, Some(Outcome::Failed(_))),
                "{why}: {report:?}"
            );
            assert!(!cfx_pack::path_in(dir.path()).exists(), "{why}");
        }
        let dir = tempfile::tempdir().unwrap();
        let mut files = published(5, &pack(5, cfx_pack::NAME), 42, DATASET, MADE);
        files.insert(
            "data/cve-dataset-42.json.gz".into(),
            b"{\"format\":1,\"sequence\":43}".to_vec(),
        );
        let (base, _) = origin(files).await;
        let report = update(&base, dir.path()).await;
        assert!(
            matches!(&report.dataset, Some(Outcome::Failed(why)) if why.contains("SHA-256")),
            "{report:?}"
        );
        assert!(!cfx_cve::path_in(dir.path()).exists());
        assert_eq!(read_record(dir.path()).dataset, None);
    }

    /// A build that demands a signature takes nothing on a manifest the data key did not
    /// sign, or that has no signature.
    #[tokio::test]
    async fn a_manifest_the_data_key_did_not_sign_takes_nothing() {
        use ed25519_dalek::Signer;
        let data = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let release = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let data_pk = super::super::release_sig::b64_for_tests(data.verifying_key().as_bytes());
        let verify = move |body: &[u8], sig: &str| {
            super::super::release_sig::verify_data_with(&[&data_pk], body, sig)
        };
        let mut files = published(5, &pack(5, cfx_pack::NAME), 42, DATASET, MADE);
        let body = files[PATH].clone();
        let dir = tempfile::tempdir().unwrap();
        let (unsigned_origin, _) = origin(files.clone()).await;
        let err = fetch(&unsigned_origin, dir.path(), true, &verify, NOW)
            .await
            .unwrap_err();
        assert!(err.contains("requires a signed data manifest"), "{err}");
        let by = |key: &ed25519_dalek::SigningKey| {
            super::super::release_sig::b64_for_tests(&key.sign(&body).to_bytes()).into_bytes()
        };
        files.insert(format!("{PATH}.sig"), by(&release));
        let (wrong_key, _) = origin(files.clone()).await;
        let err = fetch(&wrong_key, dir.path(), true, &verify, NOW)
            .await
            .unwrap_err();
        assert!(
            err.starts_with("data manifest signature does not verify"),
            "{err}"
        );
        assert!(walk(dir.path()).is_empty(), "nothing was written");
        files.insert(format!("{PATH}.sig"), by(&data));
        let (right_key, _) = origin(files).await;
        let report = fetch(&right_key, dir.path(), true, &verify, NOW)
            .await
            .unwrap();
        assert_eq!(report.pack, Some(Outcome::Updated { from: None, to: 5 }));
    }

    /// The node's run says in its status what is in place and, after a refusal, why the
    /// data in place was kept; its log has a line for each thing.
    #[tokio::test]
    async fn the_nodes_run_says_what_is_in_place_and_what_went_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let (later, _) = origin(published(5, &pack(5, cfx_pack::NAME), 42, DATASET, MADE)).await;
        let (status, lines, _) = refresh(&later, dir.path(), false, &unsigned, NOW).await;
        assert_eq!(
            status,
            Status {
                checked: NOW,
                pack: Some(5),
                dataset: Some(42),
                problem: None
            }
        );
        assert_eq!(lines, ["templates 5", "dataset 42"]);
        let (earlier, _) = origin(published(4, &pack(4, cfx_pack::NAME), 42, DATASET, MADE)).await;
        let (status, lines, _) = refresh(&earlier, dir.path(), false, &unsigned, NOW).await;
        assert_eq!((status.pack, status.dataset), (Some(5), Some(42)));
        let problem = status.problem.expect("the refusal is said");
        assert!(
            problem.starts_with("templates 4 is published, older than the 5"),
            "{problem}"
        );
        assert!(
            lines.contains(&"dataset 42 is up to date".to_string()),
            "{lines:?}"
        );
        assert_eq!(
            status_json(&Status {
                checked: 1,
                pack: Some(5),
                dataset: None,
                problem: None
            }),
            serde_json::json!({"checked": 1, "pack": 5, "dataset": null, "problem": null})
        );
        let (gone, _) = origin(BTreeMap::new()).await;
        let (status, lines, _) = refresh(&gone, dir.path(), false, &unsigned, NOW).await;
        assert_eq!((status.pack, status.problem), (Some(5), None));
        assert_eq!(lines, ["no data is published yet"]);
    }

    fn status_json(status: &Status) -> serde_json::Value {
        status.to_json()
    }

    /// With nothing published, nothing is done; published data more than two weeks old is
    /// said to be.
    #[tokio::test]
    async fn nothing_published_is_no_error_and_old_data_is_said_to_be() {
        let dir = tempfile::tempdir().unwrap();
        let (empty, _) = origin(BTreeMap::new()).await;
        assert_eq!(update(&empty, dir.path()).await, Report::default());
        let (old, _) = origin(published(
            5,
            &pack(5, cfx_pack::NAME),
            42,
            DATASET,
            "2026-11-01T15:00:00Z",
        ))
        .await;
        assert_eq!(update(&old, dir.path()).await.stale_days, Some(20));
        let (fortnight, _) = origin(published(
            5,
            &pack(5, cfx_pack::NAME),
            42,
            DATASET,
            "2026-11-07T15:00:00Z",
        ))
        .await;
        assert_eq!(update(&fortnight, dir.path()).await.stale_days, None);
    }
}
