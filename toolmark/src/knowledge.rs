//! What toolmark knows: its signatures, the mappings its CVE leads are looked up with, and
//! the CVE data the leads come from.
//!
//! The signatures and mappings are crossfyre-templates'. Each release compiles in a copy,
//! and the pack `crossfyre update` puts in the toolchain directory takes its place when it
//! is later and every file in it loads. The leads come from the CVE dataset `crossfyre
//! update` puts in toolmark's data folder or, with none there that reads, from the
//! known-exploited snapshot compiled in. toolmark fetches none of it. The daemon reads what
//! is there as it starts and again when told to reload, and a scan takes what is known as
//! it starts and keeps it to its end.

use crate::cve::{self, Mappings};
use crate::signatures::{self, Signatures, StampTables};
use cfx_cve::{Asked, Cpe, Dataset, Lead};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// The mappings compiled in: toolmark/data's, copied from crossfyre-templates.
const MAPPINGS: &[(&str, &str)] = &[
    ("aliases.yaml", include_str!("../data/aliases.yaml")),
    ("versions.yaml", include_str!("../data/versions.yaml")),
    (
        "netscaler-stamps.csv",
        include_str!("../data/netscaler-stamps.csv"),
    ),
];

/// Whether `name` is the name of a mapping file: aliases.yaml, versions.yaml, or a stamp
/// table, `<name>-stamps.csv`.
pub(crate) fn is_mapping(name: &str) -> bool {
    matches!(name, "aliases.yaml" | "versions.yaml") || name.ends_with("-stamps.csv")
}

/// The stamp tables among `mappings`, by file name and text: each `<name>-stamps.csv`,
/// named `<name>`.
fn stamp_tables(mappings: &[(&str, &str)]) -> Result<StampTables, String> {
    mappings
        .iter()
        .filter_map(|(file, text)| Some((*file, file.strip_suffix("-stamps.csv")?, *text)))
        .map(|(file, name, text)| {
            signatures::read_stamps(text)
                .map(|table| (name.to_string(), Arc::new(table)))
                .map_err(|e| format!("{file}: {e}"))
        })
        .collect()
}

/// The stamp tables compiled in, for the tests that load signatures of their own.
#[cfg(test)]
pub(crate) fn compiled_stamps() -> StampTables {
    stamp_tables(MAPPINGS).expect("the stamp tables compiled into toolmark read")
}

/// The signatures and mappings in `signatures` and `mappings`, files by name and text, or
/// each thing in them that does not load: all of it loads, or none of it is used.
pub(crate) fn read(
    signatures: &[(&str, &str)],
    mappings: &[(&str, &str)],
) -> Result<(Signatures, Mappings), Vec<String>> {
    let mut problems = Vec::new();
    let text = |name: &str| mappings.iter().find(|(f, _)| *f == name).map(|(_, t)| *t);
    let read = match (text("aliases.yaml"), text("versions.yaml")) {
        (Some(aliases), Some(versions)) => Mappings::read(aliases, versions)
            .map_err(|e| problems.push(e))
            .ok(),
        (aliases, versions) => {
            for (name, given) in [("aliases.yaml", aliases), ("versions.yaml", versions)] {
                if given.is_none() {
                    problems.push(format!("there is no {name}"));
                }
            }
            None
        }
    };
    let tables = stamp_tables(mappings).unwrap_or_else(|e| {
        problems.push(e);
        StampTables::new()
    });
    let (signatures, skipped) = Signatures::load(signatures, &tables);
    problems.extend(skipped);
    match read {
        Some(mappings) if problems.is_empty() => Ok((signatures, mappings)),
        _ => Err(problems),
    }
}

/// The first seven characters of a commit, as it is named in a log.
fn short(commit: &str) -> &str {
    commit.get(..7).unwrap_or(commit)
}

/// The copy compiled in, and what it is.
fn compiled() -> (Signatures, Mappings, String) {
    let (signatures, mappings) = read(signatures::COMPILED, MAPPINGS).unwrap_or_else(|problems| {
        panic!("the copy compiled into toolmark loads, as its test shows: {problems:?}")
    });
    let from = format!(
        "crossfyre-templates {} ({}), compiled in",
        cfx_pack::COMPILED.sequence,
        short(cfx_pack::COMPILED.commit)
    );
    (signatures, mappings, from)
}

/// The pack in the toolchain directory `dir`, and what it is, when there is one to use in
/// place of the copy compiled in. One there that is not used says why.
fn from_pack(dir: &Path) -> Option<(Signatures, Mappings, String)> {
    let path = cfx_pack::path_in(dir);
    let pack = match cfx_pack::installed(dir) {
        Ok(Some(pack)) => pack,
        Ok(None) => return None,
        Err(e) => {
            eprintln!("[toolmark] the pack at {} is not used: {e}", path.display());
            return None;
        }
    };
    if !pack.replaces_compiled() {
        eprintln!(
            "[toolmark] the pack at {} is {} {}, which is no later than the copy compiled in, {}",
            path.display(),
            pack.name(),
            pack.sequence(),
            cfx_pack::COMPILED.sequence
        );
        return None;
    }
    let signatures: Vec<(&str, &str)> = pack.files_in("toolmark").collect();
    let mappings: Vec<(&str, &str)> = pack.files_in("mappings").collect();
    match read(&signatures, &mappings) {
        Ok((signatures, mappings)) => {
            let from = format!(
                "crossfyre-templates {} ({}), from {}",
                pack.sequence(),
                short(pack.commit()),
                path.display()
            );
            Some((signatures, mappings, from))
        }
        Err(problems) => {
            eprintln!(
                "[toolmark] the pack at {} is not used, as not all of it loads:",
                path.display()
            );
            for problem in problems {
                eprintln!("[toolmark]   {problem}");
            }
            None
        }
    }
}

/// What toolmark knows at one time. It does not change: a reload makes another.
pub struct Known {
    pub signatures: Signatures,
    mappings: Mappings,
    dataset: Dataset,
    signatures_from: String,
    cves_from: String,
}

impl Known {
    /// What is in `dir`, the toolchain directory, where it is there and used, and what is
    /// compiled in where it is not.
    pub fn load(dir: Option<&Path>) -> Self {
        let (signatures, mappings, signatures_from) =
            dir.and_then(from_pack).unwrap_or_else(compiled);
        let names: HashSet<Cpe> = signatures
            .cpes()
            .iter()
            .flat_map(|cpe| mappings.with_aliases(cpe))
            .collect();
        let (dataset, cves_from) = dir
            .and_then(|d| cve::read(&d.join("toolmark").join(cve::DATASET_FILE), &names))
            .unwrap_or_else(|| cve::snapshot(&names));
        Self {
            signatures,
            mappings,
            dataset,
            signatures_from,
            cves_from,
        }
    }

    /// Where CVE leads come from.
    pub fn cves_from(&self) -> &str {
        &self.cves_from
    }

    /// What is known, said in a line.
    pub fn said(&self) -> String {
        format!(
            "signatures from {}; CVE leads from {}",
            self.signatures_from, self.cves_from
        )
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
            .filter_map(|p| {
                let filed = self.mappings.as_filed(p, version)?;
                Some(Asked::new(self.mappings.with_aliases(p), &filed))
            })
            .collect();
        (self.dataset.leads(&asked, distro), self.cves_from.clone())
    }
}

/// What the daemon knows now, and where it reads it again from.
pub struct Knowledge {
    dir: Option<PathBuf>,
    now: RwLock<Arc<Known>>,
}

impl Knowledge {
    /// What is in the toolchain directory `dir`, and compiled in.
    pub fn load(dir: Option<&Path>) -> Self {
        Self {
            dir: dir.map(Path::to_path_buf),
            now: RwLock::new(Arc::new(Known::load(dir))),
        }
    }

    /// What is known now. A scan takes it once, as it starts.
    pub fn now(&self) -> Arc<Known> {
        self.now.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Read the toolchain directory again, and say what is known now. What a scan already
    /// took stays as it was.
    pub async fn reload(&self) -> Result<String, String> {
        let dir = self.dir.clone();
        let known = tokio::task::spawn_blocking(move || Known::load(dir.as_deref()))
            .await
            .map_err(|e| format!("nothing was read again: {e}"))?;
        let said = known.said();
        *self.now.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(known);
        Ok(said)
    }
}

/// The copy compiled in and the snapshot, as a daemon with nothing in its toolchain
/// directory knows them: for the tests.
#[cfg(test)]
static COMPILED_FOR_TESTS: std::sync::LazyLock<Arc<Known>> =
    std::sync::LazyLock::new(|| Arc::new(Known::load(None)));

/// What a daemon with nothing in its toolchain directory knows, for the tests.
#[cfg(test)]
pub fn compiled_for_tests() -> Arc<Known> {
    COMPILED_FOR_TESTS.clone()
}

/// The signatures compiled in, for the tests.
#[cfg(test)]
pub fn compiled_signatures_for_tests() -> &'static Signatures {
    &COMPILED_FOR_TESTS.signatures
}

/// What a daemon knows with the dataset `json` in its data folder, for the tests.
#[cfg(test)]
pub fn with_dataset_for_tests(json: &str) -> Arc<Known> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("toolmark")).unwrap();
    std::fs::write(dir.path().join("toolmark").join(cve::DATASET_FILE), json).unwrap();
    Arc::new(Known::load(Some(dir.path())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cve::{DATASET_FILE, SNAPSHOT_LABEL};
    use serde_json::json;

    fn apache() -> Cpe {
        Cpe::new("a", "apache", "http_server")
    }

    fn ids(leads: &[Lead]) -> Vec<&str> {
        leads.iter().map(|l| l.cve.as_str()).collect()
    }

    /// A pack numbered `sequence` of the copy compiled in, with `extra` files added or
    /// put in place of theirs, and the files `without` names left out.
    fn pack(sequence: u64, extra: &[(&str, &str)], without: &[&str]) -> Vec<u8> {
        let mut files = serde_json::Map::new();
        for (name, text) in signatures::COMPILED {
            files.insert(format!("toolmark/{name}"), json!(text));
        }
        for (name, text) in MAPPINGS {
            files.insert(format!("mappings/{name}"), json!(text));
        }
        for (path, text) in extra {
            files.insert(path.to_string(), json!(text));
        }
        for path in without {
            files.remove(*path);
        }
        json!({"format": 1, "name": cfx_pack::NAME, "sequence": sequence,
               "made": "2026-11-21T07:00:00Z", "commit": "abcdef0123456789", "files": files})
        .to_string()
        .into_bytes()
    }

    /// Put `bytes` where `crossfyre update` keeps the pack in the toolchain directory `dir`.
    fn install(dir: &Path, bytes: &[u8]) {
        let path = cfx_pack::path_in(dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    const ACME: (&str, &str) = (
        "toolmark/acme.yaml",
        "id: acme\ninfo:\n  name: Acme\n  category: Test\n  metadata:\n    vendor: acme\n    \
         product: widget\ndetect: { header: { name: server, regex: acme } }\n",
    );

    fn acme() -> Cpe {
        Cpe::new("a", "acme", "widget")
    }

    /// With nothing in the toolchain directory, or no directory, the copy compiled in and
    /// the snapshot answer, and say so.
    #[test]
    fn with_nothing_in_the_toolchain_directory_the_compiled_copy_and_the_snapshot_answer() {
        let dir = tempfile::tempdir().unwrap();
        for known in [Known::load(None), Known::load(Some(dir.path()))] {
            assert_eq!(
                known.signatures_from,
                format!(
                    "crossfyre-templates {} ({}), compiled in",
                    cfx_pack::COMPILED.sequence,
                    &cfx_pack::COMPILED.commit[..7]
                )
            );
            let (leads, from) = known.leads(&[apache()], "2.4.49", None);
            assert_eq!(from, SNAPSHOT_LABEL);
            for cve in ["CVE-2021-41773", "CVE-2021-42013"] {
                assert!(ids(&leads).contains(&cve), "{cve} in {:?}", ids(&leads));
            }
            assert!(leads.iter().all(|l| l.known.kev));
            let (later, _) = known.leads(&[apache()], "2.4.51", None);
            assert!(
                !ids(&later)
                    .iter()
                    .any(|c| *c == "CVE-2021-41773" || *c == "CVE-2021-42013")
            );
        }
    }

    /// A later pack in the toolchain directory, all of which loads, takes the place of the
    /// copy compiled in: its signatures name its products, and it says which pack it is.
    #[test]
    fn a_later_pack_takes_the_place_of_the_compiled_copy() {
        let dir = tempfile::tempdir().unwrap();
        install(
            dir.path(),
            &pack(cfx_pack::COMPILED.sequence + 1, &[ACME], &[]),
        );
        let known = Known::load(Some(dir.path()));
        assert!(known.signatures.cpes().contains(&acme()));
        assert_eq!(
            known.signatures_from,
            format!(
                "crossfyre-templates {} (abcdef0), from {}",
                cfx_pack::COMPILED.sequence + 1,
                cfx_pack::path_in(dir.path()).display()
            )
        );
        assert!(Known::load(None).signatures.cpes().contains(&apache()));
        assert!(!Known::load(None).signatures.cpes().contains(&acme()));
    }

    /// A pack no later than the copy compiled in, one of another name, one that does not
    /// read, and one with a file that does not load, or a mapping missing, are not used:
    /// the copy compiled in answers.
    #[test]
    fn a_pack_is_used_only_when_it_is_later_and_all_of_it_loads() {
        let later = cfx_pack::COMPILED.sequence + 1;
        let broken = ("toolmark/broken.yaml", "id: [");
        let not_later = pack(cfx_pack::COMPILED.sequence, &[ACME], &[]);
        let other_name = String::from_utf8(pack(later, &[ACME], &[]))
            .unwrap()
            .replace(cfx_pack::NAME, "someone-elses")
            .into_bytes();
        for bytes in [
            not_later,
            other_name,
            b"not a pack".to_vec(),
            pack(later, &[ACME, broken], &[]),
            pack(later, &[ACME], &["mappings/versions.yaml"]),
            pack(later, &[ACME], &["mappings/netscaler-stamps.csv"]),
            pack(later, &[ACME, ("mappings/aliases.yaml", "[")], &[]),
        ] {
            let dir = tempfile::tempdir().unwrap();
            install(dir.path(), &bytes);
            let known = Known::load(Some(dir.path()));
            assert!(known.signatures_from.ends_with("compiled in"));
            assert!(!known.signatures.cpes().contains(&acme()));
        }
    }

    /// A reload reads the toolchain directory again, and what was taken before it stays
    /// as it was taken.
    #[tokio::test]
    async fn a_reload_reads_the_directory_again_and_what_was_taken_stays() {
        let dir = tempfile::tempdir().unwrap();
        let knowledge = Knowledge::load(Some(dir.path()));
        let before = knowledge.now();
        install(
            dir.path(),
            &pack(cfx_pack::COMPILED.sequence + 1, &[ACME], &[]),
        );
        std::fs::create_dir_all(dir.path().join("toolmark")).unwrap();
        std::fs::write(
            dir.path().join("toolmark").join(DATASET_FILE),
            r#"{"format": 1, "sequence": 9, "made": "2026-11-21T15:00:00Z",
            "products": [{"part": "a", "vendor": "acme", "product": "widget",
              "affected": [{"cve": "CVE-2099-0060", "ranges": [{"lt": "2.0"}]}]}],
            "cves": {"CVE-2099-0060": {}}}"#,
        )
        .unwrap();
        assert!(!knowledge.now().signatures.cpes().contains(&acme()));
        let said = knowledge.reload().await.unwrap();
        assert!(said.contains("from "), "{said}");
        assert!(
            said.ends_with("CVE leads from CVE dataset 9 of 2026-11-21"),
            "{said}"
        );
        let now = knowledge.now();
        assert!(now.signatures.cpes().contains(&acme()));
        assert_eq!(ids(&now.leads(&[acme()], "1.0", None).0), ["CVE-2099-0060"]);
        assert!(!before.signatures.cpes().contains(&acme()));
        assert_eq!(before.cves_from(), SNAPSHOT_LABEL);
    }

    /// The dataset in the data folder answers in place of the snapshot, and its leads say
    /// which dataset they come from; a file there that does not read leaves the snapshot.
    #[test]
    fn the_dataset_in_the_data_folder_answers_and_is_named() {
        let known = with_dataset_for_tests(
            r#"{"format": 1, "sequence": 9, "made": "2026-11-21T15:00:00Z",
            "products": [{"part": "a", "vendor": "apache", "product": "http_server",
              "affected": [{"cve": "CVE-2099-0049", "ranges": [{"eq": "2.4.49"}]}]}],
            "cves": {"CVE-2099-0049": {"severity": "high", "score": 7.5}}}"#,
        );
        let (leads, from) = known.leads(&[apache()], "2.4.49", Some("Ubuntu"));
        assert_eq!(from, "CVE dataset 9 of 2026-11-21");
        assert_eq!(ids(&leads), ["CVE-2099-0049"]);
        assert!(leads[0].backport);
        let garbage = with_dataset_for_tests("not a dataset");
        assert_eq!(garbage.leads(&[apache()], "2.4.49", None).1, SNAPSHOT_LABEL);
    }

    /// Exchange's build is asked for as the cumulative update NVD names, SharePoint's as its
    /// release, and Erlang/OTP's ssh version as the OTP release that shipped it; a build
    /// the map does not hold gives nothing.
    #[test]
    fn a_version_filed_under_other_numbering_is_asked_for_as_it_is_filed() {
        let cves = with_dataset_for_tests(
            r#"{"format": 1, "sequence": 3, "made": "2026-11-22T15:00:00Z", "products": [
              {"part": "a", "vendor": "microsoft", "product": "exchange_server",
               "affected": [{"cve": "CVE-2099-0040", "ranges": [{"eq": "2019cumulative_update_12"}]}]},
              {"part": "a", "vendor": "microsoft", "product": "sharepoint_server",
               "affected": [{"cve": "CVE-2099-0041", "ranges": [{"eq": "2019"}]}]},
              {"part": "a", "vendor": "erlang", "product": "erlang/otp",
               "affected": [{"cve": "CVE-2099-0042", "ranges": [{"ge": "27.0", "lt": "27.3.3"}]}]}],
             "cves": {"CVE-2099-0040": {}, "CVE-2099-0041": {}, "CVE-2099-0042": {}}}"#,
        );
        let exchange = Cpe::new("a", "microsoft", "exchange_server");
        let sharepoint = Cpe::new("a", "microsoft", "sharepoint_server");
        let otp = Cpe::new("a", "erlang", "erlang/otp");
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
        let cves = compiled_for_tests();
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
        let cves = with_dataset_for_tests(
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
        );
        let netscaler = [
            Cpe::new("a", "citrix", "netscaler_application_delivery_controller"),
            Cpe::new("a", "citrix", "netscaler_gateway"),
        ];
        let zimbra = [Cpe::new("a", "zimbra", "collaboration")];
        let fortinet = [
            Cpe::new("o", "fortinet", "fortios"),
            Cpe::new("a", "fortinet", "fortiproxy"),
        ];
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
        let known = Known::load(None);
        let names = known.signatures.cpes();
        assert!(names.contains(&apache()), "{} products", names.len());
        assert!(!known.leads(&[apache()], "2.4.49", None).0.is_empty());
    }
}
