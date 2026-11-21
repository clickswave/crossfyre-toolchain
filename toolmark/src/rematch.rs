//! The `rematch` operation: the signatures toolmark has now, run over the pages it kept
//! from earlier scans, and the CVE data it has now, run over the products it holds,
//! reporting only what is new. It sends nothing to any host.

use crate::libs::toolmark_db::{KeptHost, ToolmarkDb};
use crate::observe::Asked;
use crate::signatures::{Answered, Detection, Host, RENDERED, Signatures};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tokio::sync::mpsc;

/// Run the signatures `known` holds over every host's kept pages and send, as a
/// fingerprint would, a finding for each product that is new there, or whose version is
/// new. Then send each CVE lead `known` gives a product toolmark holds, or has just found,
/// that was not reported for it before.
pub async fn run(
    db: &ToolmarkDb,
    known: &crate::knowledge::Known,
    tx: mpsc::UnboundedSender<Value>,
) {
    let signatures = &known.signatures;
    let _ = tx.send(json!({"type": "ack", "target": "the pages toolmark kept"}));
    let hosts = match db.kept().await {
        Ok(hosts) => hosts,
        Err(e) => {
            let _ = tx.send(json!({"type": "error",
                "message": format!("could not read the pages toolmark kept: {e}")}));
            return;
        }
    };
    let stored = match db.stored().await {
        Ok(stored) => stored,
        Err(e) => {
            let _ = tx.send(json!({"type": "error",
                "message": format!("could not read the products toolmark holds: {e}")}));
            return;
        }
    };
    // Each product held at a version, by host, port and name: what the inventory has, with
    // what this re-match finds in its place.
    let mut held: BTreeMap<(String, u16, String), Held> = stored
        .into_iter()
        .filter_map(|s| {
            let url = match s.scheme.as_str() {
                "http" | "https" => format!("{}://{}:{}/", s.scheme, s.host, s.port),
                _ => format!("{}:{}", s.host, s.port),
            };
            let key = (s.host.clone(), s.port, s.product.clone());
            (!s.cpes.is_empty()).then_some((
                key,
                Held {
                    cpes: s.cpes,
                    url,
                    host: s.host,
                    port: s.port,
                    scheme: s.scheme,
                    product: s.product,
                    version: s.version,
                    distro: s.distro,
                    reported: s.reported,
                },
            ))
        })
        .collect();
    for kept in &hosts {
        for (url, d) in new_on(kept, signatures) {
            let _ = tx.send(crate::fingerprint::technology(
                &d,
                &url,
                &kept.host,
                kept.port,
                &kept.scheme,
            ));
            let Some(version) = d.version.clone().filter(|_| !d.cpe_names.is_empty()) else {
                continue;
            };
            let key = (kept.host.clone(), kept.port, d.name.clone());
            let reported = held.remove(&key).map(|h| h.reported).unwrap_or_default();
            held.insert(
                key,
                Held {
                    cpes: d.cpe_names.clone(),
                    url,
                    host: kept.host.clone(),
                    port: kept.port,
                    scheme: kept.scheme.clone(),
                    product: d.name.clone(),
                    version,
                    distro: d.distro.clone(),
                    reported,
                },
            );
        }
    }
    for h in held.values() {
        let subject = crate::fingerprint::Subject {
            product: &h.product,
            version: &h.version,
            cpes: &h.cpes,
            distro: h.distro.as_deref(),
            url: &h.url,
            host: &h.host,
            port: h.port,
            scheme: &h.scheme,
        };
        for (cve, lead) in crate::fingerprint::leads_for(known, &subject) {
            if !h.reported.contains(&cve) {
                let _ = tx.send(lead);
            }
        }
    }
    let _ = tx.send(json!({"type": "done"}));
}

/// A product toolmark holds at a version, where, and the CVE leads reported for it.
struct Held {
    cpes: Vec<cfx_cve::Cpe>,
    url: String,
    host: String,
    port: u16,
    scheme: String,
    product: String,
    version: String,
    distro: Option<String>,
    reported: std::collections::HashSet<String>,
}

/// What `signatures` find on `kept`'s pages that toolmark had not found there: a product
/// it had not, or a version other than the one it had. With the landing page's URL.
fn new_on(kept: &KeptHost, signatures: &Signatures) -> Vec<(String, Detection)> {
    let Some(landing) = kept.pages.iter().find(|p| p.asked == Asked::Landing) else {
        return Vec::new();
    };
    let cookies: Vec<String> = landing
        .headers
        .iter()
        .filter(|(name, _)| name == "set-cookie")
        .map(|(_, value)| value.clone())
        .collect();
    let body = String::from_utf8_lossy(&landing.body).into_owned();
    let mut host = Host::new(
        signatures,
        &landing.url,
        &landing.headers,
        &cookies,
        &body,
        RENDERED,
    );
    let pages = |asked: Asked| -> Vec<(String, Answered)> {
        kept.pages
            .iter()
            .filter(|p| p.asked == asked)
            .filter_map(|p| {
                let url = transport::Url::parse(&p.url).ok()?;
                let path = match url.query() {
                    Some(query) => format!("{}?{query}", url.path()),
                    None => url.path().to_string(),
                };
                Some((path, Answered::new(p.status, p.moved, &p.body)))
            })
            .collect()
    };
    // The certificate the landing page came with; one kept from a TLS page without it is
    // not known.
    match &landing.certificate {
        Some(der) => host.certificate(der),
        None if !landing.url.starts_with("https:") => host.no_tls(),
        None => {}
    }
    // The landing page as a browser built it, when the scan rendered it and kept what it
    // saw; without it the `rendered` leaves are unknown.
    if let Some(built) = kept
        .pages
        .iter()
        .find(|p| p.asked == Asked::Rendered && !p.body.is_empty())
    {
        host.rendered(String::from_utf8_lossy(&built.body).into_owned());
    }
    host.remember(pages(Asked::NotFound), pages(Asked::Path));
    host.detections()
        .into_iter()
        .filter(|d| match kept.found.get(&d.name) {
            None => true,
            Some(had) => d.version.as_deref().is_some_and(|now| now != had),
        })
        .map(|d| (landing.url.clone(), d))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::libs::toolmark_db::ENGINE;
    use crate::observe::{Observation, Observer};
    use cfx_db::scans::Status;

    /// A page to keep: what it was asked for, its path, status, headers and body.
    type KeptPage<'a> = (Asked, &'a str, u16, &'a [(&'a str, &'a str)], &'a str);

    /// Keep, as one scan of `url`'s host, `pages` it saw: what each was asked for, its
    /// path, status, headers and body, and the certificate the landing page came with.
    async fn keep(db: &ToolmarkDb, url: &str, pages: &[KeptPage<'_>], certificate: Option<&[u8]>) {
        let params = json!({"target": url});
        let scan = db.start("fingerprint", url, &params).await;
        let observer = db.observer(scan.as_ref(), &params);
        let base = transport::Url::parse(url).unwrap();
        for (asked, path, status, headers, body) in pages {
            let headers: Vec<(String, String)> = headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect();
            observer
                .observed(Observation {
                    asked: *asked,
                    url: base.join(path).unwrap().as_str(),
                    host: base.host_str().unwrap(),
                    port: base.port_or_known_default().unwrap(),
                    scheme: base.scheme(),
                    status: *status,
                    headers: &headers,
                    body: body.as_bytes(),
                    moved: false,
                    certificate: certificate.filter(|_| *asked == Asked::Landing),
                })
                .await;
        }
        db.finish(scan, Status::Completed).await;
    }

    /// What a re-match reports, by name and version, keeping it as the daemon does.
    async fn rematch(db: &ToolmarkDb) -> Vec<(String, Option<String>)> {
        let params = json!({});
        let scan = db.start("rematch", "kept", &params).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        run(db, &crate::knowledge::compiled_for_tests(), tx).await;
        let mut found = Vec::new();
        while let Ok(event) = rx.try_recv() {
            db.event(scan.as_ref().map(|s| s.id.as_str()), &event).await;
            if event.pointer("/data/type") == Some(&json!("technology")) {
                found.push((
                    event["data"]["name"].as_str().unwrap().to_string(),
                    event["data"]["version"].as_str().map(str::to_string),
                ));
            }
        }
        db.finish(scan, Status::Completed).await;
        found
    }

    /// The leads a re-match with `cves` sends, kept as the daemon keeps them.
    async fn rematch_leads(db: &ToolmarkDb, cves: &crate::knowledge::Known) -> Vec<Value> {
        let scan = db.start("rematch", "kept", &json!({})).await;
        let (tx, mut rx) = mpsc::unbounded_channel();
        run(db, cves, tx).await;
        let mut leads = Vec::new();
        while let Ok(event) = rx.try_recv() {
            db.event(scan.as_ref().map(|s| s.id.as_str()), &event).await;
            if event.pointer("/data/type") == Some(&json!("vulnerability")) {
                leads.push(event["data"].clone());
            }
        }
        db.finish(scan, Status::Completed).await;
        leads
    }

    /// A dataset numbered `sequence` in the data folder of the toolchain directory `dir`,
    /// with `cves` on Apache 2.4.49.
    fn apache_dataset(dir: &std::path::Path, sequence: u64, cves: &[&str]) {
        let affected: Vec<Value> = cves
            .iter()
            .map(|c| json!({"cve": c, "ranges": [{"eq": "2.4.49"}]}))
            .collect();
        let known: serde_json::Map<String, Value> = cves
            .iter()
            .map(|c| (c.to_string(), json!({"severity": "high", "score": 7.5})))
            .collect();
        let dataset = json!({
            "format": 1, "sequence": sequence, "made": "2026-11-22T15:00:00Z",
            "products": [{"part": "a", "vendor": "apache", "product": "http_server",
                          "affected": affected}],
            "cves": known,
        });
        let path = cfx_cve::path_in(dir);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, dataset.to_string()).unwrap();
    }

    /// A dataset a day newer, holding one more CVE for a product toolmark holds, gives
    /// exactly that one lead, says which dataset it came from and that the distribution
    /// that built it may have backported the fix, and gives nothing the next time.
    /// Nothing reaches the host.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_newer_dataset_gives_only_the_new_lead_and_sends_nothing() {
        let scratch = cfx_db::testing::Scratch::new(&ENGINE).await;
        let db = ToolmarkDb::new(scratch.pool.clone());
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let at = |data: Value| {
            let mut data = data;
            data["host"] = json!("127.0.0.1");
            data["port"] = json!(port);
            data["scheme"] = json!("http");
            json!({"type": "finding", "data": data})
        };
        // A scan found Apache 2.4.49 that Ubuntu built, and reported one CVE for it.
        let scan = db
            .start("fingerprint", "http://127.0.0.1/", &json!({}))
            .await;
        let id = scan.as_ref().map(|s| s.id.as_str());
        db.event(
            id,
            &at(json!({"type": "technology", "name": "Apache HTTP Server",
            "version": "2.4.49", "distro": "Ubuntu", "confidence": 50, "evidence": [],
            "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            "cpe_names": ["a:apache:http_server"]})),
        )
        .await;
        db.event(
            id,
            &at(json!({"type": "vulnerability", "source": "toolmark-cve",
            "product": "Apache HTTP Server", "cve": "CVE-2099-0001"})),
        )
        .await;
        db.finish(scan, Status::Completed).await;

        let folder = tempfile::tempdir().unwrap();
        apache_dataset(folder.path(), 2, &["CVE-2099-0001", "CVE-2099-0002"]);
        let cves = crate::knowledge::Known::load(Some(folder.path()));
        let leads = rematch_leads(&db, &cves).await;
        assert_eq!(leads.len(), 1, "{leads:?}");
        assert_eq!(leads[0]["cve"], "CVE-2099-0002");
        assert_eq!(leads[0]["cve_data"], "CVE dataset 2 of 2026-11-22");
        assert_eq!(leads[0]["backport"], true);
        assert_eq!(leads[0]["target"], format!("http://127.0.0.1:{port}/"));
        assert!(
            rematch_leads(&db, &cves).await.is_empty(),
            "a lead is reported once"
        );
        assert!(listener.accept().is_err(), "a connection reached the host");
        scratch.done().await;
    }

    /// A product today's signatures find on a kept page is reported once: the next
    /// re-match has nothing new. Nothing reaches the host while it runs.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn what_is_found_on_kept_pages_is_reported_once_and_nothing_is_sent() {
        let scratch = cfx_db::testing::Scratch::new(&ENGINE).await;
        let db = ToolmarkDb::new(scratch.pool.clone());
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "http://127.0.0.1:{}/",
            listener.local_addr().unwrap().port()
        );
        keep(
            &db,
            &url,
            &[(Asked::Landing, "/", 403, &[("x-jenkins", "2.426.1")], "")],
            None,
        )
        .await;
        assert_eq!(
            rematch(&db).await,
            [
                ("Jenkins".to_string(), Some("2.426.1".to_string())),
                ("Java".to_string(), None)
            ]
        );
        assert_eq!(rematch(&db).await, []);
        assert!(listener.accept().is_err(), "a connection reached the host");
        scratch.done().await;
    }

    /// The certificate a landing page came with is kept with it, so a signature that reads
    /// the certificate finds on the kept page what the scan could have found.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_kept_certificate_is_read_again() {
        let scratch = cfx_db::testing::Scratch::new(&ENGINE).await;
        let db = ToolmarkDb::new(scratch.pool.clone());
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "TRAEFIK DEFAULT CERT");
        let key = rcgen::KeyPair::generate().unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();
        keep(
            &db,
            "https://127.0.0.1:8443/",
            &[(Asked::Landing, "/", 404, &[], "404 page not found")],
            Some(&der),
        )
        .await;
        assert_eq!(rematch(&db).await, [("Traefik".to_string(), None)]);
        scratch.done().await;
    }

    /// The landing page a browser built is kept with what the scan saw, so a signature
    /// that reads the rendered page finds there what the rendered tier could have.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_kept_rendered_page_is_read_again() {
        let scratch = cfx_db::testing::Scratch::new(&ENGINE).await;
        let db = ToolmarkDb::new(scratch.pool.clone());
        let shell = "<html><body><app-root></app-root></body></html>";
        let built =
            "<html><body><app-root ng-version=\"17.3.0\"><h1>Console</h1></app-root></body></html>";
        keep(
            &db,
            "http://127.0.0.1:8081/",
            &[
                (Asked::Landing, "/", 200, &[], shell),
                (Asked::Rendered, "/", 200, &[], built),
            ],
            None,
        )
        .await;
        assert_eq!(
            rematch(&db).await,
            [("Angular".to_string(), Some("17.3.0".to_string()))]
        );
        scratch.done().await;
    }

    /// A version other than the one toolmark had is new; the same version is not.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn a_version_that_changed_on_kept_pages_is_new() {
        let scratch = cfx_db::testing::Scratch::new(&ENGINE).await;
        let db = ToolmarkDb::new(scratch.pool.clone());
        let url = "https://app.test/";
        keep(
            &db,
            url,
            &[(
                Asked::Landing,
                "/",
                200,
                &[("server", "nginx/1.24.0"), ("x-powered-by", "PHP/8.2.12")],
                "",
            )],
            None,
        )
        .await;
        assert_eq!(
            rematch(&db).await,
            [
                ("Nginx".to_string(), Some("1.24.0".to_string())),
                ("PHP".to_string(), Some("8.2.12".to_string()))
            ]
        );
        keep(
            &db,
            url,
            &[(
                Asked::Landing,
                "/",
                200,
                &[("server", "nginx/1.25.3"), ("x-powered-by", "PHP/8.2.12")],
                "",
            )],
            None,
        )
        .await;
        assert_eq!(
            rematch(&db).await,
            [("Nginx".to_string(), Some("1.25.3".to_string()))]
        );
        scratch.done().await;
    }

    /// The kept answers for the random paths and for the paths signatures asked are read
    /// as they were answered: here a Tomcat 404 page and Vault's health endpoint.
    #[tokio::test]
    #[ignore = "needs PostgreSQL's programs"]
    async fn kept_not_found_pages_and_paths_answer_as_they_did() {
        let scratch = cfx_db::testing::Scratch::new(&ENGINE).await;
        let db = ToolmarkDb::new(scratch.pool.clone());
        let tomcat_404 = "<html><body><h3>Apache Tomcat/9.0.83</h3></body></html>";
        keep(
            &db,
            "https://ops.test/",
            &[
                (Asked::Landing, "/", 200, &[], "<title>Ops</title>"),
                (Asked::NotFound, "/0123456789abcdef", 404, &[], tomcat_404),
                (Asked::NotFound, "/fedcba9876543210", 404, &[], tomcat_404),
                (
                    Asked::Path,
                    "/v1/sys/health",
                    200,
                    &[],
                    r#"{"initialized":true,"sealed":false,"version":"1.15.2"}"#,
                ),
            ],
            None,
        )
        .await;
        let found = rematch(&db).await;
        for want in [
            ("Apache Tomcat".to_string(), Some("9.0.83".to_string())),
            ("HashiCorp Vault".to_string(), Some("1.15.2".to_string())),
        ] {
            assert!(found.contains(&want), "{want:?} not in {found:?}");
        }
        scratch.done().await;
    }
}
