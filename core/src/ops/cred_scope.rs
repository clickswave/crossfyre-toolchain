//! A saved credential goes only to the hosts it was saved for.
//!
//! The platform checks a credential's hosts against the op's target. An op can also
//! name other hosts for its engine to reach: endpoints, a GraphQL URL, a crawl allowed
//! onto other hosts. The engines put the credential on every request they send, so
//! before the request goes to the engine, whatever the credential's hosts do not cover
//! is taken out of it, and the operator is told what was.
//!
//! Hosts are compared the way the platform compares them: a host is covered by an
//! entry naming it or a parent domain of it, with a scheme, port, path or `*.` on the
//! entry ignored. A credential that records no hosts is not restricted.

use reqwest::Url;
use serde_json::Value;
use std::net::Ipv6Addr;

/// How many skipped URLs a note names before it only counts the rest.
const NAMED: usize = 5;

/// `entry` reduced to the bare host the platform compares.
fn bare(entry: &str) -> String {
    let v = entry.trim().to_ascii_lowercase();
    let v = v
        .strip_prefix("https://")
        .or_else(|| v.strip_prefix("http://"))
        .unwrap_or(&v);
    let v = v.strip_prefix("*.").unwrap_or(v);
    let v = v.split('/').next().unwrap_or(v);
    // An IPv6 address, bare or in brackets with or without a port, is read whole and
    // written as the URL parser writes its host, so `2001:db8::80` is not taken for
    // `2001:db8:` on port 80.
    if let Ok(ip) = v.parse::<Ipv6Addr>() {
        return format!("[{ip}]");
    }
    if let Some((addr, after)) = v.strip_prefix('[').and_then(|r| r.split_once(']'))
        && let Ok(ip) = addr.parse::<Ipv6Addr>()
        && (after.is_empty() || is_port(after.strip_prefix(':').unwrap_or("")))
    {
        return format!("[{ip}]");
    }
    match v.split_once(':') {
        Some((head, port)) if is_port(port) => head.to_string(),
        _ => v.to_string(),
    }
}

fn is_port(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// True when a credential saved for `hosts` may be sent to `host`.
pub fn covers(hosts: &[String], host: &str) -> bool {
    if hosts.is_empty() {
        return true;
    }
    let h = bare(host);
    !h.is_empty()
        && hosts.iter().map(|s| bare(s)).any(|b| {
            !b.is_empty()
                && (h == b || h.strip_suffix(b.as_str()).is_some_and(|r| r.ends_with('.')))
        })
}

/// The target as the engines read it, `http://` added when no http(s) scheme is written.
fn target_url(target: &str) -> Option<Url> {
    let t = target.trim();
    if t.starts_with("http://") || t.starts_with("https://") {
        Url::parse(t).ok()
    } else {
        Url::parse(&format!("http://{t}")).ok()
    }
}

/// The host a request to `url` connects to, read with the URL parser the engines' HTTP
/// client uses. A reference that is not a URL of its own is taken relative to the
/// target. `None` when it names no host at all.
fn dialled(url: &str, base: Option<&Url>) -> Option<String> {
    let u = match Url::parse(url) {
        Ok(u) => u,
        Err(_) => base?.join(url).ok()?,
    };
    u.host_str().map(str::to_string)
}

fn listed(urls: &[String]) -> String {
    let mut s = urls
        .iter()
        .take(NAMED)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if urls.len() > NAMED {
        s.push_str(&format!(" and {} more", urls.len() - NAMED));
    }
    s
}

/// Take every endpoint out of `req["endpoints"]` that one of the credentials saved for
/// `scopes` may not be sent to. Returns a note for the operator when any was.
///
/// The engine would send such an endpoint the same credential it sends the target, so
/// it is not tested in this pass at all. An endpoint whose URL is not text is left for
/// the engine to refuse, as before.
pub fn keep_endpoints(req: &mut Value, target: &str, scopes: &[&[String]]) -> Option<String> {
    if scopes.iter().all(|s| s.is_empty()) {
        return None;
    }
    let base = target_url(target);
    let list = req.get_mut("endpoints")?.as_array_mut()?;
    let mut skipped = Vec::new();
    list.retain(|ep| {
        let Some(url) = ep.get("url").and_then(Value::as_str) else {
            return true;
        };
        let ok = dialled(url, base.as_ref()).is_some_and(|h| scopes.iter().all(|s| covers(s, &h)));
        if !ok {
            skipped.push(url.to_string());
        }
        ok
    });
    if skipped.is_empty() {
        return None;
    }
    Some(format!(
        "{} endpoint(s) were not tested because the saved credential for this pass is not \
         for their host, and the engine sends it with every request: {}. Test them in a \
         pass without the credential, or add their host to the credential.",
        skipped.len(),
        listed(&skipped)
    ))
}

/// The URL the GraphQL pass posts to: an absolute endpoint as written, anything else
/// joined onto the target. The same reading as the engine's.
fn graphql_url(target: &str, endpoint: &str) -> String {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        return endpoint.to_string();
    }
    let base = target.trim_end_matches('/');
    if endpoint.is_empty() {
        format!("{base}/graphql")
    } else {
        format!("{base}/{}", endpoint.trim_start_matches('/'))
    }
}

/// Whether the GraphQL pass of `req` may carry a credential saved for `hosts`. When it
/// may not, its auth is removed and a note for the operator comes back: the endpoint
/// is on the workspace's scope, so it is still tested, without the credential.
pub fn graphql(req: &mut Value, hosts: &[String]) -> Option<String> {
    if hosts.is_empty() {
        return None;
    }
    let target = req["target"].as_str().unwrap_or("");
    let endpoint = req["endpoint"].as_str().unwrap_or("").to_string();
    let url = graphql_url(target, &endpoint);
    let ok = Url::parse(&url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .is_some_and(|h| covers(hosts, &h));
    if ok {
        return None;
    }
    let obj = req.as_object_mut()?;
    obj.remove("auth");
    obj.remove("auth_pool");
    Some(format!(
        "The GraphQL endpoint {endpoint} is not on a host the saved credential is for, so it \
         was tested without the credential."
    ))
}

/// Hold an authenticated crawl to the hosts the credential is for. Links off them are
/// not followed, and each extra crawl host is narrowed to the part of it the credential
/// covers. Returns a note for the operator when anything changed.
///
/// The seed and its subdomains need nothing here: the platform checked the seed's host
/// against the credential, and a subdomain of a covered host is covered.
pub fn crawl(req: &mut Value, hosts: &[String]) -> Option<String> {
    if hosts.is_empty() {
        return None;
    }
    let mut own: Vec<String> = Vec::new();
    for b in hosts.iter().map(|h| bare(h)) {
        if !b.is_empty() && !own.contains(&b) {
            own.push(b);
        }
    }
    let obj = req.as_object_mut()?;
    let external = obj.get("follow_external").and_then(Value::as_bool) == Some(true);
    let mut changed = external;
    let mut kept: Vec<Value> = Vec::new();
    if let Some(list) = obj.get("scope_hosts").and_then(Value::as_array) {
        for entry in list {
            let Some(s) = entry.as_str() else {
                push(&mut kept, entry.clone());
                continue;
            };
            if covers(hosts, s) {
                push(&mut kept, entry.clone());
                continue;
            }
            // The crawler admits `s` and every name ending in `.s`. Of those, the
            // credential's own hosts that fall inside `s` are kept.
            changed = true;
            let s = s.trim().to_ascii_lowercase();
            for b in &own {
                if *b == s || b.strip_suffix(s.as_str()).is_some_and(|r| r.ends_with('.')) {
                    push(&mut kept, Value::String(b.clone()));
                }
            }
        }
    }
    if external {
        obj.insert("follow_external".into(), Value::Bool(false));
        for b in &own {
            push(&mut kept, Value::String(b.clone()));
        }
    }
    if !changed {
        return None;
    }
    obj.insert("scope_hosts".into(), Value::Array(kept));
    Some(format!(
        "The crawl carries a saved credential, so it was kept to the hosts the credential is \
         for ({}) and links to anywhere else were not followed.",
        own.join(", ")
    ))
}

fn push(kept: &mut Vec<Value>, v: Value) {
    if !kept.contains(&v) {
        kept.push(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// The same reading as the platform's check of the target.
    #[test]
    fn hosts_are_read_as_the_platform_reads_them() {
        let h = s(&["http://app.example.test:5179", "*.api.example.test"]);
        assert!(covers(&h, "app.example.test"));
        assert!(covers(&h, "APP.example.test"));
        assert!(covers(&h, "x.app.example.test"));
        assert!(covers(&h, "api.example.test"));
        assert!(covers(&h, "v1.api.example.test"));
        assert!(!covers(&h, "example.test"));
        assert!(!covers(&h, "evilapp.example.test"));
        assert!(!covers(&h, "app.example.test.evil.test"));
        assert!(covers(&s(&["[::1]:8080"]), "[::1]"));
        assert!(!covers(&s(&[""]), "app.example.test."));
        assert!(covers(&[], "anything.test"));
    }

    /// An IPv6 address is one host however it is written, and two addresses are two hosts
    /// even where one ends in what looks like a port.
    #[test]
    fn an_ipv6_address_is_read_whole() {
        let h = s(&["2001:db8::80"]);
        assert!(!covers(&h, "2001:db8::90"));
        assert!(!covers(&h, "[2001:db8::90]"));
        assert!(!covers(&h, "2001:db8::"));
        assert!(covers(&h, "2001:db8::80"));
        assert!(covers(&h, "[2001:db8::80]"));
        assert!(covers(&h, "[2001:DB8:0::80]"));
        assert!(covers(
            &s(&["http://[2001:db8::80]:8080/x"]),
            "[2001:db8::80]"
        ));
        assert!(covers(&s(&["[2001:db8::80]"]), "2001:db8::80"));
        assert!(!covers(&s(&["[2001:db8::80]:8080"]), "[2001:db8::8080]"));

        let mut req = json!({"seed": "http://[2001:db8::80]/", "scope_hosts": ["2001:db8::90"]});
        crawl(&mut req, &h);
        assert_eq!(req["scope_hosts"], json!([]));
        let mut req = json!({"seed": "http://[2001:db8::80]/", "follow_external": true});
        crawl(&mut req, &h);
        assert_eq!(req["scope_hosts"], json!(["[2001:db8::80]"]));
    }

    /// An endpoint is read with the URL parser the engines send with, so a name before
    /// an `@` is not taken for the host.
    #[test]
    fn endpoints_are_read_for_the_host_they_dial() {
        let mut req = json!({"endpoints": [
            {"url": "http://app.example.test/a"},
            {"url": "http://app.example.test:@evil.test/b"},
            {"url": "http://app.example.test\\@evil.test/c"},
            {"url": "/relative?x=1"},
            {"url": "//evil.test/d"},
            {"url": 7},
        ]});
        let hosts = s(&["app.example.test"]);
        let note = keep_endpoints(&mut req, "http://app.example.test/", &[&hosts]);
        assert_eq!(
            req["endpoints"],
            json!([
                {"url": "http://app.example.test/a"},
                {"url": "http://app.example.test\\@evil.test/c"},
                {"url": "/relative?x=1"},
                {"url": 7},
            ])
        );
        let note = note.unwrap();
        assert!(note.starts_with("2 endpoint(s)"), "{note}");
        assert!(note.contains("//evil.test/d"), "{note}");
    }

    /// Every credential in an authorization pass has to cover an endpoint, since each
    /// identity's headers go to it. An identity without a credential restricts nothing.
    #[test]
    fn every_identity_must_cover_an_endpoint() {
        let mut req = json!({"endpoints": [
            {"url": "https://a.example.test/x"},
            {"url": "https://b.example.test/x"},
        ]});
        let one = s(&["a.example.test", "b.example.test"]);
        let two = s(&["a.example.test"]);
        let none: Vec<String> = Vec::new();
        keep_endpoints(&mut req, "https://a.example.test", &[&one, &two, &none]);
        assert_eq!(
            req["endpoints"],
            json!([{"url": "https://a.example.test/x"}])
        );
    }

    #[test]
    fn a_crawl_without_external_hosts_is_left_alone() {
        let mut req = json!({"seed": "http://a.example.test/", "include_subdomains": true,
                             "scope_hosts": ["x.a.example.test"]});
        let before = req.clone();
        assert!(crawl(&mut req, &s(&["a.example.test"])).is_none());
        assert_eq!(req, before);
    }

    #[test]
    fn a_crawl_told_to_follow_anywhere_follows_only_the_credentials_hosts() {
        let mut req = json!({"seed": "http://a.example.test/", "follow_external": true});
        assert!(
            crawl(
                &mut req,
                &s(&["a.example.test", "https://b.example.test:8443"])
            )
            .is_some()
        );
        assert_eq!(req["follow_external"], false);
        assert_eq!(
            req["scope_hosts"],
            json!(["a.example.test", "b.example.test"])
        );
    }
}
