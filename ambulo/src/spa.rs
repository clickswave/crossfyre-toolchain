//! What a single-page application hides from a static crawl, recovered without
//! running a browser.
//!
//! The crawler already mines a bundle for quoted paths, `fetch`/`axios` call
//! sites and template literals. That gets the API calls written plainly in the
//! code the page loads. It does not get the three things that actually make a
//! SPA under-mapped, and those are what this module is for:
//!
//!   1. **Source maps.** A production bundle is minified, and minification
//!      mangles exactly what a scanner reads: string concatenation gets folded,
//!      route tables become single-letter identifiers, and a path assembled from
//!      constants disappears into the fold. When the build ships a `.map` - and
//!      an enormous number of them do, by accident - `sourcesContent` carries the
//!      ORIGINAL files. Mining those instead is not a cleverer regex, it is
//!      reading the source rather than the compiler's output.
//!
//!   2. **Lazily-loaded chunks.** Code-splitting means most of a SPA is in files
//!      the first page never references. Nothing links to them; the bundle names
//!      them in a chunk map and loads them on navigation. A crawler that only
//!      follows what a page references will never see the admin section at all,
//!      which is routinely where the interesting endpoints are.
//!
//!   3. **Client-side route tables.** The router config lists every view the
//!      application has, including the ones behind a role the crawl does not
//!      hold. These are not URLs the server routes, so they are reported as
//!      views rather than endpoints, but they are the map of the application.
//!
//! # Why not a headless browser
//!
//! Because it does not need one for these, and a browser is a very large thing
//! to put on a customer's node: a Chrome binary to distribute and keep patched,
//! a sandbox to get right, and hundreds of megabytes of memory per crawl worker.
//! Runtime extraction still has a genuine remainder - endpoints that only exist
//! after a click, URLs assembled from values fetched at runtime - and this module
//! does not pretend to cover those. It covers the part that is sitting in files
//! the server is already serving.

use regex::Regex;
use std::sync::LazyLock;

/// `//# sourceMappingURL=main.1a2b3c.js.map`, at the end of a bundle.
static RE_SOURCEMAP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[/*#@\s]*sourceMappingURL\s*=\s*([^\s*]+)\s*\*?/?\s*$"#).unwrap()
});

/// Webpack and Vite both emit a chunk-id to filename map. The shapes differ but
/// both reduce to "an id mapped to a string that becomes part of a .js name".
///
/// Deliberately loose about the surrounding syntax and strict about the value:
/// anything that is not a plausible filename fragment is dropped, because a
/// wrong guess here costs a request against someone's server.
static RE_CHUNK_MAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(\d{1,5})\s*:\s*["']([A-Za-z0-9_.\-]{4,64})["']"#).unwrap());

/// `path: "/admin/users"` or `path: '/orders/:id'` in a router config.
/// Also matches Angular's `path: 'orders/:id'` (no leading slash).
static RE_ROUTE_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bpath\s*:\s*["']([A-Za-z0-9_\-./:*]{0,200})["']"#).unwrap()
});

/// Resolve a `sourceMappingURL` against the bundle it came from.
///
/// Returns `None` for a data: URI, which carries the map inline and needs no
/// fetch, and for anything that is not a same-looking relative or absolute path.
pub fn source_map_url(bundle_url: &str, body: &str) -> Option<String> {
    let m = RE_SOURCEMAP.captures(body)?.get(1)?.as_str().trim();
    if m.is_empty() || m.starts_with("data:") {
        return None;
    }
    let base = reqwest::Url::parse(bundle_url).ok()?;
    base.join(m).ok().map(|u| u.to_string())
}

/// The original source files a `.map` carries, if it carries any.
///
/// A map without `sourcesContent` is common and useless here: it names the
/// original files but does not include them, and fetching each one is a guess
/// about a path layout that may not be served at all.
pub fn sources_from_map(map_body: &str) -> Vec<String> {
    let v: serde_json::Value = match serde_json::from_str(map_body) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    v.get("sourcesContent")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Chunk filenames a bundle names but nothing links to.
///
/// `base` is the directory the bundle was served from, which is where a chunk
/// map's names are relative to.
///
/// Bounded hard. A chunk map can name hundreds of files and each one is a
/// request against someone's server; the point is to reach the parts of the app
/// a crawl cannot see, not to mirror the build output.
pub fn chunk_urls(bundle_url: &str, body: &str, limit: usize) -> Vec<String> {
    let Ok(base) = reqwest::Url::parse(bundle_url) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for c in RE_CHUNK_MAP.captures_iter(body) {
        let name = c.get(2).map(|m| m.as_str()).unwrap_or("");
        // A chunk name is a hash or a readable id. Reject anything that looks
        // like prose, a mime type, or a version string being mapped to a number.
        if name.contains(' ') || name.contains('/') {
            continue;
        }
        let file = if name.ends_with(".js") {
            name.to_string()
        } else {
            format!("{name}.js")
        };
        if let Ok(u) = base.join(&file) {
            let s = u.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

/// Client-side routes a router config declares.
///
/// Returned as written, including `:id` segments: a parameterised route is more
/// useful to the asset graph than a concrete one, because it says the segment is
/// a variable rather than leaving something to infer that from a corpus.
pub fn route_paths(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for c in RE_ROUTE_PATH.captures_iter(body) {
        let p = c.get(1).map(|m| m.as_str()).unwrap_or("").trim();
        // `path: ""` is a router's index route and `path: "*"` its catch-all.
        // Neither is a location on the server.
        if p.is_empty() || p == "*" || p == "**" {
            continue;
        }
        // A file path in a build config is not a route.
        if p.contains("./") || p.ends_with(".js") || p.ends_with(".json") || p.ends_with(".css") {
            continue;
        }
        let norm = if p.starts_with('/') {
            p.to_string()
        } else {
            format!("/{p}")
        };
        if !out.contains(&norm) {
            out.push(norm);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_map_comment_resolves_against_its_bundle() {
        let body = "console.log(1)\n//# sourceMappingURL=main.1a2b3c.js.map\n";
        assert_eq!(
            source_map_url("https://app.test/static/js/main.1a2b3c.js", body),
            Some("https://app.test/static/js/main.1a2b3c.js.map".to_string())
        );
    }

    #[test]
    fn an_inline_map_needs_no_fetch() {
        let body = "//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==";
        assert_eq!(source_map_url("https://app.test/a.js", body), None);
    }

    #[test]
    fn a_bundle_without_a_map_asks_for_nothing() {
        assert_eq!(source_map_url("https://app.test/a.js", "var x=1"), None);
    }

    #[test]
    fn original_sources_come_out_of_the_map() {
        let map = r#"{"version":3,"sources":["src/api.js","src/empty.js"],
                      "sourcesContent":["export const BASE='/api/v2';\nfetch(BASE+'/users')",""]}"#;
        let s = sources_from_map(map);
        assert_eq!(s.len(), 1, "empty entries carry nothing");
        assert!(s[0].contains("/api/v2"));
    }

    #[test]
    fn a_map_that_names_sources_without_shipping_them_gives_nothing() {
        // Common, and the reason this returns a list rather than a promise:
        // fetching each named file would be guessing at a layout that is
        // probably not served.
        let map = r#"{"version":3,"sources":["src/api.js"]}"#;
        assert!(sources_from_map(map).is_empty());
    }

    #[test]
    fn lazily_loaded_chunks_are_recovered_from_the_chunk_map() {
        let body = r#"({1:"admin.4f2a",2:"reports.9c1b",17:"settings.aa01"}[e]+".js")"#;
        let urls = chunk_urls("https://app.test/static/js/main.js", body, 20);
        assert!(urls.contains(&"https://app.test/static/js/admin.4f2a.js".to_string()));
        assert!(urls.contains(&"https://app.test/static/js/reports.9c1b.js".to_string()));
        assert_eq!(urls.len(), 3);
    }

    #[test]
    fn the_chunk_limit_is_a_limit() {
        let body: String = (1..50).map(|i| format!("{i}:\"chunk{i:04}\",")).collect();
        assert_eq!(chunk_urls("https://app.test/a/main.js", &body, 8).len(), 8);
    }

    #[test]
    fn prose_and_paths_are_not_chunk_names() {
        let body = r#"{1:"hello world",2:"a/b/c",3:"real.9f"}"#;
        let urls = chunk_urls("https://app.test/main.js", body, 20);
        assert_eq!(urls, vec!["https://app.test/real.9f.js".to_string()]);
    }

    #[test]
    fn a_router_config_gives_up_the_whole_application() {
        let body = r#"const routes=[{path:"/",c:H},{path:"/admin/users",c:A},
                      {path:"orders/:id",c:O},{path:"*",c:NF}]"#;
        let r = route_paths(body);
        assert!(r.contains(&"/admin/users".to_string()));
        // Angular-style relative routes are normalised.
        assert!(r.contains(&"/orders/:id".to_string()));
        // The catch-all is not a location.
        assert!(!r.contains(&"/*".to_string()));
    }

    #[test]
    fn a_build_config_path_is_not_a_route() {
        let body = r#"{path:"./src/index.js"},{path:"/real/route"}"#;
        let r = route_paths(body);
        assert_eq!(r, vec!["/real/route".to_string()]);
    }
}
