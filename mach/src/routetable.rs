//! Applications that publish their own route table on an error page.
//!
//! A crawler finds what is linked. That is a real limit, and it is not evenly
//! distributed: the routes worth attacking are frequently the ones nothing links
//! to. RailsGoat's `POST /password_resets` runs
//! `Marshal.load(Base64.decode64(params[:user]))` on an unauthenticated
//! request, and no page anywhere in the application links to it - the form is
//! rendered only after a valid reset token - so a crawl has never seen it and
//! never will.
//!
//! It does not have to. Ask that application for a path that does not exist and
//! its development-mode error page answers with the complete routing table:
//! every path, every verb, every controller action. Django's DEBUG 404 does the
//! same with its URLconf. Neither is obscure and neither needs a wordlist; the
//! application volunteers its entire attack surface to anyone who mistypes a
//! URL.
//!
//! So: one request for a path nothing could have registered, and if the answer
//! is one of these pages, the routes go into the frontier and the exposure is
//! reported in its own right. A production deployment serving a debug error
//! page is a finding whether or not anything is done with the routes.
//!
//! # Only two frameworks, on purpose
//!
//! Rails and Django publish route tables. Laravel's Ignition page, Werkzeug's
//! debugger and Express's stack traces do not - they show a trace, which is
//! worth reporting elsewhere but contains no routes to harvest. Guessing at a
//! third parser would produce endpoints that were never in the application, and
//! a crawl that invents URLs is worse than one that misses them: everything
//! downstream then spends its budget on 404s.

use std::collections::BTreeSet;

/// What an error page gave up.
pub struct Harvest {
    /// Which framework's page this was, for the finding text.
    pub framework: &'static str,
    /// `(method, path)`, deduplicated. `method` is empty when the page does not
    /// say, which means "any".
    pub routes: Vec<(String, String)>,
}

/// A path no application registers, used to provoke the error page.
///
/// Deliberately inert and obviously synthetic: it is not a guess at a hidden
/// file, it does not look like an attack in a log, and if the site answers it
/// with a 200 then this whole technique is inapplicable there anyway.
pub const PROBE_PATH: &str = "/crossfyre-route-probe-404";

/// Parse a response body for a published route table.
pub fn parse(body: &str) -> Option<Harvest> {
    rails(body).or_else(|| django(body))
}

/// Rails' development routing-error page.
///
/// Each route is a `<tr class='route_row'>` whose third cell carries
/// `data-route-path='/password_resets(.:format)'` and whose second cell is the
/// verb. Anchoring on `data-route-path` rather than on the visible text means a
/// change to the page's wording does not silently empty the result.
fn rails(body: &str) -> Option<Harvest> {
    if !body.contains("route_row") || !body.contains("data-route-path") {
        return None;
    }
    let mut out: BTreeSet<(String, String)> = BTreeSet::new();
    for row in body.split("class='route_row'").skip(1) {
        let Some(path) = attr(row, "data-route-path") else {
            continue;
        };
        let path = clean_rails_path(&path);
        if path.is_empty() {
            continue;
        }
        out.insert((rails_verb(row), path));
    }
    (!out.is_empty()).then(|| Harvest {
        framework: "Rails (development routing-error page)",
        routes: out.into_iter().collect(),
    })
}

/// The verb sits in a bare `<td>` between the route name and the path. An empty
/// one means the route answers any verb, which is recorded as such rather than
/// guessed at.
fn rails_verb(row: &str) -> String {
    let Some(before) = row.split("data-route-path").next() else {
        return String::new();
    };
    for cell in before.split("<td").skip(1) {
        let Some(inner) = cell.split_once('>').map(|(_, r)| r) else {
            continue;
        };
        let text = inner.split('<').next().unwrap_or("").trim();
        let up = text.to_ascii_uppercase();
        if ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
            .iter()
            .any(|m| up == *m || up.starts_with(&format!("{m}|")))
        {
            // A cell reading "GET|POST" is one route reachable two ways; the
            // first is enough to reach it.
            return up.split('|').next().unwrap_or("GET").to_string();
        }
    }
    String::new()
}

/// `/password_resets(.:format)` -> `/password_resets`.
///
/// The `(.:format)` suffix is Rails offering `.json`/`.xml` variants; the bare
/// path is the one to request. Segments like `:id` are LEFT as they are - they
/// are the path parameters, and telling a downstream engine that a segment is a
/// parameter is more useful than substituting a number and pretending it is
/// fixed text.
fn clean_rails_path(p: &str) -> String {
    let p = p.trim();
    let p = p.strip_suffix("(.:format)").unwrap_or(p);
    if !p.starts_with('/') {
        return String::new();
    }
    p.to_string()
}

/// Django's DEBUG=True 404, which prints the URLconf it tried.
///
/// The patterns are regexes as written in `urls.py`, so they arrive with
/// anchors and capture groups. Anything still carrying regex syntax after the
/// obvious anchors come off is dropped rather than requested: a URL built out of
/// a half-understood regex is a URL the application does not have.
fn django(body: &str) -> Option<Harvest> {
    if !body.contains("Using the URLconf defined in") {
        return None;
    }
    let mut out: BTreeSet<(String, String)> = BTreeSet::new();
    for chunk in body.split("<code>").skip(1) {
        let Some(raw) = chunk.split("</code>").next() else {
            continue;
        };
        if let Some(path) = clean_django_pattern(raw) {
            out.insert((String::new(), path));
        }
    }
    (!out.is_empty()).then(|| Harvest {
        framework: "Django (DEBUG=True URLconf page)",
        routes: out.into_iter().collect(),
    })
}

fn clean_django_pattern(raw: &str) -> Option<String> {
    let s = unescape(raw.trim());
    let s = s.trim_start_matches('^').trim_end_matches('$');
    if s.is_empty() {
        return None;
    }
    // Django 2+ path() entries look like `articles/<int:year>/`; re_path()
    // entries are raw regex. Keep the first, drop the second.
    if s.contains('(') || s.contains('[') || s.contains('\\') || s.contains('?') {
        return None;
    }
    Some(format!("/{}", s.trim_start_matches('/')))
}

/// The value of `name='...'` or `name="..."` in this fragment.
fn attr(fragment: &str, name: &str) -> Option<String> {
    let at = fragment.find(name)?;
    let rest = &fragment[at + name.len()..];
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let rest = &rest[quote.len_utf8()..];
    let end = rest.find(quote)?;
    Some(unescape(&rest[..end]))
}

fn unescape(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&#39;", "'")
        .replace("&quot;", "\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAILS_ROW: &str = r#"
<tr class='route_row' data-helper='path'>
  <td data-route-name='password_resets'>password_resets<span class='helper'>_path</span></td>
  <td>
    POST
  </td>
  <td data-route-path='/password_resets(.:format)'>/password_resets(.:format)</td>
  <td><p>password_resets#reset_password</p></td>
</tr>
<tr class='route_row' data-helper='path'>
  <td data-route-name='user'></td>
  <td>
    GET
  </td>
  <td data-route-path='/users/:id(.:format)'>/users/:id(.:format)</td>
</tr>
"#;

    #[test]
    fn rails_rows_give_up_verb_and_path() {
        let h = parse(RAILS_ROW).expect("rails page not recognised");
        assert!(h.framework.starts_with("Rails"));
        assert!(
            h.routes
                .contains(&("POST".into(), "/password_resets".into()))
        );
        // The path parameter stays a path parameter.
        assert!(h.routes.contains(&("GET".into(), "/users/:id".into())));
    }

    #[test]
    fn a_page_without_a_route_table_gives_nothing() {
        assert!(parse("<html><h1>404 Not Found</h1></html>").is_none());
        // Has the words, has no rows: an empty harvest is not a harvest.
        assert!(parse("route_row data-route-path but no rows").is_none());
    }

    #[test]
    fn django_keeps_path_entries_and_drops_regexes() {
        let page = r#"<p>Using the URLconf defined in <code>myapp.urls</code>, Django tried
        these URL patterns:</p><ol>
        <li><code>admin/</code></li>
        <li><code>articles/&lt;int:year&gt;/</code></li>
        <li><code>^legacy/(?P&lt;pk&gt;\d+)$</code></li>
        </ol>"#;
        let h = parse(page).expect("django page not recognised");
        let paths: Vec<&str> = h.routes.iter().map(|(_, p)| p.as_str()).collect();
        assert!(paths.contains(&"/admin/"));
        assert!(paths.contains(&"/articles/<int:year>/"));
        // The regex one is not a URL, so it is not offered as one.
        assert!(!paths.iter().any(|p| p.contains("legacy")));
    }

    #[test]
    fn a_verbless_row_says_so_rather_than_guessing() {
        let row = r#"<tr class='route_row'><td data-route-name='x'></td><td>
        </td><td data-route-path='/anything(.:format)'></td></tr>"#;
        let h = parse(row).unwrap();
        assert_eq!(h.routes, vec![(String::new(), "/anything".to_string())]);
    }
}
