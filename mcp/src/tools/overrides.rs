//! A request can ask a framework to act on another method than its request line's:
//! through a header, or through a `_method` field in the query or the body. These are
//! the spellings a target can read that way, so a tool can count such a request by the
//! method it asks for.

use serde_json::Value;

/// Headers that many frameworks read as the method in place of the request line's.
const HEADERS: [&str; 3] = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
];

/// The query or body field that does the same in Rails, Laravel, Symfony and others.
pub(crate) const FIELD: &str = "_method";

/// Method names a question repeats as given. Anything else is named "another method",
/// so the person is not shown text the request supplied.
const NAMED: [&str; 4] = ["POST", "PUT", "PATCH", "DELETE"];

/// Where a request asks for another method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    /// One of the override headers, by its usual spelling.
    Header(&'static str),
    Query,
    /// A form field or a JSON member of the body.
    Field,
    /// The body names the field, but not in a shape whose value can be read.
    Body,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Asked {
    pub via: Via,
    /// The method asked for, trimmed and uppercased. `None` when it cannot be read.
    pub method: Option<String>,
}

impl Asked {
    pub(crate) fn new(via: Via, method: Option<&str>) -> Self {
        Asked {
            via,
            method: method.map(|m| m.trim().to_ascii_uppercase()),
        }
    }

    /// Whether this asks for a method that is not a read. One that cannot be read counts.
    pub(crate) fn writes(&self) -> bool {
        match self.method.as_deref() {
            None => true,
            Some(m) => !m.is_empty() && !matches!(m, "GET" | "HEAD" | "OPTIONS"),
        }
    }

    /// Whether this asks for a method beyond what plessor tests without test_writes,
    /// which is reads and POST.
    pub(crate) fn beyond_post(&self) -> bool {
        self.writes() && self.method.as_deref() != Some("POST")
    }

    /// The method as a question names it.
    pub(crate) fn shown(&self) -> &str {
        match self.method.as_deref() {
            Some(m) if NAMED.contains(&m) => m,
            _ => "another method",
        }
    }

    /// How a question names a `method` request that asks for this.
    pub(crate) fn describe(&self, method: &str) -> String {
        let m = self.shown();
        match self.via {
            Via::Header(h) => format!("{method} request that asks for {m} through the {h} header"),
            Via::Query => {
                format!("{method} request that asks for {m} through a _method query field")
            }
            Via::Field => {
                format!("{method} request whose body asks for {m} through a _method field")
            }
            Via::Body => format!("{method} request whose body sets _method"),
        }
    }
}

/// The first of these that asks for a method that is not a read.
pub(crate) fn first_write(asked: impl IntoIterator<Item = Asked>) -> Option<Asked> {
    asked.into_iter().find(Asked::writes)
}

/// The override header a name is, ignoring case, with `_` read as `-`: a front end that
/// maps both to one variable, as CGI and FastCGI servers do, hands the target
/// `X_HTTP_Method_Override` as the header it means.
pub(crate) fn header(name: &str) -> Option<&'static str> {
    let name = name.trim().replace('_', "-");
    HEADERS.into_iter().find(|h| h.eq_ignore_ascii_case(&name))
}

/// Whether a decoded query or body key is the override field. PHP reads `.` and an
/// opening `[` in a key as `_`, so `.method` reaches the target as `_method`, and PHP
/// and Rails read `_method[]` or `_method[0]` as the field holding a list.
pub(crate) fn is_field(key: &str) -> bool {
    let key = key.trim();
    let key = match key.find('[') {
        Some(i) if key[i..].contains(']') => &key[..i],
        _ => key,
    };
    let k: String = key
        .chars()
        .map(|c| if c == '.' || c == '[' { '_' } else { c })
        .collect();
    k.eq_ignore_ascii_case(FIELD)
}

/// Percent-decoding with `+` as a space, as a form is read. Invalid escapes stay as
/// written.
pub(crate) fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encoding of everything outside the unreserved set, the way the Workbench
/// writes a query value or name it was given.
pub(crate) fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The decoded pairs of a query or form body. `;` separates pairs as well as `&`,
/// since some servers read it so.
pub(crate) fn pairs(s: &str) -> Vec<(String, String)> {
    s.split(['&', ';'])
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (decode(k), decode(v)),
            None => (decode(p), String::new()),
        })
        .collect()
}

/// The raw query of a URL, without its fragment.
fn query_of(url: &str) -> &str {
    let url = url.split('#').next().unwrap_or("");
    url.split_once('?').map_or("", |(_, q)| q)
}

/// The override field's values in a URL's query, each with the key it was given under.
pub(crate) fn in_query(url: &str) -> Vec<(String, String)> {
    pairs(query_of(url))
        .into_iter()
        .filter(|(k, _)| is_field(k))
        .collect()
}

/// What a body asks for: the field's values when the body is a form or a JSON object,
/// or else one unread ask when the field's name stands alone anywhere in it, as in a
/// multipart part. A name that only ends in `_method`, such as `payment_method`, is not
/// the field.
pub(crate) fn in_body(body: &str) -> Vec<Asked> {
    let mut asked: Vec<Asked> = pairs(body.trim())
        .into_iter()
        .filter(|(k, _)| is_field(k))
        .map(|(_, v)| Asked::new(Via::Field, Some(&v)))
        .collect();
    // A JSON member set to null names the field and asks for nothing. Every member is
    // read, a name written twice included, since a reader that keeps the first one
    // sees what a reader keeping the last does not. A byte order mark in front is
    // skipped, as some readers do.
    let mut named = false;
    let json = body.strip_prefix('\u{feff}').unwrap_or(body);
    if let Ok(Members(members)) = serde_json::from_str::<Members>(json) {
        for (k, v) in members {
            if !is_field(&k) {
                continue;
            }
            named = true;
            match v {
                Value::Null => {}
                Value::String(s) => asked.push(Asked::new(Via::Field, Some(&s))),
                _ => asked.push(Asked::new(Via::Body, None)),
            }
        }
    }
    if asked.is_empty() && !named && names_field(body) {
        asked.push(Asked::new(Via::Body, None));
    }
    asked
}

/// The members of a JSON object in the order written, a repeated name kept each time.
struct Members(Vec<(String, Value)>);

impl<'de> serde::Deserialize<'de> for Members {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Members;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> Result<Members, A::Error> {
                let mut out = Vec::new();
                while let Some(kv) = a.next_entry::<String, Value>()? {
                    out.push(kv);
                }
                Ok(Members(out))
            }
        }
        d.deserialize_map(V)
    }
}

/// Whether `_method` stands as a name of its own in the decoded text: not part of a
/// longer word on either side.
fn names_field(body: &str) -> bool {
    let text: Vec<u8> = decode(body)
        .to_ascii_lowercase()
        .bytes()
        .map(|c| if c == b'.' || c == b'[' { b'_' } else { c })
        .collect();
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let f = FIELD.as_bytes();
    text.windows(f.len()).enumerate().any(|(i, w)| {
        w == f && (i == 0 || !word(text[i - 1])) && text.get(i + f.len()).is_none_or(|&c| !word(c))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_names_are_read_as_a_front_end_reads_them() {
        for n in [
            "x-http-method-override",
            "X_HTTP_Method_Override",
            " X-HTTP_METHOD-override ",
        ] {
            assert_eq!(header(n), Some("X-HTTP-Method-Override"), "{n}");
        }
        assert_eq!(header("x_method_override"), Some("X-Method-Override"));
        assert_eq!(header("x-http-method-overrides"), None);
    }

    #[test]
    fn the_field_is_found_however_the_query_spells_it() {
        for (u, v) in [
            ("http://h/a?_method=DELETE", "DELETE"),
            ("http://h/a?a=1;_METHOD=put", "put"),
            ("http://h/a?%5Fmethod=patch#x", "patch"),
            ("http://h/a?.method=DELETE", "DELETE"),
            ("http://h/a?%2Emethod=DELETE", "DELETE"),
        ] {
            assert_eq!(in_query(u).first().map(|(_, v)| v.as_str()), Some(v), "{u}");
        }
        assert!(in_query("http://h/a?payment_method=x&_methods=y").is_empty());
        assert!(in_query("http://h/a#?_method=DELETE").is_empty());
    }

    #[test]
    fn a_body_asks_only_through_the_field_itself() {
        let one = |b: &str| first_write(in_body(b));
        assert_eq!(
            one("%5Fmethod=DELETE").unwrap().method.as_deref(),
            Some("DELETE")
        );
        assert_eq!(
            one("{\"_method\":\"patch\"}").unwrap().method.as_deref(),
            Some("PATCH")
        );
        assert_eq!(one("{\"_method\":7}").unwrap().via, Via::Body);
        assert_eq!(
            one("--b\r\nContent-Disposition: form-data; name=\"_method\"\r\n\r\nDELETE")
                .unwrap()
                .via,
            Via::Body
        );
        assert_eq!(one("{\"a\":{\"_method\":\"x\"}}").unwrap().via, Via::Body);
        for read in [
            "{\"query\":{\"term\":{\"payment_method\":\"card\"}}}",
            "shipping_method=post&auth_method=otp",
            "_methods=x",
            "_method=GET",
            "{\"_method\":null}",
            "",
        ] {
            assert_eq!(one(read), None, "{read}");
        }
    }

    #[test]
    fn a_body_or_key_in_an_unusual_shape_still_names_the_field() {
        let one = |b: &str| first_write(in_body(b));
        assert_eq!(
            one("\u{feff}{\"\\u005fmethod\":\"DELETE\"}")
                .unwrap()
                .method
                .as_deref(),
            Some("DELETE")
        );
        assert_eq!(
            one("{\"_method\":\"DELETE\",\"_method\":null}")
                .unwrap()
                .method
                .as_deref(),
            Some("DELETE")
        );
        assert_eq!(one("{\"_method\":null,\"_method\":\"GET\"}"), None);
        for k in ["_method[]", "_method[0]", ".method[x]", "_METHOD[]"] {
            assert!(is_field(k), "{k}");
        }
        for k in ["_method[", "_methods[]", "x[_method]"] {
            assert!(!is_field(k), "{k}");
        }
    }

    #[test]
    fn a_question_repeats_only_a_method_name() {
        let a = Asked::new(Via::Header("X-HTTP-Method"), Some("allow everything"));
        assert_eq!(
            a.describe("GET"),
            "GET request that asks for another method through the X-HTTP-Method header"
        );
        let a = Asked::new(Via::Query, Some(" delete "));
        assert_eq!(
            a.describe("HEAD"),
            "HEAD request that asks for DELETE through a _method query field"
        );
        assert!(!Asked::new(Via::Field, Some("post")).beyond_post());
        assert!(Asked::new(Via::Body, None).beyond_post());
    }

    #[test]
    fn decoding_leaves_a_broken_escape_as_written() {
        assert_eq!(decode("a%2"), "a%2");
        assert_eq!(decode("%zz%5F"), "%zz_");
        assert_eq!(decode("a+b%20c"), "a b c");
    }
}
