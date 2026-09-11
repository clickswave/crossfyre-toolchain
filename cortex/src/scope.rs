//! Destinations the operator has asserted they are allowed to test.
//!
//! A scan's scope has always been one target, and `inject::in_scope` derives
//! everything from its hostname. That is the right default and it is why a
//! crawled `https://www.paypal.com/cgi-bin/webscr` form action stopped receiving
//! SQL injection payloads.
//!
//! It is also too narrow for anything that follows a finding somewhere. An SSRF
//! confirmed on the app reaches an internal service on another address by
//! definition, and refusing to look is refusing to report the thing that makes
//! the SSRF matter.
//!
//! So: an explicit list, and every word of that is load-bearing.
//!
//! * **Explicit.** The operator writes it down. Nothing a scan discovers is ever
//!   added to it, because "the scanner found an internal range" is not the same
//!   sentence as "you may attack this internal range", and conflating them is
//!   how a tool ends up probing somebody else's network.
//! * **A list.** Not a switch. "Allow internal addresses" would authorise every
//!   internal address, including the ones belonging to whoever shares the host.
//! * **Fail closed.** An entry that does not parse is refused, named, and
//!   dropped. It is never treated as a wildcard, and a malformed list is an
//!   empty list rather than a permissive one.
//!
//! Empty scope reproduces today's behaviour exactly, so every existing scan is
//! unaffected by this file existing.

use std::net::IpAddr;

/// One thing the operator said they may test.
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    /// A hostname, any port. `api.example.com`
    Host(String),
    /// A hostname on one port. `api.example.com:8443`
    HostPort(String, u16),
    /// Subdomains of a name. `*.example.com`
    ///
    /// Subdomains only. `*.example.com` does not admit `example.com`, because an
    /// authorisation list should mean exactly what it says and someone who wants
    /// the apex can write the apex. The alternative is a rule whose reach
    /// depends on which convention the reader has in mind.
    Suffix(String),
    /// An address range. `10.0.0.0/8`, `fd00::/8`
    Net(IpAddr, u8),
}

/// A parsed authorisation list.
#[derive(Debug, Default, Clone)]
pub struct Scope {
    rules: Vec<Rule>,
}

/// Parse a list, returning what was understood and what was refused.
///
/// The refused entries are returned rather than dropped silently: a scan running
/// with two of an operator's five rules misunderstood is a scan whose results
/// mean something different from what they think it means.
pub fn parse(entries: &[String]) -> (Scope, Vec<String>) {
    let mut rules = Vec::new();
    let mut refused = Vec::new();
    for raw in entries {
        match parse_one(raw) {
            Some(r) => rules.push(r),
            None => refused.push(raw.clone()),
        }
    }
    (Scope { rules }, refused)
}

fn parse_one(raw: &str) -> Option<Rule> {
    let e = raw.trim().to_lowercase();
    if e.is_empty() || e.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    // A scope entry is a destination, not a URL. Refusing these outright avoids
    // guessing what someone meant by `https://example.com/admin`.
    if e.contains("://") || e.contains('@') || e.contains('?') || e.contains('#') {
        return None;
    }

    if let Some((addr, bits)) = e.split_once('/') {
        let ip: IpAddr = addr.parse().ok()?;
        let bits: u8 = bits.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return None;
        }
        return Some(Rule::Net(ip, bits));
    }
    // Any other slash is a path, which a destination does not have.
    if e.contains('/') {
        return None;
    }

    if let Some(rest) = e.strip_prefix("*.") {
        // `*.com` is not an authorisation, it is an accident.
        if !rest.contains('.') || rest.starts_with('.') {
            return None;
        }
        return Some(Rule::Suffix(rest.to_string()));
    }
    if e.contains('*') {
        return None;
    }

    // A bare address, including IPv6 which is full of colons and must not be
    // mistaken for host:port.
    if let Ok(ip) = e.parse::<IpAddr>() {
        return Some(Rule::Host(ip.to_string()));
    }
    if let Some(inner) = e.strip_prefix('[') {
        // [::1] or [::1]:8080
        let (addr, rest) = inner.split_once(']')?;
        let ip: IpAddr = addr.parse().ok()?;
        return match rest {
            "" => Some(Rule::Host(ip.to_string())),
            _ => {
                let port: u16 = rest.strip_prefix(':')?.parse().ok()?;
                Some(Rule::HostPort(ip.to_string(), port))
            }
        };
    }
    if let Some((host, port)) = e.rsplit_once(':') {
        let port: u16 = port.parse().ok()?;
        if host.is_empty() {
            return None;
        }
        return Some(Rule::HostPort(host.to_string(), port));
    }
    if !e.contains('.') && e != "localhost" {
        // A single label that is not localhost is almost always a typo, and a
        // typo in an authorisation list should be loud.
        return None;
    }
    Some(Rule::Host(e))
}

impl Scope {
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Is this destination one the operator listed?
    ///
    /// `host` is the bare hostname or address with no port and no brackets;
    /// `port` is the URL's port, explicit or defaulted from its scheme.
    pub fn admits(&self, host: &str, port: Option<u16>) -> bool {
        let h = host
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_lowercase();
        if h.is_empty() {
            return false;
        }
        self.rules.iter().any(|r| match r {
            Rule::Host(name) => *name == h,
            Rule::HostPort(name, p) => *name == h && port == Some(*p),
            // The leading dot is what stops `*.example.com` admitting
            // `evil-example.com`, which is the whole reason suffix rules are
            // dangerous when written as a plain `ends_with`.
            Rule::Suffix(base) => h.len() > base.len() + 1 && h.ends_with(&format!(".{base}")),
            Rule::Net(net, bits) => h
                .parse::<IpAddr>()
                .map(|ip| in_net(&ip, net, *bits))
                .unwrap_or(false),
        })
    }
}

/// Containment, per family. A v4 address is never inside a v6 range and the
/// reverse, which matters because the two are trivially confusable once both
/// have been widened to integers.
fn in_net(ip: &IpAddr, net: &IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let (a, n) = (u32::from(*a), u32::from(*n));
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            a & mask == n & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let (a, n) = (u128::from(*a), u128::from(*n));
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            a & mask == n & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(entries: &[&str]) -> Scope {
        parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).0
    }

    #[test]
    fn an_empty_list_admits_nothing() {
        let s = scope(&[]);
        assert!(s.is_empty());
        assert!(!s.admits("example.com", Some(443)));
        assert!(!s.admits("10.0.0.1", None));
    }

    #[test]
    fn a_wildcard_matches_on_a_dot_and_not_on_a_prefix() {
        let s = scope(&["*.example.com"]);
        assert!(s.admits("api.example.com", Some(443)));
        assert!(s.admits("a.b.example.com", None));
        // The one that matters: a plain ends_with would admit this.
        assert!(!s.admits("evil-example.com", Some(443)));
        assert!(!s.admits("exampleXcom", None));
        // Subdomains only, as documented.
        assert!(!s.admits("example.com", Some(443)));
    }

    #[test]
    fn a_port_rule_needs_the_port() {
        let s = scope(&["api.example.com:8443"]);
        assert!(s.admits("api.example.com", Some(8443)));
        assert!(!s.admits("api.example.com", Some(443)));
        assert!(!s.admits("api.example.com", None));
    }

    #[test]
    fn a_host_rule_ignores_the_port() {
        let s = scope(&["api.example.com"]);
        assert!(s.admits("api.example.com", Some(443)));
        assert!(s.admits("api.example.com", Some(9999)));
        assert!(s.admits("api.example.com", None));
    }

    #[test]
    fn ranges_contain_what_they_should_and_nothing_else() {
        let s = scope(&["10.0.0.0/8", "192.168.1.0/24"]);
        assert!(s.admits("10.255.3.4", None));
        assert!(s.admits("192.168.1.7", Some(6379)));
        assert!(!s.admits("192.168.2.7", None));
        assert!(!s.admits("11.0.0.1", None));
        // A name that is not an address is not in a range.
        assert!(!s.admits("ten.example.com", None));
    }

    #[test]
    fn families_do_not_cross() {
        let s = scope(&["::/0"]);
        // Everything in v6, nothing in v4, even though /0 is "all" in its family.
        assert!(s.admits("fd00::1", None));
        assert!(!s.admits("10.0.0.1", None));
    }

    #[test]
    fn nonsense_is_refused_rather_than_widened() {
        let (s, refused) = parse(
            &[
                "https://example.com", // a URL
                "example.com/admin",   // a path
                "*",                   // everything
                "*.com",               // a TLD
                "10.0.0.0/99",         // impossible prefix
                "not a host",          // whitespace
                "",                    // empty
                "localhost:notaport",  // bad port
                "admin",               // bare label, almost certainly a typo
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        );
        assert!(s.is_empty(), "nothing in that list is an authorisation");
        assert_eq!(refused.len(), 9, "and every one of them is reported");
    }

    #[test]
    fn the_forms_an_operator_actually_writes_all_parse() {
        let (s, refused) = parse(
            &[
                "example.com",
                "*.example.com",
                "10.0.0.0/8",
                "localhost",
                "127.0.0.1:6379",
                "[::1]",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
        );
        assert!(refused.is_empty(), "refused: {refused:?}");
        assert_eq!(s.len(), 6);
        assert!(s.admits("127.0.0.1", Some(6379)));
        assert!(s.admits("::1", None));
        assert!(s.admits("localhost", Some(3000)));
    }

    #[test]
    fn entries_are_case_insensitive_and_trimmed() {
        let s = scope(&["  API.Example.COM  "]);
        assert!(s.admits("api.example.com", None));
    }
}
