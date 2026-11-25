//! Which addresses count as internal: the ranges `transport`'s guard and the node's
//! gateway both refuse for a request that must not reach a private network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Addresses an untrusted caller must never be able to reach through us.
///
/// Deliberately the same classification as the control plane's own guard. Two
/// copies is not ideal, but they sit in different repositories with different
/// release cadences, and a shared crate for eleven lines of range checks would
/// couple the open toolchain to the closed control plane. If you change one,
/// change the other.
pub fn is_internal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // 169.254.0.0/16, incl. the cloud metadata address
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 198.18.0.0/15 benchmarking
                || (v4.octets()[0] == 198 && (18..20).contains(&v4.octets()[1]))
                // 240.0.0.0/4 reserved
                || v4.octets()[0] >= 240
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // 64:ff9b:1::/48, NAT64 for use inside one network
                || v6.segments()[..3] == [0x64, 0xff9b, 1]
                // A v4 address carried inside, re-checked as v4 so ::ffff:127.0.0.1 and
                // 64:ff9b::7f00:1 are caught
                || carried_v4(v6).is_some_and(|v4| is_internal(&IpAddr::V4(v4)))
        }
    }
}

/// The IPv4 address an IPv6 address stands for, where one is written into it: mapped
/// (`::ffff:0:0/96`), IPv4-compatible (`::/96`), NAT64's well-known prefix
/// (`64:ff9b::/96`), whose translator dials it, and 6to4 (`2002::/16`).
fn carried_v4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    let low = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    match s {
        [0, 0, 0, 0, 0, 0xffff, hi, lo] | [0, 0, 0, 0, 0, 0, hi, lo] => Some(low(hi, lo)),
        [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] => Some(low(hi, lo)),
        [0x2002, hi, lo, ..] => Some(low(hi, lo)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn blocks_the_ranges_that_matter() {
        for s in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            // The one an SSRF is usually aiming for.
            "169.254.169.254",
            "0.0.0.0",
            "100.64.0.1", // CGNAT
            "198.18.0.1", // benchmarking
            "240.0.0.1",  // reserved
            "255.255.255.255",
        ] {
            assert!(is_internal(&v4(s)), "{s} should be blocked");
        }
    }

    #[test]
    fn allows_ordinary_public_addresses() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.32.0.1",
            "100.128.0.1",
        ] {
            assert!(!is_internal(&v4(s)), "{s} should be allowed");
        }
    }

    #[test]
    fn ipv6_mapped_v4_is_not_a_bypass() {
        // ::ffff:127.0.0.1 is the classic way past a v4-only check.
        assert!(is_internal(&"::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_internal(&"::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_internal(&"::1".parse().unwrap()));
        assert!(is_internal(&"fc00::1".parse().unwrap()));
        assert!(is_internal(&"fe80::1".parse().unwrap()));
        assert!(!is_internal(&"2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn ipv6_forms_that_carry_an_internal_v4_address_are_internal() {
        for s in [
            // IPv4-compatible, the deprecated ::a.b.c.d.
            "::127.0.0.1",
            "::a9fe:a9fe",
            // NAT64's well-known prefix: a translator on the path dials the v4 inside.
            "64:ff9b::7f00:1",
            "64:ff9b::a00:5",
            "64:ff9b::169.254.169.254",
            // NAT64's local-use prefix, which only means something inside one network.
            "64:ff9b:1::1",
            "64:ff9b:1:ffff::808:808",
            // 6to4, whose next 32 bits are the v4 address.
            "2002:7f00:1::",
            "2002:c0a8:101::1",
        ] {
            assert!(is_internal(&s.parse().unwrap()), "{s} should be blocked");
        }
        for s in ["64:ff9b::808:808", "2002:808:808::1", "::8.8.8.8"] {
            assert!(!is_internal(&s.parse().unwrap()), "{s} should be allowed");
        }
    }

    #[test]
    fn ipv4_multicast_is_internal() {
        for s in ["224.0.0.1", "239.255.255.250"] {
            assert!(is_internal(&v4(s)), "{s} should be blocked");
        }
    }
}
