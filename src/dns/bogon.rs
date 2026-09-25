//! Which addresses a public name is allowed to answer with.
//!
//! A poisoned answer is almost never a routable public address: routing it
//! would reach the real server and defeat the point. "This answer contains an
//! address that cannot be reached from the public internet" is therefore the
//! one anti-spoofing signal that needs no configuration at all, and it is worth
//! having a complete, auditable table behind it rather than a handful of
//! hand-masked octets.
//!
//! The ranges are the IANA special-purpose registries restricted to the
//! entries whose *Globally Reachable* column is `False`, plus
//! `192.88.99.0/24` (the deprecated 6to4 relay anycast prefix) and RFC 6052's
//! local-use translation prefix. Every network is held as a
//! [`recurse_x::cidr`] value, so containment is answered by the same
//! implementation the resolver itself uses — this crate holds no second CIDR
//! matcher.
//!
//! # Why classification and not just a boolean
//!
//! `is_bogon` is what the anti-poisoning gate needs, but the log line it
//! produces needs the reason: "`10.0.0.1` is private" tells the operator the
//! upstream handed back LAN space, while "reserved" points at something
//! stranger. [`BogonType`] carries that without a second traversal.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use recurse_x::cidr::{Ipv4Cidr, Ipv6Cidr};

/// How an address fails to be globally reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BogonType {
    /// Globally routable: the only outcome that clears an answer.
    Global,
    /// RFC 1918 space, or an IPv6 unique local address (RFC 4193).
    Private,
    /// Loopback (`127.0.0.0/8`, `::1`).
    Loopback,
    /// Link-local (`169.254.0.0/16`, `fe80::/10`).
    LinkLocal,
    /// Multicast (`224.0.0.0/4`, `ff00::/8`).
    Multicast,
    /// Assigned to a special purpose and not globally reachable: "this
    /// network", IETF protocol assignments, benchmarking, the discard prefix.
    Reserved,
    /// Documentation and example space (RFC 5737, RFC 3849).
    Documentation,
    /// Not globally reachable for some other assigned reason: carrier-grade
    /// NAT, NAT64, Teredo, ORCHID, 6to4.
    Other,
}

impl BogonType {
    /// Whether an address of this class may appear in an answer for a public
    /// name.
    pub fn is_globally_routable(self) -> bool {
        self == BogonType::Global
    }
}

impl std::fmt::Display for BogonType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BogonType::Global => "globally routable",
            BogonType::Private => "private",
            BogonType::Loopback => "loopback",
            BogonType::LinkLocal => "link-local",
            BogonType::Multicast => "multicast",
            BogonType::Reserved => "reserved",
            BogonType::Documentation => "documentation",
            BogonType::Other => "special-purpose",
        })
    }
}

/// The IPv4 table, **in priority order**: [`classify_bogon`] returns the class
/// of the first match, so a network listed here before another wins an overlap.
///
/// The order groups the classes an operator can act on (`Private`, `Loopback`,
/// `LinkLocal`) ahead of the ones that only mean "an upstream is lying"
/// (`Reserved`, `Other`).
const V4_RANGES: &[(&str, BogonType)] = &[
    ("127.0.0.0/8", BogonType::Loopback),
    ("10.0.0.0/8", BogonType::Private),
    ("172.16.0.0/12", BogonType::Private),
    ("192.168.0.0/16", BogonType::Private),
    ("169.254.0.0/16", BogonType::LinkLocal),
    ("224.0.0.0/4", BogonType::Multicast),
    ("192.0.2.0/24", BogonType::Documentation),
    ("198.51.100.0/24", BogonType::Documentation),
    ("203.0.113.0/24", BogonType::Documentation),
    ("0.0.0.0/8", BogonType::Reserved),
    ("192.0.0.0/24", BogonType::Reserved),
    ("192.88.99.0/24", BogonType::Reserved),
    ("240.0.0.0/4", BogonType::Reserved),
    ("100.64.0.0/10", BogonType::Other),
    ("198.18.0.0/15", BogonType::Other),
];

/// The IPv6 table, in priority order. IPv4-mapped addresses are **not** listed:
/// they are unwrapped and classified as IPv4 instead, because a mapped public
/// address is reachable and calling it an IPv6 anomaly would be wrong in the
/// one direction that matters.
const V6_RANGES: &[(&str, BogonType)] = &[
    ("::1/128", BogonType::Loopback),
    ("fc00::/7", BogonType::Private),
    ("fe80::/10", BogonType::LinkLocal),
    ("ff00::/8", BogonType::Multicast),
    ("2001:db8::/32", BogonType::Documentation),
    ("::/128", BogonType::Reserved),
    ("100::/64", BogonType::Reserved),
    ("2001:2::/48", BogonType::Reserved),
    ("64:ff9b::/96", BogonType::Other),
    ("64:ff9b:1::/48", BogonType::Other),
    ("2001::/32", BogonType::Other),
    ("2001:10::/28", BogonType::Other),
    ("2001:20::/28", BogonType::Other),
    ("2002::/16", BogonType::Other),
];

fn v4_rules() -> &'static [(Ipv4Cidr, BogonType)] {
    static RULES: OnceLock<Vec<(Ipv4Cidr, BogonType)>> = OnceLock::new();
    RULES.get_or_init(|| {
        V4_RANGES
            .iter()
            .filter_map(|(cidr, class)| Ipv4Cidr::parse(cidr).map(|net| (net, *class)))
            .collect()
    })
}

fn v6_rules() -> &'static [(Ipv6Cidr, BogonType)] {
    static RULES: OnceLock<Vec<(Ipv6Cidr, BogonType)>> = OnceLock::new();
    RULES.get_or_init(|| {
        V6_RANGES
            .iter()
            .filter_map(|(cidr, class)| Ipv6Cidr::parse(cidr).map(|net| (net, *class)))
            .collect()
    })
}

fn classify_v4(ip: Ipv4Addr) -> BogonType {
    for (network, class) in v4_rules() {
        if network.contains(ip) {
            return *class;
        }
    }
    BogonType::Global
}

fn classify_v6(ip: Ipv6Addr) -> BogonType {
    for (network, class) in v6_rules() {
        if network.contains(ip) {
            return *class;
        }
    }
    BogonType::Global
}

/// Every range in both tables, as CIDR text.
///
/// The same table answers two questions, and this is what lets one table serve
/// both: [`is_bogon`] asks "is this address routable?" one address at a time,
/// and the client-facing listener hands the whole list to RecurseX's
/// answer-quality filter, which asks "does this answer contain anything that
/// cannot be routable?" about a set of addresses.
///
/// A second list written out for the filter would be a second thing to keep
/// right, and the failure mode of a stale one is silent — the gate would simply
/// stop recognising a range.
pub fn all_ranges() -> impl Iterator<Item = &'static str> {
    V4_RANGES
        .iter()
        .chain(V6_RANGES.iter())
        .map(|(cidr, _)| *cidr)
}

/// Classify an address.
///
/// An IPv4-mapped IPv6 address is classified as the IPv4 address it carries,
/// not as IPv6: `::ffff:1.1.1.1` is reachable, and `::ffff:10.0.0.1` is private.
pub fn classify_bogon(ip: IpAddr) -> BogonType {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => classify_v4(v4),
            None => classify_v6(v6),
        },
    }
}

/// Whether an address cannot legitimately answer for a public name.
#[inline]
pub fn is_bogon(ip: IpAddr) -> bool {
    !classify_bogon(ip).is_globally_routable()
}

/// Whether any address in a set cannot legitimately answer for a public name.
///
/// One is enough. A polluted response typically mixes the real record with
/// fabricated ones, and trusting the response because one address looked fine
/// is exactly the mistake this is here to prevent.
#[inline]
pub fn contains_bogon(ips: &[IpAddr]) -> bool {
    ips.iter().any(|ip| is_bogon(*ip))
}

// The public surface is deliberately four things: ask about one address
// (`is_bogon`, `classify_bogon`), ask about a set (`contains_bogon`), and read
// the table (`all_ranges`). Per-class shortcuts — `is_private`, `is_loopback`,
// `is_reserved` — and a `filter_bogons` were removed because each is one
// comparison away from `classify_bogon` and nothing called them: a second way to
// ask the same question is a second thing to keep right.

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().expect("ipv4 literal"))
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().expect("ipv6 literal"))
    }

    #[test]
    fn private_space_is_private() {
        for address in [
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
        ] {
            assert_eq!(classify_bogon(v4(address)), BogonType::Private, "{address}");
            assert!(is_bogon(v4(address)), "{address}");
        }
        assert_eq!(classify_bogon(v6("fd00::1")), BogonType::Private);
        assert_eq!(classify_bogon(v6("fc00::1")), BogonType::Private);
    }

    /// The boundaries of the two RFC 1918 blocks whose masks are not byte
    /// aligned: `172.16/12` ends at `172.31.255.255`, and `172.32.0.0` is
    /// public.
    #[test]
    fn private_block_boundaries_are_exact() {
        assert_eq!(classify_bogon(v4("172.15.255.255")), BogonType::Global);
        assert_eq!(classify_bogon(v4("172.16.0.0")), BogonType::Private);
        assert_eq!(classify_bogon(v4("172.31.255.255")), BogonType::Private);
        assert_eq!(classify_bogon(v4("172.32.0.0")), BogonType::Global);
    }

    #[test]
    fn loopback_is_loopback() {
        assert_eq!(classify_bogon(v4("127.0.0.1")), BogonType::Loopback);
        assert_eq!(classify_bogon(v4("127.255.255.255")), BogonType::Loopback);
        assert_eq!(classify_bogon(v6("::1")), BogonType::Loopback);
    }

    #[test]
    fn link_local_and_multicast() {
        assert_eq!(classify_bogon(v4("169.254.1.1")), BogonType::LinkLocal);
        assert_eq!(classify_bogon(v6("fe80::1")), BogonType::LinkLocal);
        assert_eq!(classify_bogon(v4("224.0.0.1")), BogonType::Multicast);
        assert_eq!(classify_bogon(v4("239.255.255.255")), BogonType::Multicast);
        assert_eq!(classify_bogon(v6("ff02::1")), BogonType::Multicast);
    }

    #[test]
    fn reserved_covers_this_network_and_the_top_of_the_space() {
        for address in [
            "0.0.0.0",
            "0.1.2.3",
            "192.0.0.1",
            "192.88.99.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert_eq!(
                classify_bogon(v4(address)),
                BogonType::Reserved,
                "{address}"
            );
        }
        assert_eq!(classify_bogon(v6("::")), BogonType::Reserved);
        assert_eq!(classify_bogon(v6("100::1")), BogonType::Reserved);
    }

    #[test]
    fn documentation_space_is_named() {
        for address in ["192.0.2.1", "198.51.100.1", "203.0.113.1"] {
            assert_eq!(
                classify_bogon(v4(address)),
                BogonType::Documentation,
                "{address}"
            );
        }
        assert_eq!(classify_bogon(v6("2001:db8::1")), BogonType::Documentation);
    }

    #[test]
    fn carrier_grade_nat_and_benchmarking_are_special_purpose() {
        // 100.64/10 ends at 100.127.255.255; 100.128.0.0 is public.
        assert_eq!(classify_bogon(v4("100.64.0.1")), BogonType::Other);
        assert_eq!(classify_bogon(v4("100.127.255.255")), BogonType::Other);
        assert_eq!(classify_bogon(v4("100.128.0.0")), BogonType::Global);
        // 198.18/15 covers both 198.18/16 and 198.19/16.
        assert_eq!(classify_bogon(v4("198.18.0.1")), BogonType::Other);
        assert_eq!(classify_bogon(v4("198.19.255.255")), BogonType::Other);
        assert_eq!(classify_bogon(v4("198.20.0.0")), BogonType::Global);
    }

    #[test]
    fn v6_special_purpose_ranges() {
        assert_eq!(classify_bogon(v6("64:ff9b::1")), BogonType::Other);
        assert_eq!(classify_bogon(v6("2002::1")), BogonType::Other);
        assert_eq!(classify_bogon(v6("2001::1")), BogonType::Other);
        assert_eq!(classify_bogon(v6("2001:db8::1")), BogonType::Documentation);
        assert_eq!(
            classify_bogon(v6("2001:4860:4860::8888")),
            BogonType::Global
        );
    }

    /// An IPv4-mapped address carries an IPv4 address, and the answer must be
    /// the IPv4 answer: a mapped public address is reachable.
    #[test]
    fn ipv4_mapped_addresses_are_classified_as_ipv4() {
        assert_eq!(classify_bogon(v6("::ffff:1.1.1.1")), BogonType::Global);
        assert_eq!(classify_bogon(v6("::ffff:10.0.0.1")), BogonType::Private);
        assert_eq!(classify_bogon(v6("::ffff:127.0.0.1")), BogonType::Loopback);
    }

    #[test]
    fn public_addresses_are_global() {
        for address in [
            "8.8.8.8",
            "1.1.1.1",
            "142.250.185.78",
            "223.5.5.5",
            "93.184.216.34",
        ] {
            assert_eq!(classify_bogon(v4(address)), BogonType::Global, "{address}");
            assert!(!is_bogon(v4(address)), "{address}");
        }
        for address in ["2001:4860:4860::8888", "2606:4700:4700::1111"] {
            assert_eq!(classify_bogon(v6(address)), BogonType::Global, "{address}");
        }
    }

    #[test]
    fn one_bad_address_is_enough() {
        let mixed = [v4("93.184.216.34"), v4("10.0.0.1")];
        assert!(contains_bogon(&mixed));
        assert!(contains_bogon(&[v4("1.1.1.1"), v4("169.254.0.1")]));
        assert!(!contains_bogon(&[v4("93.184.216.34"), v4("1.1.1.1")]));
    }

    /// Every table entry must parse, or the class it carries would silently
    /// disappear from the gate.
    #[test]
    fn every_table_entry_parses() {
        assert_eq!(v4_rules().len(), V4_RANGES.len());
        assert_eq!(v6_rules().len(), V6_RANGES.len());
    }

    /// The list handed to a filter is the same table, so it parses for the same
    /// reason — and it is complete, because a range missing from it is a range
    /// the filter stops recognising.
    #[test]
    fn the_exported_range_list_is_the_whole_table() {
        let exported: Vec<&str> = all_ranges().collect();
        assert_eq!(exported.len(), V4_RANGES.len() + V6_RANGES.len());
        for cidr in &exported {
            assert!(
                recurse_x::cidr::IpCidr::parse(cidr).is_some(),
                "{cidr} is in the table but does not parse"
            );
        }
        // Every range the classifier knows about is one the filter will see.
        for (cidr, _) in V4_RANGES.iter().chain(V6_RANGES.iter()) {
            assert!(
                exported.contains(cidr),
                "{cidr} is missing from all_ranges()"
            );
        }
    }
}
