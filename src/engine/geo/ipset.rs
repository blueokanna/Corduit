//! A compact set of IP addresses, built from CIDRs or from raw ranges.
//!
//! Every Geo database and every binary rule set is ultimately a list of address
//! ranges, and a rule set such as `geoip:cn` carries about ten thousand of them.
//! Comparing a destination against ten thousand ranges one by one is what makes
//! a "big rule set" feel like a stall, so the ranges are sorted, merged and
//! bisected instead:
//!
//! * **memory** — one `(u32, u32)` pair per merged range, so `geoip:cn` costs
//!   about 80 KiB rather than a node per prefix bit;
//! * **lookup** — `log2(regions)` comparisons, one branch, no allocation, and
//!   the two arrays a lookup touches stay in cache. A pointer-chasing 32-level
//!   trie is the textbook answer for *insert* workloads; for a set that is built
//!   once and read millions of times, a sorted interval array beats it on both
//!   memory and cache behaviour;
//! * **merging** makes adjacent prefixes (the overwhelming majority of a
//!   `geoip.dat` category) collapse into ranges, so the array stays short.
//!
//! Ranges are inclusive on both ends, which is the form both `netipx`'s IP set
//! and the Geo databases already speak.

use crate::engine::error::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An immutable-after-[`IpRangeSet::finish`] set of addresses.
#[derive(Debug, Default, Clone)]
pub struct IpRangeSet {
    /// Sorted, disjoint, inclusive IPv4 ranges.
    v4: Vec<(u32, u32)>,
    /// Sorted, disjoint, inclusive IPv6 ranges.
    v6: Vec<(u128, u128)>,
    /// Set by every insert and cleared by [`IpRangeSet::finish`]. A lookup on a
    dirty: bool,
}

impl IpRangeSet {
    /// An empty set.
    pub fn new() -> Self {
        Self {
            v4: Vec::new(),
            v6: Vec::new(),
            dirty: false,
        }
    }

    /// Whether the set holds no address at all.
    ///
    /// A built set is always sorted, so "empty" needs no separate flag.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Number of merged ranges, for diagnostics.
    pub fn range_count(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Add a CIDR in wire form: raw address bytes plus a prefix length.
    ///
    /// This is the shape `geoip.dat` stores (`CIDR.ip` is 4 or 16 bytes,
    /// `CIDR.prefix` a bit count) and the shape an `IP-CIDR` payload parses to.
    /// Returns `false` for a prefix length that does not fit the address, so the
    /// caller can report the entry instead of widening it to something that
    /// matches too much.
    pub fn insert_wire_cidr(&mut self, address: &[u8], prefix: u32) -> bool {
        match address.len() {
            4 => {
                let octets = [address[0], address[1], address[2], address[3]];
                self.insert_v4_cidr(u32::from(Ipv4Addr::from(octets)), prefix)
            }
            16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(address);
                self.insert_v6_cidr(u128::from(Ipv6Addr::from(octets)), prefix)
            }
            _ => false,
        }
    }

    /// Add an IPv4 network by its network address bits and prefix length.
    pub fn insert_v4_cidr(&mut self, network: u32, prefix: u32) -> bool {
        let Some((start, end)) = cidr_bounds_v4(network, prefix) else {
            return false;
        };
        self.push_v4(start, end);
        true
    }

    /// Add an IPv6 network by its network address bits and prefix length.
    pub fn insert_v6_cidr(&mut self, network: u128, prefix: u32) -> bool {
        let Some((start, end)) = cidr_bounds_v6(network, prefix) else {
            return false;
        };
        self.push_v6(start, end);
        true
    }

    /// Add an `ipnet` network.
    ///
    /// A convenience for callers that already hold a parsed network — the text
    /// rule index does — so the conversion from prefix length to interval lives
    /// in exactly one place.
    pub fn insert_net(&mut self, network: ipnet::IpNet) {
        match network {
            ipnet::IpNet::V4(net) => {
                self.insert_v4_cidr(u32::from(net.network()), u32::from(net.prefix_len()));
            }
            ipnet::IpNet::V6(net) => {
                self.insert_v6_cidr(u128::from(net.network()), u32::from(net.prefix_len()));
            }
        }
    }
    /// Add an inclusive range of addresses.
    ///
    /// Both ends must be the same family; a mixed-family range is nonsense and
    /// is refused rather than silently split.
    pub fn insert_range(&mut self, from: IpAddr, to: IpAddr) -> Result<()> {
        match (from, to) {
            (IpAddr::V4(from), IpAddr::V4(to)) => {
                let (from, to) = (u32::from(from), u32::from(to));
                if from > to {
                    return Err(Error::config(format!("IP range {from}..{to} is inverted")));
                }
                self.push_v4(from, to);
                Ok(())
            }
            (IpAddr::V6(from), IpAddr::V6(to)) => {
                let (from, to) = (u128::from(from), u128::from(to));
                if from > to {
                    return Err(Error::config(format!("IP range {from}..{to} is inverted")));
                }
                self.push_v6(from, to);
                Ok(())
            }
            _ => Err(Error::config("IP range mixes an IPv4 and an IPv6 address")),
        }
    }

    fn push_v4(&mut self, start: u32, end: u32) {
        if start <= end {
            self.v4.push((start, end));
            self.dirty = true;
        }
    }

    fn push_v6(&mut self, start: u128, end: u128) {
        if start <= end {
            self.v6.push((start, end));
            self.dirty = true;
        }
    }

    /// Sort and merge overlapping or adjacent ranges.
    ///
    /// Idempotent, so a caller that builds a set in several phases can finish
    /// after each one.
    pub fn finish(&mut self) {
        merge_ranges(&mut self.v4);
        merge_ranges(&mut self.v6);
        self.dirty = false;
    }

    /// Whether `address` is in the set.
    ///
    /// An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) is checked against the
    /// IPv4 ranges as well: a socket may hand the engine either form for the same
    /// host, and the Geo databases describe that host once, in IPv4.
    pub fn contains(&self, address: IpAddr) -> bool {
        debug_assert!(!self.dirty, "IpRangeSet used before finish()");
        match address {
            IpAddr::V4(address) => contains_u32(&self.v4, u32::from(address)),
            IpAddr::V6(address) => {
                if contains_u128(&self.v6, u128::from(address)) {
                    return true;
                }
                match address.to_ipv4_mapped() {
                    Some(mapped) => contains_u32(&self.v4, u32::from(mapped)),
                    None => false,
                }
            }
        }
    }
}

/// Inclusive bounds of an IPv4 CIDR, or `None` when the prefix does not fit.
fn cidr_bounds_v4(network: u32, prefix: u32) -> Option<(u32, u32)> {
    if prefix > 32 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let start = network & mask;
    Some((start, start | !mask))
}

/// Inclusive bounds of an IPv6 CIDR, or `None` when the prefix does not fit.
fn cidr_bounds_v6(network: u128, prefix: u32) -> Option<(u128, u128)> {
    if prefix > 128 {
        return None;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    let start = network & mask;
    Some((start, start | !mask))
}

/// Sort `ranges` and fold every overlap and adjacency into one range.
fn merge_ranges<T: Copy + Ord + Bounded>(ranges: &mut Vec<(T, T)>) {
    if ranges.len() < 2 {
        return;
    }
    ranges.sort_unstable();
    let mut write = 0;
    for read in 1..ranges.len() {
        let (start, end) = ranges[read];
        let (_, merged_end) = ranges[write];
        if start <= merged_end.saturating_add_one() {
            if end > merged_end {
                ranges[write].1 = end;
            }
        } else {
            write += 1;
            ranges[write] = (start, end);
        }
    }
    ranges.truncate(write + 1);
}

/// `Bounded` for the two integer widths the ranges use, so the merge loop is
/// written once instead of twice.
trait Bounded {
    fn saturating_add_one(self) -> Self;
}

impl Bounded for u32 {
    fn saturating_add_one(self) -> Self {
        self.saturating_add(1)
    }
}

impl Bounded for u128 {
    fn saturating_add_one(self) -> Self {
        self.saturating_add(1)
    }
}

fn contains_u32(ranges: &[(u32, u32)], value: u32) -> bool {
    let index = ranges.partition_point(|&(start, _)| start <= value);
    index > 0 && ranges[index - 1].1 >= value
}

fn contains_u128(ranges: &[(u128, u128)], value: u128) -> bool {
    let index = ranges.partition_point(|&(start, _)| start <= value);
    index > 0 && ranges[index - 1].1 >= value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(set: &IpRangeSet, address: &str) -> bool {
        set.contains(address.parse().expect("address"))
    }

    #[test]
    fn a_cidr_covers_its_own_bounds_and_nothing_else() {
        let mut set = IpRangeSet::new();
        assert!(set.insert_wire_cidr(&[10, 0, 0, 0], 8));
        set.finish();

        assert!(v4(&set, "10.0.0.0"));
        assert!(v4(&set, "10.255.255.255"));
        assert!(!v4(&set, "9.255.255.255"));
        assert!(!v4(&set, "11.0.0.0"));
    }

    /// The `/0` and `/32` extremes are where shift arithmetic usually breaks.
    #[test]
    fn the_extreme_prefix_lengths_are_exact() {
        let mut set = IpRangeSet::new();
        assert!(set.insert_wire_cidr(&[203, 0, 113, 7], 32));
        set.finish();
        assert!(v4(&set, "203.0.113.7"));
        assert!(!v4(&set, "203.0.113.6"));
        assert!(!v4(&set, "203.0.113.8"));

        let mut everything = IpRangeSet::new();
        assert!(everything.insert_wire_cidr(&[0, 0, 0, 0], 0));
        everything.finish();
        assert!(v4(&everything, "0.0.0.0"));
        assert!(v4(&everything, "255.255.255.255"));
    }

    #[test]
    fn adjacent_and_overlapping_ranges_collapse() {
        let mut set = IpRangeSet::new();
        set.insert_v4_cidr(u32::from(Ipv4Addr::new(10, 0, 0, 0)), 25);
        set.insert_v4_cidr(u32::from(Ipv4Addr::new(10, 0, 0, 128)), 25);
        set.insert_v4_cidr(u32::from(Ipv4Addr::new(10, 0, 0, 0)), 24);
        set.finish();

        assert_eq!(set.range_count(), 1);
        assert!(v4(&set, "10.0.0.255"));
        assert!(!v4(&set, "10.0.1.0"));
    }

    /// Insertion order must not matter: a `geoip.dat` entry is a set, and two
    /// categories that overlap describe the same addresses either way.
    #[test]
    fn insertion_order_does_not_change_the_answer() {
        let mut forward = IpRangeSet::new();
        for (network, prefix) in [(0x0A00_0000u32, 16), (0x0A01_0000, 16), (0xC0A8_0000, 16)] {
            forward.insert_v4_cidr(network, prefix);
        }
        forward.finish();

        let mut reverse = IpRangeSet::new();
        for (network, prefix) in [(0xC0A8_0000u32, 16), (0x0A01_0000, 16), (0x0A00_0000, 16)] {
            reverse.insert_v4_cidr(network, prefix);
        }
        reverse.finish();

        for address in ["10.0.0.1", "10.1.2.3", "192.168.1.1", "11.0.0.1"] {
            assert_eq!(v4(&forward, address), v4(&reverse, address), "{address}");
        }
    }

    #[test]
    fn ipv6_ranges_are_independent_of_ipv4_ranges() {
        let mut set = IpRangeSet::new();
        set.insert_v6_cidr(
            u128::from("2001:db8::".parse::<Ipv6Addr>().expect("v6")),
            32,
        );
        set.insert_v4_cidr(0x0A00_0000, 8);
        set.finish();

        assert!(set.contains("2001:db8::1".parse().expect("v6")));
        assert!(!set.contains("2001:db9::1".parse().expect("v6")));
        assert!(set.contains("10.0.0.1".parse().expect("v4")));
        assert!(!set.contains("11.0.0.1".parse().expect("v4")));

        let mut only_v4 = IpRangeSet::new();
        only_v4.insert_v4_cidr(0x0A00_0000, 8);
        only_v4.finish();
        assert!(!only_v4.contains("::a00:1".parse().expect("v6")));
    }

    /// A dual-stack socket may hand over the mapped form for an IPv4 host.
    #[test]
    fn an_ipv4_mapped_address_matches_the_ipv4_ranges() {
        let mut set = IpRangeSet::new();
        set.insert_v4_cidr(0x0A00_0000, 8);
        set.finish();
        assert!(set.contains("::ffff:10.1.2.3".parse().expect("mapped")));
    }

    #[test]
    fn bad_prefixes_and_mixed_ranges_are_refused() {
        let mut set = IpRangeSet::new();
        assert!(!set.insert_wire_cidr(&[10, 0, 0, 0], 33));
        assert!(!set.insert_wire_cidr(&[10, 0, 0], 8));
        assert!(set.is_empty());

        assert!(
            set.insert_range(
                "10.0.0.1".parse().expect("v4"),
                "10.0.0.0".parse().expect("v4")
            )
            .is_err()
        );
        assert!(
            set.insert_range("10.0.0.1".parse().expect("v4"), "::1".parse().expect("v6"))
                .is_err()
        );
    }

    #[test]
    fn ranges_are_added_directly_which_is_what_srs_stores() {
        let mut set = IpRangeSet::new();
        set.insert_range(
            "192.0.2.0".parse().expect("v4"),
            "192.0.2.255".parse().expect("v4"),
        )
        .expect("range");
        set.finish();
        assert_eq!(set.range_count(), 1);
        assert!(v4(&set, "192.0.2.128"));
        assert!(!v4(&set, "192.0.3.0"));
    }
}
