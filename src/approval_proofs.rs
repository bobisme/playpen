//! Proofs over the production pure address and port primitives.
//!
//! Reproduce with Kani 0.68.0:
//! `cargo kani --lib --default-unwind 1`
//!
//! The mask and valid-port harnesses have no reachable loop iterations. The
//! address interval and edge harnesses use 17 for byte comparisons of up to
//! 16 address bytes. Kani checks all unwind assertions.
//!
//! Arithmetic inputs cover all canonical CIDRs at their family width,
//! including internal ranges that `Net::new` rejects. Public construction
//! additionally rejects any overlap with the reserved ranges in
//! `Net::check_approvable`. The constructor's formatted error paths are
//! outside these proofs. In particular, a trial of symbolic invalid
//! `Ports::new` inputs at unwind 17 ran past a 180-second budget in the
//! formatting paths for reversed ranges. Ordinary tests exercise invalid
//! inputs, and the port proof covers every valid pair and every candidate.
//!
//! To check that the IPv4 mask proof detects a regression, temporarily
//! clear the low input bit in the IPv4 arm of `mask_host_bits`. The
//! `ipv4_mask_retains_exactly_the_prefix_bits` harness fails its bit assertion.

use super::*;

#[kani::proof]
fn ipv4_mask_retains_exactly_the_prefix_bits() {
    let bits: u32 = kani::any();
    let prefix: u8 = kani::any();
    let index: u8 = kani::any();
    kani::assume(prefix <= 32 && index < 32);
    let actual = mask_host_bits(Ipv4Addr::from(bits).into(), prefix);
    let IpAddr::V4(actual) = actual else {
        panic!("masking changed address family");
    };
    let bit = 1 << (31 - index);
    assert_eq!(
        u32::from(actual) & bit != 0,
        index < prefix && bits & bit != 0
    );
    kani::cover!(prefix == 0 && bits != 0);
    kani::cover!(prefix == 32 && bits != 0);
    kani::cover!(prefix == 24 && index == 23 && bits & bit != 0);
    kani::cover!(prefix == 24 && index == 24 && bits & bit != 0);
}

#[kani::proof]
fn ipv6_mask_retains_exactly_the_prefix_bits() {
    let bits: u128 = kani::any();
    let prefix: u8 = kani::any();
    let index: u8 = kani::any();
    kani::assume(prefix <= 128 && index < 128);
    let actual = mask_host_bits(Ipv6Addr::from(bits).into(), prefix);
    let IpAddr::V6(actual) = actual else {
        panic!("masking changed address family");
    };
    let bit = 1 << (127 - index);
    assert_eq!(
        u128::from(actual) & bit != 0,
        index < prefix && bits & bit != 0
    );
    kani::cover!(prefix == 0 && bits != 0);
    kani::cover!(prefix == 128 && bits != 0);
    kani::cover!(prefix == 64 && index == 63 && bits & bit != 0);
    kani::cover!(prefix == 64 && index == 64 && bits & bit != 0);
}

// CIDRs denote aligned intervals of size two to the power of the host width.
// /0 spans its entire family and is handled separately to avoid overflow.
// These proofs also cover valid CIDRs used internally as forbidden ranges by
// Net::new. Passing these arithmetic preconditions alone does not approve a CIDR.
macro_rules! network_interval_proof {
    ($name:ident, $integer:ty, $address:ty, $width:literal, $other:expr) => {
        #[kani::proof]
        #[kani::unwind(17)]
        fn $name() {
            let first: $integer = kani::any();
            let other_first: $integer = kani::any();
            let candidate: $integer = kani::any();
            let prefix: u8 = kani::any();
            let other_prefix: u8 = kani::any();
            kani::assume(prefix <= $width && other_prefix <= $width);
            let tail = |prefix| {
                if prefix == 0 {
                    <$integer>::MAX
                } else {
                    ((1 as $integer) << ($width - prefix)) - 1
                }
            };
            let host_max = tail(prefix);
            let other_host_max = tail(other_prefix);
            kani::assume(first & host_max == 0 && other_first & other_host_max == 0);
            let last = first + host_max;
            let other_last = other_first + other_host_max;
            let net = Net {
                addr: <$address>::from(first).into(),
                prefix,
            };
            let other_net = Net {
                addr: <$address>::from(other_first).into(),
                prefix: other_prefix,
            };
            let contains = net.contains(<$address>::from(candidate).into());
            let overlaps = net.overlaps(other_net);
            assert_eq!(contains, (first..=last).contains(&candidate));
            assert_eq!(overlaps, first <= other_last && other_first <= last);
            assert!(!net.contains($other.addr));
            assert!(!net.overlaps($other));
            kani::cover!(contains && overlaps && prefix == 0);
            kani::cover!(contains && overlaps && prefix == $width);
            kani::cover!(!contains && !overlaps);
        }
    };
}

network_interval_proof!(
    ipv4_membership_and_overlap_match_intervals,
    u32,
    Ipv4Addr,
    32,
    Net {
        addr: Ipv6Addr::LOCALHOST.into(),
        prefix: 128
    }
);

network_interval_proof!(
    ipv6_membership_and_overlap_match_intervals,
    u128,
    Ipv6Addr,
    128,
    Net {
        addr: Ipv4Addr::LOCALHOST.into(),
        prefix: 32
    }
);

#[kani::proof]
#[kani::unwind(17)]
fn network_edges_follow_the_ipv4_host_convention() {
    let first: u32 = kani::any();
    let prefix: u8 = kani::any();
    kani::assume(prefix <= 32);
    let last = if prefix == 0 {
        kani::assume(first == 0);
        u32::MAX
    } else {
        let size = 1_u32 << (32 - prefix);
        kani::assume(first % size == 0);
        first + (size - 1)
    };
    let v4 = Net {
        addr: Ipv4Addr::from(first).into(),
        prefix,
    };
    let edges = v4.edges();
    let expected = if prefix < 31 {
        Some([Ipv4Addr::from(first), Ipv4Addr::from(last)])
    } else {
        None
    };
    assert_eq!(edges, expected);
    let v6_bits: u128 = kani::any();
    let v6_prefix: u8 = kani::any();
    kani::assume(v6_prefix <= 128);
    let v6 = Net {
        addr: mask_host_bits(Ipv6Addr::from(v6_bits).into(), v6_prefix),
        prefix: v6_prefix,
    };
    assert_eq!(v6.edges(), None);
    kani::cover!(prefix == 0 && edges.is_some());
    kani::cover!(prefix == 30 && edges.is_some());
    kani::cover!(prefix == 31 && edges.is_none());
    kani::cover!(prefix == 32 && edges.is_none());
}

#[kani::proof]
fn ports_constructor_and_inclusive_membership() {
    let first: u16 = kani::any();
    let last: u16 = kani::any();
    let candidate: u16 = kani::any();
    // This is the documented constructor domain, including singleton ranges.
    // Error diagnostics for invalid inputs are covered by ordinary parser tests.
    kani::assume(first != 0 && first <= last);
    let Ok(ports) = Ports::new(first, last) else {
        panic!("valid port ranges must construct");
    };
    assert_eq!(ports.first(), first);
    assert_eq!(ports.last(), last);
    let width = u32::from(last) - u32::from(first) + 1;
    let offset = u32::from(candidate).wrapping_sub(u32::from(first));
    let contains = ports.contains(candidate);
    assert_eq!(contains, offset < width);
    kani::cover!(contains && first == 1 && candidate == first);
    kani::cover!(contains && last == u16::MAX && candidate == last);
    kani::cover!(contains && first == last && candidate == first);
    kani::cover!(!contains && candidate < first);
    kani::cover!(!contains && candidate > last);
}
