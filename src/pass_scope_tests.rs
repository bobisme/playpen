//! Finite comparison of Playpen grants with the pinned Hallpass decision.

use super::*;
use hallpass::{Decision, Protocol, Target};
use std::net::{IpAddr, Ipv6Addr};
use time::macros::datetime;

const NOW: OffsetDateTime = datetime!(2026-01-01 12:00:00 UTC);
const HEADER: &str = r#"
format = 1
id = "finite-scope"
name = "Finite packet scope"

[approval]
owner = "Pat Owner"
reference = "fixture"
operator = "Sam Tester"
valid_from = 2026-01-01T00:00:00Z
valid_until = 2026-01-02T00:00:00Z
revoked = false

[ceilings]
calls = 6
"#;

// Nested and disjoint IPv4 scopes, a duplicate grant, a single-host
// exception, /31 host semantics, and overlapping native IPv6 scopes.
const DESTINATIONS: [(&str, &str, &str, &str); 8] = [
    (
        "v4-wide",
        "network",
        "192.0.2.0/28",
        r#"tcp|[443, "445-446"]"#,
    ),
    ("v4-nested", "network", "192.0.2.4/30", r#"udp|["442-445"]"#),
    ("duplicate", "network", "192.0.2.4/30", r#"udp|["442-445"]"#),
    ("v4-host", "address", "192.0.2.7", "tcp|444"),
    ("v4-pair", "network", "192.0.2.6/31", r#"tcp|["443-444"]"#),
    (
        "v4-disjoint",
        "network",
        "192.0.2.32/30",
        r#"udp|["65534-65535"]"#,
    ),
    ("v6-wide", "network", "2001:db8::/124", r#"udp|["1-4"]"#),
    ("v6-nested", "network", "2001:db8::4/126", r#"udp|["4-7"]"#),
];

fn fixture(mask: usize) -> Pass {
    let mut text = HEADER.to_owned();
    for (index, &(label, kind, addr, scope)) in DESTINATIONS.iter().enumerate() {
        if mask & (1 << index) != 0 {
            let (proto, ports) = scope.split_once('|').expect("protocol and port scope");
            writeln!(
                text,
                "\n[[destination]]\nlabel = \"{label}\"\n{kind} = \"{addr}\"\nprotocol = \"{proto}\"\nports = {ports}"
            )
            .expect("write to String");
        }
    }
    Pass::parse(&text).unwrap_or_else(|problems| panic!("invalid fixture: {problems:?}"))
}

fn packets() -> Vec<Target> {
    let mut addresses: Vec<IpAddr> = (0..=16)
        .chain(31..=36)
        .map(|tail| IpAddr::from([192, 0, 2, tail]))
        .collect();
    addresses.push(IpAddr::from([192, 0, 1, 255]));
    addresses
        .extend((0..=16).map(|tail| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, tail))));
    addresses.push(IpAddr::V6(Ipv6Addr::new(
        0x2001, 0xdb7, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    )));

    let mut packets = Vec::new();
    for ip in addresses {
        for port in (1..=8).chain(441..=447).chain(65533..=65535) {
            for protocol in [Protocol::Tcp, Protocol::Udp] {
                packets.push(Target { ip, port, protocol });
            }
        }
    }
    packets
}

fn reference(pass: &Pass, packets: &[Target]) -> Vec<bool> {
    // This test concerns literal packet tuples and the full-pass address
    // decision. Host names, request limits, and fixed kernel exceptions
    // such as in-sandbox loopback and established traffic are out of scope.
    packets
        .iter()
        .map(|p| {
            matches!(
                pass.permits(p, NOW, time::Duration::ZERO),
                Decision::Allowed { .. }
            )
        })
        .collect()
}

fn allows(approval: &Approval, target: Target) -> bool {
    let proto = match target.protocol {
        Protocol::Tcp => Proto::Tcp,
        Protocol::Udp => Proto::Udp,
    };
    approval.permits_packet(target.ip, proto, target.port)
}

fn disagreement(approval: &Approval, packets: &[Target], reference: &[bool]) -> Option<Target> {
    assert_eq!(packets.len(), reference.len());
    packets
        .iter()
        .zip(reference)
        .find_map(|(&packet, &allowed)| (!allowed && allows(approval, packet)).then_some(packet))
}

fn selected(pass: &Pass, labels: &[String]) -> FromPass {
    from_pass(
        Path::new("finite-fixture"),
        pass,
        Digest::of(b"finite-fixture"),
        labels,
        NOW,
    )
    .expect("valid packet scope")
}

#[test]
fn label_selection_stays_within_the_full_pass_packet_scope() {
    let packets = packets();
    let mut masks: Vec<usize> = (1..1 << DESTINATIONS.len()).collect();
    // A failure reports the smallest full pass and selected scope first.
    masks.sort_unstable_by_key(|&m| (m.count_ones(), m));
    let mut checked = 0;
    let mut admitted = false;
    let mut denied = false;
    for &full in &masks {
        let pass = fixture(full);
        let reference = reference(&pass, &packets);
        assert_eq!(
            disagreement(&Approval::new(vec![], None), &packets, &reference),
            None
        );
        for &mask in masks.iter().filter(|&&m| m & full == m) {
            let labels: Vec<_> = DESTINATIONS
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, &(label, _, _, _))| label.to_owned())
                .collect();
            let converted = selected(&pass, &labels);
            assert_eq!(
                disagreement(&converted.approval, &packets, &reference),
                None,
                "full fixture {full:08b}; selected labels {labels:?}"
            );
            if mask == full {
                assert_eq!(selected(&pass, &[]).approval, converted.approval);
                admitted |= packets.iter().any(|&p| allows(&converted.approval, p));
                denied |= packets.iter().any(|&p| !allows(&converted.approval, p));
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 6_305);
    assert!(admitted && denied);
}

#[test]
fn inclusion_comparison_detects_a_stricter_synthetic_reference() {
    let packets = packets();
    let approval = selected(&fixture(1 << 7), &[]).approval;
    let stricter = fixture(1 << 6);
    let reference = reference(&stricter, &packets);
    assert!(
        packets
            .iter()
            .zip(&reference)
            .any(|(&p, &r)| r && allows(&approval, p))
    );
    assert!(disagreement(&approval, &packets, &reference).is_some());
}

#[test]
fn selected_rendering_and_recheck_keep_full_pass_edges() {
    let labels = ["v4-wide".to_owned()];
    let full = fixture(0b11);
    let loaded = selected(&full, &labels);
    let selected_rule = &loaded.approval.rules()[0];
    assert_eq!(
        loaded.approval.exclusions(selected_rule),
        [0, 4, 7, 15].map(|tail| Ipv4Addr::new(192, 0, 2, tail))
    );
    assert!(
        crate::ruleset::render_approval(&loaded.approval)
            .contains("ip daddr != { 192.0.2.0, 192.0.2.4, 192.0.2.7, 192.0.2.15 }")
    );
    assert!(
        !loaded
            .approval
            .covers_addr(Ipv4Addr::new(192, 0, 2, 7).into())
    );

    let mut watch = selected(&fixture(0b1), &labels).watch;
    let edit = Digest::of(b"changed fixture");
    assert!(
        matches!(watch.judge(&full, edit, NOW), Recheck::Stop(message)
        if message.contains("network or broadcast address"))
    );
    let mut watch = loaded.watch;
    assert!(matches!(
        watch.judge(&fixture(0b1), edit, NOW),
        Recheck::Edited(_)
    ));
}
