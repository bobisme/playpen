# nftables table readbacks

Recorded on Linux 7.2.8-arch1-2 with nftables 1.1.7 (JSON schema 1).
Playpen's generated rules were loaded into disposable unprivileged user
and network namespaces with `unshare -Urn`. Only documentation addresses
were granted. The JSON was reformatted without changing its values.

```sh
playpen rules > empty.nft
playpen rules --allow 192.0.2.0/30:8000-8002/tcp \
    --allow 192.0.2.4/32:53/udp --allow '[2001:db8::/124]:80/udp' > nonempty.nft
playpen rules --allow 192.0.2.0/28:444/tcp --allow 192.0.2.6/31:445/udp \
    --allow 192.0.2.4/30:443/tcp --allow '[2001:db8::1]:1024/tcp' > edges.nft
playpen rules --allow 192.0.2.0/30:8000-8002/tcp --until 2026-12-01T12:34:56Z > until.nft
playpen rules --allow 192.0.2.0/30:8000-8002/tcp --allow 192.0.2.4/32:53/udp \
    --allow '[2001:db8::/124]:80/udp' --report-contacts > contacts.nft
playpen rules --allow 192.0.2.0/30:8000-8002/tcp --until 2026-12-01T12:34:56Z \
    --on-drop cut > on-drop.nft
playpen rules --allow 192.0.2.0/30:8000-8002/tcp --allow 192.0.2.4/32:53/udp \
    --allow '[2001:db8::/124]:80/udp' --report-contacts --on-drop stop > contacts-on-drop.nft
list='nft -f "$1" && TZ=UTC0 nft --json list table inet playpen'
unshare -Urn sh -c "$list" _ edges.nft
unshare -Urn sh -c "$list" _ empty.nft
unshare -Urn sh -c "$list" _ nonempty.nft
unshare -Urn sh -c "$list" _ until.nft
unshare -Urn sh -c "$list" _ contacts.nft
unshare -Urn sh -c 'nft -f "$1" && TZ=UTC0 nft --numeric --json list table inet playpen' _ nonempty.nft
unshare -Urn sh -c 'nft -f "$1" && TZ=Asia/Kolkata nft --json list table inet playpen' _ until.nft
unshare -Urn sh -c "$list" _ on-drop.nft
unshare -Urn sh -c 'nft -f "$1" && TZ=UTC0 nft --numeric --json list table inet playpen' _ on-drop.nft
unshare -Urn sh -c "$list" _ contacts-on-drop.nft
```

The last one is `until-kolkata.json`. `nft --json` prints `meta time` as a
date without an offset (`"2026-12-01 12:34:56"`), in the local time zone of
the `nft` process, with or without `--numeric`. Playpen lists the table with
`TZ=UTC0` and reads that date as UTC. The Kolkata dump names another moment
(`"2026-12-01 18:04:56"`) and is refused.

The two before the last are `on-drop.json` and `on-drop-numeric.json`. With
`--on-drop` the refusal path adds the mark 0 to the `cut` set before the
`dropped` counter (`{"set": {"op": "add", "elem": 0, "set": "@cut"}}`, the
same in both spellings) and ends with `drop` instead of the reject. The
`cut` set is declared with `size 65535`, the size nft gives a set that a
rule adds to when none is declared, so the readback has `"size": 65535`
with either.

The comparator accepts the following expression vocabulary from these dumps.
It checks connection state, interface, IP destination and prefix, IPv6 hop
limit and ICMP type, transport protocol and inclusive ports, the packet
mark against the `cut` set, the time, the four dynamic additions to the
drop sets, the two to the `seen` sets and, with `--on-drop`, the addition
of the mark 0 to the `cut` set, the named counters, and accept, drop,
`goto contacted` and ICMPx reject verdicts. Named and
numeric spellings from the recorded dumps are equivalent, as are anonymous
set member permutations and textual IP address spellings. Rule order and
expression order are checked. Handles, counter values and the elements of
the dynamic drop sets vary at runtime. The `cut`, `seen4` and `seen6` sets
must be empty. Unknown material objects and expressions are refused.

Startup qualification used Playpen's normal `run` path on the same host
with pasta 2026_09_25.df90211. A temporary forwarding adapter captured the
real `nft` JSON at startup and teardown. Both `run --no-network -- true`
and `run --allow 192.0.2.1:8000-8002/tcp -- true` succeeded. With the
`cut` rule added since, the readbacks have 12 and 13 output rules
respectively, with four input rules and an empty forward chain; an end
time adds one rule to each of the two chains. The integration suite separately checks rejection of
a failing load, an empty readback and a narrower reported range. The
narrower-readback adapter delegates the real load unchanged.

`contacts.json` is the `nonempty.json` approval with `--report-contacts`,
recorded on the same host with nftables 1.1.7. It differs from
`nonempty.json` only in the `contacted` counter, the `seen4` and `seen6`
sets, the regular `contacted` chain with its four rules, and `goto
contacted` in place of `accept` in the three grant rules. nft prints the two
additions in that chain without their `meta nfproto` matches.

`contacts-on-drop.json` is the `contacts.json` approval with `--on-drop`
as well (`cut` and `stop` render the same table). It differs from
`contacts.json` only in the size of the `cut` set, the addition to it
before the `dropped` counter, and `drop` in place of the reject: the two
options change separate parts of the table.
