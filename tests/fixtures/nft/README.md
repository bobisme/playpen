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
unshare -Urn sh -c 'nft -f "$1" && nft --json list table inet playpen' _ edges.nft
unshare -Urn sh -c 'nft -f "$1" && nft --json list table inet playpen' _ empty.nft
unshare -Urn sh -c 'nft -f "$1" && nft --json list table inet playpen' _ nonempty.nft
unshare -Urn sh -c 'nft -f "$1" && nft --numeric --json list table inet playpen' _ nonempty.nft
```

The comparator accepts the following expression vocabulary from these dumps.
It checks connection state, interface, IP destination and prefix, IPv6 hop
limit and ICMP type, transport protocol and inclusive ports, the four dynamic
set additions, the named drop counter, and accept, drop and ICMPx reject
verdicts. Named and numeric spellings from the recorded dumps are equivalent,
as are anonymous set member permutations and textual IP address spellings.
Rule order and expression order are checked. Handles, counter values and
dynamic set elements vary at runtime. Unknown material objects and expressions
are refused.

Startup qualification used Playpen's normal `run` path on the same host
with pasta 2026_09_25.df90211. A temporary forwarding adapter captured the
real `nft` JSON at startup and teardown. Both `run --no-network -- true`
and `run --allow 192.0.2.1:8000-8002/tcp -- true` succeeded. The readbacks
had 11 and 12 output rules respectively, with three input rules and an
empty forward chain. The integration suite separately checks rejection of
a failing load, an empty readback and a narrower reported range. The
narrower-readback adapter delegates the real load unchanged.
