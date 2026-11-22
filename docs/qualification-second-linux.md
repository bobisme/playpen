# Routed peer qualification on Linux 7.1.4

On 2026-11-21, Playpen ran as UID 1000 inside a disposable QEMU 11.1.1
guest with no virtual NIC or host filesystem shares. The initramfs used
the following cached Arch Linux packages, whose signatures were checked
against the Arch Linux keyring before extraction.

| Component | Verified version |
| --- | --- |
| Linux | `7.1.4-arch1-1` |
| nftables | `1.1.6` (Arch package `1:1.1.6-3`) |
| pasta | `2026_07_28.f8df3f1` (Arch package release 1) |
| Landlock | ABI 9 |

The kernel, modules and two network tools came from those packages.
The guest's local dummy interface supplied the route to the isolated
documentation-address peers.

| Check | Observed result |
| --- | --- |
| `playpen doctor --format json` | Exit 0, egress available, Landlock and Unix-socket checks passed |
| `playpen run --no-network --report FILE -- /usr/bin/true` | Exit 0, `exec_and_exit`, Landlock socket guard, zero drops |
| Two-peer IPv4 HTTP redirect | Both approved peers logged the expected requests, with zero drops. With only the first peer approved, the second peer logged no request and the report counted one TCP drop for it. |
| IPv4 and IPv6 UDP | Each receiver saw the traffic to its approved ports. With the second port excluded, its receiver saw no datagram and the report counted one UDP drop for that address and port. |
| Routed IPv6 HTTP | The approved peer logged the expected request and the report counted zero drops. |

Both the assessment harness and the checked-in `tests/routed_peer.py`
fixture ran to completion. The fixture can be repeated against an installed
binary with `python3 tests/routed_peer.py --playpen /path/to/playpen`.

Tested source was `ae70da1160b1db104402c6605ade1571783fbb65`.
SHA-256 values identify the tested artifacts.

- **Playpen release binary** `d76052dee65de69426ee93ea51804d3a2dae5d9f106c7d68b45036f5c604dc04`
- **Routed fixture** `8271099a3a1fa708ab399a57f8c32f73a34196b52c58d0acb94cebdcf7adbbf2`
- **Guest serial log** `3d71598188068296b5d875f089e5f2d9b8b9100687c3c47fd1664e2568d8d0d5`

This run qualifies the listed scenarios on the exact combination above.
It exercised traffic through pasta to peers in the guest. Physical
interfaces and external networks were outside the fixture.
