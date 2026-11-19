# playpen design

This document gives the reasons for the mechanism and the leak analysis.
What playpen does, option by option, is in [spec.md](spec.md); this file
does not repeat it.

## Choices

**Namespaces, not a proxy or LD_PRELOAD.** A proxy only sees tools that
honour proxy settings; LD_PRELOAD misses static binaries and direct
syscalls. A network namespace whose only route out is filtered by the
kernel covers every process and every socket type.

**nftables inside the namespace.** The namespace is created with a mapped
root, which holds `CAP_NET_ADMIN` over it, so nftables can be loaded there
without any host privilege. The ruleset is passed to `nft` on stdin and is
rendered only from typed values (parsed addresses, integers, an enum), so
no command-line text can inject nftables syntax. A property test checks
that every rendered allow line has the fixed shape
`ip|ip6 daddr ADDR tcp|udp dport PORTS accept`.

**pasta for connectivity.** It is the rootless user-mode network stack that
is installed (slirp4netns is not). It attaches to an existing namespace
given a PID, and forks to the background only once the namespace is
configured, so its exit status is a reliable "up" signal.

**`reject` before the drop policy.** The chain policy is drop, but the last
rule rejects with `admin-prohibited`. Without it a blocked TCP connect hangs
for minutes in SYN retries; with it the tool fails at once with "No route to
host", which is clearer and makes test runs fast. The policy is still drop,
so anything that gets past the reject (nothing should) is dropped.

**nix, not rustix.** playpen needs fork, unshare, setns, mount, signalfd,
prctl (pdeathsig, dumpable, no_new_privs), setresuid/gid, waitpid, poll and
netlink sockets. nix has safe wrappers for all of them; rustix has no
supported `fork`. `libc` (already a dependency of nix) is used for the one
call nix lacks, `capset`.

**`unsafe`** appears in three places, each with a comment saying why it is
sound: `fork` (the process is checked to be single-threaded first, and
playpen starts no threads), `capset` (fixed `repr(C)` structs matching the
kernel ABI), and borrowing raw descriptors listed in `/proc/self/fd` to set
close-on-exec.

**Single-id mappings.** The outer namespace maps only `0 -> caller`, the
nested one only `caller -> 0`. No subuid/subgid ranges and no setuid
helper (newuidmap) are needed. The price: inside, every other uid and gid
shows as `nobody`, and supplementary groups cannot be dropped (writing
`setgroups` is denied in an unprivileged user namespace), so they still
count for file access. That is why the docker socket is hidden: a member of
the `docker` group could otherwise start a container on the host network.

## The mechanism, step by step

The process tree and the order are given in the spec. The points that
matter for safety:

1. **No connectivity before the rules.** The network namespace starts with
   only `lo`. The ruleset is loaded and verified first; pasta is attached
   only afterwards. There is no moment at which a route out exists without
   the filter.
2. **The verification does not trust nft's exit status alone.** After the
   load, playpen lists the table as JSON and checks the three base chains,
   their hooks and drop policies, and the number of rules in the output
   chain. A broken or fake `nft` that exits 0 without loading is caught
   (tested with a fake `nft` that does exactly that).
3. **The process holding the capabilities never runs user code** and is
   made non-dumpable before any user code exists. It stays dumpable only
   until pasta has attached, because pasta (running as the same user,
   outside) must open its `/proc/PID/ns/*` entries.
4. **The privilege drop is a nested user namespace.** Capabilities over a
   network namespace belong to the user namespace that owns it. The
   command runs in a child user namespace, so even a full capability set
   there gives nothing over the network namespace. On top of that playpen
   sets the uid and gid, clears all capability sets with `capset`, and sets
   `no_new_privs` (so file capabilities and setuid bits do nothing). Before
   `exec` it checks `/proc/self/status` (all capability sets zero,
   NoNewPrivs 1, the right uid and gid) and checks that raw IPv4, raw IPv6
   and packet sockets and a netlink link change all fail with `EPERM`. If
   any check fails the command is not run.
5. **PID namespace with an init.** The command is not PID 1 (PID 1 ignores
   signals it has no handler for, which would break SIGTERM). A small init
   forwards signals and reaps orphans. When the command exits, init exits,
   and the kernel kills everything left in the PID namespace, so nothing
   the command started outlives it.
6. **Death of playpen kills the sandbox.** Each stage sets
   `PR_SET_PDEATHSIG(SIGKILL)` and checks its parent is still the expected
   one. If playpen is killed with SIGKILL, the chain collapses, and pasta
   exits when the namespace's process is gone.

## Leaks considered

| Leak | How it is closed | Tested |
|---|---|---|
| Traffic to any unapproved address, port or protocol, IPv4 or IPv6 | output policy drop; only listed `daddr`+`dport`+protocol accepted | yes (TCP, UDP, IPv6, network ranges, protocol mismatch) |
| IPv6 forgotten while IPv4 is filtered | `inet` family table covers both; an IPv4 approval never opens IPv6 | yes |
| ICMP / ICMPv6 as a side channel | not approvable; only neighbour solicitation/advertisement with hop limit 255 (link-local by RFC 4861) pass; kernel MLD reports and router solicitations are dropped silently; ICMP errors for accepted flows pass as `related` | NDP needed for pasta works (IPv6 tests pass through pasta-configured namespaces); not tested separately |
| pasta's gateway mapped to the host's loopback | `--map-host-loopback none`; and the gateway address is not approved, so the filter drops it too | flag checked by unit test; filter drop covered by "different address blocked". Not tested end to end, because testing it would need an approval of the real gateway, which would send to the LAN router if the mapping were off |
| pasta forwarding namespace loopback ports to the host (`-T auto`, its default) | `--tcp-ns none --udp-ns none`. The filter does **not** catch this: it accepts loopback inside the namespace, and pasta's sockets there are spliced to the host | yes: a host listener on 127.0.0.1 and ::1 below 32768 is not reached. Removing the flags makes the test fail (checked). Note: pasta's auto mode skips the ephemeral range, so a test on an ephemeral port proves nothing |
| pasta forwarding host ports into the namespace | `--tcp-ports none --udp-ports none`; input chain drops new inbound connections anyway | flag unit-tested |
| DNS forwarded by pasta | `--dns none --search none`, no `--dns-forward`; port 53 to the gateway is not approved | flag unit-tested |
| Names resolved by host daemons over filesystem sockets (systemd-resolved varlink, nscd, avahi) | generated `nsswitch.conf` with `hosts: files`; their sockets are bound over with `/dev/null` | `--host` name resolves, other names do not |
| Host files changed | none are: all overrides are bind mounts in a private mount namespace | yes (`/etc/hosts` unchanged) |
| Command changes the rules, adds addresses or links, opens raw/packet sockets, joins init's user namespace, reads init's memory | nested user namespace, no capabilities, init non-dumpable | yes, each one, for the command and for a grandchild; and the rules still block after the command ran `nft flush ruleset` |
| Command joins the host's network namespace | it would need `CAP_SYS_ADMIN` in the host's user namespace; host processes are invisible (PID namespace, fresh `/proc`) | indirectly (no capabilities; `setns` to init's namespace denied) |
| Inherited sockets from the caller (a host-namespace socket on fd 3+) | every descriptor above 2 is marked close-on-exec before the sandbox starts | not tested |
| Children and daemons escaping | PID namespace; init's exit kills them all | yes (a background job does not outlive the command) |
| Host daemons that start processes or open connections for the command (session/system D-Bus, systemd user manager, podman, docker, dirmngr, PulseAudio tunnels) | known sockets hidden (`/dev/null` bind for sockets, empty read-only tmpfs for directories); `--hide` for more | the session bus is no longer a socket inside |
| ptrace of the privileged helper or of playpen | helpers non-dumpable; playpen and other host processes invisible in the PID namespace; Yama ptrace_scope 1 on this machine adds another layer | `/proc/1/mem` and `/proc/1/ns/user` denied |
| A fake or broken `nft` | output structure verified after load | yes |
| pasta not coming up | its exit status is checked; the command is not started | yes (fake pasta) |
| Approval running out while the command runs | timer in playpen: SIGTERM, then SIGKILL after 3 s to the PID namespace's init | yes, both paths |

## What is not closed

- **Filesystem sockets to host daemons in general.** The abstract socket
  namespace is per network namespace, so abstract sockets are isolated,
  but a path socket is reachable by anyone with file permissions. playpen
  hides a list of known dangerous ones. Others on your machine (an
  ssh-agent with forwarding, a local proxy's control socket, an X server, a
  Wayland compositor, an editor's server) remain reachable. If one of them
  can make network connections for a client, it is a way out. Use `--hide`.
- **The approved destination.** If it is a proxy, a VPN endpoint or a
  jump host, traffic continues from there. playpen cannot see it.
- **Volume and content.** No rate limits, no inspection.
- **Covert channels through approved flows**, and timing channels.
- **Kernel or tool bugs.** A kernel exploit, or a bug in nftables
  (ruleset evaluation) or in pasta (which runs on the host), defeats the
  guard.
- **Time is wall-clock at start.** `--until` is converted to a monotonic
  deadline when the command starts; changing the system clock later does
  not move it.
- **Report file tampering.** The command runs as the same user and could
  write to the `--report` path while it runs. playpen writes the report
  through the file it opened before starting, after the command and every
  process it started are gone, so the final content is playpen's, unless
  the command replaced the path with another file. Put the report in a
  directory the command is not expected to touch.
- **Interactive job control** (a shell inside playpen using Ctrl-Z and
  `fg`) was not tested.

## Things that did not work rootless, and what was done instead

- **Binding a memfd over `/etc/hosts`.** The kernel refuses to bind-mount
  from a memfd's internal mount (`EINVAL`). playpen instead mounts a small
  tmpfs over `/tmp` for a moment, writes the generated files there, binds
  them into place read-only, and detaches the tmpfs again; the bind mounts
  keep the files alive and the real `/tmp` is visible again.
- **Making the capability-holding process non-dumpable from the start.**
  Non-dumpable `/proc/PID/*` entries are owned by root, so the process
  could not write its own `uid_map`, and pasta could not open its
  namespace files. The process is made non-dumpable after both, before any
  user code exists.
- **Dropping supplementary groups.** Not possible in an unprivileged user
  namespace (see "Single-id mappings").
- **Kernel logging of dropped packets.** `log` statements do nothing in a
  non-initial network namespace by default (`nf_log_all_netns`), so
  per-destination counts come from a dynamic nftables set with per-element
  counters instead. It holds 1024 destinations per address family; beyond
  that the total is still exact and the report says the list is
  truncated.
