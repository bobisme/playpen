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

## Passes (`--pass`)

A hallpass pass is the owner's written approval in a form a tool can
check. `--pass` exists so the operator does not retype it as `--allow`
flags, where a typo widens or narrows the approval without anyone
noticing.

**hallpass's own loader, not a second parser.** playpen calls
`hallpass::load`, so the pass is held to exactly the rules `hallpass check`
applies (no links, mode, size, every validation rule), and an operator sees
the same codes and messages from both tools. The price is three crates
(sha2, toml, thiserror, with their own small dependencies). playpen
depends on hallpass with `default-features = false`: hallpass's binary and
clap sit behind its default `cli` feature, added for this.

**Same `Approval`, plus a watch handle.** The pass becomes the same list of
allow rules and the same end time as `--allow` and `--until`; the
namespace code is unchanged except that the supervisor (P) holds a
`PassWatch` and calls it on a timer. Nothing about the start-up order or
the ruleset changes.

**`--pass` and `--allow` cannot be combined.** The point of a pass is that
every reachable destination is one the owner put in writing. An `--allow`
beside it would add a destination nobody approved, and the report would
still name the pass and its owner, which would be misleading. `--only`
exists to go the other way: narrow the pass, never widen it. `--no-network`
with a pass is refused as a contradiction.

**`--until` only shortens.** The owner's `valid_until` is the outer limit;
an operator may want to stop earlier (end of a working day), never later.

**A name grants nothing.** A destination's `hostname` is informational in
hallpass. playpen never writes it into `/etc/hosts` on its own: doing so
would make the pass's text, not the operator, decide what a name resolves
to inside the sandbox, and a wrong `hostname` would silently send a tool to
the destination of another label. The start line says how to map it with
`--host` instead, and `--host` must point at an address of a destination in
use.

**Loopback destinations are refused.** hallpass allows `127.0.0.0/8` and
`::1` when listed. playpen cannot enforce them: inside the sandbox loopback
is always allowed and is the sandbox's own, and the host's loopback is not
reachable at all. Refusing (with a hint to leave the label out with
`--only`) is clearer than a rule that means something else.

**Ceilings are not spent.** playpen sees packets, not calls or requests,
and cannot tell what one unit of a ceiling is. Spending would need a
meaning it does not have, so it neither spends nor mentions ceilings. The
tool that knows its units spends.

**Re-reading while the command runs.** The pass can be revoked or edited
during a run. P re-reads it every 2 seconds, once more just before the
command starts, and judges the result:

- anything that makes the pass permit nothing (unreadable, invalid,
  revoked, expired, not yet valid) stops the command;
- an edit to anything the run relies on stops it: the `id` or
  `approval.owner` (the identity the report names), or any destination in
  use (by label: removed, or converting to different allow rules, even if
  wider);
- any other edit is reported once and the run continues **under the rules
  loaded at start**.

Why keep running rather than stop on any change: the ruleset in the kernel
is fixed when the sandbox starts, and playpen never changes it afterwards
(C, the process that holds the capabilities over the network namespace,
only waits after "go" and reads the drop counters at the end; reloading
rules mid-run would add a second load, and a moment of changing rules, to
the most sensitive step). So an edit can never widen the running command's
access, whatever it says, and every edit that would narrow what is in use
already stops it. What is left (a raised ceiling, a later `valid_until`, a
new destination, a corrected `reference`) changes nothing the command can
do. Stopping a long scan because the owner raised a ceiling it does not
even use would only teach operators to avoid editing the pass during a
run, which is when revocation matters. The notice tells the operator that
the edit does not apply until a new run. A later `valid_until` does not
extend the run: the end time is fixed at start like the rules.

Why polling and not inotify: editors replace files by rename, which an
inotify watch on the old inode misses unless the directory is watched too;
a deleted or moved directory needs more cases; polling a small file every
2 seconds costs nothing measurable and fails closed in every case (a file
that cannot be read stops the run). A file caught half-written also stops
the run; editors that write a new file and rename it never show one.

The interval is the delay between the owner's revocation reaching the file
and SIGTERM. 2 seconds keeps that well below a human reaction time without
measurable load. It is the constant `pass::RECHECK_INTERVAL`; the hidden
`--pass-recheck-ms` may only shorten it (tests use 200 ms).

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
| A pass revoked, deleted or edited (destination in use) while the command runs | re-read every 2 s; SIGTERM, then SIGKILL after 3 s | yes (revoke, delete, port change) |
| A pass edited to add a destination or extend the window during a run | rules and end time fixed at start; never reloaded | yes (added destination stays blocked) |
| A pass swapped for a symbolic link, or made writable by others | hallpass's loader refuses both, at start and on every re-read | at start (symlink, mode 0666) |
| `--allow` adding a destination beside a pass | refused | yes |

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
- **The re-read gap.** A revoked pass stops the command at the next
  re-read (up to 2 s) plus the grace (3 s); the command can still send in
  that time. Anyone who can write the pass file can also put the old
  content back between two re-reads, or edit it before the run starts;
  hallpass's own threat model applies (it does not protect against a
  writer of the engagement directory).
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
