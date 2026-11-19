# playpen specification

This document describes what playpen does at this commit. Anything not built
yet is marked **planned**. The reasons behind the design and the leak
analysis are in [DESIGN.md](DESIGN.md).

## 1. Purpose and non-goals

playpen runs one command so that the command, and every process it starts,
can send network traffic only to approved literal destinations (address or
network, port range, protocol) until an optional end time. All other traffic
is dropped, counted and reported. It runs as an ordinary user on Linux.

Non-goals:

- limiting how much is sent or inspecting what is sent;
- confining anything except network egress (files, other processes, CPU);
- resolving names: there is no DNS inside the sandbox;
- protecting against kernel bugs, processes started outside playpen, or an
  approved destination that forwards traffic onwards.

## 2. Concepts

**Allow rule.** One approved destination: a network (a single address, or
an address with a prefix length and no host bits set), an inclusive port
range, and a protocol (`tcp` or `udp`). Type `approval::AllowRule`.

**Approval end time.** An optional moment (`--until`) after which the
approval no longer holds. Type `approval::EndsAt`. The rules and the end
time together are an `approval::Approval`. This module does not depend on
the namespace code.

**Pass.** A hallpass permission slip (a TOML file: owner, literal
destinations with protocol and ports, an approval window with a revocation
marker, ceilings; format in hallpass's `docs/PASS-FORMAT.md`). With
`--pass FILE`, module `pass` loads it with hallpass's own loader and turns
it into the same `approval::Approval` (one allow rule per destination and
port range; end time `valid_until`), plus a `pass::PassWatch` that the
supervisor uses to re-read the file while the command runs (section 4.1).
The namespace code does not know where the rules came from.

**Sandbox.** The set of namespaces the command runs in:

- a user namespace whose root is mapped to the caller (the *outer* user
  namespace), owning
- a network namespace that has `lo` and, unless `--no-network`, one
  interface managed by pasta;
- a PID namespace, so the command sees only its own processes and they all
  end when it ends;
- a private mount namespace, with a fresh `/proc` and generated resolver
  files;
- a *nested* user namespace in which the command runs as the caller's own
  uid and gid with no capabilities.

**Ruleset.** The nftables table `inet playpen` loaded inside the network
namespace (section 6). `playpen rules` prints it.

**Privilege drop.** Running the command in the nested user namespace,
which owns nothing, with all capability sets cleared and `no_new_privs` set,
and checking the result before `exec` (section 5, step 9).

**Report.** The summary of a run: what was approved, how the command ended,
and the drop counters. Printed to stderr as text at the end of every run;
written as JSON to `--report FILE` (section 4.5).

## 3. Requirements

- Linux with user namespaces: `user.max_user_namespaces` greater than 0,
  and, where those settings exist, `kernel.unprivileged_userns_clone = 1`
  and `kernel.apparmor_restrict_unprivileged_userns = 0`.
- Kernel support for network, PID and mount namespaces, nftables with the
  `inet` family, dynamic sets with counters, and `reject`.
- `nft` (nftables). Found from the `PLAYPEN_NFT` environment variable, else
  `PATH`, else `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`.
- `pasta` (passt package), unless `--no-network`. Found the same way, with
  `PLAYPEN_PASTA`.
- Not running as root (playpen refuses).

No setuid helper, no subuid/subgid ranges, no host setting changes.

## 4. Commands

Every command accepts `--help`. A command-line usage error (unknown option,
missing `COMMAND`) prints clap's message and exits 2.

### 4.1 `playpen run`

```text
playpen run --pass FILE [--only LABEL]... [--host NAME=ADDR]...
            [--until RFC3339] [--hide PATH]... [--format text|json]
            [--report FILE] -- COMMAND [ARGS...]
playpen run [--allow SPEC]... [--host NAME=ADDR]... [--until RFC3339]
            [--no-network] [--hide PATH]... [--format text|json]
            [--report FILE] -- COMMAND [ARGS...]
```

Runs `COMMAND` (looked up on `PATH`) in the sandbox with the caller's
environment, working directory, stdin, stdout and stderr. Every other file
descriptor the caller passed is closed at `exec`.

**`--pass FILE`**. Take the approval from a hallpass pass:

- The file is read with `hallpass::load`: not a symbolic link (also if one
  is swapped in while opening), a regular file, not writable by group or
  others, at most 1 MiB, UTF-8, and every validation rule of the pass
  format. Then its window is checked at the current time
  (`check_window(now, 0)`).
- Refused (exit 2, `refused:`, the hallpass code and message, `nothing was
  run`): a missing or unreadable file (`io`), `symlink`,
  `not-regular-file`, `too-large`, `insecure-permissions`, `invalid-pass`
  (every problem listed with its field path), `not-yet-valid`, `expired`,
  `revoked`.
- The allow list is exactly the pass's destinations in file order: one
  allow rule per destination and port range (`ports = [443, "8000-8100"]`
  gives two rules), with the destination's address or network and
  protocol.
- A destination playpen cannot enforce is refused, naming its label:
  loopback (hallpass accepts it when listed; inside the sandbox loopback is
  always allowed and the host's loopback cannot be reached). Use `--only`
  to leave such a destination out.
- The end time is the pass's `valid_until`.
- Cannot be combined with `--allow`: the pass lists every destination the
  owner approved in writing, and an `--allow` beside it would add one the
  owner did not. Cannot be combined with `--no-network` either. Both
  combinations are refused with a message that says why.
- The pass's `[ceilings]` are not used and not shown. playpen limits where
  packets go, not how many, so it does not spend from the ledger and never
  writes beside the pass. A tool that counts calls or requests must spend
  itself (hallpass's `spend`).
- Times are judged against the real clock. hallpass's
  `HALLPASS_UNSAFE_TEST_CLOCK` belongs to the hallpass command and has no
  effect on playpen.

**`--only LABEL`** (repeatable, needs `--pass`). Use only the destinations
with these labels (in file order, whatever the order of the options). A
label the pass does not have is refused, listing the labels it has.
`--only` without `--pass` is refused.

**While the command runs, with `--pass`**, the supervisor re-reads the
pass every 2 seconds (`pass::RECHECK_INTERVAL`) with the same loader, and
once more just before the command starts. It stops the command, the same
way as at the end time (SIGTERM, a grace of 3 seconds, then SIGKILL to the
whole PID namespace), and prints why, when the pass:

- cannot be read or no longer validates (deleted, moved, made a symbolic
  link, made writable by others, a syntax error, a half-written file);
- is revoked, expired, or not yet valid (for example `valid_from` moved
  later, or `valid_until` moved earlier and passed: the stop then comes
  within one interval of the new end, not at it);
- has a different `id` or `approval.owner` than at start;
- no longer has a destination in use (by label), or a destination in use
  now converts to different allow rules (address, network, protocol or
  ports changed, narrowed or widened).

Any other edit (a raised or lowered ceiling, a later `valid_until`, a new
destination, a changed `hostname`, `name`, `reference`, comment, or a
destination not in use) prints once per new digest that the run continues
under the rules loaded at start. Nothing an edit adds applies to the
running command: the ruleset in the kernel is never changed after start,
and the end time is never moved later. If the pass is rejected by the
re-read just before the command starts, the run stops with `nothing was
run` (exit 1, like an end time that passes during set-up).

**`--allow SPEC`** (repeatable). Grammar:

```text
SPEC   = ADDR4 ":" PORTS "/" PROTO
       | ADDR4 "/" PREFIX ":" PORTS "/" PROTO
       | "[" ADDR6 "]" ":" PORTS "/" PROTO
       | "[" ADDR6 "/" PREFIX "]" ":" PORTS "/" PROTO
PORTS  = PORT | PORT "-" PORT        (1..65535, first <= last)
PROTO  = "tcp" | "udp"               (lower case)
ADDR4  = four plain decimal parts 0..255, no leading zeros
ADDR6  = an IPv6 address without zone (%...)
PREFIX = plain decimal, 0..32 for IPv4, 0..128 for IPv6
```

Numbers are plain decimal: no sign, no leading zeros. Refused, with a
message saying why:

- host names (anything with a letter in the IPv4 position);
- IPv4 with leading zeros, fewer than four parts, or integer forms;
- IPv6 without brackets, with a zone, or IPv4-mapped (`::ffff:a.b.c.d`);
- a prefix with host bits set (`192.0.2.1/24`), or longer than the address;
- port 0, reversed ranges, ports above 65535;
- networks that include unspecified (`0.0.0.0/8`, `::`), loopback
  (`127.0.0.0/8`, `::1`), multicast (`224.0.0.0/4`, `ff00::/8`), the IPv4
  broadcast address, or IPv6 link-local (`fe80::/10`) addresses;
- anything with whitespace, control characters or non-ASCII.

**`--no-network`**. No pasta: the sandbox has only `lo`. Cannot be combined
with `--allow`.

With none of `--pass`, `--allow` and `--no-network`, playpen refuses: an
empty allow list is almost always a mistake.

**`--host NAME=ADDR`** (repeatable). Inside the sandbox, `NAME` resolves to
`ADDR` through the generated `/etc/hosts`. `NAME` is a host name (labels of
letters, digits and `-`, not starting or ending with `-`, at most 63
characters per label and 253 in all, not all digits); it is lower-cased.
`ADDR` is a literal address, as strict as in `--allow`, with or without
brackets for IPv6. `ADDR` must be covered by some `--allow` rule (any port
or protocol), otherwise playpen refuses. With `--pass`, `ADDR` must be in
the address or network of a destination in use (after `--only`), for at
least one port; otherwise playpen refuses, naming the labels in use.

A destination's `hostname` in the pass is informational: it grants nothing
and playpen never uses it to fill `/etc/hosts`. When a destination in use
has a `hostname` that no `--host` maps, the start line (and a `--host`
refusal) ends with `host names in the pass grant nothing and are not
resolved; if the tool needs them, map them with --host NAME=ADDR
(destination LABEL)`; for a network destination `ADDR` is written
`ADDR-IN-NETWORK`.

**`--until RFC3339`**. The approval ends at this moment. It must be an RFC
3339 timestamp with an explicit offset (`Z` or `+hh:mm`); `-00:00`
("unknown offset") is refused. A time at or before now is refused. With
`--pass`, it may only make the end earlier: a time later than the pass's
`valid_until` is refused (`--until can only end the run earlier`); equal
or earlier replaces `valid_until` as the end time. While
the command runs, when the time comes playpen prints why, sends SIGTERM to
the command, and after a grace of 3 seconds kills the whole PID namespace
with SIGKILL. The deadline is fixed against the monotonic clock when the
sandbox starts.

**`--hide PATH`** (repeatable). Hide one more host path from the command:
a directory gets an empty read-only tmpfs over it; anything else gets
`/dev/null` bound over it. A path that does not exist is ignored. These are
added to the default list (section 7).

**`--report FILE`**. Write the JSON report to `FILE`, for every outcome,
refusals by policy included. The file is created (truncated) before
anything else; if that fails, playpen refuses.

**`--format text|json`**. `json` requires `--report` (otherwise refused).
The text summary is printed to stderr in both cases.

Messages on stderr, all prefixed `playpen:`:

- just before the command starts, one line: `allowing only SPECS until TIME
  (no DNS[, names NAME=ADDR, ...]); everything else is dropped`, with
  `with no time limit` when there is no `--until`; with `--no-network`:
  `no network, loopback only, ...`. With `--pass` the line starts `under
  pass ID ("NAME", owner "OWNER", sha256:DIGEST, window ends TIME,
  destinations LABEL, ...): allowing only ...` and may end with the
  `hostname` hint above. It says nothing about ceilings;
- when the end time is reached: what happened and that SIGKILL follows;
- with `--pass`, when a re-read finds a harmless edit: `the pass was edited
  (now sha256:...); nothing this run uses changed, so the command continues
  under the rules loaded at start. ...`;
- with `--pass`, when a re-read withdraws the approval: the reason (for
  example `the pass no longer permits anything (revoked): ...`, `the pass
  can no longer be read (io: ...)`, `the pass was edited and destination
  `web`, which this run uses, changed`), then that SIGTERM is sent and
  SIGKILL follows;
- at the end: how the command ended; then either `no packets to
  unapproved destinations were dropped`, or a block between lines of
  asterisks starting `WARNING: N packet(s) to UNAPPROVED destinations were
  dropped.` listing each destination with protocol, port and packet count.

### 4.2 Exit status of `run`

| Status | Meaning |
|---|---|
| the command's own status | the command ran and exited |
| 128 + N | the command was killed by signal N (including SIGTERM 15 or SIGKILL 9 sent because the approval ended or the pass withdrew it) |
| 2 | refused by policy before anything was built; nothing was run |
| 1 | the sandbox could not be built (nothing was run), or something failed after the command started |

A command can itself exit with 1 or 2. To tell these apart, use
`--report`: `outcome` is `"ran"` when the command ran (and `exit_code`
holds its status), `"refused"` or `"not_started"` when nothing ran,
`"error"` when playpen failed after starting it. Messages for the
not-run cases always contain `nothing was run`.

### 4.3 `playpen rules`

```text
playpen rules [--allow SPEC]... [--format text|json]
playpen rules --pass FILE [--only LABEL]... [--format text|json]
```

Prints the ruleset that `run` would load for these rules. Sends nothing,
creates nothing. Text: the ruleset. JSON: `{"allowed": [SPEC...], "pass":
{...} or null, "ruleset": "..."}` with canonical specs; `pass` has the same
fields as in the report (4.5). A bad spec is refused (exit 2, nothing
printed on stdout). An empty `--allow` list is allowed here and prints the
ruleset that allows nothing. With `--pass`, the pass is loaded and checked
exactly as by `run` (window included: an expired, not-yet-valid or revoked
pass is refused), and `--allow` beside it, `--only` without it, and an
unknown label are refused.

### 4.4 `playpen doctor`

```text
playpen doctor [--format text|json]
```

Checks, without changing any host setting:

1. user namespace settings (section 3);
2. `nft --version` and `pasta --version` run;
3. a self-test of the real mechanism, run only if 1 and 2 pass: playpen
   runs itself in a sandbox with pasta, with documentation addresses
   (`192.0.2.1`, `192.0.2.2`, `2001:db8::1`, `2001:db8::2`) added to the
   sandbox's own `lo`, approves some ports on the first of each, and checks
   that approved TCP, UDP and IPv6 destinations are reached and the others
   are not;
4. a second sandbox in which the command tries `nft flush ruleset`, `nft
   add table`, netlink address, link and link-state changes, raw IPv4, raw
   IPv6 and packet sockets, joining the user namespace of PID 1, and
   reading PID 1's memory, and must have no capabilities.

Each line says `ok` or `FAIL` and what is missing. Exit status 0 when all
pass, 1 otherwise. JSON: `{"ok": bool, "checks": [{"name", "ok",
"detail"}]}`.

### 4.5 JSON report fields

Written by `run --report FILE`. Field names are stable.

| Field | Type | Meaning |
|---|---|---|
| `playpen_version` | string | version of playpen |
| `outcome` | `"ran"`, `"refused"`, `"not_started"`, `"error"` | see 4.2 |
| `message` | string or null | why, for anything but `"ran"` |
| `command` | array of strings | the command line |
| `allowed` | array of strings | approved specs (canonical form once parsed; as typed when refused; with `--pass`, the rules from the pass once loaded) |
| `hosts` | array of strings | `--host` entries as given |
| `until` | string or null | end time (RFC 3339 UTC once parsed; as typed when refused); with `--pass`, `valid_until` or the earlier `--until` |
| `network` | `"pasta"` or `"none"` | |
| `exit_code` | integer or null | the command's exit status |
| `signal` | integer or null | the signal that killed the command |
| `stopped_by_until` | bool | playpen stopped the command because the end time was reached |
| `stopped_by_pass` | bool | playpen stopped the command after re-reading the pass |
| `stop_reason` | string or null | why playpen stopped the command, when `stopped_by_until` or `stopped_by_pass` |
| `pass` | object or null | null without `--pass`; else `{"file", "id", "name", "owner", "digest", "valid_until", "labels"}`: the file as given, the pass id, name, `approval.owner`, `sha256:` digest of the file at start, `valid_until` (RFC 3339 UTC), and the labels in use. When the pass could not be loaded, everything but `file` is null and `labels` is empty |
| `playpen_exit_status` | integer | the status playpen exits with |
| `dropped` | object or null | `{"packets": N, "destinations": [{"address", "protocol", "port", "packets"}], "destinations_truncated": bool}`; `port` is null for protocols other than TCP and UDP; destinations are sorted by packet count, largest first |
| `dropped_error` | string or null | why the counters could not be read |

### 4.6 Hidden test aids

Not part of the stable interface, hidden from `--help`:

- `run --lo-addr ADDR` adds `ADDR` to the sandbox's `lo` before the
  ruleset is loaded. Used by tests and `doctor` to have destinations that
  exist only inside the sandbox.
- `playpen probe reach|privs|resolve` are the checks run inside the
  sandbox by `doctor` and the tests.
- `run --pass-recheck-ms MS` re-reads the pass every `MS` milliseconds
  instead of every 2 seconds. Clamped to 50 ms .. 2 s, so it can only make
  the re-read more frequent. Used by the tests.

## 5. Start-up sequence

Each step either succeeds or stops the run with a message that ends
`nothing was run`; the command is never started after a failed step.

1. **Check the request** (CLI): load and check the pass (with `--pass`),
   parse every spec, `--host` and `--until`; apply the refusals in 4.1.
   Policy failures exit 2.
2. **Find the tools**: `nft`, and `pasta` unless `--no-network`.
3. **Check the process**: exactly one thread (required for creating a user
   namespace) and not root. Mark every descriptor above 2 close-on-exec.
   Block the forwarded signals and SIGCHLD, to be read from a signalfd.
4. **C: create the user and network namespaces.** Fork a child C. C sets
   "die with parent", unshares a user and a network namespace, and maps
   root inside to the caller (`setgroups` denied, single-id uid and gid
   maps). It brings `lo` up through netlink and adds any `--lo-addr`.
5. **C: load the ruleset** by running `nft -f -` with the ruleset on
   stdin. A non-zero exit stops the run.
6. **C: verify the ruleset**: `nft --json list table inet playpen` must show
   the output, input and forward chains on their hooks with policy drop,
   and the output chain must hold exactly the expected number of rules.
   Only then does C report "ready". Until this point the namespace has only
   `lo`.
7. **P: attach pasta** (unless `--no-network`) to C's namespaces with the
   options in section 6.3, and wait for it to exit 0 (it daemonizes after
   configuring the namespace). Failure stops the run. P checks the end time
   has not passed while setting up and, with `--pass`, re-reads the pass
   once, prints the start line, and tells C to go. (Steps 4 to 6 must
   finish within 30 seconds.)
8. **C makes itself non-dumpable**, then forks S, which unshares a PID
   namespace and forks I, its PID 1. I unshares a mount namespace, makes
   all mounts private, mounts a fresh `/proc`, hides the paths in section 7
   and binds the generated `/etc/hosts`, `/etc/resolv.conf` and
   `/etc/nsswitch.conf` read-only over the host's (each failure stops the
   run).
9. **X: drop privileges.** I forks X. X unshares a nested user namespace,
   maps the caller's uid and gid to the outer root, sets uid and gid,
   clears all capability sets, sets `no_new_privs`, and verifies: all of
   CapInh, CapPrm, CapEff and CapAmb are zero, NoNewPrivs is 1, the uid and
   gid are the caller's, raw IPv4, raw IPv6 and packet sockets cannot be
   opened, and a netlink link change is refused with `EPERM`. Any failure
   stops the run.
10. **X: exec the command.** If `exec` fails (for example the command does
    not exist), the run stops with `cannot run ...; nothing was run`
    (exit 1). Otherwise I reports "started".

While the command runs, P forwards SIGINT, SIGTERM, SIGHUP, SIGQUIT,
SIGUSR1, SIGUSR2 and SIGWINCH it receives from another process to I, which
passes them to the command. Signals the kernel generated (for example
Ctrl-C from the terminal) already reach the command directly and are not
sent twice. I reaps orphaned processes.

**Teardown.** When the command exits, I reports its status and exits; the
kernel kills every process left in the PID namespace. C then lists the
table again to read the counters, reports them, and exits. P stops pasta
if it is still running (pasta also exits when the namespace's process is
gone), removes pasta's PID file and its private directory, prints the
summary, writes the report, and exits.

If playpen itself is killed, each stage dies with its parent
(`PR_SET_PDEATHSIG`), so the sandbox goes with it.

## 6. What is allowed and dropped

### 6.1 Output chain (policy drop)

In this order:

1. `ct state established,related` accepted (replies, and ICMP errors for
   accepted flows);
2. loopback inside the sandbox: destination `127.0.0.0/8` or `::1` on `lo`
   accepted;
3. IPv6 neighbour solicitation and advertisement with hop limit 255
   accepted (address resolution with pasta's side of the link);
4. kernel-generated IPv6 MLD reports and router solicitations to
   `ff02::/16` dropped without being counted;
5. one accept rule per `--allow`: destination address or network,
   protocol, destination port range;
6. everything else: added to a per-destination set with a counter
   (address, protocol, port; port 0 for protocols other than TCP and UDP),
   counted in the `dropped` counter, and rejected with ICMP
   administratively prohibited.

So by default:

| Traffic | Default |
|---|---|
| IPv4 and IPv6 to unapproved destinations | dropped and counted (TCP connect fails with "No route to host", UDP send with "Operation not permitted") |
| ICMP and ICMPv6 (ping and others) | dropped and counted; cannot be approved |
| DNS | none: no nameserver configured, `hosts: files` only, port 53 not approved unless you approve it |
| the host's loopback | unreachable: pasta maps nothing to it and forwards no loopback ports |
| the sandbox's own loopback (`127.0.0.0/8`, `::1`) | allowed |
| the sandbox's own non-loopback addresses (copied by pasta from the host) | treated like any other destination: only if approved; such traffic stays inside the sandbox anyway |

### 6.2 Input chain (policy drop) and forward chain (policy drop)

Input accepts established/related traffic, anything arriving on `lo`, and
IPv6 neighbour solicitation/advertisement with hop limit 255. So nothing
from outside can open a connection to the command. Forward accepts
nothing.

### 6.3 pasta options

`--config-net --quiet --tcp-ports none --udp-ports none --tcp-ns none
--udp-ns none --map-host-loopback none --dns none --search none --no-dhcp
--no-dhcpv6 --no-ra --pid FILE PID`, where `FILE` is in a new private
directory (mode 0700) under `$XDG_RUNTIME_DIR` (or the temporary directory)
and `PID` is C.

## 7. Files the command sees differently

- `/etc/hosts`: `127.0.0.1` and `::1` as `localhost` (plus the machine's
  host name if it is a valid host name), then one line per `--host`.
- `/etc/resolv.conf`: comments and `options timeout:1 attempts:1`, no
  nameserver. (Not bound if the host has none.)
- `/etc/nsswitch.conf`: the host's file with its `hosts:` line replaced by
  `hosts: files`. (Not bound if the host has none.)
- `/proc`: the sandbox's own PID namespace.
- Hidden by default, if present (sockets get `/dev/null`, directories an
  empty read-only tmpfs; symlinks are followed): 
  `/run/systemd/resolve/io.systemd.Resolve`,
  `/run/systemd/resolve/io.systemd.Resolve.Monitor`, `/run/nscd/socket`,
  `/run/avahi-daemon/socket`, `/run/dbus/system_bus_socket`,
  `/run/systemd/private`, `/run/podman`, `/run/docker.sock`, and under
  `/run/user/UID`: `bus`, `systemd`, `podman`, `docker.sock`,
  `gnupg/S.dirmngr`, `pulse/native`; plus the path in
  `DBUS_SESSION_BUS_ADDRESS` if it is `unix:path=...`.

Inside, the command's uid and gid are the caller's; other users and groups
show as `nobody`.

## 8. Threat model and known limits

Guarded against: accidental or misconfigured traffic, redirects and name
resolution to unapproved places, the command's children and daemons, and
the command trying to change the firewall, interfaces or addresses, open
raw sockets, or join another network namespace.

Not guarded against, or known limits:

- kernel exploits; bugs in nftables or pasta;
- processes started outside playpen;
- host daemons reachable through filesystem sockets other than the hidden
  ones, which may act on the host's network for the command;
- an approved destination that forwards traffic further;
- volume, content and covert channels within approved flows;
- the report file can be overwritten by the command while it runs (same
  user); playpen writes it last, through the file it opened at start;
- supplementary groups of the caller still apply to file access inside;
- per-destination drop lists hold 1024 destinations per address family;
  the total count stays exact and `destinations_truncated` says when the
  list is incomplete;
- interactive job control (Ctrl-Z, `fg`) inside playpen is untested;
- with `--pass`: a revocation or edit takes effect at the next re-read (up
  to 2 seconds) plus the grace; traffic in that time is still allowed. Who
  can write the pass file can also restore it between two re-reads.
  Ceilings are not enforced by playpen.

DESIGN.md has the full list with the reasons.

## 9. Not yet built (planned)

- **planned:** approving ICMP echo to specific addresses.
- **planned:** an option to keep a hidden default socket visible.
