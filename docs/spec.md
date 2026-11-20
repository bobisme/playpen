# playpen specification

This document describes what playpen does at this commit. Anything not built
yet is marked **planned**. The reasons behind the design and the leak
analysis are in [DESIGN.md](DESIGN.md).

## Changes since v0.1

If you used v0.1, these will be different:

- **Host Unix sockets are unreachable by default, wherever they are.**
  v0.1 hid a fixed list (D-Bus, systemd, resolvers, container engines,
  dirmngr, PulseAudio). Now every pathname socket created outside the
  sandbox is refused (Landlock), so the session and system bus,
  `systemctl --user`, `ssh-agent`, `gpg-agent`, PulseAudio/PipeWire,
  syslog and the journal (log messages are lost), and user or group names
  served by sssd, systemd-userdb or nscd no longer work inside. Bring one
  back with `--expose PATH` (for example `--expose "$SSH_AUTH_SOCK"`);
  graphical programs need `--display`.
- **The runtime directory is private and empty.** `/run/user/UID` (and
  `XDG_RUNTIME_DIR`) is a fresh writable directory, mode 0700. Files and
  sockets the command makes there vanish with the run. The same holds for
  `/tmp/.X11-unix`, `/tmp/.ICE-unix`, `/tmp/.XIM-unix`, `/tmp/.font-unix`,
  `/tmp/tmux-UID`, `/dev/shm` and `/dev/mqueue`. `/tmp` itself is still
  the host's.
- **A new kernel requirement**: Landlock ABI 9. On older kernels `run`
  does not start; `--without-landlock` runs with the weaker mount-only
  hiding (section 4.1).
- **Standard streams that are network sockets are refused** (UDP and
  TCP, connected or not).
- **Ctrl-Z stops the whole sandbox**, and `fg` resumes it. On kernels that
  still allow `TIOCSTI`, the command runs in its own session without a
  controlling terminal (section 4.1, `--new-session`).
- **The start line** has new clauses about host sockets, exposed paths and
  the session; **the report** has the new fields `socket_guard`,
  `exposed`, `display` and `new_session`.

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
- a private mount namespace, with a fresh `/proc`, generated resolver
  files, and private directories where host sockets live (section 7);
- an IPC namespace of its own;
- a *nested* user namespace in which the command runs as the caller's own
  uid and gid with no capabilities;
- a Landlock domain that refuses connections to Unix sockets created
  outside the sandbox, except exposed ones (unless `--without-landlock`).

**Exposed path.** A host socket, or a directory of sockets, the command
may reach after all: `--expose PATH` and the display sockets of
`--display`.

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
- Kernel support for network, PID, mount and IPC namespaces, nftables
  with the `inet` family, dynamic sets with counters, and `reject`.
- Landlock ABI 9 or later (`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`), with
  `landlock` in the kernel's active security modules. Without it `run`
  does not start unless `--without-landlock` is given.
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
            [--until RFC3339] [SOCKETS] [--format text|json]
            [--report FILE] -- COMMAND [ARGS...]
playpen run [--allow SPEC]... [--host NAME=ADDR]... [--until RFC3339]
            [--no-network] [SOCKETS] [--format text|json]
            [--report FILE] -- COMMAND [ARGS...]

SOCKETS = [--expose PATH]... [--display] [--hide PATH]...
          [--without-landlock] [--new-session]
```

Runs `COMMAND` (looked up on `PATH`) in the sandbox with the caller's
environment, working directory, stdin, stdout and stderr. Every other file
descriptor the caller passed is closed at `exec`. The environment is not
changed: variables such as `DBUS_SESSION_BUS_ADDRESS` or `SSH_AUTH_SOCK`
still name sockets the command cannot reach.

Standard input, output or error that is a socket is checked first.
Allowed: Unix sockets. Refused (exit 2, `standard output is ...;
nothing was run`): every IP socket, that is UDP and raw sockets (they can
send to any address) and TCP sockets, listening, unconnected or connected
(a connected one can be disconnected and connected again to any address);
and sockets of any other family. With `--without-landlock` a Unix socket
is allowed only when it is a connected stream or sequenced-packet socket
or a listening one; any other could be connected to a Unix socket of the
host. The message says to give the command a pipe, a file or a terminal
instead (`| cat`, `< /dev/null`).

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
label the pass does not have is refused, listing the labels it has. Network
and broadcast exclusions come from the complete pass. An unselected
destination can exclude an address from a selected network rule. A
single-address rule grants its own ports and protocol only when selected.
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
  ports changed, narrowed or widened);
- adds a network or broadcast exclusion inside a network rule already in
  use, including through an unselected destination.

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
or protocol), otherwise playpen refuses; the network and broadcast
addresses of a listed network (section 6.1) are not covered. With `--pass`, `ADDR` must be in
the address or network of a destination in use (after `--only`), for at
least one port; otherwise playpen refuses, naming the labels in use.

A destination's `hostname` in the pass is informational: it grants nothing
and playpen never uses it to fill `/etc/hosts`. When a destination in use
has a `hostname` that no `--host` maps, the start line (and a `--host`
refusal) ends with `host names in the pass grant nothing and are not
resolved; if the tool needs them, map them with --host NAME=ADDR
(destination LABEL)`; for a network destination `ADDR` is written
`ADDR-IN-NETWORK`.

A destination's `names` in the pass (the only host names the owner approved
on that address) is **not enforced**: playpen filters addresses and ports
and cannot see the name inside a request, least of all an encrypted one.
The rules for such a destination are the same as without `names`. When a
destination in use lists names, a second start line says so: `playpen:
NOTE: the pass approves these destinations only for the listed host names:
LABEL (NAME, NAME). … it does NOT enforce this; the command must send only
those names`. Keeping to the names is the job of the tool that writes the
request (`hallpass permits --name`). A change to `names` alone changes no
rule, so the running command is not stopped.

**`--until RFC3339`**. The approval ends at this moment. It must be an RFC
3339 timestamp with an explicit offset (`Z` or `+hh:mm`); `-00:00`
("unknown offset") is refused. A time at or before now is refused. With
`--pass`, it may only make the end earlier: a time later than the pass's
`valid_until` is refused (`--until can only end the run earlier`); equal
or earlier replaces `valid_until` as the end time. While
the command runs, when the time comes playpen prints why, sends SIGTERM to
the command, and after a grace of 3 seconds kills the whole PID namespace
with SIGKILL. The time has come when a monotonic deadline fixed at the
start of the sandbox has passed, or the system clock shows the end time,
whichever is first: setting the clock back does not extend the run, and
time the machine spent suspended counts.

**Host Unix sockets.** By default the command cannot connect to, or send
by address to, any pathname Unix socket created outside the sandbox
(Landlock; the connection fails with "Permission denied"), and the places
where host sockets usually are look empty (section 7). Sockets the command
creates itself work, anywhere it may create them. Abstract sockets of the
host do not exist inside (the network namespace has its own).

**`--expose PATH`** (repeatable). Let the command reach this host socket,
or every socket below this directory. `PATH` must exist and is resolved to
its canonical form (symbolic links followed); `/` is refused. If the mount
layer hid it (for example a socket in the runtime directory), it is bound
back into place at the same path. An `--expose` path inside a `--hide`
path is refused.

**`--display`**. Expose the display: the Wayland socket named by
`WAYLAND_DISPLAY` (an absolute path, or a name in `XDG_RUNTIME_DIR`), the
X11 socket `/tmp/.X11-unix/XN` for a local `DISPLAY` (`:N`, `:N.S`,
`unix:N`; a display over the network is never exposed), and the file named
by `XAUTHORITY` if it exists. Those that exist are exposed; if none does,
playpen refuses (exit 2) and says what it looked for. Off by default,
because an X11 server lets any client type into other windows.

**`--without-landlock`**. For kernels without Landlock ABI 9: run without
the Landlock rule. The mount layer still applies, and in addition every
socket found under `/run`, `/tmp` and `/var/tmp` at start (not following
symbolic links; more than 2,000,000 entries stops the run with `nothing
was run`) gets `/dev/null` bound over it, except exposed ones. Sockets
anywhere else (for example in the home directory), and ones created after
the start, stay reachable. Without this option and without Landlock ABI 9,
`run` stops with a message that says so (exit 1, `nothing was run`).

**`--new-session`**. Run the command in a new session with no controlling
terminal, so it cannot push input into the caller's terminal with
`TIOCSTI`. This is automatic when the kernel allows `TIOCSTI` for
unprivileged processes (`/proc/sys/dev/tty/legacy_tiocsti` is missing or
not `0`). In this mode playpen passes Ctrl-C (SIGINT), Ctrl-\ (SIGQUIT) and
resizes (SIGWINCH) from the terminal on to the command's process group,
Ctrl-Z works as below, reading the terminal on stdin works, but `/dev/tty`
cannot be opened (password prompts that use it fail) and a shell inside has
no job control.

**`--hide PATH`** (repeatable). Hide one more host path from the command:
a directory gets an empty read-only tmpfs over it; anything else gets
`/dev/null` bound over it. A path that does not exist is ignored. Applied
after the mount layer and `--expose`.

**Terminal and job control.** Without a new session the command stays in
the terminal's foreground process group: Ctrl-C, Ctrl-\, resizes and
reading from the terminal reach it as they would without playpen, and a
shell inside (`-- bash -i`) has job control for its own jobs. Ctrl-Z (or
SIGTSTP sent to playpen) stops every process in the sandbox, including
those in other process groups or sessions, and then playpen itself, so the
shell shows the job as stopped; `fg` or `bg` continues playpen, which
continues exactly the processes it stopped. playpen does not stop for
terminal input or output.

SIGSTOP sent to playpen directly cannot be caught, so playpen cannot ask
for that freeze first. Instead playpen tells the sandbox's init every
second that it is running. When init hears nothing for 5 seconds
(`sandbox::SILENCE_LIMIT`: playpen is stopped, or stuck), it stops every
process in the sandbox itself and prints `playpen itself has been stopped
or stuck for 5 s ...; the command is paused until playpen continues`. When
playpen is heard again, init continues the processes it stopped, and
playpen enforces the end time and re-reads the pass at once. So the
command runs at most 5 seconds without supervision.

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
  destinations LABEL, ...): allowing only ...` and may continue with the
  `hostname` hint above. It says nothing about ceilings. Then, always,
  `; host Unix sockets: none reachable` (with `--without-landlock`: `;
  host Unix sockets: hidden under /run, /tmp, /var/tmp and the runtime
  directory only (--without-landlock); sockets elsewhere stay reachable`),
  then `; exposed: PATH, ...` when `--expose` was given, `; display
  exposed: PATH, ...` with `--display`, and `; the command runs in its own
  session, without a controlling terminal` in a new session;
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

### Supervisor lifecycle events

`run --events-fd N` accepts an inherited pipe writer above stderr. Close the
caller's copy after spawning. Read newline-delimited JSON until EOF. For
example, with Bash process substitution:

```bash
playpen run --events-fd 3 --no-network -- printf hello 3> >(jq -c '{seq,event,details}' >&2)
```

Version 1 records have `version`, a sequence number starting at 1, `event`
and `details`. Ignore unfamiliar fields. Buffer partial lines until a newline.
A validated request emits `validated`; `starting` is immediately before the
supervisor releases the workload. `stopping` carries `reason` of `expiry` or
`pass_withdrawn`. `terminal` carries the outcome, startup evidence, child
exit/signal, wrapper exit and drop assertion. A policy refusal can emit just
the terminal record. Pre-parse errors and an invalid descriptor have no stream.
The supervisor sets the supplied pipe writer nonblocking and closes it on a
write failure, including a full pipe. A missing terminal record, a sequence
gap or a partial final line means the stream is incomplete. An event reader
can disappear without delaying supervision.

### Previewing a run

`playpen plan --no-network -- printf hello` describes the command and its
effective settings. Use `--format json` for the versioned `plan` object.
For example, its `network` field is `"none"` for this invocation. Preview
uses the same validation as run, reads the current pass and resolves socket
exposures. It leaves the report path untouched. Availability of helpers,
namespace setup and installation of the filter are determined at launch.
Command arguments and paths use JSON strings for UTF-8 and an object with a
`unix_bytes` array for other byte sequences. Grant order is canonical; host
mapping and argument order are preserved.

The top-level `digest` is SHA-256 of the compact JSON encoding of the v1
plan (object keys in lexical order). Give it to `run --expect-plan DIGEST`
to require the same effective settings, working directory, argument bytes,
and original pass bytes. Playpen compares at validation and again before it
releases the workload. Normal expiry and revocation checks apply throughout.
The digest describes configuration. Program and filesystem contents, the
environment inherited by the child, and later pass edits have their own
lifetimes.

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

1. user namespace settings (section 3), including the AppArmor
   restriction where the setting exists;
2. `nft --version` and `pasta --version` run;
3. Landlock ABI 9 or later (`FAIL` otherwise, with the same message `run`
   gives);
4. whether the kernel allows `TIOCSTI` (always `ok`; says whether the
   command will run in its own session);
5. a self-test of the real mechanism, run only if 1 to 4 pass: playpen
   runs itself in a sandbox with pasta, with documentation addresses
   (`192.0.2.1`, `192.0.2.2`, `2001:db8::1`, `2001:db8::2`) added to the
   sandbox's own `lo`, approves some ports on the first of each, and checks
   that approved TCP, UDP and IPv6 destinations are reached and the others
   are not;
6. a second sandbox in which the command tries `nft flush ruleset`, `nft
   add table`, netlink address, link and link-state changes, raw IPv4, raw
   IPv6 and packet sockets, joining the user namespace of PID 1, and
   reading PID 1's memory, and must have no capabilities;
7. a third sandbox (`--no-network`) that must not be able to connect to a
   Unix socket and an abstract Unix socket doctor creates on the host for
   the purpose.

Each line says `ok` or `FAIL` and what is missing. Exit status 0 when all
pass, 1 otherwise. JSON: `{"ok": bool, "checks": [{"name", "ok",
"detail"}]}`.

### 4.5 JSON report fields

For retry decisions, read `startup_evidence`. A value of `not_started`
means refusal before release or an explicit pre-exec failure.
`exec_and_exit` means the exec-error pipe closed cleanly and the
supervisor observed a normal child exit. A signal can close that pipe
before exec; a signaled exit or missing startup evidence is `unknown`.
A report with `outcome: "error"` can therefore describe a command that
executed. For a non-idempotent job, retry automatically only on an explicit
`not_started` result. Older reports omit the field.


Written by `run --report FILE`. Field names are stable.

| Field | Type | Meaning |
|---|---|---|
| `playpen_version` | string | version of playpen |
| `outcome` | `"ran"`, `"refused"`, `"not_started"`, `"error"` | see 4.2 |
| `startup_evidence` | `"not_started"`, `"exec_and_exit"`, `"unknown"` | evidence available for deciding whether a retry is safe |
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
| `enforcement_coverage` | object, if available | selected pass enforcement coverage; omitted when unavailable |
| `pass` | object or null | null without `--pass`; else `{"file", "id", "name", "owner", "digest", "valid_until", "labels"}`: the file as given, the pass id, name, `approval.owner`, `sha256:` digest of the file at start, `valid_until` (RFC 3339 UTC), and the labels in use. When the pass could not be loaded, everything but `file` is null and `labels` is empty |
| `playpen_exit_status` | integer | the status playpen exits with |
| `dropped` | object or null | `{"packets": N, "destinations": [{"address", "protocol", "port", "packets"}], "destinations_truncated": bool}`; `port` is null for protocols other than TCP and UDP; destinations are sorted by packet count, largest first |
| `drop_assertion` | `"pass"`, `"violated"`, or `"unknown"` | present only with `--fail-on-drop` |
| `dropped_error` | string or null | why the counters could not be read |
| `socket_guard` | `"landlock"` or `"mounts_only"` | how host Unix sockets were kept from the command; `"mounts_only"` with `--without-landlock` |
| `exposed` | array of strings | every exposed path (`--expose` and `--display`), canonical once checked; the `--expose` values as typed when refused |
| `display` | bool | `--display` was given |
| `new_session` | bool | the command ran (or would have run) in its own session without a controlling terminal |

### 4.6 Hidden test aids

Not part of the stable interface, hidden from `--help`:

- `run --lo-addr ADDR` adds `ADDR` to the sandbox's `lo` before the
  ruleset is loaded. Used by tests and `doctor` to have destinations that
  exist only inside the sandbox.
- `playpen probe reach|privs|resolve|unix|unix-send|unix-recv-fd|stdout-reconnect|fds|tty|signals|listen` are the checks
  run inside the sandbox by `doctor` and the tests (`unix` connects to Unix
  sockets and closes at once, writing nothing; `listen` reports
  connections to a TCP listener).
- `run --pass-recheck-ms MS` re-reads the pass every `MS` milliseconds
  instead of every 2 seconds. Clamped to 50 ms .. 2 s, so it can only make
  the re-read more frequent. Used by the tests.

## 5. Start-up sequence

Each step either succeeds or stops the run with a message that ends
`nothing was run`; the command is never started after a failed step.

1. **Check the request** (CLI): load and check the pass (with `--pass`),
   parse every spec, `--host` and `--until`, check every `--expose` path
   and find the display sockets for `--display`, check standard input,
   output and error; apply the refusals in 4.1. Policy failures exit 2.
2. **Find the tools**: `nft`, and `pasta` unless `--no-network`.
3. **Check the process**: exactly one thread (required for creating a user
   namespace) and not root; Landlock ABI 9 unless `--without-landlock`.
   Mark every descriptor above 2 close-on-exec. Block the forwarded
   signals, SIGCHLD and the job-control signals (SIGTSTP, SIGCONT,
   SIGTTIN, SIGTTOU), to be read from a signalfd.
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
   namespace and forks I, its PID 1. I unshares a mount and an IPC
   namespace, makes all mounts private, and mounts a fresh `/proc`. Then,
   in this order (each failure stops the run): it opens every exposed path
   and, with `--without-landlock`, finds the sockets to cover, both in the
   host's view of the tree; binds the generated `/etc/hosts`,
   `/etc/resolv.conf` and `/etc/nsswitch.conf` read-only over the host's;
   replaces the directories of section 7 with private ones and mounts a
   fresh `/dev/mqueue`; covers the sockets found; binds every exposed path
   that is now hidden back into place; and applies `--hide`.
9. **X: drop privileges.** I forks X. X unshares a nested user namespace,
   maps the caller's uid and gid to the outer root, sets uid and gid,
   clears all capability sets, sets `no_new_privs`, and verifies: all of
   CapInh, CapPrm, CapEff and CapAmb are zero, NoNewPrivs is 1, the uid and
   gid are the caller's, raw IPv4, raw IPv6 and packet sockets cannot be
   opened, and a netlink link change is refused with `EPERM`. Any failure
   stops the run. Unless `--without-landlock`, X then restricts itself
   with Landlock: no connection to Unix sockets created outside, except
   below exposed paths; abstract sockets scoped. In a new session X calls
   `setsid`.
10. **X: exec the command.** If `exec` fails (for example the command does
    not exist), the run stops with `cannot run ...; nothing was run`
    (exit 1). Otherwise I reports "started".

While the command runs, P forwards SIGINT, SIGTERM, SIGHUP, SIGQUIT,
SIGUSR1, SIGUSR2 and SIGWINCH it receives from another process to I (as a
byte on its pipe to I, not as a signal), which passes them to the command
(to its process group in a new session).
Signals the kernel generated (for example Ctrl-C from the terminal) already
reach the command directly and are not sent twice; in a new session they
reach I instead (it is in playpen's process group), which passes them on.
I also passes on a signal that a process inside the sandbox sends to PID 1.
A signal I receives from outside is not passed on: P received it too. So a
signal sent to playpen, or to each playpen process (`killall playpen`),
reaches the command once. A signal sent to playpen's whole process group
(`kill -TERM -PGID`, `timeout` without `--foreground`, a shell's `kill
%1`) reaches the command once in a new session; otherwise the command is
in that group, gets its own copy from the kernel and P's as well: twice.
P cannot tell the two cases apart.
On SIGTSTP, P asks I to stop every
process in the sandbox that is not stopped already, then stops itself; on
SIGCONT it asks I to continue them. P sends I one byte every second; after
5 seconds without any, I stops the sandbox's processes itself until the
next one (section 4.1). I reaps orphaned processes.

If any step before the command starts fails and
`kernel.apparmor_restrict_unprivileged_userns` is 1, the message adds that
AppArmor's restriction is the likely cause and what an administrator can do
(a profile granting `userns,` to playpen, shown in DESIGN.md, or the
sysctl set to 0).

**Teardown.** When the command exits, I reports its status and exits; the
kernel kills every process left in the PID namespace. C then lists the
table again to read the counters, reports them, and exits. P stops pasta
if it is still running (pasta also exits when the namespace's process is
gone), removes pasta's PID file and its private directory, prints the
summary, writes the report, and exits.

If playpen itself is killed, each stage dies with its parent
(`PR_SET_PDEATHSIG`), and I exits when its pipe from P closes, so the
sandbox goes with it. Only the directory of pasta's PID file is left.

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
   protocol, destination port range. A rule for an IPv4 network does not
   accept the network address and the broadcast (all-ones) address of any
   listed network of /30 or broader (`ip daddr NET ip daddr != { ... }`):
   they are not hosts, and a packet to the all-ones address may reach every
   host on the network. They fall through to 6 like any other unapproved
   destination. For a pass, the listed networks used for these exclusions
   include unselected destinations. An address listed on its own (`203.0.113.255:443/tcp`) is a
   host and is accepted on that rule's ports and protocol. /31 and /32 and
   IPv6 networks have no such addresses. Hallpass also refuses an edge
   address (`network-or-broadcast`) unless the full pass lists it as a
   single host;
6. everything else: added to a per-destination set with a counter
   (address, protocol, port; port 0 for protocols other than TCP and UDP),
   counted in the `dropped` counter, and rejected with ICMP
   administratively prohibited.

The finite packet-scope regression builds 255 valid full passes from an
eight-destination universe and checks all 6,305 nonempty full-pass/subset
pairs. It exercises every address inside the fixture's IPv4 and native
IPv6 networks, adjacent outside representatives, both transports, and
port values 1–8, 441–447 and 65533–65535. These sample both sides of each
port boundary and all intervening partitions. CLI omission of `--only`
selects the full pass. The empty mathematical selection is checked as an
empty approval. The comparison evaluates explicit grants at a fixed valid
time. It excludes the fixed sandbox exceptions above and application
fields such as host names and request budgets. IPv6 transition forms are
outside this finite check.

So by default:

| Traffic | Default |
|---|---|
| IPv4 and IPv6 to unapproved destinations | dropped and counted (TCP connect fails with "No route to host" over IPv4 and "Permission denied" over IPv6, UDP send with "Operation not permitted") |
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
- Replaced by fresh, empty, writable private directories (tmpfs) with the
  host directory's mode, if present; what the command writes there is gone
  after the run:
  - `/run/user`, containing only `/run/user/UID` (mode 0700, owned by the
    caller), and `XDG_RUNTIME_DIR` if it is set and elsewhere;
  - `/tmp/.X11-unix`, `/tmp/.ICE-unix`, `/tmp/.XIM-unix`,
    `/tmp/.font-unix`, `/tmp/tmux-UID`;
  - `/dev/shm`.
- `/dev/mqueue`: the sandbox's own message queues (fresh mqueue mount).
- `/tmp`, `/var/tmp`, the home directory and everything else: the host's.
  Host sockets in them are visible but refused (Landlock).
- With `--without-landlock`: also every socket under `/run`, `/tmp` and
  `/var/tmp` found at start has `/dev/null` bound over it.
- Exposed paths: bound back at their own path.
- `--hide` paths: `/dev/null` or an empty read-only tmpfs.

Inside, the command's uid and gid are the caller's; other users and groups
show as `nobody`.

## 8. Threat model and known limits

Guarded against: accidental or misconfigured traffic, redirects and name
resolution to unapproved places, the command's children and daemons, the
command trying to change the firewall, interfaces or addresses, open raw
sockets, or join another network namespace, and the command reaching the
host's network through a host daemon's Unix socket, an inherited
descriptor, a socket on standard input or output, host IPC, the display
server (unless `--display`) or the terminal's input queue.

Not guarded against, or known limits:

- host-specific non-IP transports, including AF_VSOCK. The nft table filters
  IPv4 and IPv6, and Landlock separately guards pathname Unix sockets. Playpen
  checks inherited descriptors but does not impose a family allowlist on new
  sockets. VM socket isolation depends on the kernel, transport and namespace
  mode. A missing VSOCK sysctl establishes no general isolation guarantee.
  See the [kernel VSOCK namespace documentation](https://docs.kernel.org/admin-guide/sysctl/net.html#ns-mode);
- kernel exploits; bugs in nftables, pasta or Landlock;
- processes started outside playpen;
- what the daemon behind an exposed socket (`--expose`, `--display`) does
  for the command, including handing it descriptors;
- with `--without-landlock`: host sockets outside `/run`, `/tmp`,
  `/var/tmp` and the runtime directory, or created after the start;
- host processes that act on files the command writes (sync clients,
  spoolers, named pipes), and network file systems;
- an approved destination that forwards traffic further;
- volume, content and covert channels within approved flows;
- the report file can be overwritten by the command while it runs (same
  user); playpen writes it last, through the file it opened at start;
- supplementary groups of the caller still apply to file access inside;
- per-destination drop lists hold 1024 destinations per address family;
  `destinations_truncated` is true when the list is incomplete or its
  consistency cannot be established. A non-null `dropped.packets` is the
  total counter observed in the dump; null means the snapshot was unavailable.
  The nft JSON dump does not establish an atomic snapshot of the total and
  individual set counters under concurrent traffic, so matching values alone
  do not guarantee an exact breakdown at one instant. The netfilter
  [internals documentation](https://wiki.nftables.org/wiki-nftables/index.php/Portal%3ADeveloperDocs/nftables_internals)
  describes getters as non-batched and dumps as potentially resumed across
  messages; its atomic generation guarantee concerns ruleset updates. It
  does not specify an atomic cross-counter snapshot or a version range for
  one, so no supported nft version is claimed to provide that guarantee;
- a signal sent to playpen's whole process group reaches the command
  twice unless it runs in a new session (section 5);
- SIGSTOP sent to playpen itself (not Ctrl-Z) stops the command only
  after 5 seconds of silence (section 4.1); in that time the end time and
  the pass re-read are not enforced;
- the command can open the caller's other terminals (`/dev/pts/N`);
- with `--pass`: a revocation or edit takes effect when a scheduled re-read observes it
  (normally every 2 seconds), followed by the grace; traffic in that time is still allowed. Who
  can write the pass file can also restore it between two re-reads.
  Ceilings are not enforced by playpen.

DESIGN.md has the full list with the reasons.

## 9. Not yet built (planned)

ICMP echo approval is deferred. The CLI and the pinned Hallpass format
represent TCP and UDP destinations with port ranges. Echo would need an
explicit operation in both formats. A future approval would cover outbound
echo requests to one literal IPv4 or IPv6 destination and corresponding
replies. Other message types and existing rules for neighbour discovery and
related errors keep their own semantics. Denied requests must still be counted.
Before enabling it, use namespace-local fixtures to demonstrate both families,
a permitted reply, denial of an unlisted peer, and unchanged behavior for a
pass without an echo grant.

### Counted-drop assertion

With `--fail-on-drop`, the report includes `drop_assertion`: `pass` for a
known zero total, `violated` for a positive total even with partial detail,
and `unknown` when counters are unavailable or the command did not start.
For a child exit of zero, violated or unknown makes playpen exit 1. A nonzero
child status is retained; signals retain their normal status, and a stop by
expiry or pass revocation cannot become success. Refusal and setup failures
retain their existing statuses. This counts dropped IP packets, not DNS
misses, Unix sockets, or packets that never reached the ruleset. Without the
option, the existing exit contract and JSON shape are unchanged.

### Shareable reports

`--shareable-report --report FILE` writes a separate `playpen-shareable-v1`
JSON object directly. Its only fields are `schema`, `outcome`, `exit_code`,
`signal`, `playpen_exit_status`, `network`, `socket_guard`, `stopped_by_until`,
`stopped_by_pass`, `dropped_packets`, `destinations_truncated`, and
`drop_assertion`. The two drop fields are null when unavailable; zero is a
known zero. The stop booleans classify expiry and pass stops without copying
free-text reasons. The normal full report remains the default and retains its
existing compatibility contract. Future shareable fields require an explicit
allowlist addition and a schema compatibility decision.

```json
{"schema":"playpen-shareable-v1","outcome":"ran","exit_code":0,"signal":null,"playpen_exit_status":0,"network":"pasta","socket_guard":"landlock","stopped_by_until":false,"stopped_by_pass":false,"dropped_packets":0,"destinations_truncated":false,"drop_assertion":null}
```

Child output and files created by the caller or child are separate from this
report and may contain sensitive data. Aggregate counts and the occurrence of
stops can themselves disclose information, including timing-related behavior.

### Offline report comparison

`playpen compare BEFORE AFTER [--format json]` reads full 0.1.0 reports as
inert data (at most 1 MiB each). It compares effective grants, network, host
mappings, exposed sockets, display and socket guard independently of observed
blocked endpoint tuples. Packet counts do not themselves trigger changes.
Policy differences are shown before the observations. A newly observed tuple
requires a complete baseline; a no-longer-observed tuple requires a complete
later report and does not mean it is allowed or fixed. Missing or partial
counters, malformed detail, unstarted runs and unsupported/reduced schemas
cannot establish equality. Exit 0 means comparable policy and complete
observations with no new denials; 1 means new denials were observed; 2 means
comparison is indeterminate, policy differs without a new denial, or input
is invalid. When new denials and a policy change coexist, exit 1 reports the
new denial and the output still marks the policy change.

### Pass enforcement coverage

`--require-enforced` refuses before command execution when a selected pass
destination restricts names or any pass-wide application ceiling is present.
The full report's `enforcement_coverage` identifies packet and time filtering
and lists selected labels and ceiling names requiring external enforcement,
including on this refusal. Informational `hostname` is not a restriction;
`--host` does not enforce request names. A strict run rechecks the pass and
stops using the existing grace period if unsupported terms become applicable.
The plan digest includes the strict option and coverage.

### Offline policy examples

`playpen policy-test cases.json --allow 192.0.2.1:443/tcp` evaluates a JSON
array of outbound application tuples without loading nft or sending packets.
Each case has `address`, `protocol` (`tcp` or `udp`), `port`, `expect` (`allow`
or `deny`), and optional `name`. Use `--pass FILE` and optional repeated
`--only LABEL` instead of `--allow` to test a narrowed pass. The pass must be
currently valid. Loopback, multicast, unspecified addresses, port zero, and
special kernel traffic are outside this test's scope.

```json
[{"name":"upload","address":"192.0.2.1","protocol":"tcp","port":443,"expect":"allow"},
 {"name":"admin","address":"192.0.2.1","protocol":"tcp","port":8443,"expect":"deny"}]
```

The example exits 0. Changing the admin expectation to `allow` reports the
failed case and exits 1. Invalid input or policy is refused with exit 2.

### IPv6 pass prefixes

For Hallpass-derived grants, playpen conservatively refuses any IPv6 prefix
that can contain an address Hallpass rejects as IPv4 embedded or transitional.
This includes 6to4, Teredo, SIIT, mapped/compatible, well-known and local-use
NAT64, and ISATAP interface identifiers. ISATAP can occur under many native
prefixes, so a broad prefix may be refused even when its base address is
ordinary; select narrower ranges that cannot contain the pattern. Native
addresses and narrow prefixes outside these classes remain supported. This
check follows the pinned Hallpass predicate and does not recognize provider
specific 6rd, MAP, or network-specific NAT64 prefixes.
