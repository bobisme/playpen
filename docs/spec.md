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
- **At the top level, Ctrl-Z stops the whole sandbox**, and `fg` resumes it. On kernels that
  still allow `TIOCSTI`, the default command runs in its own session without a
  controlling terminal (section 4.1, `--new-session`).
- **The start line** has new clauses about host sockets, exposed paths and
  the session; **the report** has the new fields `socket_guard`,
  `exposed`, `display`, `new_session` and `private_tty`.

## 1. Purpose and non-goals

playpen runs one command so that the command, and every process it starts,
can send network traffic only to approved literal destinations (address or
network, port range, protocol) until an optional end time. All other traffic
is dropped, counted and reported. It runs as an ordinary user on Linux.

Non-goals:

- limiting how much is sent or inspecting what is sent;
- confining anything except network egress (files, other processes, CPU);
- resolving names: there is no DNS inside the sandbox. A stub on the
  sandbox's loopback answers the `--host` names, says every other name
  does not exist, and forwards nothing ("Name lookups", section 4.1). DNS
  over HTTPS or TLS is traffic like any other;
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

**Report.** The summary of a run: what was approved, when the command
started and ended, how it ended, and the drop counters. Printed to stderr as text at the end of every run;
written as JSON to `--report FILE` (section 4.5).

## 3. Requirements

- Linux with user namespaces: `user.max_user_namespaces` greater than 0,
  and, where that setting exists, `kernel.unprivileged_userns_clone = 1`.
  With `kernel.apparmor_restrict_unprivileged_userns = 1`, the installed
  Playpen binary needs an AppArmor profile granting `userns,` (see the
  AppArmor section of DESIGN.md).
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

Every public command accepts `--help` and `--format text|pretty|json`.
The global format may appear on either side of the command name and overrides
`FORMAT`. With neither set, a terminal selects pretty output and a pipe selects
text. Workload argv starts after `--`. `playpen help [COMMAND] --format json`
describes the public command tree, argument requirements, examples and workflow.
`playpen version --format json` returns the binary version. JSON objects include
an `advice` array. In JSON mode a usage error produces an error object on stderr
and exits 2.

### 4.1 `playpen run`

```text
playpen run --pass FILE [--only LABEL]... [--pass-hosts]
            [--host NAME=ADDR]... [--until RFC3339] [SOCKETS]
            [--format text|pretty|json] [--report FILE] [--capture FILE]
            -- COMMAND [ARGS...]
playpen run [--allow SPEC]... [--host NAME=ADDR]... [--until RFC3339]
            [--no-network] [SOCKETS] [--format text|pretty|json]
            [--report FILE] [--capture FILE] -- COMMAND [ARGS...]

SOCKETS = [--expose PATH]... [--display] [--hide PATH]...
          [--without-landlock] [--new-session | --private-tty]
```

Runs `COMMAND` (looked up on `PATH`) in the sandbox with the caller's
environment, working directory and standard streams (see the JSON output option below). Every other file
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
and the end time is never moved later. With `--pass-hosts`, a changed,
added or removed `hostname` of a single-address destination in use is such
an edit too: it changes no rule, so the run continues, and `/etc/hosts`
keeps the names written at start. The notice then says ``the hostname of
destination `LABEL` changed``. If the pass is rejected by the
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
`ADDR` through the generated `/etc/hosts` and through the DNS stub ("Name
lookups" below). `NAME` is a host name (labels of
letters, digits and `-`, not starting or ending with `-`, at most 63
characters per label and 253 in all, not all digits); it is lower-cased.
`ADDR` is a literal address, as strict as in `--allow`, with or without
brackets for IPv6. `ADDR` must be covered by some `--allow` rule (any port
or protocol), otherwise playpen refuses; the network and broadcast
addresses of a listed network (section 6.1) are not covered. With `--pass`, `ADDR` must be in
the address or network of a destination in use (after `--only`), for at
least one port; otherwise playpen refuses, naming the labels in use.

A destination's `hostname` in the pass is informational: it grants nothing,
and playpen uses it to fill `/etc/hosts` only with `--pass-hosts`. Without
`--pass-hosts`, when a destination in use has a `hostname` that no `--host`
maps, the start line (and a `--host` refusal) ends with `host names in the
pass grant nothing and are not resolved; if the tool needs them, map them
with --host NAME=ADDR (destination LABEL)`; for a network destination
`ADDR` is written `ADDR-IN-NETWORK`. When one of them is a single address,
the start line adds `; --pass-hosts maps the name of each single-address
destination to its address`.

**`--pass-hosts`** (needs `--pass`; without it, a usage error, exit 2).
For each destination in use (after `--only`) that has a `hostname` and is
a single address, `/etc/hosts` gets the line `ADDR NAME`, after the
`--host` lines. `NAME` is the `hostname` in lower case. playpen looks
nothing up and adds no rule: the name and the address both come from the
destination the owner wrote, so the address is one the pass approves.

- Two destinations with the same `hostname` give that name both addresses.
  Two destinations with the same `hostname` and the same address give one
  line.
- A destination without a `hostname` is skipped. So is a network
  destination with one; the start line is then followed by ``playpen:
  NOTE: --pass-hosts does not map NAME: destination `LABEL` is a network
  (NETWORK), not one address. If the tool needs the name, map it with
  --host NAME=ADDR-IN-NETWORK``. A `hostname` that `--host` would refuse
  (hallpass also accepts `_`) is skipped with a NOTE that says so.
- A `--host` for the same name (compared in lower case) wins: the pass's
  entries for that name are left out, and the names clause of the start
  line says `--host NAME replaces NAME=ADDR (pass: LABEL)`. No NOTE is
  printed for a network destination whose name a `--host` maps.
- The start line, the plan's `hosts` and the report's `hosts` list each
  entry taken from the pass as `NAME=ADDR (pass: LABEL[, LABEL]...)`, after
  the `--host` entries. Without `--pass-hosts` the start line ends with the
  hint above instead.
- The allow list, the ruleset and `playpen rules` are the same with and
  without `--pass-hosts`.
- A mid-run edit of a `hostname` does not stop the run (see the re-read
  rules above).

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
`TIOCSTI`. This is the default when the kernel allows `TIOCSTI` for
unprivileged processes (`/proc/sys/dev/tty/legacy_tiocsti` is missing or
not `0`). In this mode playpen passes Ctrl-C (SIGINT), Ctrl-\ (SIGQUIT) and
resizes (SIGWINCH) from the terminal on to the command's process group,
Ctrl-Z works as below, reading the terminal on stdin works, but `/dev/tty`
cannot be opened (password prompts that use it fail) and a shell inside has
no job control.

**`--hide PATH`** (repeatable). Hide one more host path from the command:
a directory gets an empty read-only tmpfs over it; anything else gets
`/dev/null` bound over it. A path that does not exist is ignored, and playpen
prints a note to stderr naming the explicit `--hide` path that was not found.
A dangling symlink is treated the same way. Command stdout is unchanged.
Applied after the mount layer and `--expose`.

**`--private-tty`**. Run the workload with a private controlling terminal.
Start playpen in the foreground and dedicate its controlling terminal’s
keyboard input to this run. A pipe or file on stdin stays connected to the
workload. Programs can open `/dev/tty` for keyboard input, and shells can
use job control. Playpen forwards signals addressed to its PID or process
group to the private foreground job. Redirected output retains its destination. Terminal
availability is checked at launch. The plan digest covers `--private-tty`.

**Terminal and job control.** In the default attached mode, the command stays in
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
playpen checks the end time and re-reads the pass if due. Five seconds
is the silence threshold. The time until processes stop also depends on
Linux scheduling the sandbox init and delivering its stop signals.

**`--report FILE`**. Write the JSON report to `FILE`, for every outcome,
refusals by policy included. The file is created (truncated) before
anything else; if that fails, playpen refuses.

**`--capture FILE`**. pasta writes a pcap file (Ethernet link type) of every
frame on the sandbox's outside interface, in both directions, to `FILE`
(pasta's `--pcap`). That is the approved traffic and its replies, and
address resolution with pasta (ARP, IPv6 neighbour solicitation and
advertisement). A packet the output chain rejects (section 6.1) never
reaches that interface, so it is not in the file; the drop counters count
it. Traffic on the sandbox's loopback, and to the sandbox's own addresses,
does not cross the interface either.

- **The capture holds payloads**, including passwords, tokens and cookies
  the command sends in clear. Treat it like the pass: keep it, share it and
  delete it under the same rules.
- playpen creates `FILE` itself after the request checks pass, before
  anything is built: a new file (`O_CREAT|O_EXCL`), mode 0600, never
  through a symbolic link. Refused (exit 2, nothing runs, the report's
  `outcome` is `refused`): a name that exists (`already exists; playpen
  never overwrites a capture`), a symbolic link (`is a symbolic link`), a
  directory that cannot be written (`cannot create the capture file ...`),
  a directory that its group or others can write to unless it has the
  sticky bit (see DESIGN.md, "Packet capture"), and `--capture` with
  `--no-network` (there is no outside interface).
- pasta opens the file by name. When it cannot, it goes on without a
  capture; playpen checks that pasta wrote the pcap header into the file
  playpen created, and otherwise stops with `pasta did not write the
  packet capture to FILE ...; nothing was run` (exit 1).
- Inside the sandbox `FILE` is `/dev/null`, as with `--hide`: the command
  cannot read or change the capture.
- When nothing was run (`refused`, `not_started`), playpen removes the
  file again, if the name still leads to the file it created. When the
  command was released, the file stays, and the report's `capture` gives
  its path, size and SHA-256, read after pasta has exited. A run stopped by
  its end time or by the pass leaves a complete file: playpen waits up to
  2 seconds for pasta to exit by itself (it looks once a second whether
  the sandbox is gone) and sends it SIGTERM only after that.

**`--format text|pretty|json`**. With JSON and no report path, stdout carries
one final JSON report. The workload’s stdout and stderr both stream to
Playpen’s stderr alongside supervisor diagnostics. With `--report FILE`,
the workload keeps its original stdout and stderr and the file receives the
report in every format. Keep stdout and stderr separate when parsing JSON.

The supervisor’s human-readable diagnostics on stderr include the following messages.

- just before the command starts, one line: `allowing only SPECS until TIME
  (no DNS[, names NAME=ADDR, ...]; lookups recorded); everything else is
  dropped`, with
  `with no time limit` when there is no `--until`; with `--no-network`:
  `no network, loopback only, ...`. With `--pass` the line starts `under
  pass ID ("NAME", owner "OWNER", sha256:DIGEST, window ends TIME,
  destinations LABEL, ...): allowing only ...` and may continue with the
  `hostname` hint above. With `--pass-hosts` the names include the entries
  from the pass (`NAME=ADDR (pass: LABEL)`) and any `; --host NAME replaces
  ...`. It says nothing about ceilings. Then, with `--capture`,
  `; packet capture: PATH` (the absolute path). Then, always,
  `; host Unix sockets: none reachable` (with `--without-landlock`: `;
  host Unix sockets: hidden under /run, /tmp, /var/tmp and the runtime
  directory only (--without-landlock); sockets elsewhere stay reachable`),
  then `; exposed: PATH, ...` when `--expose` was given, `; display
  exposed: PATH, ...` with `--display`, and `; the command runs in its own
  session, without a controlling terminal` in detached mode, or
  `; private controlling terminal` with `--private-tty`. The NOTE lines
  about `names` and about `--pass-hosts` follow it, one per line;
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
  dropped.` listing each destination with protocol, port and packet count;
  then, with `--capture`, `packet capture PATH: N bytes, sha256 HEX`.
- then, when the command looked up names that no `--host` maps: `The
  command looked up names that have no --host mapping:`, one line `NAME: N
  lookup(s)` per name (as shown in "Name lookups"), `(the list is
  incomplete: playpen keeps 256 names)` when names were left out, and
  `Each was answered "no such name". If the command needs one, map it
  with --host NAME=ADDR (ADDR must be approved).` When the record could
  not be read: `could not read the names the command looked up: WHY`.

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

### Offline HTTP fixture

With `--no-network --fixture FILE`, playpen reads a JSON object containing
`method`, `path`, `status` and a literal UTF-8 response `body`. GET, POST,
PUT, PATCH and DELETE are supported. Requests must match the path exactly,
including the query string. Unmatched routes return 404. The recipe and
fixed-length request body each have a 64 KiB limit; request headers have
an 8 KiB limit. Chunked uploads and HTTP upgrades are outside this protocol.
A bodyless response status (204, 205 or 304) requires an empty body.

The helper binds the sandbox loopback interface and reports its port
before the client can exec. The client receives the base URL in
`PLAYPEN_FIXTURE_URL`. Invalid configuration or failed readiness prevents
launch. The helper inherits the workload restrictions, runs as a separate
process under namespace init and ends with that namespace. If the helper
dies mid-run, the client sees the ordinary local connection failure.
Preview and pin include the fixture contents. See the README for a curl example.

### Name lookups

A DNS stub listens on 127.0.0.1 port 53, UDP and TCP, in the sandbox's
network namespace, from before the command starts until it has ended. It
is the only nameserver in the generated `/etc/resolv.conf`, and the
generated `/etc/nsswitch.conf` has `hosts: files dns`, so the system
resolver asks it after `/etc/hosts` (section 7). It reads the question of
each query and nothing else:

- a `--host` name: `NOERROR`, with the name's IPv4 addresses for type A,
  its IPv6 addresses for type AAAA, both for type ANY, and no records for
  any other type or for a class other than IN and ANY. Records have TTL 0.
  A UDP reply that would exceed 512 bytes has no records and the TC flag,
  so the client asks again over TCP;
- every other name: `NXDOMAIN` ("no such name");
- a message that is not one query with one question (an uncompressed name
  of at most 255 bytes): `FORMERR`; another opcode: `NOTIMP`; a response:
  no reply. None of these is recorded.

The stub forwards nothing, keeps no cache, and sends nothing but replies to
the sandbox's loopback. It keeps at most 16 TCP connections and closes one
that is idle for 5 seconds.

It records up to 256 distinct names, each with the number of queries for
it and whether `--host` maps it. A name after the 256th is not kept and
sets `truncated`. A name is shown lower-cased, its labels joined by `.`;
a byte in a label other than a letter, digit, `-` or `_` (a `.` in a label
too) is written `\DDD` in decimal (`\027` for ESC); the root is `.`. If
the result is longer than 253 bytes, it is cut to at most 250 bytes, never
inside a `\DDD`, and ends in `...`. So a name never holds a control byte.
At teardown the stub sends the record to C, which sends it to P (section
5). P checks each name again and drops any entry it would not show.

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
For example, its `network` field is `"none"` for this invocation, and its
`dns_stub` field, `"127.0.0.1:53"`, is where the DNS stub listens ("Name
lookups", 4.1). Preview
uses the same validation as run, reads the current pass and resolves socket
exposures. It leaves the report path untouched. With `--capture FILE` the
plan has a `capture` field, the path as given; plan neither creates nor
checks the file. Without `--capture` the plan has no such field, so
digests of earlier plans stay valid. Availability of helpers,
namespace setup and installation of the filter are determined at launch.
Command arguments and paths use JSON strings for UTF-8 and an object with a
`unix_bytes` array for other byte sequences. Grant order is canonical; host
mapping and argument order are preserved. With `--pass-hosts` the plan has
`"pass_hosts": true`, and `hosts` lists the entries from the pass after the
`--host` ones. Without it the field is absent, so plans without the option
keep their digest.

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
playpen rules [--allow SPEC]... [--format text|pretty|json]
playpen rules --pass FILE [--only LABEL]... [--pass-hosts]
              [--format text|pretty|json]
```

Prints the ruleset that `run` would load for these rules. Sends nothing,
creates nothing. Text: the ruleset. JSON: `{"allowed": [SPEC...], "pass":
{...} or null, "ruleset": "..."}` with canonical specs; `pass` has the same
fields as in the report (4.5). A bad spec is refused (exit 2, nothing
printed on stdout). An empty `--allow` list is allowed here and prints the
ruleset that allows nothing. With `--pass`, the pass is loaded and checked
exactly as by `run` (window included: an expired, not-yet-valid or revoked
pass is refused), and `--allow` beside it, `--only` without it, and an
unknown label are refused. `--pass-hosts` is accepted as by `run` and
changes nothing in the output: host names add no rule.

### 4.4 `playpen doctor`

```text
playpen doctor [--mode offline|egress] [--format text|pretty|json]
```

`--mode egress` is the default and retains the full egress check. `--mode
offline` does not require `pasta`; it demonstrates a real `--no-network`
command and verifies that only loopback is visible. Both modes require user
namespaces, a working `nft`, and Landlock ABI 9 or later, and run local
privilege and Unix-socket checks. Egress mode additionally requires `pasta`
and tests approved TCP, UDP, and IPv6 destinations against blocked ones.

For example:

```text
playpen doctor --mode offline --format json
playpen doctor --mode egress --format json
```

JSON retains the existing top-level `ok` and `checks` fields, and adds
`mode`, `capability`, and `probes`. The capability status is `available` when
every requested probe passed, `unavailable` when a prerequisite prevented
the mode from being demonstrated, and `failed` when an executed probe failed.
Probe entries say `executed` or `untested`; untested entries include the
preflight reason. For example, an absent pasta makes egress `unavailable` and
its egress probes `untested`, while offline can still be tested successfully.

The egress checks, without changing any host setting:

1. user namespace settings (section 3). The AppArmor restriction setting is
   informational: a per-binary profile may permit playpen, so live namespace
   probes determine whether the process can actually use namespaces;
2. `nft --version` and `pasta --version` run;
3. Landlock ABI 9 or later (`FAIL` otherwise, with the same message `run`
   gives);
4. whether the kernel allows `TIOCSTI` (always `ok`; says whether the
   default command will run in its own session);
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
7. a third sandbox (`--no-network`) that must reach its own private Unix
   socket and must fail to connect to the host pathname and abstract sockets
   doctor creates. Doctor requires one structured result for each endpoint.

Pretty output labels each check `ok` or `FAIL`. Text output places the check name first. Unrun checks are marked
`untested`. Exit status 0 when the selected mode is demonstrated, 1
otherwise. Existing JSON check objects retain `name`, `ok`, and `detail`.

### 4.4.1 `playpen qualify`

```text
playpen qualify --list [--format text|pretty|json]
playpen qualify [--source TRUSTED_PATH] [--require SCENARIO]... [--format text|pretty|json]
```

`--list` prints the scenario catalog and prerequisites without executing checks.
The default invocation runs the named native scenarios and records results. The
scenario set covers offline command isolation and loopback, local privilege
and Unix-socket guards, egress filtering, run-loopback behavior, hallpass
egress, the private runtime-directory fixture, the gateway mapping test on its
dummy-interface fixture, routed peer redirect and UDP controls, and ordinary
PTY input. The terminal scenario checks interactive input.

Direct doctor probes exercise the installed `playpen` executable and are
labelled `installed_binary`. Cargo integration tests require an
explicit trusted `--source` directory containing this package's `Cargo.toml`
and `Cargo.lock`; they are labelled `source_tree` and run with `cargo test
--locked --offline --manifest-path ...`. Without `--source`, those scenarios
are `unsupported` and Cargo is not started. This prevents qualification from
silently testing a different checkout than the operator selected.

The result for each scenario is `executed`, `unsupported`, or `failed`.
Cargo scenarios invoke one named test with `cargo test --locked
--offline`; a test's `SKIPPED:` reason becomes `unsupported`. A failed
assertion remains `failed`. Repeat `--require` for scenarios a qualification
job needs. The command fails if any scenario failed, or if any required
scenario is unsupported. Optional unsupported scenarios remain visible
without blocking the job.

For example, `playpen qualify --source "$PWD" --require offline-command
--require unix-socket-guard --format json` requires those two native checks.
If `PLAYPEN_PASTA` names a missing executable, `playpen qualify --source
"$PWD" --require egress-filter --format json` reports that scenario as
unsupported and exits 1; offline scenarios may still execute.

The scenario IDs are `offline-command`, `offline-loopback`,
`network-privileges`, `unix-socket-guard`, `socket-runtime-directory`,
`egress-filter`, `run-loopback`, `pass-egress`, `gateway-host-loopback`,
`routed-peer`, `terminal-pty-input`, and `private-tty-signals`.

The `routed-peer` scenario runs `tests/routed_peer.py` from the trusted source
against the qualifying executable. It needs Python 3, ip, unshare, curl,
dummy-interface support and the egress prerequisites. HTTP and UDP listeners
record actual deliveries in an isolated namespace. The fixture compares these
observations with the command outcome and firewall counters for each run.

Read qualification as evidence for the named host scenarios only. The
ordinary Rust unit and integration tests remain useful on constrained hosts,
and portable tests or pure Rust proofs provide separate evidence; neither
should be mistaken for a native scenario marked `executed` here.

### 4.5 JSON report fields

For retry decisions, read `startup_evidence`. A value of `not_started`
means refusal before release or an explicit pre-exec failure.
`exec_and_exit` means the exec-error pipe closed cleanly and the
supervisor observed a normal child exit. A signal can close that pipe
before exec; a signaled exit or missing startup evidence is `unknown`.
A report with `outcome: "error"` can therefore describe a command that
executed. For a non-idempotent job, retry automatically only on an explicit
`not_started` result. Older reports omit the field.


Written by `run --format json` or `run --report FILE`. Field names are stable.

| Field | Type | Meaning |
|---|---|---|
| `playpen_version` | string | version of playpen |
| `outcome` | `"ran"`, `"refused"`, `"not_started"`, `"error"` | see 4.2 |
| `startup_evidence` | `"not_started"`, `"exec_and_exit"`, `"unknown"` | evidence available for deciding whether a retry is safe |
| `message` | string or null | why, for anything but `"ran"` |
| `command` | array of strings | the command line |
| `allowed` | array of strings | approved specs (canonical form once parsed; as typed when refused; with `--pass`, the rules from the pass once loaded) |
| `hosts` | array of strings | `--host` entries as given; then, with `--pass-hosts` and once the pass is loaded, each entry taken from the pass as `NAME=ADDR (pass: LABEL[, LABEL]...)` |
| `until` | string or null | end time (RFC 3339 UTC once parsed; as typed when refused); with `--pass`, `valid_until` or the earlier `--until` |
| `started_at` | string or null | when the supervisor released the command (sent "go"), RFC 3339 UTC like `until`, with the fraction of a second; null when nothing was run |
| `ended_at` | string or null | when the supervisor learned that the command had ended: when it read init's report of the exit status, or, when none came, when the sandbox ended; RFC 3339 UTC; null when nothing was run, and when supervision failed before the supervisor saw the end (`outcome: "error"`) |
| `network` | `"pasta"` or `"none"` | |
| `exit_code` | integer or null | the command's exit status |
| `signal` | integer or null | the signal that killed the command |
| `stopped_by_until` | bool | playpen stopped the command because the end time was reached |
| `stopped_by_pass` | bool | playpen stopped the command after re-reading the pass |
| `stop_reason` | string or null | why playpen stopped the command, when `stopped_by_until` or `stopped_by_pass` |
| `enforcement_coverage` | object, if available | selected pass enforcement coverage; omitted when unavailable |
| `pass` | object or null | null without `--pass`; else `{"file", "id", "name", "owner", "digest", "valid_until", "labels"}`: the file as given, the pass id, name, `approval.owner`, `sha256:` digest of the file at start, `valid_until` (RFC 3339 UTC), and the labels in use. When the pass could not be loaded, everything but `file` is null and `labels` is empty |
| `capture` | object or null | null without `--capture` and when nothing was run; else `{"file", "bytes", "sha256"}`: the capture file (absolute), its size, and the SHA-256 of its bytes in lower-case hex as `sha256sum` prints it, read through the descriptor playpen created it with, after pasta has exited. Also null when the file could not be read back; `message` then says why |
| `playpen_exit_status` | integer | the status playpen exits with |
| `dropped` | object or null | `{"packets": N, "destinations": [{"address", "protocol", "port", "packets"}], "destinations_truncated": bool}`; `port` is null for protocols other than TCP and UDP; destinations are sorted by packet count, largest first |
| `drop_assertion` | `"pass"`, `"violated"`, or `"unknown"` | present only with `--fail-on-drop` |
| `dropped_error` | string or null | why the counters could not be read |
| `lookups` | object or null | the names the command looked up: `{"names": [{"name", "count", "mapped"}], "truncated": bool}`, in the order first asked, as shown in "Name lookups" (4.1); `mapped` is true for a `--host` name; null when the command did not run or the record could not be read |
| `lookups_error` | string or null | why the record of names could not be read |
| `socket_guard` | `"landlock"` or `"mounts_only"` | how host Unix sockets were kept from the command; `"mounts_only"` with `--without-landlock` |
| `exposed` | array of strings | every exposed path (`--expose` and `--display`), canonical once checked; the `--expose` values as typed when refused |
| `private_tty` | bool | whether the caller requested a private controlling terminal |
| `display` | bool | `--display` was given |
| `new_session` | bool | the command ran (or would have run) in its own session without a controlling terminal |

### Counted-drop assertion

A zero total accompanied by positive per-destination packet counts makes the
assertion indeterminate and the wrapper exits unsuccessfully.

With `--fail-on-drop`, the report includes `drop_assertion`: `pass` for a
known zero total, `violated` for a positive total even with partial detail,
and `unknown` when counters are unavailable or the command did not start.
For a child exit of zero, violated or unknown makes playpen exit 1. A nonzero
child status is retained; signals retain their normal status, and a stop by
expiry or pass revocation cannot become success. Refusal and setup failures
retain their existing statuses. This counts dropped IP packets, not names
the stub answered "no such name", Unix sockets, or packets that never
reached the ruleset. Without the
option, the existing exit contract and JSON shape are unchanged.

### Grant use in private reports

Use `--report-grant-use --report FILE` to include `grant_use` in a
successful run's private JSON report. Playpen adds a packet counter before
the accept verdict of each of the first 256 explicit grant rules. Startup
verification checks the counter names and their positions, and the teardown
readback supplies both grant and drop counts. The report contains an ordered
`grants` array and a `truncated` flag when later rules went uninstrumented.
Each row has a one-based ID (`grant_1` and so on) stable for the same ordered
policy, the canonical rule including port range, the source pass label or
null for `--allow`, a `packets` count, and a `state`.

- `observed` means at least one packet reached this grant rule. A failed
  connection can still produce a counted packet.
- `no_observed_match` means the rule's counter was zero.
- `shadowed_or_ambiguous` means the counter was zero and an earlier rule's
  address and port ranges overlap on the same protocol. Rule order decides
  which explicit accept sees each packet. The overlap check conservatively
  ignores individual address exclusions.
- `unavailable` means the counter could not be read for this rule. Its
  `packets` field is null.

Established and related traffic and fixed sandbox exceptions match before
explicit grants. These counters measure packets that reached each explicit
accept rule. They do not measure connections or total bytes exchanged.
A quiet observation alone does not establish that a future run will need
less permission. A `--no-network` report has an empty grant list. Grant
telemetry cannot be combined with `--shareable-report`. Without the option,
the report schema and the installed accept rules are unchanged.

### Shareable reports

`--shareable-report --report FILE` writes a separate `playpen-shareable-v1`
JSON object directly. Its only fields are `advice` (always an empty array), `schema`, `outcome`, `exit_code`,
`signal`, `playpen_exit_status`, `network`, `socket_guard`, `stopped_by_until`,
`stopped_by_pass`, `dropped_packets`, `destinations_truncated`, and
`drop_assertion`. The two drop fields are null when unavailable; zero is a
known zero. The stop booleans classify expiry and pass stops without copying
free-text reasons. It has no host names: not the `--host` mappings and not
the names the command looked up. The normal full report remains the default and retains its
existing compatibility contract. Future shareable fields require an explicit
allowlist addition and a schema compatibility decision.

```json
{"advice":[],"schema":"playpen-shareable-v1","outcome":"ran","exit_code":0,"signal":null,"playpen_exit_status":0,"network":"pasta","socket_guard":"landlock","stopped_by_until":false,"stopped_by_pass":false,"dropped_packets":0,"destinations_truncated":false,"drop_assertion":null}
```

Decision (`started_at`, `ended_at`): not added. The shareable report leaves
out the destinations on purpose. Exact start and end times are a key into
the logs of every destination the command reached, so a reader who has
such logs could find the destinations again. The full report has both
times for the owner. The schema stays `playpen-shareable-v1`, unchanged.
`capture` is never added: the capture holds payloads, and its path and
digest name a file that must not travel with a shared report.

Child output and files created by the caller or child are separate from this
report and may contain sensitive data. Aggregate counts and the occurrence of
stops can themselves disclose information, including timing-related behavior.

### Offline report comparison

`playpen compare BEFORE AFTER [--format json]` reads full 0.1.0 reports as
inert data (at most 1 MiB each). It compares effective grants, network, host
mappings (an entry from `--pass-hosts` counts as its `NAME=ADDR`), exposed
sockets, display and socket guard independently of observed
blocked endpoint tuples. Packet counts do not themselves trigger changes.
`started_at`, `ended_at` and `capture` are ignored: two runs of the same
policy differ in them by nature. Policy differences are shown before the
observations. A newly observed tuple
requires a complete baseline; a no-longer-observed tuple requires a complete
later report and does not mean it is allowed or fixed. Missing or partial
counters, malformed detail, unstarted runs and unsupported/reduced schemas
cannot establish equality.

Names looked up without a `--host` mapping are observations too, compared
the same way: `new_unmapped_lookups` needs a complete `lookups` record in
the baseline, and `unmapped_lookups_no_longer_observed` a complete one in
the later report. A record is complete when it is present, not truncated,
from a run that ran, and every entry has a name playpen would show, a
positive count and a `mapped` flag, with no name twice. Lookup counts, and
names that `--host` maps, do not count as changes. Evidence is `complete`
only when both the drop counters and the lookup records of both reports are.

Exit 0 means comparable policy and complete observations with nothing new;
1 means new denials or new unmapped lookups were observed; 2 means
comparison is indeterminate, policy differs without a new observation, or
input is invalid. When new observations and a policy change coexist, exit
1 reports them and the output still marks the policy change.

### Pass enforcement coverage

`--require-enforced` refuses before command execution when a selected pass
destination restricts names or any pass-wide application ceiling is present.
The full report's `enforcement_coverage` identifies packet and time filtering
and lists selected labels and ceiling names requiring external enforcement,
including on this refusal. Informational `hostname` is not a restriction;
`--host` and `--pass-hosts` do not enforce request names. A strict run
rechecks the pass and stops using the existing grace period if unsupported
terms become applicable.
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

### 4.6 Hidden test aids

Not part of the stable interface, hidden from `--help`:

- `run --lo-addr ADDR` adds `ADDR` to the sandbox's `lo` before the
  ruleset is loaded. Used by tests and `doctor` to have destinations that
  exist only inside the sandbox.
- `playpen probe reach|privs|resolve|dns|unix|unix-send|unix-recv-fd|stdout-reconnect|fds|tty|signals|listen` are the checks
  run inside the sandbox by `doctor` and the tests (`unix` connects to Unix
  sockets and closes at once, writing nothing; `listen` reports
  connections to a TCP listener; `dns [--tcp] HEX` sends one DNS message
  to the stub and describes the reply).
- `run --pass-recheck-ms MS` re-reads the pass every `MS` milliseconds
  instead of every 2 seconds. Clamped to 50 ms .. 2 s, so it can only make
  the re-read more frequent. Used by the tests.

## 5. Start-up sequence

Each step either succeeds or stops the run with a message that ends
`nothing was run`; the command is never started after a failed step.

1. **Check the request** (CLI): load and check the pass (with `--pass`),
   parse every spec, `--host` and `--until`, check every `--expose` path
   and find the display sockets for `--display`, check standard input,
   output and error; apply the refusals in 4.1. Then create the
   `--capture` file. Policy failures exit 2.
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
6. **C: verify the ruleset.** Compare `nft --json list table inet playpen`
   with the approved policy. The comparator checks the table family, the
   filter hooks, priorities and drop policies, ordered matches and verdicts
   in all chains, and the drop-accounting declarations and rules. Supported
   schema-1 expressions cover connection state, interfaces, IP addresses
   and prefixes, IPv6 hop limits and ICMP types, transport ports and ranges,
   set additions, counters and verdicts. Handles and changing counter values
   are ignored. Unknown material expressions stop setup. Only then does C
   report "ready". Until this point the namespace has only `lo`. Playpen
   relies on the kernel and the configured nft binary to report the installed
   table faithfully.
7. **P: attach pasta** (unless `--no-network`) to C's namespaces with the
   options in section 6.3, and wait for it to exit 0 (it daemonizes after
   configuring the namespace). Failure stops the run. With `--capture`, P
   checks that pasta wrote the pcap header into the capture file. P
   checks the end time has not passed while setting up and, with
   `--pass`, re-reads the pass
   once, prints the start line, and tells C to go. That moment is the
   report's `started_at`. (Steps 4 to 6 must finish within 30 seconds.)
8. **C makes itself non-dumpable and starts the DNS stub D.** D sets
   "die with parent", makes itself non-dumpable, binds 127.0.0.1 port 53
   for UDP and TCP (C's root in the user namespace may bind ports below
   1024), then clears every capability set, sets `no_new_privs`, checks
   that raw sockets and a netlink link change are refused, closes every
   other descriptor, and reports "ready". D stays in C's PID namespace:
   the command cannot see it in `/proc` or signal it. Then C forks S,
   which keeps no handle on D and unshares a PID
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
SIGUSR1, SIGUSR2 and SIGWINCH from other processes to I, one byte per
signal on their control pipe. I also accepts those signals directly from
other processes in its PID namespace. Signal routing depends on the job:

| Job | Target of a forwarded signal | External signal sent to P's group |
| --- | --- | --- |
| No controlling terminal | Workload's current process group | P forwards one copy |
| `--new-session` (explicit or automatic) | Workload's initial session process group | P forwards one copy |
| `--private-tty` | Private terminal foreground group | P forwards one copy |
| Attached to the caller's terminal | Workload PID | The kernel delivers the workload's copy; P forwards one only if the workload has left P's group |

In an attached job P has a second child, the witness W, in its own process
group, and I leaves that group once the command is forked. A signal P
receives from `kill` was sent to the whole group when W received it too
and I did not; to P alone when W did not; to playpen's processes one by
one (`killall playpen`) when both did. P forwards the last two. A signal
sent to P and W by PID, and not to I, is taken for the group's and is not
forwarded. Without W (it could not be started, or stopped answering) P
forwards every signal, so a workload in P's group gets a group's signal
twice.

The supervisor's controlling terminal determines the default even when
stdin, stdout and stderr are redirected. In an attached job the kernel
delivers terminal-generated signals to the foreground group directly. In a
new session P forwards those signals. Standard signals of the same kind can
coalesce while pending. With a private terminal, a nested foreground job
receives its keyboard interrupts and stops through that terminal.
On a top-level SIGTSTP, P asks I to stop every
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
kernel kills every process left in the PID namespace. The moment P reads
that status is the report's `ended_at`. C then closes D's
control pipe; D stops and sends its record of names (within 2 seconds, or
C kills it and reports why). C reports the record, lists the table again to
read the counters, reports them, and exits. P stops pasta
if it is still running (pasta also exits when the namespace's process is
gone; it looks once a second), removes pasta's PID file and its private
directory, prints the summary, writes the report, and exits. With
`--capture`, P first waits up to 2 seconds for pasta to exit by itself,
sends SIGTERM only after that, and reads the capture's size and digest
once pasta is gone.

If playpen itself is killed, each stage dies with its parent
(`PR_SET_PDEATHSIG`), and I exits when its pipe from P closes, so the
sandbox goes with it. Only the directory of pasta's PID file is left, and
the capture file without a report; pasta exits by itself within a second
of C, between two packets.

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
| DNS | no DNS: the only nameserver is the stub on the sandbox loopback (127.0.0.1 port 53), which answers `--host` names, says every other name does not exist, and forwards nothing; port 53 elsewhere is not approved unless you approve it |
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
and `PID` is C. With `--capture`, also `--pcap NAME` before `PID`, where
`NAME` is the capture file's bare name and pasta starts in the capture's
directory, reached through the descriptor playpen holds for it.

## 7. Files the command sees differently

- `/etc/hosts`: `127.0.0.1` and `::1` as `localhost` (plus the machine's
  host name if it is a valid host name), then one line per `--host`, then
  one line per entry from `--pass-hosts`.
- `/etc/resolv.conf`: comments, `nameserver 127.0.0.1` (the stub),
  `search .` (no search list, so a name is not also asked for with the
  machine's own domain appended) and `options timeout:1 attempts:1`. (Not
  bound if the host has none; glibc then asks 127.0.0.1 all the same.)
- `/etc/nsswitch.conf`: the host's file with its `hosts:` line replaced by
  `hosts: files dns`: the generated `/etc/hosts`, then the stub. The host's
  other sources (`resolve`, `mdns`, `myhostname`, `mymachines` and the
  like) are left out. (Not bound if the host has none; glibc's default
  then asks the stub first.)
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
- the capture file (`--capture`) holds what the command sent, credentials
  sent in clear included. It is mode 0600 and is `/dev/null` inside the
  sandbox, but every other process of the caller can read it. The capture
  is what pasta saw on its side of the interface; playpen checks its
  header, size and digest, not its packets;
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
- an approval of this host's own address, on the interface pasta copies
  into the sandbox, does not reach the host: inside, that address is the
  sandbox's. playpen prints a NOTE at the start when a rule approves such
  an address on its own. A local service has to listen on an address the
  sandbox does not have (DESIGN.md, "The host's own addresses");
- playpen does not run inside playpen: Landlock refuses the inner one's
  mounts;
- when the command shares its caller's terminal process group, a signal
  sent by PID to playpen and to its witness process, and not to the
  sandbox's init, does not reach the command (section 5);
- When SIGSTOP reaches playpen itself, its deadline and pass checks pause.
  The sandbox init begins freezing the command when it observes 5 seconds
  of silence (section 4.1).
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
