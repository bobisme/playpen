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
host" (over IPv6: "Permission denied"), which is clearer and makes test
runs fast. The policy is still drop,
so anything that gets past the reject (nothing should) is dropped.

**nix, not rustix.** playpen needs fork, unshare, setns, mount, signalfd,
prctl (pdeathsig, dumpable, no_new_privs), setresuid/gid, waitpid, poll and
netlink sockets. nix has safe wrappers for all of them; rustix has no
supported `fork`. `libc` (already a dependency of nix) is used for the one
call nix lacks, `capset`.

**`unsafe`** appears in a few places, each with a comment saying why it is
sound: `fork` (the process is checked to be single-threaded first, and
playpen starts no threads), `capset` and the three Landlock system calls
(fixed `repr(C)` structs matching the kernel ABI), borrowing raw
descriptors listed in `/proc/self/fd` to set close-on-exec, and the
`TIOCSTI` ioctl in the hidden `probe tty`.

**Single-id mappings.** The outer namespace maps only `0 -> caller`, the
nested one only `caller -> 0`. No subuid/subgid ranges and no setuid
helper (newuidmap) are needed. The price: inside, every other uid and gid
shows as `nobody`, and supplementary groups cannot be dropped (writing
`setgroups` is denied in an unprivileged user namespace), so they still
count for file access. That is one more reason host sockets are refused: a
member of the `docker` group could otherwise start a container on the host
network through `/run/docker.sock`.

## Host Unix sockets

A daemon on the host has the host's network. If the command can talk to
one that opens connections, fetches things, starts processes or forwards
messages for its clients (a session bus, a container engine, a user
service manager, a resolver, an SSH agent with a control master, a browser
automation server, a sync client, a syslog daemon that forwards), the
filter does not see that traffic. v0.1 hid a fixed list of such sockets; a
list cannot be complete (on the development machine there were sockets of
this kind in the home directory, which no list of system paths covers).
Since this version host sockets are refused by default and brought back
one by one with `--expose`.

### Which kinds of socket can cross out of the sandbox

| Kind | Crosses out? | Status | Test |
|---|---|---|---|
| Abstract Unix sockets (`@name`) | no: the abstract namespace belongs to the network namespace, and the sandbox has its own | closed by the network namespace; Landlock's abstract-socket scope is a second layer | `abstract_sockets_of_the_host_are_not_reachable` (a host abstract listener, with and without Landlock; the command's own abstract socket works) |
| Pathname Unix sockets (stream, datagram, seqpacket) | yes, wherever the path is visible and the socket file writable | closed by Landlock everywhere; the mount layer hides the usual places as well | `no_host_socket_is_connectable_from_inside` walks the runtime directory, `/run`, `/var/run`, `/tmp`, `/var/tmp`, `/dev/shm` and the home directory (4 levels) on the host and connects to every socket from inside |
| `sendmsg` to a pathname datagram socket by address (syslog, the journal) | yes, same as above | closed by Landlock (it checks `sendmsg` with an explicit address too) | `a_datagram_sent_by_address_to_a_host_socket_is_refused` (to a datagram socket the test owns: it arrives when sent from the host, not from inside) |
| Sockets the command creates itself | stay inside | allowed (they are created in the command's own Landlock domain) | runtime directory, Python, and abstract sockets of its own |
| Inherited descriptors above 2 | yes, if passed on | closed: marked close-on-exec before the sandbox starts | `inherited_descriptors_do_not_reach_the_command` (a file, Unix and TCP sockets, a UDP socket, a listener and a pipe) |
| Standard input, output, error that are sockets | they are the caller's, in the host's network namespace | every IP socket (UDP, raw, TCP in any state: a connected one can be dissolved and connected elsewhere) and other families are refused; Unix sockets are allowed (Landlock refuses connecting them to host sockets; without Landlock only a connected stream or a listener) | `stdio_sockets_that_reach_the_host_network_are_refused`, `a_tcp_socket_on_stdout_cannot_be_pointed_elsewhere`, `a_unix_socket_on_stdout_cannot_reach_host_abstract_sockets`, `connected_unix_stdio_works` |
| Descriptors passed with `SCM_RIGHTS` | yes: the peer of an exposed socket or of a Unix socket on stdio can hand the command any descriptor, including a socket in the host's network namespace | open, by design: a peer exists only where the operator exposed one or chose it as stdio | `the_peer_of_an_exposed_socket_can_pass_a_host_network_socket` shows it: a UDP socket passed over an exposed socket sends to the host's loopback; not exposed, the connection is refused and nothing can be passed |
| `/proc` of host processes | would expose their descriptors and namespaces | closed: PID namespace and a fresh `/proc`; host processes do not exist inside | `host_processes_are_not_visible_in_proc` |
| System V IPC, POSIX message queues | would reach host processes that cooperate | closed: own IPC namespace, fresh `/dev/mqueue` | `host_ipc_and_shared_memory_are_not_reachable` (a host shared memory segment, a host message queue) |
| POSIX shared memory (`/dev/shm`) | files in a host tmpfs | closed: private empty `/dev/shm` | same test |
| Named pipes (FIFOs), and files a host process reads or watches | yes, if a host process reads them: a sync client, a spooler, a mail drop | open: playpen does not confine files | none possible |
| Network file systems (NFS, SMB, sshfs and other FUSE mounts) | yes: writing a file sends it | open, except FUSE mounts in the runtime directory (gvfs, the document portal), which the private runtime directory hides; use `--hide` | none |
| The terminal: `TIOCSTI` (pushing input into the terminal, read by the host shell after playpen exits) | only where the kernel allows it | closed: refused by the kernel when `dev.tty.legacy_tiocsti` is 0; elsewhere the default runs the command in a new session without a controlling terminal, and `TIOCSTI` needs one | `the_command_cannot_type_into_the_terminal` (both modes; on this machine the kernel refuses in both, so the new-session layer is shown only by `/dev/tty` being unavailable) |
| Other terminals of the same user (`/dev/pts/N`) | the command can open them: write text, read keystrokes | open; not a network path (`TIOCSTI` on them needs them to be the controlling terminal) | none |
| The display server (X11, Wayland) | yes: an X11 client can type into any other window, for example a host terminal | closed by default (the sockets are refused and hidden); `--display` opens it, and the start line says so | `display_exposes_the_wayland_socket_and_is_off_by_default`; `display_works_with_a_real_x_server_and_is_off_by_default` (a private headless X server with a cookie, a real client, with and without Landlock) |

### The default: Landlock plus a mount layer

**Landlock refuses, the mounts tidy up.** Landlock ABI 9 added
`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`: a process restricted by it cannot
connect to, or send by address to, a pathname Unix socket whose server was
created outside its Landlock domain, wherever the socket is. Sockets the
command creates itself are not affected. That is exactly the rule wanted,
and it needs no list. X applies it just before `exec`, handling only that
right (files and directories are not restricted) and scoping abstract
sockets. A path-beneath rule lets a socket, or every socket below a
directory, through again: that is `--expose`.

The mount layer comes on top, for three reasons. Programs need a working
runtime directory, and an empty private one behaves better than a host
directory full of sockets that all fail with "Permission denied". It hides
the FUSE mounts that live there. And it is the fallback on kernels without
Landlock ABI 9. It replaces, with fresh empty writable tmpfs mounts that
keep the host directory's mode:

- `/run/user` (with a new `/run/user/UID`, mode 0700, owned by the caller)
  and `XDG_RUNTIME_DIR` if it is elsewhere;
- `/tmp/.X11-unix`, `/tmp/.ICE-unix`, `/tmp/.XIM-unix`, `/tmp/.font-unix`
  and `/tmp/tmux-UID`;
- `/dev/shm`; and `/dev/mqueue` gets a fresh mqueue mount for the
  sandbox's own IPC namespace.

**`/tmp` itself stays the host's.** A file a tool writes to `/tmp` is
there after the run, as an operator expects (`curl -o /tmp/page`). Only
the directories where servers put sockets are private. Sockets elsewhere in
`/tmp` are refused by Landlock.

**Why fail without Landlock, and `--without-landlock`.** Without ABI 9
playpen does not start: the mount layer cannot reach sockets in the home
directory or created after the start, so it is not the default-deny it
promises. `--without-landlock` accepts that for older kernels and is said
in the start line and the report (`socket_guard: "mounts_only"`). In that
mode I also walks `/run`, `/tmp` and `/var/tmp` (not following links, at
most 2,000,000 entries, else the run does not start) and binds `/dev/null`
over every socket it finds. What stays open in that mode: sockets anywhere
else (the home directory, `/var/lib`, ...), sockets created after the
start, and a socket whose daemon removes and recreates it during the run
(removing a mount point in another mount namespace detaches the mount).
The test `without_landlock_the_mount_layer_still_hides_the_usual_places`
shows both the hiding and that a home-directory socket stays reachable.

**`--expose PATH`.** The path must exist (refused otherwise, and `/` is
refused). It is canonicalised, held open by I before any mount changes, and
after the mount layer bound back into place if the path no longer names
the same object (creating parent directories in the private runtime
directory as needed); then it gets a Landlock rule. A file in the walk's
list is skipped if exposed. `--expose` inside a `--hide` path is refused.
Exposing gives the command whatever the daemon behind the socket can do.

**`--display`.** Off by default: an X11 server lets any client send key
and mouse events to any other window, so a command with the display could
type into a host terminal. Wayland compositors are stricter, but what they
allow varies with the compositor. One flag turns it on: it exposes the
Wayland socket named by `WAYLAND_DISPLAY` (relative to `XDG_RUNTIME_DIR`
or absolute), the X11 socket for a local `DISPLAY` (`:N` gives
`/tmp/.X11-unix/XN`; a display over the network is never exposed), and the
`XAUTHORITY` file. With neither found it refuses. The start line lists the
display sockets separately (`display exposed: ...`). X11 clients usually
also try the abstract socket `@/tmp/.X11-unix/XN`, which does not exist in
the sandbox's network namespace; they fall back to the path.

**What the default breaks, on purpose.** Anything that needs a host
daemon over a socket: the session and system D-Bus, `systemctl --user`,
`ssh-agent` (`SSH_AUTH_SOCK`), `gpg-agent`, PulseAudio and PipeWire,
logging to syslog or the journal (messages are lost), and user and group
names served by a daemon (sssd, systemd-userdb, nscd: `ls -l` then shows
numbers for directory users). Each can be brought back with `--expose`
(for example `--expose "$SSH_AUTH_SOCK"`). The environment is not changed:
variables such as `DBUS_SESSION_BUS_ADDRESS` still point at the hidden
paths, and programs fail to connect as they would with the daemon down.

## The terminal, job control and inherited descriptors

**Standard streams.** The command gets the caller's stdin, stdout and
stderr; every other descriptor is closed at `exec`. A stream that is a
socket came from the caller's network namespace, outside the filter: a UDP
socket can send to any address (also when connected), an unconnected TCP
socket can be connected anywhere, a listening one accepts anyone. A
connected TCP socket is no better: `connect` with an `AF_UNSPEC` address
dissolves the connection, and the socket, still in the host's network
namespace, can then be connected to any address the host reaches. (An
earlier version let connected TCP through as "reaches only its peer"; a
test now does the reconnect, to a second listener on the host's loopback.)
So every IP socket is refused before anything runs; `playpen ... | nc host
port` gives the command a pipe, and the connection stays the caller's.

A Unix socket is let in. With Landlock, connecting it (or sending by
address) to a pathname socket of the host is refused like any other, and
to an abstract one by the abstract-socket scope. That scope is the only
layer there: the socket was made outside, so the abstract names it sees
are the host's, not the sandbox's. Without Landlock nothing refuses
either, so `--without-landlock` lets in only a Unix socket that cannot be
pointed anywhere: a connected stream or sequenced-packet socket, or a
listening one. A datagram socket, connected or not, and an unconnected
stream socket are refused in that mode.

**Job control.** In an attached job the command stays in the terminal's foreground process
group, as without playpen, so Ctrl-C, Ctrl-\, resizes and reading from the
terminal reach it directly from the kernel. Ctrl-Z needed work: in v0.1 it
stopped playpen (P) and the command, but a process in another process
group (one started with `setsid`, or a job of a shell with job control)
kept running while P, which enforces the end time and re-reads the pass,
was stopped. Now P, C, S and I block the job-control signals. P reads
SIGTSTP from its signalfd, asks I (one byte on the pipe P already used for
"go") to freeze the sandbox, and stops itself with SIGSTOP, so the shell
reports the job as stopped. I sends SIGSTOP to every process in the PID
namespace that is not stopped already, repeating until a pass finds
nothing new, and remembers them. On `fg` or `bg` the shell continues P,
P reads SIGCONT and asks I to thaw, and I continues the processes it
stopped (not those that were stopped before, such as a job a shell inside
suspended). P never stops for terminal input or output (SIGTTIN and
SIGTTOU are blocked in it). A shell inside (`playpen run -- bash -i`) takes
the terminal for its own jobs; Ctrl-Z then suspends its foreground job, as
usual. The test `ctrl_z_stops_the_whole_sandbox_and_fg_resumes_it` uses a
child in its own session; with the freeze disabled, it fails (checked).

**SIGSTOP sent to playpen directly** (`kill -STOP`) cannot be caught, so P
cannot ask for the freeze first. A watchdog covers it: P sends I one byte a
second on their pipe, and when I has heard nothing for 5 seconds
(`SILENCE_LIMIT`) it freezes the sandbox the same way, says so on stderr,
and repeats the freeze every second for anything a pass missed. The next
byte from P thaws it, and P, running again, looks at the clock and the pass
before anything else. This also covers a P that is stuck (a pass on a file
system that hangs, a stderr nobody reads). Why a heartbeat and not a second
timer in I: I would enforce the end time but not a revocation, and
re-reading the pass in I would put a second copy of that judgement in the
process that sits beside the command. Why 5 seconds and not 2: a freeze is
visible to the command (SIGSTOP and SIGCONT interrupt some system calls,
and a shell inside sees its jobs stop), so it must not happen because P was
slow to be scheduled; 5 seconds is the size of the gap already accepted for
a revocation (re-read plus grace). What is left is those 5 seconds, and the
freeze's own limit: a process that forks faster than 20 passes over `/proc`
can stay ahead of it until the next pass a second later. The filter itself
is in the kernel and keeps working throughout.

**New session where `TIOCSTI` works.** Where the kernel still lets an
unprivileged process push input into its controlling terminal (kernels
before the `dev.tty.legacy_tiocsti` setting, or with it set to 1), a
command could queue a shell command for the operator's shell to read after
playpen exits. There the default runs the command in a new session (`setsid`
in X), with no controlling terminal: `TIOCSTI` needs the terminal to be the
caller's controlling one. `--new-session` forces this mode. Playpen retains its place in the caller's job.
PID 1 leaves that group before it forks the command. The supervisor sends
terminal interrupts, quits and resize signals over the control pipe. PID 1
delivers them to the workload group. The existing freeze and thaw protocol
handles Ctrl-Z. Programs can read terminal stdin but have no controlling
terminal for `/dev/tty` or nested shell job control.

**Headless jobs.** Playpen checks Linux's controlling terminal field
(`tty_nr` in `/proc/self/stat`) before it forks. With no controlling terminal,
PID 1 leaves the caller’s group before forking. The workload joins a separate
group led briefly by a setup child, then reaps that child before exec. This
keeps the workload free to create a session of its own and keeps PID 1 out
of signals sent by the command to its own group. PID 1 forwards a signal from
the control pipe to the workload's current group. A sender inside the namespace
can also signal PID 1.

**Private interactive jobs.** With `--private-tty`, the command leads a
new session with a private controlling terminal. The supervisor stays in
the caller's job. PID 1 forwards a signal from the supervisor to the private
terminal's foreground process group. A signal addressed to the caller's
whole job takes the same route. The relay copies the initial terminal
settings and propagates window size changes. It connects terminal-backed
streams to the private terminal and preserves redirected input and output.
The relay reads keyboard input from the caller’s controlling terminal,
including when all three standard streams are redirected.

At the top level, Ctrl-Z lets the outer shell suspend and resume Playpen.
When an inner shell gives the private terminal to a foreground job, the
relay passes control characters through to that terminal. Ctrl-Z then
returns control to the inner shell, including when Playpen's stdout goes
through an outer pipeline. The relay samples terminal modes and foreground
ownership every 20 ms, so a key pressed during a mode or job transition
can follow the previous setting. While the relay is active, host terminal
output processing is disabled. A sibling pipeline stage writing directly
to the host terminal may emit a newline without a carriage return. At
teardown the relay drains pending
output and restores the caller's terminal settings.

**Attached jobs.** A group signal sent with `kill` can reach both the
supervisor and the workload. Linux supplies the sender's PID and UID to the
supervisor for both PID-targeted and group-targeted sends. Suppressing the
forward could lose a signal sent to the supervisor alone. The shared group
also lets other pipeline stages read the real terminal and lets a command
open `/dev/tty` with redirected stdin. For single delivery in this mode,
address the supervisor PID.

Giving the terminal to a separate workload group fixes signal delivery but
also moves the other pipeline stages into the background. A sibling with
SIGTTIN blocked then gets EIO on a keyboard read that would have succeeded
in the original foreground job. It need not produce any signal that Playpen
could use to hand the terminal back. The shared-terminal acceptance test
must therefore cover both signal counts and input at a sibling stage.

## AppArmor

Some distributions (Ubuntu 24.04 and later, for example) set
`kernel.apparmor_restrict_unprivileged_userns = 1`. There an unprivileged
program can still create a user namespace, but it holds no capabilities in
it unless an AppArmor profile allows it. A privileged setup step can then
fail with a permission error. `doctor` reports the global setting, including
when a matching profile is loaded. When `run` fails during setup and the
setting is 1, the error includes the AppArmor profile remedy.
An administrator can allow playpen with a profile like this, saved as
`/etc/apparmor.d/playpen` and loaded with `apparmor_parser -r
/etc/apparmor.d/playpen` (adjust the path to the installed binary):

```text
abi <abi/4.0>,
include <tunables/global>

profile playpen /usr/local/bin/playpen flags=(unconfined) {
  userns,
  include if exists <local/playpen>
}
```

The per-binary profile lets the administrator keep the global restriction.
Qualify an installation with an ordinary account running
`/usr/local/bin/playpen run --no-network -- /usr/bin/true` on a system with
Landlock ABI 9 or later.

On 2026-11-20, a networkless QEMU guest ran Ubuntu 24.04.5 LTS with kernel
6.8.0-147-generic, AppArmor `4.0.1really4.0.1-0ubuntu0.24.04.9` and nftables
`1.0.9-1ubuntu0.1`. The cloud disk, kernel and initramfs matched manifests
signed by Canonical's cloud image key. [Canonical Noble cloud image,
2026-10-17](https://cloud-images.ubuntu.com/noble/20261017/).

In that guest `kernel.apparmor_restrict_unprivileged_userns` and
`kernel.unprivileged_userns_clone` were both 1. The unprofiled launch
returned 1 before exec after AppArmor denied access to
`/proc/self/setgroups` with `EACCES`. The kernel audit identified a
capability denial under `unprivileged_userns`, and Playpen printed the
profile remedy. After loading the profile above, AppArmor listed
`playpen (unconfined)`, and
`run --no-network --without-landlock -- /usr/bin/true` returned 0 with
`exec_and_exit` evidence. Both the original verifier (source `63b7925`)
and the semantic nft verifier (source `2c8f342`) passed the profiled
offline launch. The global AppArmor restriction stayed enabled.

This guest has Landlock ABI 4 and no pasta, so the run used mount-only
socket hiding and loopback. `doctor --format json` returned 1 before and
after profile installation, reported the global AppArmor restriction and
the other missing requirements, and skipped its namespace self-test.
The successful offline launch is the evidence for the profile in this
configuration.

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

The supervisor schedules pass checks at `pass::RECHECK_INTERVAL` (2 seconds).
A scheduled check must run and read the file before it can send SIGTERM.
The original monotonic deadline is captured before namespace setup and is
checked alongside the wall deadline, including immediately before release.
The first stop decision starts one monotonic grace period. Once it expires,
the supervisor requests SIGKILL if needed. A delayed supervisor or init and
kernel signal delivery affect when the command actually stops. The hidden
`--pass-recheck-ms` may shorten the poll interval in tests.

## The mechanism, step by step

The process tree and the order are given in the spec. The points that
matter for safety:

1. **No connectivity before the rules.** The network namespace starts with
   only `lo`. The ruleset is loaded and verified first; pasta is attached
   only afterwards. There is no moment at which a route out exists without
   the filter.
2. **Read back the installed policy.** After loading, Playpen compares
   the JSON for its table with the typed approval before reporting ready.
   It checks table family, chain hooks, priorities and policies, ordered rule
   expressions and verdicts, and the accounting sets and counter. It
   normalizes the supported numeric and symbolic spellings and ignores
   handles, counter values and runtime set elements. Unknown material
   objects or expressions fail closed. A real-load test adapter reports a
   narrower port range while preserving the rule count and confirms that
   the workload never starts. This check trusts Linux and the selected
   `nft` executable (including a `PLAYPEN_NFT` override) to return the
   installed table. The workload cannot choose that executable after
   setup.
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
   exits when the namespace's process is gone. The sandbox's init does not
   rely on the chain alone: the end of its pipe from playpen means playpen
   is gone, and it exits, which kills everything in the PID namespace
   (`killing_playpen_kills_the_sandbox`). What a killed playpen leaves
   behind is the small directory of pasta's PID file.

## Leaks considered

| Leak | How it is closed | Tested |
|---|---|---|
| Traffic to any unapproved address, port or protocol, IPv4 or IPv6 | output policy drop; only listed `daddr`+`dport`+protocol accepted | yes (TCP, UDP, IPv6, network ranges, protocol mismatch) |
| The broadcast address of an approved network (one packet, every host on it), and its network address | a network rule does not accept the network and all-ones address of any listed IPv4 network of /30 or broader; dropped and counted unless listed on its own. Same rule as hallpass | yes (`network_and_broadcast_addresses_of_a_listed_network_are_dropped`) |
| IPv6 forgotten while IPv4 is filtered | `inet` family table covers both; an IPv4 approval never opens IPv6 | yes |
| ICMP / ICMPv6 as a side channel | not approvable; only neighbour solicitation/advertisement with hop limit 255 (link-local by RFC 4861) pass; kernel MLD reports and router solicitations are dropped silently; ICMP errors for accepted flows pass as `related` | NDP needed for pasta works (IPv6 tests pass through pasta-configured namespaces); not tested separately |
| pasta's gateway mapped to the host's loopback | `--map-host-loopback none`; and unless approved, the filter drops the gateway too | yes, end to end (`tests/gateway.rs`): playpen runs inside a throwaway network namespace whose only outside is a `dummy` interface, with gateway 192.0.2.1. With the gateway approved, a connection to it does not arrive at a listener on that namespace's wildcard address; with a pasta wrapper that drops the flag (the control) it does; unapproved, it is dropped and counted. The test reads the gateway pasta configured from `/proc/net/route` inside. The same for IPv6, with gateway 2001:db8::1 and a listener on `[::]`. Nothing can leave the machine: the dummy interface discards everything |
| pasta forwarding namespace loopback ports to the host (`-T auto`, its default) | `--tcp-ns none --udp-ns none`. The filter does **not** catch this: it accepts loopback inside the namespace, and pasta's sockets there are spliced to the host | yes: a host listener on 127.0.0.1 and ::1 below 32768 is not reached. Removing the flags makes the test fail (checked). Note: pasta's auto mode skips the ephemeral range, so a test on an ephemeral port proves nothing |
| pasta forwarding host ports into the namespace | `--tcp-ports none --udp-ports none`; input chain drops new inbound connections anyway | flag unit-tested |
| DNS forwarded by pasta | `--dns none --search none`, no `--dns-forward`; port 53 to the gateway is not approved | flag unit-tested |
| Names resolved by host daemons over filesystem sockets (systemd-resolved varlink, nscd, avahi) | generated `nsswitch.conf` with `hosts: files`; their sockets are refused like every host socket | `--host` name resolves, other names do not; the sockets are in the walk of `no_host_socket_is_connectable_from_inside` |
| Host files changed | none are: all overrides are bind mounts in a private mount namespace | yes (`/etc/hosts` unchanged) |
| Command changes the rules, adds addresses or links, opens raw/packet sockets, joins init's user namespace, reads init's memory | nested user namespace, no capabilities, init non-dumpable | yes, each one, for the command and for a grandchild; and the rules still block after the command ran `nft flush ruleset` |
| Command joins the host's network namespace | it would need `CAP_SYS_ADMIN` in the host's user namespace; host processes are invisible (PID namespace, fresh `/proc`) | indirectly (no capabilities; `setns` to init's namespace denied) |
| Inherited sockets from the caller (a host-namespace socket on fd 3+) | every descriptor above 2 is marked close-on-exec before the sandbox starts | yes (file, Unix, TCP, UDP, listener, pipe) |
| Standard streams that are host-network sockets (UDP, TCP in any state, other families; without Landlock also Unix sockets that can still be connected somewhere) | refused before anything runs | yes, with the reconnect attempted from inside |
| Children and daemons escaping | PID namespace; init's exit kills them all | yes (a background job does not outlive the command) |
| Host daemons reached over pathname Unix sockets (buses, service managers, container engines, agents, resolvers, syslog, browser automation, sync clients), anywhere in the file system | Landlock `RESOLVE_UNIX`: refused unless exposed; private runtime and X11/ICE/tmux directories; `--expose` brings a path back | yes: every socket under the runtime directory, `/run`, `/var/run`, `/tmp`, `/var/tmp`, `/dev/shm` and the home directory is unreachable; exposed ones are reachable, their siblings not |
| The same on kernels without Landlock ABI 9 (`--without-landlock`) | mount layer, plus `/dev/null` over every socket under `/run`, `/tmp`, `/var/tmp` at start | yes for those places; the test also shows a home-directory socket stays reachable |
| Abstract Unix sockets of the host | own network namespace; Landlock scope | yes |
| Host processes' System V IPC, message queues, `/dev/shm` | own IPC namespace, fresh `/dev/mqueue`, private `/dev/shm` | yes |
| The display server typing into host windows | display sockets refused and hidden unless `--display` | yes |
| Input pushed into the operator's terminal (`TIOCSTI`) | refused by the kernel (`legacy_tiocsti = 0`), else a separate session with either no controlling terminal or a private one | yes (both modes; see the Unix sockets section for what that shows here) |
| The command running on while playpen is suspended (Ctrl-Z), unchecked by the end time and the pass re-read | P freezes every process in the sandbox through I before it stops | yes, with a child outside the terminal's process group; the test fails without the freeze |
| The command running on while playpen is stopped with SIGSTOP (which it cannot catch) or is stuck | I freezes the sandbox after 5 s without a byte from P, until P is heard again | yes (`sigstop_of_playpen_itself_freezes_the_command`: the end time passes while playpen is stopped; the command does not run on, and is stopped when playpen continues) |
| ptrace of the privileged helper or of playpen | helpers non-dumpable; playpen and other host processes invisible in the PID namespace; Yama ptrace_scope 1 on this machine adds another layer | `/proc/1/mem` and `/proc/1/ns/user` denied |
| A fake or broken `nft` | output structure verified after load | yes |
| pasta not coming up | its exit status is checked; the command is not started | yes (fake pasta) |
| Approval running out while the command runs | timer in playpen: SIGTERM, then SIGKILL after 3 s to the PID namespace's init | yes, both paths |
| A pass revoked, deleted or edited (destination in use) while the command runs | re-read every 2 s; SIGTERM, then SIGKILL after 3 s | yes (revoke, delete, port change; and SIGKILL for a command that ignores SIGTERM after a revocation) |
| A pass edited to add a destination or extend the window during a run | rules and end time fixed at start; never reloaded | yes (added destination stays blocked) |
| A pass swapped for a symbolic link, or made writable by others | hallpass's loader refuses both, at start and on every re-read | yes, at start (symlink, mode 0666) and during the run (renamed over by a symlink; mode 0620 and 0602) |
| `--allow` adding a destination beside a pass | refused | yes |

## What is not closed

- **Exposed sockets.** `--expose` and `--display` give the command
  whatever the daemon behind the socket can do, including handing it
  descriptors (`SCM_RIGHTS`) that belong to the host's network. The start
  line and the report list every exposed path.
- **Without Landlock** (`--without-landlock`): sockets outside `/run`,
  `/tmp`, `/var/tmp` and the runtime directory, sockets created after the
  start, and sockets a daemon recreates during the run stay reachable.
- **Files as a channel.** A host process that reads files or named pipes
  the command can write (a sync client watching the home directory, a print
  spooler, a mail drop), and network file systems (NFS, SMB, sshfs and
  other FUSE mounts outside the runtime directory), carry data off the
  machine. playpen does not confine files; `--hide` covers known places.
- **Other terminals of the same user.** The command can open the user's
  other `/dev/pts/N` and write to them or read keystrokes from them. Not a
  network path.
- **SIGSTOP to playpen itself.** Unlike Ctrl-Z it cannot be caught. The
  sandbox is frozen by its init after 5 seconds without a sign of P; for
  those 5 seconds the end time and the pass re-read are not enforced. The
  kernel's filter keeps working.
- **The approved destination.** If it is a proxy, a VPN endpoint or a
  jump host, traffic continues from there. playpen cannot see it.
- **Volume and content.** No rate limits, no inspection.
- **Covert channels through approved flows**, and timing channels.
- **Kernel or tool bugs.** A kernel exploit, or a bug in nftables
  (ruleset evaluation) or in pasta (which runs on the host), defeats the
  guard.
- **A system clock set forward ends the run early.** The end time is
  held on two clocks: a monotonic deadline fixed when the command starts,
  and the wall clock, read every second. The run ends when either says so.
  Setting the system clock back therefore does not extend the run; and a
  machine that was suspended (the monotonic clock stands still meanwhile)
  stops the command when it wakes after the end, instead of giving it the
  time slept on top. A clock set forward past the end stops the command at
  once.
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
