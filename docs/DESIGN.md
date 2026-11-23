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
`ip|ip6 daddr ADDR tcp|udp dport PORTS accept`, and `goto contacted` in
place of `accept` with `--report-contacts`.

**pasta for connectivity.** It is the rootless user-mode network stack that
is installed (slirp4netns is not). It attaches to an existing namespace
given a PID, and forks to the background only once the namespace is
configured, so its exit status is a reliable "up" signal.

**`reject` before the drop policy.** The chain policy is drop, but the last
rule rejects with `admin-prohibited`. Without it a blocked TCP connect hangs
for minutes in SYN retries; with it the tool fails at once with "No route to
host" (over IPv6: "Permission denied"), which is clearer and makes test
runs fast. The policy is still drop,
so anything that gets past the reject (nothing should) is dropped. With
`--on-drop` the last rule is a drop instead ("The tripwire").

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
| VM sockets (AF_VSOCK) the command creates | yes, in the kernel's default `global` mode: to the hypervisor host, to the machine's VMs, and to vsock listeners on the machine (also by acting as a VM through `/dev/vhost-vsock`) | open; see "Socket families" | `tests/socket_families.py` in disposable guests (see "Socket families"); not an automated test |
| Qualcomm IPC router sockets (AF_QIPCRTR) the command creates | before 7.2: yes, to QRTR ports of the machine; from 7.2 the family exists in the initial namespace only | open before 7.2 | same; 7.1.4 and 7.2.8 |

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

## Socket families

The nft table sees IPv4 and IPv6, and host Unix sockets are covered above.
playpen installs no filter on `socket()`. The command can create a socket
of any other family that the kernel offers to an unprivileged process in a
new network namespace. This section records what each family did in a
default sandbox and what it reaches. It was measured on 2026-11-22.

**How it was measured.** `tests/socket_families.py sweep` calls `socket()`
for every family number from 0 to 63, with types 1 to 5 and protocol 0 and
the protocols in its `EXTRA` table. It prints the errno and the modules that
appeared in `/proc/modules`. It ran as uid 1000 inside `playpen run
--no-network` and inside `playpen run --allow 203.0.113.1:9/tcp`, with the
same results in both. A sweep can load modules, so it ran in disposable QEMU
guests (KVM, no NIC, no host file system). The guests booted Linux
7.2.8-arch1-2 (the host's kernel image) and 7.1.4-arch1-1, with nftables
1.1.7, pasta 2026_09_25.df90211 and Python 3.14.7. Every program, library
and kernel module in the guests came from a cached Arch package whose
signature `gpg` verified against pacman's keyring with full trust. The rest
was the release build of playpen at `b8f760f`, the probe, the test
scripts and a minimal `/etc`.

On the host the sweep ran only for families that are built in or already
loaded (`sweep --families 1,2,10,17,31,44,45`). The results matched the
7.2.8 guest, and the host's module list did not change. The host's
`modules.alias` equals the guest's apart from out-of-tree NVIDIA entries.
Of the modules in the table, `aead`, `bluetooth`, `llc` and `rfkill` are
loaded on the host. A command on the host would load the others as it did
in the guest.

### What each family does in the sandbox

The kernel loads a family's module on the first `socket()` call for it. It
does so for a process in any namespace, without privilege, and also when
the call then fails. In the sandbox the sweep loaded 48 modules for 18
families on 7.2.8, and 51 modules for 19 families on 7.1.4. Opening
`/dev/vhost-vsock` loads 3 more (see "VM sockets").

Every row comes from `P sweep` (see "Commands") on both kernels, and the
results are the same on both except where a row says otherwise. The
comparison with the initial namespace is the same sweep as uid 1000 without
playpen.

| Family (number) | `socket()` in the sandbox | Modules the attempt loaded | What the command reaches with it |
|---|---|---|---|
| Unix (1) | created | none (built in) | see "Host Unix sockets" |
| IPv4 (2), IPv6 (10) | stream and datagram created. Raw sockets are denied; `playpen doctor` checks this | none (built in) | what the nft table accepts |
| Netlink (16) | 14 of the 32 protocols created, the same as in the initial namespace | `crypto_user`, `ib_core`, `scsi_transport_iscsi`, `xfrm_user` | the kernel, and processes in the same namespace. `playpen doctor` checks that address and link changes are denied |
| PF_KEY (15), packet (17), LLC (26), Phonet (35), XDP (44) | `EPERM` | `af_key`, `aead`, `xfrm_algo` (15); `llc2`, and `llc` on 7.2.8 (26); `phonet` (35) | nothing |
| AppleTalk (5), ATM (8, 20), Bluetooth (31), IEEE 802.15.4 (36), NFC (39) | `EAFNOSUPPORT`. uid 1000 creates them in the initial namespace only. 7.2.8 has no AppleTalk module, and family 20 fails in its initial namespace too | `appletalk`, `llc`, `psnap` (7.1.4); `atm`; `bluetooth`, `rfkill`; `ieee802154`, `ieee802154_socket`; `nfc` | nothing |
| MPLS (28) | `EAFNOSUPPORT`: MPLS has no sockets | `mpls_router`, `ip_tunnel` | nothing |
| Qualcomm IPC router (42) | 7.1.4: datagram created. 7.2.8: `EAFNOSUPPORT`; `af_qrtr.c` at v7.2 allows the family in the initial namespace only, and v7.1 does not | `qrtr` | 7.1.4: the machine's QRTR ports, which all namespaces share. A datagram from the sandbox reached a root listener in the initial namespace. 7.2.8: nothing |
| RDS (21) | seqpacket created | `rds` | not tested. RDS carries messages over TCP in the namespace (the nft table applies) or over RDMA devices (the guests had none) |
| PPPoX (24) | created (PPPoE, L2TP, PPTP) | `pppox`, `pppoe`, `l2tp_ppp`, `pptp` and 7 modules they need | PPPoE frames go out on an interface of the namespace: `lo`, or pasta's tap. pasta forwards only ARP, IPv4 and IPv6 frames (`tap_add_packet` in its source). L2TP runs over UDP and PPTP over GRE in the namespace, where the nft table applies. Not tested by sending |
| CAN (29) | created (raw, BCM, ISO-TP, J1939) | `can` and its 4 protocol modules | nothing: the namespace has no CAN interface, and the command cannot add one |
| RxRPC (33) | datagram created | `rxrpc`, `krb5` and ciphers (`libdes` on 7.2.8; `fcrypt`, `pcbc` on 7.1.4) | UDP in the namespace, where the nft table applies. Not tested by sending |
| ALG (38) | seqpacket created | `af_alg` | the kernel's crypto code; no peer |
| VSOCK (40) | stream, datagram and seqpacket created | `vsock`, `vsock_loopback`, `vmw_vsock_vmci_transport`, `vmw_vmci`, `vmw_vsock_virtio_transport_common` | outside the nft table: see "VM sockets" |
| KCM (41) | datagram and seqpacket created | `kcm` | the TCP sockets the command attaches to it, where the nft table applies |
| SMC (43) | stream created | `smc`, `dibs` | TCP in the namespace, where the nft table applies. SMC-R and SMC-D need RDMA or ISM devices (the guests had none; not tested) |
| MCTP (45) | datagram created | none (built in) | nothing: the namespace has no MCTP interface, and the command cannot add one |
| TIPC (30) | `EAFNOSUPPORT` | none: `tipc` has no `net-pf-30` alias | not tested with `tipc` loaded |
| every other number from 0 to 63 | `EAFNOSUPPORT` | none | nothing |

In egress mode the namespace has `lo` and pasta's tap, which pasta names
after the host's uplink (`dummy0` in the guests).

### VM sockets (AF_VSOCK)

Linux 7.0 added a VSOCK mode to each network namespace. It is in
`/proc/sys/net/vsock/`, which exists only while the `vsock` module is
loaded:

- `ns_mode`: `global` or `local`. It is read-only and is fixed when the
  namespace is created. The initial namespace is `global`.
- `child_ns_mode`: `global` or `local`. A namespace that a process in this
  namespace creates gets it as its `ns_mode`. It starts equal to `ns_mode`.
  The first write locks it: a different value later fails with `EBUSY`. A
  `local` namespace cannot write `global` (`EPERM`). Root in the user
  namespace that owns the network namespace can write it; no privilege on
  the host is needed.
- `g2h_fallback` (7.1 and later; default 1): whether a connection to a CID
  that no local VM has goes to the hypervisor.

A `global` socket reaches the hypervisor, and the VMs and sockets of every
`global` namespace. A `local` socket reaches only the VMs and sockets of
its own namespace. The guest-to-host transports (virtio, VMCI, Hyper-V)
refuse it, so it does not reach the hypervisor. A vhost device belongs to
the namespace of the process that opened `/dev/vhost-vsock`. Before 7.0
there is no mode, and every socket behaves as `global`. Sources: the [kernel
documentation](https://docs.kernel.org/admin-guide/sysctl/net.html#ns-mode),
and `net/vmw_vsock/af_vsock.c`, `virtio_transport.c`, `vsock_loopback.c`
and `drivers/vhost/vsock.c` at v7.1 and v7.2.

playpen creates the sandbox's namespace while it is in the caller's
namespace, so the sandbox's `ns_mode` is the caller's `child_ns_mode`.
That is `global` unless an administrator wrote `local` in the initial
namespace.

The paths below were measured on 7.1.4 and 7.2.8, with the same results on
both. The command ran in a default sandbox, and the other side ran as root
in the initial namespace. CID 2 is the host and CID 3 the guest.
"Connected" means that a message and its reply went through. For `local`,
root wrote `local` to the initial namespace's `child_ns_mode` before the
sandbox started. The `local` runs used port 7001 and guest CID 43 in place
of 7000 and 42.

| Path | `global` (the default) | `local` | Command side; other side |
|---|---|---|---|
| In a VM with a vsock device, the command connects to the hypervisor host (CID 2) | connected | `ENETUNREACH` | L2: `P vsock-connect 2 1234`; L1: `P vsock-listen 1234` |
| The hypervisor host connects to a listener of the command in the VM (CID 3) | connected | `ECONNRESET` | L2: `P vsock-listen 7000`; L1: `P vsock-connect 3 7000` |
| On a host that runs a VM, the command connects to the VM (CID 3) | connected | `ENODEV` | L1: `P vsock-connect 3 5000`; L2: `P vsock-listen 5000` |
| The command connects to a listener on its own machine over loopback: CID 1, and CID 2 where no guest-to-host transport is loaded | connected | `ECONNRESET` | `P vsock-connect 1 1234`, `P vsock-connect 2 1234`; `P vsock-listen 1234` |
| The command opens `/dev/vhost-vsock`, acts as guest CID 42 and connects to a listener on its own machine | connected | reset by the kernel | `P vhost-guest 1234 --guest-cid 42`; `P vsock-listen 1234` |

The VM rows used two nested guests on the same kernel. L1 played the
hypervisor host and ran L2 with `-device vhost-vsock-pci,guest-cid=3`. The
vhost module was never loaded on the real host. The loopback and
`/dev/vhost-vsock` rows ran in L1 and in a single guest without a vsock
device.

Also measured, on both kernels:

- Any user can read `ns_mode` and `child_ns_mode`, and so can the command
  in the sandbox (`P vsock-mode`). The command cannot write its
  `child_ns_mode` (`EACCES`).
- A namespace that exists when `vsock` is loaded gets `global`. In a guest
  without `vsock`, the command loaded it (`P sweep --families 40`), and its
  `ns_mode` was `global`. Root then wrote `local` to the initial
  namespace's `child_ns_mode`. The running sandbox stayed `global`, and a
  sandbox started after the write was `local`.
- A `local` namespace needs no privilege. As uid 1000 (the last command in
  "Commands"): a user and network namespace of one's own, `local` written
  to its `child_ns_mode`, then a child network namespace. The child's
  `ns_mode` was `local`. From it, in a VM the hypervisor host was
  unreachable (`ENETUNREACH`), and on the hypervisor host the VM was
  unreachable (`ENODEV`). This also worked after root had locked the
  initial namespace's `child_ns_mode` to `global`.
- The command can load the modules. An AF_VSOCK `socket()` loads `vsock`
  and 4 transport modules. Opening `/dev/vhost-vsock` loads `vhost_vsock`,
  `vhost` and `vhost_iotlb`. systemd's `50-udev-default.rules` gives
  `/dev/vhost-vsock` mode 0666 before the module is loaded, and the sandbox
  on the host sees it with that mode. A VM's vsock driver needs `vsock`,
  and a host loads `vhost_vsock` when it starts a VM with a vsock device.
  On the development host neither module is loaded.
- On the host, `--hide /dev/vhost-vsock` made the path `/dev/null` (1:3) in
  the sandbox.

### Landlock

No Landlock right restricts which sockets a process creates. At ABI 9
(Linux 7.1), Landlock covers file access, including lookups of pathname
Unix sockets (`LANDLOCK_ACCESS_FS_RESOLVE_UNIX`, new in ABI 9). It also
covers binding and connecting TCP ports, abstract Unix sockets and
signals. ABI 10 (7.2) adds binding UDP sockets to ports and setting their
remote ports. The
source for both is `/usr/include/linux/landlock.h` from linux-api-headers
7.2-1. In the kernel sources, ABI 11 (7.3) adds only
`LANDLOCK_RESTRICT_SELF_NO_NEW_PRIVS`, and ABI 12 (7.4-rc4) adds namespace
and capability permissions. `LANDLOCK_ACCESS_FS_IOCTL_DEV` (ABI 5) can
refuse the vhost ioctls on `/dev/vhost-vsock`. But opening the device
still loads `vhost_vsock`, and `--hide` does both. There was nothing to
test.

### Commands

`P` is `python3 -I tests/socket_families.py`. The command side ran as uid
1000 in `playpen run --allow 203.0.113.1:9/tcp -- P ...`. The sweep and
the VM-to-host row also ran with `--no-network` in place of `--allow`, and
the test of a namespace that loaded `vsock` ran only with `--no-network`.

| What | Command side | Other side (root, initial namespace) |
|---|---|---|
| Family table | `P sweep`; on the host `P sweep --families 1,2,10,17,31,44,45`; for the initial namespace, `P sweep` as uid 1000 without playpen | none |
| QRTR reach | `P qrtr-send 20000` | `P qrtr-listen 20000` |
| VSOCK paths | as in the VSOCK table | as in the VSOCK table |
| Modes | `P vsock-mode` | `echo local > /proc/sys/net/vsock/child_ns_mode` |
| Mode of a namespace that loaded `vsock` | `bash -c 'P sweep --families 40; sleep 3; P vsock-mode'` | the same `echo`, while the command sleeps |
| Unprivileged `local` (uid 1000, without playpen) | in L2: `unshare --user --map-root-user --net bash -c 'echo local > /proc/sys/net/vsock/child_ns_mode && unshare --net P vsock-connect 2 1234'`; in L1 the same with `P vsock-connect 3 5000` | `P vsock-listen 1234` in L1; `P vsock-listen 5000` in L2 |

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
byte from P thaws it, and P, running again, looks at the clock first and then the pass.
When the end time passed while P was stopped, the pass has usually expired too; the end time wins, so the report says `stopped_by_until` as for any other expiry. This also covers a P that is stuck (a pass on a file
system that hangs, a stderr nobody reads). Why a heartbeat and not a second
timer in I: I would enforce the end time but not a revocation, and
re-reading the pass in I would put a second copy of that judgement in the
process that sits beside the command. Why 5 seconds and not 2: a freeze is
visible to the command (SIGSTOP and SIGCONT interrupt some system calls,
and a shell inside sees its jobs stop), so it must not happen because P was
slow to be scheduled; 5 seconds was the size of the gap accepted for a
revocation (re-read plus grace). What is left is those 5 seconds, and the
freeze's own limit: a process that forks faster than 20 passes over `/proc`
can stay ahead of it until the next pass a second later. The filter itself
is in the kernel and keeps working throughout, and so does its time rule:
from the end second on, a command that still runs while P is stopped
reaches nothing but loopback (see "Ending egress in the firewall"). What
the 5 seconds still leave open is a revocation, which only P can see.

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

**Attached jobs.** The command shares the supervisor's process group. That
is what lets other pipeline stages read the real terminal and lets a
command open `/dev/tty` with redirected stdin. It also means that a signal
sent to the group with `kill` reaches the command directly, and the
supervisor as well. Passing that one on gave the command a second copy.
Not passing on a signal that was sent to the supervisor alone loses it.
The supervisor has to tell the two apart, and nothing in the signal does:
Linux reports the same sender PID and UID for a PID-targeted and a
group-targeted send.

Two processes make the difference visible. A witness (W), a child of the
supervisor forked once init exists, stays in the supervisor's group and
reports each signal it receives. Init (I) leaves that group as soon as it
has forked the command. The supervisor then reads a signal sent with
`kill` this way:

| W received it | I received it | It was sent to | The supervisor |
| --- | --- | --- | --- |
| no | either | the supervisor alone | passes it on |
| yes | no | the whole group | does not: the command has its copy |
| yes | yes | playpen's processes, one by one | passes it on |

The last row is `killall playpen`, `pkill playpen` or `kill $(pidof
playpen)`. Those reach W, but they reach I too, because the two look the
same to them: same name, same command line, neither dumpable (so neither
shows its executable). Only the process group differs. A sender that takes
everything (`kill -1`, a control group, a session) also reaches both; the
command then gets its own copy and the passed-on one, as before.

The supervisor reads W's reports before its own signals in each turn of
its loop, asks W to report what it has (and waits for the answer) when a
signal of its own has no report beside it, and drops reports that met no
signal. So a report is matched only with a signal that was pending at the
same time, however late the supervisor runs (after Ctrl-Z, for example).
When W received the signal it asks I the same question. W is younger than
I, so its PID is the higher one: a sender walking `/proc` upwards reaches I
before W, and one walking downwards reaches the supervisor last. Either
way I's copy exists by the time it is asked.

For a group's signal the supervisor still tells I, with a byte that says
so, and I passes it on if the command is no longer in the group (a shell
with job control makes a group of its own). I leaving the group also
settles `kill 0` inside the sandbox: it reaches the command's group, which
is the caller's, and used to reach I, which passed it on a second time.

What is left: a sender that signals the supervisor and W by PID and not I.
That signal is taken for a group's and is not passed on. It takes a
hand-made list of PIDs. If W cannot be had (the fork fails, it is killed,
it does not answer within a second), the supervisor passes on every signal
as it did before.

Tests: `attached_and_new_session_pid_and_group_signals_have_one_delivery`,
`attached_signal_for_each_playpen_process_has_one_delivery` (upwards and
downwards), `attached_group_signal_reaches_a_shell_that_left_the_group`
and `attached_group_signal_from_inside_has_one_delivery`. Each fails when
the part it covers is removed (checked: I's report ignored, the byte for a
group's signal dropped by I, I left in the group).

Giving the terminal to a separate workload group was tried first. It fixes
signal delivery but moves the other pipeline stages into the background. A
sibling with SIGTTIN blocked then gets EIO on a keyboard read that would
have succeeded in the original foreground job, and need not produce any
signal that Playpen could use to hand the terminal back.

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
`hallpass::load`, so the pass is held to the same rules as in hallpass (no
links, mode, size, every validation rule), and an operator sees the same
codes and problem texts. playpen words the refusal for an invalid pass
itself: hallpass's text points to `hallpass check`, which playpen does not
ship, so playpen prints each problem on its own line and points to
`playpen rules --pass FILE`. The price is three crates
(sha2, toml, thiserror, with their own small dependencies). playpen
depends on hallpass with `default-features = false`: hallpass's binary and
clap sit behind its default `cli` feature, added for this.

**Same `Approval`, plus a watch handle.** The pass becomes the same list of
allow rules and the same end time as `--allow` and `--until`; the
namespace code is unchanged except that the supervisor (P) holds a
`PassWatch` and calls it on a timer. Nothing about the start-up order or
the ruleset changes.

**Link-local and the cloud metadata address.** A pass refuses link-local
addresses, and `--allow` accepts them. A pass is an owner's written
approval, held to the hallpass rules, which an operator cannot bend. A
`--allow` is typed by the operator, who then chose it. Because 169.254.169.254
(and fd00:ec2::254) hold cloud credentials, the start line prints a NOTE when
any allowed grant covers one on a TCP port; "covers" means the grant's
network contains the address, so a `/16` does too. The `--allow` is not
refused: a refusal would hide a legitimate choice, and the NOTE puts the risk
in front of the operator.

**The start line is one short line plus clause lines.** With a pass the
line passed 600 characters, which a CI log shows badly. The first line has
the grants, the end time and "everything else is dropped". Every other
clause group has its own line prefixed `playpen:   `, so a filter on the
`playpen:` prefix keeps all of them. The wording of the clauses is
unchanged, and the JSON report is not affected. `--hide` paths are listed
like `--expose` paths; the file of `--capture` is hidden too but left out,
because the `packet capture:` clause already names it.

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

**`--pass-hosts` is the operator's choice to use the pass's names.** It
exists so the operator does not copy an address out of the pass onto the
command line, where a typo maps a name to the wrong destination. The
operator asks for it, and the start line, the plan and the report list
every entry it adds with the label it came from. Each entry pairs a
destination's own `hostname` with that destination's own address. Both come
from the text the owner wrote, so the name can only lead to an address the
pass approves, and no rule changes: `playpen rules` prints the same ruleset
with and without it. Only a single-address destination gives an entry. For
a network, playpen would have to choose an address inside it, and that
choice is the operator's, with `--host`. A `--host` for the same name wins
for the same reason: the operator said so explicitly.

playpen does not look a name up. A lookup on the host at start, approving
the addresses it returns, was considered and dropped: playpen exists so
that a name resolving to an unexpected address cannot widen the scope, and
with a lookup playpen itself would approve whatever DNS answered.

A mid-run edit of a `hostname` follows the rule for edits that change no
rule: the run continues with a notice. `/etc/hosts` is bound at start, like
the ruleset, and is not rewritten. The old name still leads to an address
the pass approves (if that address had changed, the destination's rules
would have changed and the run would stop), so the edit cannot widen what
the command reaches. Stopping would end runs for a correction that grants
nothing.

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
is fixed when the sandbox starts. The one change playpen makes afterwards
is the cut, one set element that refuses everything but loopback when the
command is being stopped (C, the process that holds the capabilities over
the network namespace, otherwise only starts the DNS stub after "go",
waits, and collects the stub's record and the counters at the end;
reloading rules mid-run would add a second load, and
a moment of changing rules, to the most sensitive step). So an edit can
never widen the running command's access, whatever it says, and every edit
that would narrow what is in use already stops it. What is left (a raised ceiling, a later `valid_until`, a
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

## Ending egress in the firewall

Before this, the command could reach its approved destinations until it
exited: through the re-read interval, the 3-second grace after SIGTERM,
and, while P was stopped, up to 5 more seconds before the freeze. Two
things now close that in the kernel.

**The time rule.** With an end time, both the output and the input chain
have `meta time >= END-SECOND drop`, after the loopback accepts and before
everything else, `ct state established,related accept` included. So from
the end second on, no new connection, no packet of an open one and no
reply gets through, and loopback still works. The rule is in the ruleset
loaded and verified at start, so it holds whatever P does afterwards:
stopped with SIGSTOP, stuck, or slow to be scheduled. Details:

- nft takes the time as whole seconds since 1970. A fraction is a syntax
  error, and nanoseconds are read as seconds. playpen rounds the end time
  down, so egress closes up to 1 second early, never late. It also clamps
  at 18446744073 (2554-07-21T23:34:33Z): nft stores the time in
  nanoseconds in 64 bits, and a larger value wraps to a time in the past.
- `meta time` is the wall clock (`CLOCK_REALTIME`) when the packet is
  filtered, the clock P's own wall check reads. Setting the clock forward
  closes egress early, as it stops the run early. Setting it back delays
  the rule by as much; P's monotonic deadline still stops the command on
  time and adds the cut, so the delay matters only while P is also
  stopped. Suspend counts, as on the wall clock.
- Drop, not reject. In the input chain a reject would itself send an ICMP
  error out after the end; a drop sends nothing. The output chain uses the
  same verdict. A UDP send then fails with "Operation not permitted"; a
  TCP connect waits for its timeout instead of failing at once, which is
  acceptable for a command that is being stopped.
- The output rule counts in its own counter, `late`. These packets are
  reported apart from drops (`refused_after_end`) and are not judged by
  `--fail-on-drop`: a command that was using an approved destination
  legitimately when the approval ended has not tried to reach a place
  nobody approved, and a normal end must not look like one. The input rule
  has no counter: what arrives was not sent by the command.
- The kernel's own MLD reports and router solicitations are dropped
  silently before the time rule, so they are not counted there either.
- Loopback stays open, so the DNS stub on 127.0.0.1 still answers, and
  its record of names includes lookups made during the grace. Outbound
  packets these rules refuse never reach pasta, so a `--capture` file has
  none of them.

**The cut.** The end time does not cover a pass that is revoked, deleted
or edited during the run. For that, and for a monotonic deadline that
comes before the wall clock, the ruleset always has a set `cut` (type
`mark`, empty at start) and, beside the time rule in both chains, `meta
mark @cut drop`. When P decides to stop the command, it asks C, which
holds the capabilities over the network namespace, to add the element `0`
(`nft add element inet playpen cut { 0 }`). Every packet has mark 0: the
ruleset sets no marks, and the command cannot (`SO_MARK` needs
`CAP_NET_ADMIN` or `CAP_NET_RAW` over the network namespace; inside, it
fails with "Operation not permitted"). From then on only loopback
works. Why an element and not a new rule or a reload: adding an element is
one small transaction that changes no rule, can only narrow, and leaves the
verified shape of the ruleset as it was. Its counter `cut` is reported
with `late`; a packet meets at most one of the two rules.

**Asking C.** P has a pipe to C alone. The pipe it uses for "go" cannot
carry the request: after "go", I reads that pipe, and a byte for C could
be read by I instead. A signal would not do either: any process of the
caller's user can send one, and it brings no answer. The pipe's write end
is held only by P. C waits for S and reads this pipe in one `poll` loop
(with a signalfd for SIGCHLD), so later duties for C while the command
runs are one more descriptor there. C answers `cut`, or `cuterr WHY` when
`nft` failed, on the pipe it already reports on.

**The order.** P prints the notice and sends SIGTERM only after C has
answered `cut`, so nothing the command sends after the notice leaves the
sandbox. P waits up to 2 seconds (`CUT_LIMIT`). When C answers `cuterr` or
does not answer in time, P says that egress could not be closed and sends
SIGKILL at once, without the grace: a grace with egress open is the gap
this closes. When the sandbox has ended while P waits, there is nothing
left that could send.

**No polite finish over the network.** During the 3-second grace the
command can still use loopback and its files, but nothing else. A command
that would send a last report or close a session with an approved server
cannot. That is the decision: the approval has ended or was withdrawn,
and the grace exists to let the command stop cleanly on this machine, not
to use the network after the approval.

**Reading it back.** `nft --json` prints the time rule's operand as a
date without an offset (`"2026-12-01 12:34:56"`), in the time zone of the
`nft` process, with or without `--numeric`. On a machine whose local zone
is not UTC the readback would name another second. C runs `nft` with
`TZ=UTC0` for every listing and the comparator reads the date as UTC; the
time rule must be at exactly the end second. The `cut` set must be empty
at start.

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
   expressions and verdicts, and the accounting sets and counters,
   including the time rule and the empty `cut` set, and with
   `--report-contacts` the `contacted` chain, the empty `seen4`,
   `seen6`, `answered4`, `answered6`, `reset4` and `reset6` sets and the
   four reply rules of the input chain, and with `--on-drop` the tripwire and the declared size
   of `cut`. It normalizes the
   supported numeric and symbolic spellings (and reads the time, listed
   with `TZ=UTC0`, as UTC) and ignores handles, counter values and the
   elements of the drop sets. Unknown material
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

## Name lookups

There is no DNS inside the sandbox. A stub (D in the spec's start-up
sequence) answers on 127.0.0.1 port 53. A lookup of an unmapped name still
fails at once, a client that does not read `/etc/hosts` (`dig`, Node's
`dns.resolve`) finds the `--host` names, and playpen can say which names
the command wanted.

**Where it runs.** C forks D after it is told to go and before it forks
S. D is in the sandbox's network namespace, so 127.0.0.1 is the sandbox's
own loopback. It is in C's PID namespace, which is the host's: the
command, in S's PID namespace with a fresh `/proc`, cannot list it, name
it in `kill(2)` or trace it. D binds the port with C's capability (C is
root in the user namespace that owns the network namespace), then clears
every capability set, sets `no_new_privs`, checks the drop as X does,
points its standard streams at `/dev/null` and closes every descriptor
but its two sockets and its two pipes to C. Unless `--without-landlock`,
it then restricts itself with Landlock: no file access at all, no TCP
bind or connect, no abstract Unix sockets, and no signal to or trace of a
process outside its domain. It is non-dumpable. S closes its copies of
D's pipes before it forks I.

**Why the command cannot take port 53.** Binding a port below
`net.ipv4.ip_unprivileged_port_start` needs `CAP_NET_BIND_SERVICE` over
the network namespace, and changing that limit (per namespace, 1024 in a
new one) needs `CAP_NET_ADMIN` there. The command holds neither: it is in
the nested user namespace. The kernel checks the privilege before it
checks whether the port is in use, so the bind fails with `EACCES` while D
holds the port, and would fail the same way if D were gone. A query then
gets "connection refused", as quickly as before there was a stub
(`probe privs`: `bind_dns_udp`, `bind_dns_tcp`,
`lower_unprivileged_port_start`).

**Why `hosts: files dns` cannot reach a host daemon.** `files` reads the
generated `/etc/hosts`. `dns` is glibc's own resolver code, in the
command's process: it sends to the nameservers in `/etc/resolv.conf`, and
the generated file lists only 127.0.0.1, which in this network namespace
is D. The host's other sources are left out: `resolve` asks
systemd-resolved over a Unix socket, `mdns` asks avahi, and `myhostname`
and `mymachines` answer from the host's own state. glibc asks nscd over
its socket in `/run` before any source; that socket is refused like
every host socket (covered, without Landlock). `search .` stops glibc
from also asking for the name with the host's domain appended. Without a
`resolv.conf` or an `nsswitch.conf` on the host, playpen binds neither;
glibc's defaults then ask the nameserver at 127.0.0.1, which is D.

**Why it forwards nothing.** D has no upstream and no cache; it answers
from the `--host` list alone. Its sockets are bound to 127.0.0.1, and the
kernel refuses to send from a loopback address over a route that is not
loopback (`EINVAL`), so even a reply to a forged source address stays in
the namespace. Anything else D sent would meet the same filter as the
command's traffic.

**What it believes.** Only the question. The other sections of a query
(an EDNS OPT record, for example) are ignored and never echoed. A
malformed message is refused (`FORMERR`) and not recorded. A name is
recorded as shown: escaped, and cut at 253 bytes (spec, "Name lookups").
So a name made of terminal escape sequences reaches neither the
operator's terminal nor the report as typed. The record crosses two
process boundaries on its way to P, and P checks every name again and
drops an entry it would not show.

**The record.** At most 256 names, with a count each. At teardown C
closes D's control pipe; D writes its record as one JSON line and exits;
C passes it to P. If D does not answer within 2 seconds, C kills it and
the report says why in `lookups_error`. `compare` then treats the lookup
evidence as incomplete. The record is not in the shareable report: names
can say what a run was for.

## The host's own addresses

pasta configures the sandbox's interface from the host's (`--config-net`):
it takes the interface that has the default route and copies its addresses
and routes. Inside the sandbox the host's address on that interface is
therefore the sandbox's own. A connection to it is delivered inside the
sandbox and never reaches pasta. Approving exactly that address opens
nothing on the host: the filter accepts the packet, nothing listens
inside, the command gets "connection refused", and no drop is counted.
A service on the host that listens on that address (a test fixture, for
example) cannot be reached this way.

playpen does not know which addresses pasta will copy until pasta has run,
so it looks afterwards. Once pasta is attached, C lists the addresses of
the namespace and reports each one that a rule approves on its own. The
supervisor prints a NOTE that names it. A network rule that merely
contains the address is not reported, and neither is an address playpen
put on `lo` itself (`--lo-addr`). The run goes on, because the approval
may list other destinations.

To reach a service on this host with the filter on, have the service
listen on an address the sandbox does not have:

- **Another address of the host**, on a second interface (a bridge, a VPN
  link, a dummy interface an administrator added). pasta connects to it
  from the host, where it is local. The approval names that address.
- **A throwaway host, without privileges.** Make a user and network
  namespace (`unshare --user --map-root-user --net`). In it, add a dummy
  interface with an address and the default route, and a second dummy
  interface with the service's address. Start the service, then run
  playpen as the caller's own user again (`unshare --user
  --map-user=UID --map-group=GID playpen run ...`). pasta copies the first
  interface; the service's address stays outside the sandbox. Nothing can
  leave the machine, because a dummy interface discards what is sent to
  it. `tests/gateway.rs` builds this in a dozen lines of shell;
  `a_host_service_is_reached_at_an_address_the_sandbox_does_not_have`
  reaches a listener at the second address and is refused at the copied
  one.

Two things that do not work:

- **playpen inside playpen.** The inner one has to mount (`/proc`, private
  mounts), and Landlock, which the outer one applies to the command,
  refuses every mount: `cannot make mounts private: EPERM`. (With
  `--without-landlock` on the outer run the inner one starts; checked.)
  Put the service and the program that runs playpen side by side in the
  throwaway host instead.
- **Mapping the address.** pasta's `--map-guest-addr` makes another
  address inside stand for the host's. The command would then have to
  connect to an address that is not the approved one, and the filter
  would have to approve that one. `--map-host-loopback` stays `none` (see
  the table below).

## Packet capture (`--capture`)

The capture is a record for the owner of what the command sent, to set
beside the report and the pass window.

**pasta writes it.** pasta already handles every frame that leaves the
sandbox, and it has `--pcap`. A capture inside the sandbox would need
capabilities the command must not have. pasta captures on the side of the
interface that faces the sandbox, so the file shows the packets as the
sandbox sent them, before pasta turns them into host sockets. The output
chain rejects a refused packet before it reaches that interface. So the
capture holds approved traffic and its replies, and ARP and neighbour
discovery with pasta. The drop counters, not the capture, record what was
refused. `the_capture_holds_the_approved_exchange_and_nothing_to_the_denied_address`
checks both against a fixture with one approved and one denied address.

**A path, not a descriptor.** Giving pasta the file playpen opened would
be best, but it does not work (checked with strace on pasta
2026_09_25.df90211):

- pasta closes every inherited descriptor when it starts
  (`close_range(3, ~0)`), so neither an inherited descriptor nor
  `/proc/self/fd/N` survives;
- it joins the sandbox's user namespace before it opens the capture, and
  after that the kernel refuses it `/proc/PLAYPEN/fd/N` (`EACCES`: it has
  no `CAP_SYS_PTRACE` over playpen's user namespace).

pasta opens the name it is given with `O_WRONLY|O_CREAT|O_TRUNC`, mode
0600, following symbolic links, before it sandboxes itself (afterwards it
has an empty root). When it cannot open the file, it prints a message and
goes on without a capture, and still exits 0.

**Making the path safe.**

- playpen creates the file first: `openat` in the directory it opened,
  `O_CREAT|O_EXCL|O_NOFOLLOW`, then mode 0600 with `fchmod` (the umask can
  only narrow it). A name that exists, a symbolic link included, is
  refused. A capture is never overwritten.
- pasta starts in that directory, reached through playpen's descriptor
  (its working directory is `/proc/self/fd/N`, resolved in pasta's
  process before `exec`, while the descriptor is still open there), and
  gets the bare name. A change to a directory above cannot redirect it.
- That leaves the name itself, between playpen's create and pasta's open.
  Whoever can write the directory could put a symbolic link in place of
  the file, and pasta would truncate the link's target and write to it
  with the caller's rights. So playpen refuses a directory that its group
  or others can write to, unless it has the sticky bit (as `/tmp` does;
  there only the file's owner can rename or remove the file). It is the
  rule hallpass applies to the pass file itself (not writable by group or
  others), applied to the capture's directory. Directories made with umask
  002 are group-writable and refused; `chmod g-w DIR` is the fix.
- Once pasta is up, playpen checks that the file it created starts with a
  pcap header and that the name still leads to it. pasta writes the header
  as soon as it has opened the file, before it forks to the background. So
  this catches a file pasta could not open (for example under an AppArmor
  profile for pasta that does not allow the path) and a file it opened
  somewhere else. The run then stops before the command starts.

**The command cannot touch it.** The capture's path is added to the hidden
paths, so inside the sandbox it is `/dev/null`. The report file is written
once, at the end, through the file playpen opened; the capture is written
while the command runs, so without this the command (the same user) could
change it the whole time.

**A complete file when pasta stops.** pasta writes each packet as it goes,
with two system calls (a `write` of the 16-byte record header, then the
frame), and buffers nothing. It exits by itself, between two packets, when
it notices that C is gone. It looks once a second, on a timer. SIGTERM
ends it at once, and can come between the two calls of one packet and
leave the last record cut. So with a capture P waits up to 2 seconds for
pasta to exit by itself, sends SIGTERM only after that, and then reads
size and digest through its own descriptor. That costs up to a second at
the end of a run with a capture. Without a capture P still sends SIGTERM
at once.

**The times.** `started_at` is taken when P has sent "go", `ended_at` when
P reads init's report of the exit status. Both come from the wall clock,
so they line up with the pass window and with the capture's timestamps
(pasta writes the wall clock to the microsecond). A change of the clock
during the run changes the difference between them.

**An unused file is removed.** When the run stops before the command is
released, the file holds at most pasta's header and address resolution,
and it would make a second run with the same name fail. playpen removes
it, but only when the name still leads to the file it created.

## Drops while the command runs

`--events-fd` takes only the write end of a pipe. The reasons are one
write of at most `PIPE_BUF` bytes per record, which is atomic, and a
non-blocking pipe, so a slow reader never blocks the supervisor. A regular
file never blocks, but it has no size limit, a full disk would end the
stream without notice, and `>` without append shares an offset with other
writers. We decided to keep the refusal and show the workaround in the
message: `3> >(cat > events.jsonl)`. `cat` is the reader that keeps up.

Before this, a refused destination was known only from the summary at
the end. A long command (a build, a test suite, an agent) that hangs on a
refused connection told its owner nothing until it ended. Now, with
`--events-fd` or `--live-drops`, each new dropped destination is reported
within about 2 seconds, while the command runs.

**C reads, not P.** The counters live in the sandbox's network namespace,
and only a process with `CAP_NET_ADMIN` over it can list them. P has no
such right, and the command must not have it. C already holds it and waits
in one `poll` loop for S and for P's cut request ("Ending egress in the
firewall"). The reading is one more duty in that loop: the poll timeout
runs to the next reading. The code is apart from the teardown readback
(`report_counters`) and from the ruleset text: `src/live_drops.rs` has the
state and the parsing, and `read_drops_live` in `sandbox.rs` runs `nft`.

**Every 2 seconds, on a fixed schedule.** The interval is the one of the
pass re-read (`pass::RECHECK_INTERVAL`), so the owner learns of a drop on
the scale at which a revoked pass takes effect. The schedule starts when C
has forked S, and the next reading is due one interval after the last
was due, not after it ended, so the readings do not drift. When C falls a
whole interval behind (a stopped machine), the next reading is one
interval from now and the ones missed are not made up.

**Two steps: the counter, then the sets.** A reading first lists only the
`dropped` counter. Only when its value differs from the value at the last
listing of the table does C list the table and look at the drop sets.
Most readings of a run without drops, or with only known destinations
that are quiet, are the small step. The value C keeps is the counter as it
read it before the listing, so a packet counted between the two steps
makes the next reading list again. Nothing is missed; at worst one listing
too many.

**What it costs.** Measured on nftables 1.1.7, Linux 7.2.8, an AMD
Threadripper 9970X. Method: in a throwaway `unshare --user
--map-root-user --net` namespace, playpen's own ruleset (as `playpen
rules` prints it, with an end time) is loaded, and addresses 192.0.2.2 and
2001:db8::2 are put on `lo`. UDP datagrams to 1,100 ports of each address
fill both drop sets to their 1,024 elements from the packet path (the
counter at 2,200). Each command runs 200 times in a loop under bash's
`time`; the figures are per run, the mean wall time and the user plus
system CPU time.

| Read | Sets empty | Sets full (2 × 1,024) |
| --- | --- | --- |
| `nft --json list counter inet playpen dropped` | 1.0 ms wall, 1.0 ms CPU, 230 bytes | 1.2 ms wall, 1.2 ms CPU, 237 bytes |
| `nft --json list set inet playpen drop4` | 1.1 ms, 1.1 ms | 15 ms, 15 ms, 100 KB |
| `nft --json list table inet playpen` (`TZ=UTC0`) | 1.9 ms, 1.9 ms, 6.7 KB | 31 ms, 31 ms, 209 KB (37 ms in an earlier run) |
| `NFT_MSG_GETOBJ` for `dropped` over `NETLINK_NETFILTER`, in-process | 4 µs | 4 µs (6 µs with a new socket each time) |

So the step taken every 2 seconds costs about 1.2 ms of CPU: 0.06% of one
CPU. A run that keeps sending to known destinations moves the counter at
every reading and has C list the table each time: with both sets full,
about 31 to 37 ms per 2 seconds, under 2% of one CPU, and with a handful
of destinations about 2 ms. The figures are for `nft` alone; C's parse of
the listing is not in them. The readings run only with `--events-fd`,
`--live-drops` or `--on-drop`. Without them the counter is read once, at
teardown, as before.

**nft, not netlink.** A netlink request would be 300 times cheaper, but
1.2 ms per 2 seconds does not need it. It would also be raw nfnetlink
message code in playpen beside the `nft` that loads and verifies the
ruleset, bypass the configured `nft` (`PLAYPEN_NFT`, which the tests
replace with fakes), and need its own parser of the sets' attributes for
the second step, where the cost is. If a later need (a shorter interval,
many runs on one machine) makes the cost matter, the counter step alone
can move to netlink. The measurement used a short script (not in the
repository) that sends `NFT_MSG_GETOBJ` with `NFTA_OBJ_TABLE`,
`NFTA_OBJ_NAME` and `NFTA_OBJ_TYPE` (counter) and reads
`NFTA_COUNTER_PACKETS` from the answer.

**Each destination once, kept in C.** `LiveDrops` in C keeps the set of
destinations (address, protocol, port) it has sent. A destination's
packet count grows, but it is sent once, with the count at the reading
that found it. Keeping the set in C means a destination that is dropped
the whole run costs one line on the pipe, not one per reading. The set
holds at most the 2,048 elements of the drop sets. nft prints a protocol
by name when it knows it, else as a number ("6", "17"); both are
normalized to the name before the comparison, as at teardown, so a
destination is not sent twice under two names.

**Wire format.** C writes `denied JSON` on the pipe it reports on, one
line per destination, with the fields of the report's `dropped`
destinations (`address`, `protocol`, `port`, `packets`), well under
`PIPE_BUF`, so a line is never mixed with one from S or I. P parses it
with the teardown readback's own types, and the record on `--events-fd`
is the same object. A failed reading sends `deniederr WHY` once (cut to
512 characters); C tries again at every interval and sends nothing more
for later failures. P reports both from its main loop, and once more
after the command has ended, for lines that came with the exit.

**Few lines on stderr.** stderr is the command's too, so a run that
probes many places must not bury the command's own output. `--live-drops`
prints the first 8 destinations and then one line that says there are
more and where to find them. The events stream, read by a program, gets
every one.

**Events always, stderr only when asked.** It was an open question
whether the lines come by default on a terminal. Decision: no. The `denied`
records come whenever `--events-fd` is given, and the lines only with
`--live-drops`, whatever stderr is. Reasons: the lines appear in the
middle of the command's own output on the caller's terminal, which an
attached or `--private-tty` command shares; scripts and logs that read
stderr get the lines they got before; and a program that wants to know
already reads `--events-fd`. `--live-drops` is in the plan and its digest
(only when given, so older digests stay valid) because it changes what the
run prints, as `--capture` does.

**After the end of egress.** The time rule and the cut come before the
drop rule in the output chain, so from the end second, or once the cut is
in place, a refused packet is counted in `late` or `cut` and never reaches
`@drop4`, `@drop6` or `dropped`. The command's attempts during its grace
make no `denied` record. The report counts them in `refused_after_end`.

**What a reading does not see.** A destination first dropped after the
last reading and before the command ends has no record: C does not make a
reading at teardown for this. Its readback for the report comes at once,
and P has the complete list there. A destination beyond 1,024 in its
family's set moves `dropped` but is in no set, so it has no record either.
The report's `destinations_truncated` says so.

**A cut request during a reading.** C answers P's `CUT` after the reading
in flight: at most the time of one listing, about 40 ms with full sets,
well inside P's 2-second limit.

**Later: NFLOG.** A `log group N` rule beside the drop rule would hand
each refused packet to a netlink listener at once, without polling, and
with more than the destination (the source port, the first bytes). It
needs a listener in C with its own netlink code and rate limits, and it
duplicates what the sets already count. Not done.

## The tripwire (`--on-drop`)

By default a refused packet fails only its own connection. A command that
tries a place nobody approved can go on using every approved destination,
and the owner learns of it from the summary, or within 2 seconds from the
`denied` records. For a run where the first refused packet already means
the command is not doing what was reviewed, `--on-drop cut|stop` closes
all egress at that packet, in the kernel.

**The rule.** With the option, the refusal path of the output chain adds
the element `0` to the `cut` set (`add @cut { 0 }`) after the two drop-set
rules and before `counter name "dropped"`, and ends in `drop` instead of
the reject. The first packet that gets there closes egress: the cut rule
comes before every accept but loopback, so from the next packet on, on
any CPU, everything else is refused, established connections and replies
included, exactly as after P's cut request. Nothing polls, and P being
stopped or slow changes nothing. The packet itself still goes into its
drop set and the `dropped` counter, so the report names it; later packets
never get that far.

- **The constant, not `meta mark`.** The bone that planned this named
  `add @cut { meta mark }`. Every packet in the sandbox has mark 0 and the
  command cannot set another (`SO_MARK` needs a capability over the
  namespace), so both add the same element. The constant is the element
  the cut rule matches and the one C adds, whatever the packet.
- **Drop, not reject.** Measured in a throwaway namespace with an ICMP
  counter in front of the cut rule: the reject's own ICMP error for the
  tripping packet is sent through the output chain after the element is
  in. The cut drops it and counts it in `cut`, so the command does not get
  it either (a TCP connect waits for its timeout as with a drop), and the
  `cut` counter has one packet the command did not send. With `drop` the
  command sees the same thing, "Operation not permitted" for UDP and a
  TCP connect that times out, and the counter holds only the command's
  packets.
- **The set's size.** A set that a rule adds to gets `size 65535` from nft
  when none is declared, and the readback would depend on that default.
  The tripwire ruleset declares it.
- **Only with the option.** Without it the ruleset, the readback, the
  plan and the report are what they were (`playpen rules`, `plan` and a
  run's report with a drop were compared with the previous build). `cut`
  and `stop` load the same ruleset; they differ in what P does.

**How P learns of it.** Every packet counted in `dropped` has passed the
trip statement first. So with the tripwire, the cut has tripped exactly
when the `dropped` counter is above 0, whether or not C also added the
element. The readings of "Drops while the command runs" already read that
counter every 2 seconds; they run with `--on-drop` alone too. The first
reading that finds it above 0 sends `tripped JSON` after its `denied`
lines, with the destinations its listing found (the drop sets hold
nothing else once the cut has tripped; at most 8, so the line stays one
write). The plan was to look at the `cut` set in the listing and check
that C had not added the element; the counter needs no extra read and no
memory of who added it, and a cut P asked for (end time, pass) can never
look like a trip, because after it nothing reaches the counter.

**What P does.** With `cut`, it prints the destination and that the
command runs on. With `stop`, it does what it does at the end time: asks
C for the cut (the element is there already, and adding it again changes
nothing; the answer confirms egress is closed), prints the notice, sends
SIGTERM, and SIGKILL after the 3-second grace, or SIGKILL at once when
the cut is not confirmed within 2 seconds. P acts on the first `tripped`
line only, and not when it is stopping the command already or has its
exit status: then the summary tells. The command ends within one
interval, the reading and the grace of the packet, about 5 seconds; a
command that exits on SIGTERM, within about 2.

**The report.** `on_drop`, `egress_cut` and `stopped_by_drop` are one
optional part of the report (`tripwire::OnDropReport`, flattened), so a
run without the option has none of the keys. `egress_cut` is null until
something trips it; then `tripped_by` lists the destinations from the
teardown readback (from the reading's line when the readback failed), and
`refused` the `cut` counter. Once the cut tripped, every packet the cut
refused came after the trip: none of them is an unapproved destination
the report could name, and none came after the end of the approval. So
`refused_after_end` keeps only `late` then, and `refused` has the rest.
Before this, `refused_after_end` was `late` plus `cut`; without a trip it
still is.

**The exit status.** A `stop` run whose cut tripped never exits 0. A
command that catches SIGTERM and exits 0 in its grace would otherwise
pass for success, and so would one that ended before the next reading. In
both, playpen exits 1 and `exit_code` keeps the 0. A signal stays 128 + N
and any other status stays as it is, as with `--fail-on-drop`. With `cut`
the command's own status stands: the option chose to let it run.

**The shareable report** gets `on_drop` and `stopped_by_drop` and keeps
its schema name: only added keys, only with the option. `egress_cut` names
destinations, so it stays out, like `dropped`'s list.

**`compare`.** After a trip, the cut refuses packets before the drop sets,
so a report whose `egress_cut.refused` is not 0 does not say where they
went. `compare` counts its drop evidence as incomplete. `on_drop` is not
policy: it changes what is observed, not what is allowed.

**With `--report-contacts`.** The two change separate rules: the record
is the grants' `goto` and the `contacted` chain, the tripwire is the end
of the refusal path. So the readback compares each where it is, and
`tests/fixtures/nft/contacts-on-drop.json` (both at once) differs from
`contacts.json` only in the tripwire. After a trip the cut rule refuses
every packet before the grants, so `contacted` holds what the command
reached before its first unapproved packet, and `suggest` proposes no
more than that. `contacts_are_recorded_until_the_tripwire_closes_egress`
runs both on the fake host: the record counts every datagram that reached
the approved listener before the trip, and none after it.

**What trips it without an attack.** That is why the option is opt-in:

- multicast name lookups: mDNS to 224.0.0.251 or ff02::fb port 5353, and
  LLMNR to 224.0.0.252 or ff02::1:3 port 5355, which some resolvers and
  libraries send for `.local` and single-label names;
- a client that sends to its own DNS server (a configured 8.8.8.8, or the
  host's resolver address from its own settings) instead of the stub;
- a cloud SDK that probes the instance metadata address 169.254.169.254
  to find credentials or its region;
- a client that tries the other address family first: an IPv6 address
  for a service approved only over IPv4, or the other way round.

The kernel's own IPv6 multicast listener reports and router solicitations
are dropped before the drop sets and do not trip it; nor do refused Unix
sockets, or lookups, which the stub answers on loopback. Tripping on those
is out of scope.

## Contacted destinations (`--report-contacts`)

The record lists what a wide approval was used for, so its owner can
narrow it with `playpen suggest`. It is in the private report only.

**A chain of its own, not an addition in the grant.** The obvious rule is
`MATCH add @seen4 { ... } accept`. It is wrong. An addition to a full
dynamic set fails, and a failed statement ends the rule: the `accept`
after it never runs, and the approved packet falls through to the drop
accounting and is refused. Measured on Linux 7.2.8 with nftables 1.1.7, in
a throwaway `unshare -Urn` namespace: a set of size 2 and the rule `ip daddr
192.0.2.0/24 udp dport 1-100 add @s4 { ip daddr . meta l4proto . th dport }
counter name "c" accept`. Datagrams to ports 5, 6, 7, 5 and 8: the sends to
5 and 6 succeeded and filled the set, the second send to 5 succeeded (its
entry exists), and the sends to 7 and 8 failed with "Operation not
permitted". They reached the counter after the rule, not `c`. So a run
with more than 1024 destinations would lose approved traffic only because
it was recorded.

So each grant ends in `goto contacted`. The regular chain `contacted` has
four rules: `counter name "contacted"`, the addition to `seen4` (IPv4
only), the addition to `seen6` (IPv6 only), and `accept`. A failed
addition ends only its own rule, and the `accept` still applies.
`past_1024_destinations_the_record_is_truncated_and_nothing_is_dropped`
connects to 1100 ports of a grant: every connection is refused by the
address itself ("Connection refused"), none by the firewall, `dropped` is
0, and the list has 1024 entries and is `truncated`. `goto`, not `jump`:
the packet does not come back to the output chain, so nothing after the
grants sees an approved packet. Without the option the grants still end in
`accept`, and the ruleset is byte for byte what it was before the option
existed.

**Truncation from the counter.** The chain's counter comes before the
additions, so it counts every packet that reaches the chain, also when an
addition fails. An entry's counter counts the packet that added it and
each later one. When the entries do not add up to the counter, a packet
reached the chain and found no room, and the record is `truncated`. A
duplicate entry, an entry or a set that cannot be read, and a missing set
make it `truncated` too.

**Flow starts, not volume.** The chain sees only what the grants see:
packets in conntrack state new, because `ct state established,related
accept` comes before the grants. Such a packet starts a flow, or repeats a
start that got no reply (a SYN retransmit, a datagram to a peer that has
not answered). So `packets` counts flow starts. The byte count is left
out: it would be the bytes of these packets only. ICMP never reaches a
grant.

**Answered or not.** A grant admits the first packet of a flow, so the
record alone cannot say whether anything came back. `playpen suggest` once
printed `--allow 198.51.100.9:8080/tcp`, a destination with no listener
whose connection timed out, like the working ones. The ruleset now also
sees the replies, in the input chain, just before `ct state
established,related accept`: four rules with no verdict that add `ip
saddr . meta l4proto . th sport` (or `ip6`) of an established TCP or UDP
packet to `answered4`/`answered6`, and of a TCP packet with RST to
`reset4`/`reset6`. For a flow the command started, that triple is exactly
the `seen` key of its destination.

Measured on Linux 7.2.8 with nftables 1.1.7, in a throwaway `unshare -Urn`
namespace, with the input rules on loopback: a TCP connect to a listener
added the listener to the answered set (and, because loopback shows both
directions, the client's ephemeral port too, which the real input chain
never sees: only the sandbox's own `lo` traffic is accepted before the
rules); a connect to a closed port added an entry to the reset set only;
a UDP datagram that was answered added the peer; a UDP datagram to a closed
port, whose ICMP port-unreachable came back, added nothing, since that
error is `related`, has protocol icmp and comes from another address.
Through pasta, in the fake host of `tests/contacts.rs`: a listener gives a
SYN-ACK (answered), an address of the host with no listener gives a
reset (refused), and an address that is not there gives nothing, so pasta
sent no SYN-ACK before its own connect succeeded.

**Rejected, by reasoning.** (1) A `ct state established` match in the
output chain: the output chain sees only what the command sends, never the
reply, and a rule there would run on every packet the command sends, not
only on flow starts. (2) `ct status seen-reply` in the `contacted` chain:
only flow starts reach that chain (the established rule comes first), and
a flow start has no reply yet, so the answer is always no. (3) One set
for all replies: a refusal would look like an answer. (4) One set for
the resets and one for the replies that are not resets: it needs one
more rule and the same sets. The sets here count every reply in
`answered*` and the resets in `reset*`, so a destination answered when
its count in `answered*` is above its count in `reset*`. Both counts come
from one `nft list`, which is one consistent view.

**What the answer means.** `answered` is a fact about what reached the
sandbox: a reply conntrack accepted as part of the flow, so its source
address, protocol and port are the destination's. No other host can
forge one without the command's own flow tuple. It does not say that the
command read it, or that the reply was good (a 500 is a reply; so is a
TLS alert). A TCP reset is a refusal (`reset`), also when it comes in the
middle of a connection; then both fields are true. A UDP destination that
sent an ICMP error is shown as no reply, because the error is not part of
the flow. A destination that answered some flows and not others is
`answered`. So an unanswered destination is a destination that was not
used successfully in this run, not one that is never needed: the
caution about one run stays. `suggest` prints it all the same, and says
which ones got no usable answer on stderr and in JSON, never dropping a
line: a reviewer decides.

**Cost.** Four sets (1024 entries each, so at most 4096 more entries in
the table), four rules in the input chain and one counter update per
reply packet of a TCP or UDP flow (a set lookup and an update, which is
more per packet than the single established rule). They are evaluated
only with `--report-contacts`; without the option the ruleset is byte for
byte what it was before (checked by a unit test that strips the added
text from the recorded ruleset and compares it to the plain one). No set
can fill before `seen` does: a reply of a flow has the key of a contacted
destination, so the reply sets never hold more entries than `seen`. A reply
from a key that `seen` does not hold makes the record `truncated`.

**Start empty.** The start-up readback requires all six sets to be empty, as
it does for `cut`. The rest of the record (counter, sets, chain, each
grant's `goto`) is compared like the drop accounting. `nft --json` prints
the two additions without their `meta nfproto` match, as it prints the
additions to the drop sets; the comparator expects that form
(`tests/fixtures/nft/contacts.json`).

**`suggest` is never wider.** `playpen suggest` reads a full report as
inert data, as `compare` does. It builds one rule of one address, one
port and one protocol from each destination, and prints it only when the
report's own `allowed` admits it, with the network and broadcast
exclusions. A report that does not add up (a destination outside the
grants, an entry twice) is refused, not trimmed: a list made from it could
not be trusted to be complete. A truncated or unavailable record, or a
command that did not run, is refused for the same reason. Text from the report
reaches a message only quoted, with control and format characters
escaped.

**Under a pass, destinations, not options.** `--allow` cannot be added
beside `--pass`, and only the pass's owner can write a narrower pass. So
for a pass-backed report `suggest` prints the destinations without
`--allow`, for the owner, and says that `--only LABEL` narrows the pass the
caller has. It does not print the pass id or name: they are text from a
file that someone else wrote.

**One run.** A destination that this run did not use can be needed by
the next one (a retry, a failover address, a monthly job). Every
suggestion repeats that one quiet run does not show that a later run needs
less.

## Leaks considered

| Leak | How it is closed | Tested |
|---|---|---|
| Traffic to any unapproved address, port or protocol, IPv4 or IPv6 | output policy drop; only listed `daddr`+`dport`+protocol accepted | yes (TCP, UDP, IPv6, network ranges, protocol mismatch) |
| The broadcast address of an approved network (one packet, every host on it), and its network address | a network rule does not accept the network and all-ones address of any listed IPv4 network of /30 or broader; dropped and counted unless listed on its own. Same rule as hallpass | yes (`network_and_broadcast_addresses_of_a_listed_network_are_dropped`) |
| The record of contacted destinations changing what is admitted (`--report-contacts`) | each grant goes to the `contacted` chain, where every addition is a rule of its own before `accept`; a full set ends only that rule | yes (`past_1024_destinations_the_record_is_truncated_and_nothing_is_dropped`: 1100 destinations of one grant, none dropped; `contacts_count_flow_starts_beside_grant_use_in_both_families`: the same admissions, drops and grant counts with and without the record) |
| IPv6 forgotten while IPv4 is filtered | `inet` family table covers both; an IPv4 approval never opens IPv6 | yes |
| ICMP / ICMPv6 as a side channel | not approvable; only neighbour solicitation/advertisement with hop limit 255 (link-local by RFC 4861) pass; kernel MLD reports and router solicitations are dropped silently; ICMP errors for accepted flows pass as `related` | NDP needed for pasta works (IPv6 tests pass through pasta-configured namespaces); not tested separately |
| pasta's gateway mapped to the host's loopback | `--map-host-loopback none`; and unless approved, the filter drops the gateway too | yes, end to end (`tests/gateway.rs`): playpen runs inside a throwaway network namespace whose only outside is a `dummy` interface, with gateway 192.0.2.1. With the gateway approved, a connection to it does not arrive at a listener on that namespace's wildcard address; with a pasta wrapper that drops the flag (the control) it does; unapproved, it is dropped and counted. The test reads the gateway pasta configured from `/proc/net/route` inside. The same for IPv6, with gateway 2001:db8::1 and a listener on `[::]`. Nothing can leave the machine: the dummy interface discards everything |
| pasta forwarding namespace loopback ports to the host (`-T auto`, its default) | `--tcp-ns none --udp-ns none`. The filter does **not** catch this: it accepts loopback inside the namespace, and pasta's sockets there are spliced to the host | yes: a host listener on 127.0.0.1 and ::1 below 32768 is not reached. Removing the flags makes the test fail (checked). Note: pasta's auto mode skips the ephemeral range, so a test on an ephemeral port proves nothing |
| pasta forwarding host ports into the namespace | `--tcp-ports none --udp-ports none`; input chain drops new inbound connections anyway | flag unit-tested |
| DNS forwarded by pasta | `--dns none --search none`, no `--dns-forward`; port 53 to the gateway is not approved | flag unit-tested |
| Names resolved by host daemons over filesystem sockets (systemd-resolved varlink, nscd, avahi) | generated `nsswitch.conf` with `hosts: files dns` and `resolv.conf` with `nameserver 127.0.0.1` alone: `dns` asks only the stub in the sandbox's own namespace; their sockets are refused like every host socket | a `--host` name resolves through `getent`, `dig` (UDP and TCP) and Node's `dns.resolve4`; other names get "no such name" at once; the sockets are in the walk of `no_host_socket_is_connectable_from_inside` |
| The stub forwarding a name, or answering one nobody mapped | no upstream: it answers from `--host` alone, sockets bound to 127.0.0.1 | yes (`tests/lookups.rs`; every unmapped name gets `NXDOMAIN`) |
| The command taking the stub's port, or signalling, tracing or replacing the stub | port 53 needs `CAP_NET_BIND_SERVICE` over the namespace, which the command lacks; the stub is outside the command's PID namespace | yes: binding 127.0.0.1:53 (UDP, TCP) and lowering `ip_unprivileged_port_start` fail with `EACCES`; no process visible inside holds the stub's sockets; `kill` of its host PID fails |
| A lookup that carries terminal escape sequences, or a name too long to show | escaped by the stub, cut at 253 bytes, checked again in P and in `compare` | yes (OSC and CSI sequences, a 255-byte name, a malformed label; property tests of the parser and the escaping) |
| A bug in the stub's parser, reached by a hostile query | bounds-checked parser with no `unsafe`; the stub has no capabilities, `no_new_privs`, and Landlock that leaves it only its descriptors | property tests on arbitrary bytes; `deny_all_leaves_only_the_descriptors_held`; the stub's `CapEff` and `NoNewPrivs` checked from the host |
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
| The command running on while playpen is stopped with SIGSTOP (which it cannot catch) or is stuck | I freezes the sandbox after 5 s without a byte from P, until P is heard again; from the end second the time rule refuses all but loopback meanwhile | yes (`sigstop_of_playpen_itself_freezes_the_command`: the end time passes while playpen is stopped; the command does not run on, and is stopped when playpen continues. `the_end_time_closes_egress_while_playpen_is_stopped`: playpen stopped from before the end to after it, less than 5 s; a UDP sender inside reaches a fixture on a fake host before the end and not once after, and the fixture's log agrees) |
| ptrace of the privileged helper or of playpen | helpers non-dumpable; playpen and other host processes invisible in the PID namespace; Yama ptrace_scope 1 on this machine adds another layer | `/proc/1/mem` and `/proc/1/ns/user` denied |
| A fake or broken `nft` | output structure verified after load | yes |
| pasta not coming up | its exit status is checked; the command is not started | yes (fake pasta) |
| Approval running out while the command runs | the time rule refuses all but loopback from the end second, in both chains; timer in playpen: the cut, SIGTERM, then SIGKILL after 3 s to the PID namespace's init | yes, both paths; loopback still works after the end, an approved address does not (`loopback_still_works_after_the_end`) |
| The command using approved destinations during the grace | the cut, confirmed before the notice and SIGTERM; SIGKILL at once when it is not confirmed within 2 s | yes (`a_revoked_pass_closes_egress_before_the_notice`: a command that ignores SIGTERM keeps sending through its grace, and the fixture gets nothing after the notice; `a_failed_cut_kills_the_command_at_once`: an `nft` that fails or hangs on the cut) |
| A pass revoked, deleted or edited (destination in use) while the command runs | re-read every 2 s; the cut; SIGTERM, then SIGKILL after 3 s | yes (revoke, delete, port change; and SIGKILL for a command that ignores SIGTERM after a revocation) |
| With `--on-drop`: a command that, after one refused packet, goes on using approved destinations | the refusal path adds the cut's element itself; with `stop`, P stops the command within one reading interval | yes (`the_first_unapproved_packet_closes_egress_to_every_destination`: two approved fixtures and one unapproved address on a fake host; after the one datagram to the unapproved address, nothing reaches either fixture, and their logs agree; `stop_ends_the_command_within_one_reading_and_never_exits_0`, `stop_kills_a_command_that_ignores_sigterm_after_the_grace`) |
| A pass edited to add a destination or extend the window during a run | rules and end time fixed at start; never reloaded; the only change, the cut, narrows | yes (added destination stays blocked) |
| A pass swapped for a symbolic link, or made writable by others | hallpass's loader refuses both, at start and on every re-read | yes, at start (symlink, mode 0666) and during the run (renamed over by a symlink; mode 0620 and 0602) |
| `--allow` adding a destination beside a pass | refused | yes |
| The command reading or changing the packet capture while it runs | the capture's path is `/dev/null` inside, as with `--hide` | yes: the command finds a character device at the path |
| pasta writing the capture through a link put in place of the file | playpen creates the file (`O_EXCL`, `O_NOFOLLOW`) in a directory where no other user can replace it, starts pasta there by descriptor, and checks that its own file got pasta's header | yes: an existing file, a link, an unwritable and a group-writable directory are refused; a pasta that writes no capture stops the run before the command starts |
| A capture cut by stopping pasta in the middle of a packet | P waits for pasta to exit by itself before SIGTERM | yes: a run stopped by its end time during continuous traffic leaves a file that parses to the last record, with the digest the report gives |

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
  those 5 seconds the pass re-read is not done, so a revocation is not
  seen. The kernel's filter keeps working, and from the end second on its
  time rule refuses all but loopback.
- **VM sockets (AF_VSOCK).** The nft table does not see them. In the
  kernel's default `global` mode the command reaches the hypervisor host
  from a VM with a vsock device, and the machine's VMs and vsock listeners
  from the host, also by acting as a VM through `/dev/vhost-vsock`. From
  Linux 7.0, the kernel keeps the sockets of a `local` namespace inside it.
  playpen does not create the sandbox's namespace in `local` mode. See
  "Socket families".
- **Kernel modules the command loads.** A `socket()` call for a family
  whose module is not loaded makes the kernel load the module, for any
  user and from any namespace. In the sandbox this loaded 48 modules on
  7.2.8, and opening `/dev/vhost-vsock` loads 3 more. They stay loaded
  after the run, and a bug in any of them can be reached by the command.
  playpen does not stop this.
- **The approved destination.** If it is a proxy, a VPN endpoint or a
  jump host, traffic continues from there. playpen cannot see it.
- **Names resolved elsewhere.** A client that brings its own resolver (DNS
  over HTTPS or TLS, or plain DNS to an approved address) resolves names
  without the stub, and they are not in the record.
- **The stub without Landlock.** With `--without-landlock` the stub has no
  Landlock domain. A bug in its parser would then run code with the user's
  identity but no capabilities, in the host's PID and mount namespaces.
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
  once. The ruleset's time rule follows the wall clock too: a clock set
  back delays it by as much, so while P is also stopped, egress stays open
  past the end until the wall clock reaches it or P runs again.
- **What the capture holds.** A `--capture` file holds what the command
  sent and received through pasta, payloads included: passwords, tokens
  and cookies sent in clear. It is mode 0600 and hidden from the command,
  but every other process of the caller can read it. Treat it like the
  pass.
- **Report file tampering.** The command runs as the same user and could
  write to the `--report` path while it runs. playpen writes the report
  through the file it opened before starting, after the command and every
  process it started are gone, so the final content is playpen's, unless
  the command replaced the path with another file. Put the report in a
  directory the command is not expected to touch.
- **The re-read gap.** A revoked pass closes egress at the next re-read
  (up to 2 s); the command can still send until then. During the grace
  after it, only loopback works. Anyone who can write the pass file can also put the old
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
