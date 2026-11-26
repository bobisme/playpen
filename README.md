# playpen

![PLAYPEN — A firewall for a single command. A faceless, cloaked figure kneels on flagstones to complete a circle of salt.](docs/images/playpen-cover.webp)

playpen runs a command and its children with a firewall that restricts
outbound IP traffic to the addresses, ports and protocols you approve.
It works without root on Linux and reports packets the firewall drops.

It is a guard for tools that do not police themselves. If an HTTP client follows a redirect,
the new connection must also match the allow list. The command keeps its own
loopback. An approved server can forward traffic, so choose destinations you trust.

A [Hallpass](https://github.com/bobisme/hallpass) file records the
owner, approved destinations and time window. playpen loads those
destinations into the firewall at startup. From the end of the window the
firewall itself refuses all traffic but loopback, whatever playpen does.
playpen checks the pass every 2 seconds. When it detects revocation it
closes egress in the firewall the same way, then shuts the command down.
Until revocation is detected, the command can still reach approved
destinations. See [how a pass-backed run ends](#how-a-pass-backed-run-ends)
for the timing, including what happens if playpen itself is paused.
For a quick run, supply destinations directly with `--allow`.

- [docs/spec.md](docs/spec.md): what playpen does, exactly: every command,
  option, exit code and report field. Start here.
- [docs/DESIGN.md](docs/DESIGN.md): why it is built this way, and the leaks
  considered and how each is closed or not.

## Recipes

Allow a package registry or a forge by name. Build playpen first (next
section). There is no DNS inside the sandbox, so each name needs the
addresses it has now: `playpen resolve` looks the names up on the host,
outside the sandbox, and prints the `--allow` and `--host` lines. It sends
nothing to those addresses and changes nothing. `--ipv4` keeps the output
short. `set -f` stops the shell from reading `[` and `]` in an IPv6 line
as a file name pattern.

Addresses change. A CDN or a forge moves its names between addresses, so
a literal line that works today can fail next month. Run `playpen resolve`
again, and check that the addresses belong to the service before you
approve them: it trusts this host's resolver.

Each recipe below was run as written on 2026-11-26 (UTC), with both the
`resolve` form and the literal fallback, and installed one package or
cloned one small public repository. The fallbacks show one address of the
many that `resolve` prints; the addresses are the ones of that day.
Run from a directory the command can write.

PyPI (pip):

```sh
playpen run $(playpen resolve --ipv4 pypi.org files.pythonhosted.org) \
  -- python3 -m pip download --no-cache-dir --no-deps six==1.16.0 -d out
# the literal form
playpen run --allow 151.101.0.223:443/tcp \
  --host pypi.org=151.101.0.223 --host files.pythonhosted.org=151.101.0.223 \
  -- python3 -m pip download --no-cache-dir --no-deps six==1.16.0 -d out
```

npm. `--cache ./cache` keeps npm's cache in the working directory:

```sh
playpen run $(playpen resolve --ipv4 registry.npmjs.org) \
  -- npm install --cache ./cache --no-audit --no-fund is-odd
# the literal form
playpen run --allow 104.16.0.34:443/tcp --host registry.npmjs.org=104.16.0.34 \
  -- npm install --cache ./cache --no-audit --no-fund is-odd
```

GitHub (read-only clone of a public repository):

```sh
playpen run $(playpen resolve --ipv4 github.com) \
  -- git clone --depth 1 https://github.com/octocat/Hello-World.git
# the literal form
playpen run --allow 140.82.112.3:443/tcp --host github.com=140.82.112.3 \
  -- git clone --depth 1 https://github.com/octocat/Hello-World.git
```

crates.io (cargo, from a directory with a `Cargo.toml`; `CARGO_HOME` keeps
the registry cache in the working directory):

```sh
CARGO_HOME=$PWD/cargo-home \
playpen run $(playpen resolve --ipv4 index.crates.io static.crates.io) -- cargo fetch
# the literal form
CARGO_HOME=$PWD/cargo-home \
playpen run --allow 151.101.2.137:443/tcp \
  --host index.crates.io=151.101.2.137 --host static.crates.io=151.101.2.137 \
  -- cargo fetch
```

`playpen resolve NAME... [--port PORT] [--ipv4]` prints one `--allow
ADDR:PORT/tcp` line for each address and one `--host NAME=ADDR` line for
each name and address, on stdout, and a caution on stderr. A name that
gives no address that can be approved is listed on stderr and the exit
status is 1. With `--format json` it prints `allow`, `hosts` and
`unresolved`.
## Two-minute example

```console
$ git clone https://github.com/bobisme/playpen.git
$ cd playpen
$ cargo build --release --locked
$ export PATH="$PWD/target/release:$PATH"
$ playpen doctor --mode offline --format json | jq -r .capability.status
available
$ playpen run --no-network --format json -- printf 'hello\n' | jq '{outcome, exit_code}'
```

The command's `hello` and playpen's diagnostics go to stderr. The pipe receives
one JSON report with `outcome: "ran"` and `exit_code: 0`.
This example needs no network destination, pass file or pasta. For a run with
outbound access, check `playpen doctor --mode egress` first.

### Run under a Hallpass approval

Use a current pass from the owner. For example, if the pass approves
`192.0.2.10:443/tcp` with `hostname = "app.example.test"`, the invocation
below gives curl that name for that address. Substitute the pass from your
own engagement.

```sh
playpen run --pass ~/passes/engagement.pass.toml --pass-hosts \
  -- curl -sS https://app.example.test/
```

Keep the pass in a directory of its own, outside the directory the command
works in, as above. Inside the sandbox the pass, and its `.ledger`, are
`/dev/null`. But most editors and `sed -i` save a new file, and the new
file is visible inside. A command that could write the pass's directory
could then read it and put back an unrevoked pass before playpen's next
check. So playpen keeps the command from changing that directory:

- a directory that holds only the pass (and its `.ledger`, and the
  `--report` and `--capture` files if they are there) is hidden: the
  command sees it empty;
- a directory that holds other files too is read-only for the command: it
  can read them, and the pass after an edit, but cannot create, rename or
  remove anything there;
- a directory you hid with `--hide` stays as it is;
- a pass in the working directory, in a directory above it, or inside an
  `--expose` path is refused (exit 2, "nothing was run"), with a message
  that says how to fix it. `--pass-dir-writable` runs anyway, with a NOTE
  about the risk.

The start line says which it is (`pass directory: ...`), and the report
has it as `pass.directory`. A tool that reads the pass, such as `hallpass
permits` or `hallpass spend`, must run outside the sandbox.

playpen reads the pass through the directory it opened at start. If that
directory is moved or replaced while the command runs, playpen stops the
run as for a revocation.

playpen refuses to start (exit 2, "nothing was run") when the pass is
invalid, unreadable, a symbolic link, writable by others, not yet valid,
expired or revoked. `--only LABEL` narrows the pass to some destinations;
`--until` can end the run earlier than the window, never later. The pass's
host names are never resolved for you. `--pass-hosts` writes the `hostname`
of each selected single-address destination, with that address, into the
sandbox's `/etc/hosts`; it looks nothing up and grants nothing. Map any
other name to an address of the pass with `--host NAME=ADDR`.

To check a pass you wrote by hand, run `playpen rules --pass FILE`: it prints
each problem on its own line, or the ruleset when the pass is valid.

Pass restrictions on destination names and application ceilings need a separate
application-level enforcer. playpen prints a NOTE at the start (and on
`playpen rules --pass`) for each such term in the pass. Use `--require-enforced` to refuse a pass with
such applicable terms when playpen must enforce every restriction itself.
The refusal names the destination labels and the ceilings.

### How a pass-backed run ends

If the owner sets `revoked = true`, playpen normally detects it at the
next pass check. The supervisor schedules checks 2 seconds apart. It first
closes egress in the firewall: from then on the firewall refuses every
packet that is not loopback, in both directions. Only then does it print
the notice, send the command `SIGTERM` and give it 3 seconds to exit before
killing the remaining sandbox. The same shutdown applies when the deadline
passes, the file disappears or becomes invalid, or a destination in use
changes. If egress cannot be closed within 2 seconds, playpen says so and
kills the command at once, without the 3 seconds. Nothing in the firewall
is widened during the run. Granting more destinations or extending the
deadline only affects future runs.

The ruleset also holds the end time itself (the run's `--until`, or the
pass's `valid_until`), rounded down to the second. From that second the
kernel refuses all traffic but loopback, even if the supervisor is stopped
or stuck. The rule reads the system's wall clock, as the supervisor's own
check does: setting the clock forward closes egress early, and setting it
back delays the rule (the supervisor's monotonic deadline still applies).
Packets refused after the end are counted on their own line in the
summary and in the report's `refused_after_end`. They are not unapproved
destinations and do not fail `--fail-on-drop`.

If the supervisor is stopped directly or gets stuck, it cannot check the
pass. After 5 seconds without a heartbeat, a watchdog inside the sandbox
starts freezing its processes. When the supervisor resumes, it checks the
deadline and re-reads the pass if due. Time spent in system suspend counts
toward the deadline. Poll intervals, grace periods and watchdog actions
depend on Linux scheduling the supervisor and the sandbox init. A signal
request and the final process exit can occur at different times.

For a headless job (no controlling terminal), send signals to the playpen PID
or its process group. Playpen forwards them to the workload group. Redirecting
stdio alone does not make a terminal job headless.

At a terminal, the default preserves shell pipelines, `fg`/`bg` and
`/dev/tty`. Send signals to the playpen PID or to its process group; the
command gets one copy either way. `killall playpen` also delivers one copy.

### Run an interactive shell with single signal delivery

From a foreground terminal, run:

```sh
playpen run --no-network --private-tty -- bash -i
```

The shell gets its own controlling terminal for prompts and job control.
Send a forwarded signal such as SIGTERM or SIGUSR1 to the playpen PID or
its process group. Either way, the private terminal’s foreground job gets
one copy. Use this mode when playpen has exclusive use of terminal input.
A pipe or file can supply stdin while the command reads a password or
confirmation from `/dev/tty`. For a pipeline with another stage that reads
the keyboard, use the default terminal behavior.

### Run with a command-line allow list

```sh
playpen run --allow 192.0.2.10:443/tcp \
  --host app.example.test=192.0.2.10 \
  -- curl -sS https://app.example.test/
```

`--pass` and `--allow` cannot be combined: an `--allow` beside a pass would
add a destination the owner did not approve.

Just before the command starts, playpen prints the start line on stderr.
The first line is short. Each further clause group has its own line
starting `playpen:   `, so a log filtered by the `playpen:` prefix keeps
all of them:

```text
playpen: allowing only 192.0.2.10:443/tcp with no time limit; everything else is dropped
playpen:   no DNS, names app.example.test=192.0.2.10; lookups recorded
playpen:   host Unix sockets: none reachable
playpen:   VM sockets (AF_VSOCK): only the sandbox's own (VSOCK mode local)
```

`--allow` accepts a link-local address, because you typed it, and a pass
does not. When an allowed grant covers the cloud metadata address
169.254.169.254 or fd00:ec2::254 on a TCP port, playpen adds a NOTE line
that a command reaching it may read this machine's cloud credentials.
Playpen cannot run inside playpen, or inside another sandbox that locks its
mounts; it stops with "cannot make mounts private: EPERM".

The command also cannot reach daemons on the host through their Unix
sockets: a host daemon has the host's network (a session bus, a container
engine, an SSH or browser automation agent). The command's runtime
directory (`$XDG_RUNTIME_DIR`) is a fresh, empty, private one; `/tmp` is
the host's. Bring a socket back deliberately with `--expose`; graphical
programs need `--display`. Both are listed on the start line (`--hide` paths too) and in the
report. An exposed socket is as strong as the daemon behind it: the session
bus, systemd's private socket, `docker.sock`, `podman.sock` and containerd
let the command start programs on the host, outside the network filter. The
start line prints a NOTE for these, and for an exposed directory such as
`$XDG_RUNTIME_DIR` that holds them:

```console
$ playpen run --allow 192.0.2.10:22/tcp --expose "$SSH_AUTH_SOCK" \
              -- ssh admin@192.0.2.10
```

Upgrading from v0.1? The spec lists the [changes](docs/spec.md#changes-since-v01):
the runtime directory is empty, and the session bus, `ssh-agent`, syslog
and others are not reachable without `--expose`.

If the tool tries to go somewhere else, the connection fails at once
("No route to host" for TCP over IPv4, "Permission denied" for TCP over
IPv6, "Operation not permitted" for UDP), and
playpen says so loudly on exit:

```text
playpen: ************************************************************
playpen: WARNING: 3 packet(s) to UNAPPROVED destinations were dropped.
playpen: The command tried to reach places nobody approved:
playpen:   198.51.100.7 tcp port 80: 2 packet(s)
playpen:   198.51.100.7 udp port 53: 1 packet(s)
playpen: ************************************************************
```

The summary lists at most 20 lines. Past 20 destinations it has one line
per address and protocol, so a sweep of many ports of one address does
not hide another address:

```text
playpen:   203.0.113.5 udp, 1024 ports: 1024 packet(s)
playpen:   198.51.100.66 tcp, port not recorded: 1 packet(s)
playpen:   1 packet(s) have no port in the report: the per-port record is full for IPv4 (it keeps the first 1024 destinations of each family)
```

The firewall keeps the first 1024 destinations (address, protocol and
port) and the first 1024 addresses (address and protocol) of each address
family. The report's `dropped` has both lists, and says how many packets
are in neither and which records are full.

There is no DNS inside the sandbox. A stub on the sandbox's own loopback
(127.0.0.1 port 53) answers the names given with `--host`, says every
other name does not exist, and forwards nothing. A lookup of a name with no
mapping fails at once, and playpen lists the name on exit:

```text
playpen: The command looked up names that have no --host mapping:
playpen:   updates.example.com: 2 lookup(s)
playpen: Each was answered "no such name". If the command needs one, map it with --host NAME=ADDR (ADDR must be approved).
```

The private report has the same list in `lookups`; the shareable report
leaves it out. A name is shown lower-cased, with every byte in a label
other than a letter, digit, `-` or `_` escaped (`\027` for ESC); a name
longer than 253 bytes is cut and ends in `...`.

### Allow every public address on one port

There is no keyword for "any address". `0.0.0.0/0` and `::/0` are refused
because they include addresses that cannot be approved (0.0.0.0/8,
127.0.0.0/8, 224.0.0.0/4, ::, ::1, and the others in the spec). These lines
allow every public IPv4 address on TCP port 443: 1.0.0.0 to 223.255.255.255
except loopback (127.0.0.0/8) and the networks that are not on the internet,
which are the private networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
shared address space (100.64.0.0/10) and link-local addresses
(169.254.0.0/16, which holds the cloud metadata address). The last line adds
the IPv6 global unicast block 2000::/3:

```bash
allow=()
for net in 1.0.0.0/8 2.0.0.0/7 4.0.0.0/6 8.0.0.0/7 11.0.0.0/8 12.0.0.0/6 \
          16.0.0.0/4 32.0.0.0/3 64.0.0.0/3 96.0.0.0/6 100.0.0.0/10 \
          100.128.0.0/9 101.0.0.0/8 102.0.0.0/7 104.0.0.0/5 112.0.0.0/5 \
          120.0.0.0/6 124.0.0.0/7 126.0.0.0/8 128.0.0.0/3 160.0.0.0/5 \
          168.0.0.0/8 169.0.0.0/9 169.128.0.0/10 169.192.0.0/11 \
          169.224.0.0/12 169.240.0.0/13 169.248.0.0/14 169.252.0.0/15 \
          169.255.0.0/16 170.0.0.0/7 172.0.0.0/12 172.32.0.0/11 \
          172.64.0.0/10 172.128.0.0/9 173.0.0.0/8 174.0.0.0/7 176.0.0.0/4 \
          192.0.0.0/9 192.128.0.0/11 192.160.0.0/13 192.169.0.0/16 \
          192.170.0.0/15 192.172.0.0/14 192.176.0.0/12 192.192.0.0/10 \
          193.0.0.0/8 194.0.0.0/7 196.0.0.0/6 200.0.0.0/5 208.0.0.0/4; do
  allow+=(--allow "$net:443/tcp")
done
allow+=(--allow '[2000::/3]:443/tcp')
playpen run "${allow[@]}" -- curl -sS https://example.com/
```

The start line and the report list each of these grants. This is not a
narrow approval: a command that can reach every public address can send
data anywhere on that port. To reach a private network as well, add its own
`--allow` line. In an IPv6 grant the prefix goes inside the brackets:
`[2000::/3]:443/tcp`, not `[2000::]/3:443/tcp`; the second form is refused
with that hint. A test reads these lines from this file and checks that they
cover exactly the set above and do not overlap.

To see the firewall rules without running anything:

```console
$ playpen rules --pass engagement.pass.toml
$ playpen rules --allow 192.0.2.10:443/tcp --allow '[2001:db8::10]:443/tcp'
```

For scripts, `run --format json` writes the final report to stdout and sends
workload output to stderr. Give `--report FILE` to keep workload stdout in
a pipeline and save the JSON report, including refusals. The report's
`outcome` field tells a command
that exited with status 2 (`"ran"`, `exit_code: 2`) apart from playpen
refusing to start it (`"refused"`).

### Discover the CLI from an agent

```sh
playpen help --format json | jq -r '.commands[].name'
playpen help run --format json | jq '{usage, examples, workflow}'
playpen qualify --list --format json | jq -r '.scenarios[].id'
```

Every public command accepts `--format text|pretty|json` before or after the
command name. Use `--json` as a shorthand for `--format json`. An explicit
flag overrides `FORMAT`. By default a terminal gets pretty output and a pipe
gets text. JSON results are objects with an `advice`
array. Invalid CLI syntax in JSON mode produces a structured error on stderr.
Pass the workload and its flags after `--`.

### Review a command before launch

```sh
playpen plan --no-network -- printf hello
digest=$(playpen plan --format json --no-network -- printf hello | jq -er .digest)
playpen run --expect-plan "$digest" --no-network -- printf hello
```

The digest is the SHA-256 of the plan that `playpen plan --format json`
prints. It binds exactly the fields of that `plan` object:

- the command's arguments, byte for byte, and the working directory;
- the grants (in canonical order), the `--host` entries, `--until`, and
  the pass's id, file, digest, labels and recheck interval when a pass is
  used (so the pass bytes);
- `--no-network`, `--hide`, `--expose`, `--display`, `--without-landlock`,
  `--new-session`, `--fail-on-drop`, `--require-enforced`;
- when given, `--private-tty`, `--pass-hosts`, `--capture` (the path),
  `--live-drops`, `--report-contacts`, `--report-grant-use`, `--on-drop`
  and `--pass-dir-writable`.

It does not bind:

- the environment the command inherits: `FOO=bar playpen plan ...` gives
  the same digest. That includes `PATH`, `LD_PRELOAD`, `HTTP_PROXY`,
  `HTTPS_PROXY`, `ALL_PROXY` and `NO_PROXY`;
- the program the first argument names: it is not resolved to a path, so
  a different `PATH` can run a different program, and the contents of
  that program and of every file the command reads are not hashed;
- `--report` and `--shareable-report` (where the report goes and how it
  is redacted), `--format`, and `--expect-plan` itself;
- the host: helper availability, namespace setup and the firewall are
  checked at launch, and later edits to a pass.

The firewall does not depend on those unbound inputs. A proxy variable can
only point the command at an address the grants already allow, and a
different program still meets the same grants. So playpen does not bind the
resolved path or the proxy variables. Doing so would need an opt-in option,
to keep existing digests valid, and a digest of a path says nothing about
what the program does. If you need the program fixed, give the command as
an absolute path and check its hash yourself. If the digest differs, `run` prints the
current plan's fields. It cannot say which one differs, because only the
digest was reviewed.

### Check dropped traffic in CI

For CI, fail a successful command if it tried to reach a host nobody
approved:

```sh
out=$(mktemp -d)
playpen run --allow 192.0.2.1:443/tcp --fail-on-drop --report "$out/report.json" -- ./check
playpen run --no-network --fail-on-drop --report report.json -- ./build
```

The firewall counts each packet the command sends to another host that no
grant allows, over IPv4 and IPv6. This holds with `--no-network` too, and
for an address family this host has no default route for: playpen gives
the sandbox a route for every family, so the packet reaches the firewall
(DESIGN.md, "A route for every packet"). These are not counted: traffic on
the sandbox's loopback, lookups the DNS stub answered (the summary lists
the names that have no `--host` mapping), host Unix sockets, and the
kernel's own IPv6 multicast listener reports and router solicitations.

An incomplete count also fails the assertion, as `unknown`: the counters
could not be read (`dropped_error`), or playpen could not give an address
family a route (`uncounted`; a NOTE at the start says so). The report
keeps the child status separately from playpen's exit status.

Inside the sandbox the report path is `/dev/null`, so the command cannot
change or replace the report. Keep the report outside the directory the
command works in, as above: a build that writes, renames or removes a file
at that path would get `/dev/null` or an error (`EBUSY`) there. If the
command moves a directory above the report and puts another file at its
path, playpen finds that at the end, writes the real report there again,
says so on stderr and exits 1 instead of 0. A playpen that is killed
(SIGKILL) writes no report and leaves the file empty, so check playpen's
exit status too: an empty report means playpen did not finish.

### Keep API tokens out of the command
The command inherits playpen's whole environment, including API tokens. A
token in the environment can reach every destination you allow, so clear
what the command does not need. playpen has no option for this. Put `env`
in front of the command: `playpen run ... -- env -i PATH="$PATH" HOME="$HOME"
cmd` starts it with only those two variables, and `-- env -u NAME cmd`
removes one.

### Learn of a refused destination while the command runs

The summary at the end lists every dropped destination. A long command
that hangs on a refused connection can tell you sooner:

```sh
playpen run --allow 192.0.2.10:443/tcp --live-drops --events-fd 3 -- ./scan 3> >(jq -c .)
```

`--events-fd` takes a pipe, not a regular file. To write the records to a file, use `3> >(cat > events.jsonl)`.

While the command runs, playpen reads the drop counter every 2 seconds.
With `--events-fd`, each new dropped destination gets one `denied` record
(`address`, `protocol`, `port`, `packets`, `record`) within about 2 seconds of its
first packet. When the per-port record of a family is full, a new address
gets a record with `port` null and `record` `"address"`. With `--live-drops`, stderr also gets a line for each of the
first 8, and after that for each of the first 8 addresses not seen before,
so a sweep of one address's ports does not hide another address:

```text
playpen: dropped: 198.51.100.7 tcp port 80 (not approved)
```

Without `--live-drops` stderr is as before, on a terminal too. A
destination first dropped in the last 2 seconds of the run can get no
record or line. Packets refused after the end of the approval are counted
apart (`refused_after_end`) and get none. The summary and the report's
`dropped` are read at the end and are the complete list.

### Close all egress at the first refused packet

By default a refused packet fails only its own connection, and the
command can still reach every approved destination. When the first
refused packet means the command is not doing what was reviewed, close
everything at that packet:

```sh
playpen run --allow 192.0.2.10:443/tcp --on-drop stop --report run.json -- ./scan
```

With `--on-drop cut` or `--on-drop stop`, the firewall itself closes all
egress at the first packet it drops. From the next packet on it refuses
everything but loopback, in both directions, approved destinations too,
until the run ends. Nothing polls for this. The packet that trips it is
dropped without an ICMP error, so UDP still gets "Operation not
permitted", but a TCP connect to the unapproved destination waits for
its own timeout instead of failing at once.

With `cut` the command runs on and sees its connections fail, and
playpen exits with the command's status. With `stop` playpen also stops
the command, as at the end time: it learns of the trip within about 2
seconds (it reads the drop counter every 2 seconds), sends `SIGTERM`,
and kills the command 3 seconds later. A `stop` run whose cut tripped
never exits 0: if the command exits 0 (from a `SIGTERM` handler, say),
playpen exits 1. Either way playpen names the destination while the
command runs:

```text
playpen: a packet to an unapproved destination was dropped: 198.51.100.7 udp port 53 (--on-drop stop); the firewall now refuses all traffic but loopback; sending SIGTERM to the command (SIGKILL in 3 s)
```

The report gets `on_drop`, `stopped_by_drop` and `egress_cut`: the
destinations that tripped it (`tripped_by`) and the packets refused after
that (`refused`, not counted as dropped). With `stop` it also has the
`stop_reason`. The option is on the start line, in the plan and in its
digest; a run without it has none of these. A refused Unix socket or a
lookup of a name without a `--host` mapping does not trip it.

The option is off by default because ordinary programs trip it with no
attack at all:

- multicast name lookups: mDNS (224.0.0.251 or ff02::fb, port 5353) and
  LLMNR (224.0.0.252 or ff02::1:3, port 5355);
- a client that sends to its own DNS server (8.8.8.8 port 53, say)
  instead of the sandbox's stub;
- a cloud SDK that probes the metadata address 169.254.169.254;
- a client that tries the other address family first, such as IPv6 for a
  service approved only over IPv4.

Run the command once without the option and read the summary. If its
list of dropped destinations is empty, the same run will not trip it.

### Keep a record of what was sent

`--capture FILE` writes a pcap of every packet that crossed the sandbox's
outside interface: the approved traffic, its replies, and address
resolution with pasta. A packet the firewall refuses never reaches that
interface, so it is not in the file; the report counts it instead.

```sh
playpen run --pass ~/passes/engagement.pass.toml --capture run.pcap --report run.json -- ./scan
sha256sum run.pcap   # the same digest as .capture.sha256 in run.json
```

The report gives the file's size and SHA-256. Every report of a run that
started also has `started_at` and `ended_at`, so the capture, the report
and the pass window line up.

**The capture holds payloads**, including passwords, tokens and cookies the
command sent in clear. Treat it like the pass. playpen creates it as a new
file with mode 0600. It refuses a name that exists, a symbolic link, and a
directory that its group or others can write to (a sticky directory such
as `/tmp` is accepted). The command cannot open the file while it runs.

### Narrow a wide approval

`--report-contacts` records each address, protocol and port that the
command opened a flow to through a grant. `playpen suggest` reads that
report and prints one exact `--allow` for each, with the `--host` entries
that point at them:

```console
$ playpen run --allow 198.51.100.0/24:9550-9560/tcp --report-contacts \
              --report wide.json -- ./client
$ playpen suggest wide.json
--allow 198.51.100.7:9557/tcp
--allow 198.51.100.7:9558/tcp
--host app.example.test=198.51.100.7
playpen: caution: this is what one run contacted. One quiet run does not show that a later run needs less.
$ playpen run $(playpen suggest wide.json) -- ./client
```

The options go to stdout and the caution goes to stderr. The record also
says whether each destination answered. A destination that sent nothing
back (a host that is down, a connection that timed out) or only a TCP
reset (nothing listens) is still printed, and stderr names it:

```text
playpen: 2 of the destinations above got no usable answer, so the command may not have used them; they are still listed:
playpen:   198.51.100.9:8080/tcp: no reply
playpen:   198.51.100.7:9559/tcp: refused with a TCP reset
```

Look at these first when you narrow the list. A UDP port that refused
with an ICMP error counts as no reply. `suggest` never
prints a destination that the run's own grants did not admit. It refuses a
record that is truncated or unavailable, and a report whose `outcome` is
not `ran`. A
set holds 1024 destinations of each address family. Each destination's
`packets` counts flow starts, not volume. Review the list before you use
it: a later run can need a destination that this run did not use. The
record is only in the private report. With `--on-drop` as well, the
record ends at the first refused packet, because nothing leaves after
it.

### Run an HTTP client offline

Save one response in a fixture file, then run a client against it:

```sh
printf '%s\n' '{"method":"GET","path":"/items","status":200,"body":"[]"}' > items.json
playpen run --no-network --fixture items.json -- sh -c 'curl -qsS --noproxy "*" "$PLAYPEN_FIXTURE_URL/items"'
```

The client prints `[]`. Each run has a private listener and an ephemeral port.

### Reach a test service on this machine

The sandbox gets this host's network address, so a service listening on
that address is not reachable from inside: the connection stays in the
sandbox, and playpen prints a NOTE that says so. Give the service an
address the sandbox does not have. Without privileges, build a throwaway
host and run both in it:

```sh
unshare --user --map-root-user --net sh -c '
  ip link set lo up
  ip link add host0 type dummy && ip addr add 192.0.2.10/24 dev host0
  ip addr add 2001:db8:1::10/64 dev host0 nodad
  ip link set host0 up && ip route add default via 192.0.2.1
  ip -6 route add default via 2001:db8:1::1 dev host0
  ip link add svc0 type dummy && ip addr add 198.51.100.7/32 dev svc0
  ip addr add 2001:db8:2::7/128 dev svc0 nodad
  ip link set svc0 up
  my-test-service --listen 198.51.100.7:8080 &
  my-test-service --listen "[2001:db8:2::7]:8080" &
  sleep 1
  unshare --user --map-user='"$(id -u)"' --map-group='"$(id -g)"' \
    playpen run --allow 198.51.100.7:8080/tcp --allow "[2001:db8:2::7]:8080/tcp" -- \
    my-client http://198.51.100.7:8080/ "http://[2001:db8:2::7]:8080/"
'
```

Nothing leaves the machine: a dummy interface discards what is sent to it.
host0 needs its own IPv6 address and route: pasta gives the sandbox an IPv6
address taken from the host, and without them it takes svc0's, so the service
would be the sandbox's own.
Do not run playpen inside `playpen run`; the inner one cannot start.

## Requirements

- Linux with unprivileged user namespaces enabled (the default on most
  distributions; `playpen doctor` checks). On distributions that restrict
  them with AppArmor (Ubuntu 24.04 and later, for example), an
  administrator must allow playpen; DESIGN.md shows a profile.
- Landlock ABI 9 or later, to refuse host Unix sockets. On older kernels
  `--without-landlock` runs with weaker, mount-only hiding.
- `nft` (nftables) and `pasta` (from the passt package). `--no-network`
  needs only `nft`, and the kernel's `dummy` interface driver
  (`CONFIG_DUMMY`) to count what the command sends to other hosts. Without
  the driver, the run says that the drop count is incomplete.
- Linux 7.0 or later to keep VM sockets (AF_VSOCK) inside the sandbox.
  On older kernels with VM sockets, the start line says that they are not
  confined.
- No root, no setuid helper, no subuid/subgid ranges, no change to host
  settings, with one exception: where the `vsock` module is not loaded,
  playpen loads it before it builds the sandbox, by creating and closing
  one AF_VSOCK socket, as any program can. A network namespace that exists
  when the module is loaded cannot keep VM sockets in, and the command
  could load it itself from inside. The module stays loaded. playpen
  refuses to run as root.

Build with a stable Rust toolchain: `cargo build --release`. Run the tests
with `cargo test`; they need the same requirements and send nothing to any
other host.

Rootless Podman workloads that require a nested mount setup or subordinate
UID/GID mappings are outside the supported configuration. Playpen runs the
command with no new privileges and applies Landlock by default. Use the
guarded offline invocation above to check ordinary command support.

### Check this host

Offline mode runs a real command in a sandbox with no network. The
sandbox has its loopback interface and `discard0`, which discards what is
sent to it and has both default routes. The check requires a TCP attempt
to an IPv4 address and a UDP attempt to an IPv6 address to be refused and
counted. It checks the command’s network privileges and verifies that a private Unix socket
connects while the host pathname and abstract sockets are unreachable.
It checks that a file can be renamed and hard-linked, and a directory
renamed, into another directory: package managers such as uv and bun need
that. Under Landlock, only a rename or link from outside into an
`--expose` directory fails (`EXDEV`).
It also checks that the command reads VSOCK mode `local` and cannot
connect to a VM-socket listener that doctor holds outside the sandbox
(the check passes, too, where the kernel has no VM sockets). Like every
run, doctor loads the `vsock` module where it is not loaded.
Egress mode also uses pasta and tests allowed and denied TCP, UDP and IPv6
destinations. It reports, for each address family, whether the sandbox has
this host's default route or one that playpen added because this host has
none. Both modes require user namespaces, nft and Landlock ABI 9 or later.

```console
$ playpen doctor --mode offline --format json | jq -r .capability.status
available
$ playpen doctor --mode egress --format json | jq -r .capability.status
available
```

A missing prerequisite produces `unavailable` and marks the affected probes
`untested`. A probe that ran and found unexpected behavior produces `failed`.
A machine without pasta can still demonstrate offline mode.

For CI, name the native scenarios the job requires. The command reports
every scenario and exits unsuccessfully if a required scenario could not
run or any scenario failed.

```sh
playpen qualify --require offline-command --require unix-socket-guard --format json
playpen qualify --source "$PWD" --require routed-peer --format json
```

Direct probes exercise the running Playpen binary. An explicit trusted
`--source` checkout enables named Cargo tests from the run, pass, sockets,
gateway and terminal suites. They use `--locked --offline`. Each result
identifies its evidence source, prerequisites and outcome. The `routed-peer`
scenario runs a Python fixture against the qualifying binary. It follows an
HTTP redirect with and without a grant for the second server, then sends UDP
to approved and denied ports over IPv4 and IPv6. The listeners record which
requests arrived, and playpen reports which packets it dropped.

| Tested Linux configuration | nftables | pasta | Landlock | Checks that ran |
| --- | --- | --- | --- | --- |
| Arch host, 7.2.8-arch1-2 | 1.1.7 | 2026_09_25.df90211 | ABI 10 | All 12 qualification scenarios, including private-terminal signal delivery |
| Isolated Arch guest, 7.1.4-arch1-1 | 1.1.6 | 2026_07_28.f8df3f1 | ABI 9 | Egress doctor, offline command and routed-peer fixture |

The guest had no external network interface. Its test servers ran inside the
guest. See the [guest qualification record](docs/qualification-second-linux.md)
and the [qualification command reference](docs/spec.md#441-playpen-qualify).

## Threat model

playpen guards against:

- accidents and misconfigured tools: a wrong target, a forgotten default
  host, a tool reaching for updates or telemetry;
- tools that follow redirects, or resolve names, to places nobody approved:
  the system resolver uses the sandbox hosts file, then the stub on the
  sandbox loopback, which answers only `--host` names and forwards nothing.
  A client that implements its own DNS, or DNS over HTTPS or TLS, still
  needs permission to reach its resolver;
- children and background processes of the command: they stay in the same
  sandbox and are killed when the command exits;
- the command trying to undo the guard: it cannot change the firewall,
  add addresses or interfaces, change routes, open raw sockets, or join
  another network namespace. It cannot read the pass or its ledger, and
  cannot read or replace the `--report` or `--capture` file: inside, each
  is `/dev/null`. A report replaced by moving a directory above it is
  found and written again, and playpen exits 1 (each is tested). It
  cannot change the pass's directory, which is hidden or read-only inside,
  so it cannot put back a pass after the owner's edit; a pass in or above
  the working directory is refused (see [Run under a Hallpass
  approval](#run-under-a-hallpass-approval));
- attempts that would fail before the firewall: with `--no-network`, or
  over an address family this host has no default route for, a packet to
  another host still reaches the firewall and is refused and counted. If
  playpen cannot set up the route, it says so at the start, and
  `--fail-on-drop` fails as unknown;
- side doors to the host's network: host daemons reached through Unix
  sockets anywhere in the file system (refused unless you `--expose`
  them), host abstract sockets, descriptors inherited from the caller, a
  network (TCP, UDP) socket as standard input or output, host IPC and
  shared memory, the display server (unless `--display`), and pushing
  input into your terminal for your shell to run later. Each is tested;
  DESIGN.md has the list, with what stays open;
- VM sockets (AF_VSOCK), on Linux 7.0 and later: the firewall does not see
  them, but the sandbox's network namespace is in the kernel's VSOCK mode
  `local`, so the command's VM sockets reach only the sandbox's own, not
  the hypervisor host from inside a VM, nor the machine's VMs and
  VM-socket listeners on a host. If the sandbox does not get that mode,
  nothing is run. The start line and the report (`vsock`) say what the
  sandbox got (tested).

playpen does not guard against:

- VM sockets on kernels before 7.0, which have no VSOCK mode: there the
  command reaches the hypervisor, the machine's VMs and VM-socket
  listeners, and the start line says so (`--hide /dev/vhost-vsock` at
  least keeps it from acting as a VM). Also VM sockets loaded only after
  the sandbox started, by root or as a dependency of a module the command
  loads, where playpen could not load them at the start;
- other non-IP socket families. playpen does not restrict which families
  the command creates. Before Linux 7.2 (measured on 7.1.4) this includes
  the Qualcomm IPC router (AF_QIPCRTR), whose ports every namespace shares.
  DESIGN.md ("Socket families") has what each family reaches, and what was
  not tested;
- kernel modules loaded by the command: creating a socket of a family
  whose module is not loaded makes the kernel load it, for any user. The
  module stays loaded. playpen loads `vsock` this way itself (see
  [Requirements](#requirements));
- a kernel exploit, or a bug in nftables, pasta or Landlock;
- processes started outside playpen;
- whatever the daemon behind a socket you exposed does for the command;
- host processes acting on files the command writes (a sync client
  watching your home directory, a print spooler), and network file
  systems: playpen does not confine files;
- on kernels without Landlock ABI 9 (`--without-landlock`), host sockets
  outside `/run`, `/tmp`, `/var/tmp` and the runtime directory;
- the approved destination itself forwarding traffic elsewhere (an approved
  proxy is a way out to wherever that proxy goes);
- what is sent: playpen limits where packets go, not how many or what they
  contain (so it does not enforce a pass's ceilings). `--capture` records
  what was sent; it does not inspect or stop it;
- traffic to approved destinations before playpen [detects a
  revocation](#how-a-pass-backed-run-ends) (up to one check interval, or
  longer while playpen is stopped);
- a process that restores the pass file between two checks: any process
  outside playpen, and the command itself with `--pass-dir-writable` once
  the owner's edit saved a new file. With a read-only pass directory, the
  command can read the pass after such an edit, and the other files
  there. A pass directory moved away and back between two checks is not
  noticed;
- a report forged while playpen was killed: trust the report only together
  with playpen's own exit status.

## License

[MIT License](LICENSE).
