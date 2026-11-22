#!/usr/bin/env python3
"""Routed peer qualification. Exit 77 means host prerequisites unavailable.

Run with --playpen /absolute/path/to/playpen. All peers are loopback addresses
in a fresh network namespace with only a discard-only dummy interface.
"""
import argparse
import http.server
import itertools
import json
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading

A, B, V6 = '198.51.100.20', '198.51.100.21', '2001:db8:2::20'


def unsupported(message):
    print('UNSUPPORTED: ' + message, flush=True)
    return 77


def inner(args):
    if os.readlink('/proc/self/ns/net') == args.parent_net:
        raise RuntimeError('refusing to configure the caller network namespace')
    def ip(*words):
        result = subprocess.run(['ip', *words], capture_output=True, text=True)
        if result.returncode:
            raise EnvironmentError('cannot configure isolated dummy namespace: ' + result.stderr.strip())
    nested = subprocess.run(['unshare', '--user', '--map-user=' + args.uid,
                             '--map-group=' + args.gid, 'true'], capture_output=True, text=True)
    if nested.returncode:
        return unsupported('nested user namespace unavailable: ' + nested.stderr.strip())
    try:
        ip('link', 'set', 'lo', 'up')
        ip('link', 'add', 'dummy0', 'type', 'dummy')
        ip('addr', 'add', '192.0.2.10/24', 'dev', 'dummy0')
        ip('link', 'set', 'dummy0', 'up')
        ip('route', 'add', 'default', 'via', '192.0.2.1')
        for addr in (A, B):
            ip('addr', 'add', addr + '/32', 'dev', 'lo')
        ip('-6', 'addr', 'add', '2001:db8:1::10/64', 'dev', 'dummy0', 'nodad')
        ip('-6', 'route', 'add', 'default', 'via', '2001:db8:1::1', 'dev', 'dummy0')
        ip('-6', 'addr', 'add', V6 + '/128', 'dev', 'lo', 'nodad')
    except EnvironmentError as exc:
        return unsupported(str(exc))
    requests, seen = [], []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            dest = self.server.server_address[0]
            requests.append((dest, self.path))
            self.send_response(302 if dest == A else 200)
            if dest == A:
                self.send_header('Location', f'http://{B}:8080/final')
            self.end_headers()
            if dest != A:
                self.wfile.write(b'peer-ok')
        def log_message(self, *unused):
            pass
    class Http6(http.server.HTTPServer):
        address_family = socket.AF_INET6
    servers, sockets = [], []
    try:
        for addr, cls in ((A, http.server.HTTPServer), (B, http.server.HTTPServer), (V6, Http6)):
            server = cls((addr, 8080), Handler)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        def echo(sock):
            while True:
                try:
                    packet, peer = sock.recvfrom(512)
                    seen.append((sock.getsockname()[0], sock.getsockname()[1]))
                    sock.sendto(packet, peer)
                except OSError:
                    return
        for addr, family in ((A, socket.AF_INET), (V6, socket.AF_INET6)):
            for port in (8090, 8091):
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.bind((addr, port))
                sockets.append(sock)
                threading.Thread(target=echo, args=(sock,), daemon=True).start()
        with tempfile.TemporaryDirectory(prefix='playpen-routed-') as temp:
            prefix = ['unshare', '--user', '--map-user=' + args.uid, '--map-group=' + args.gid,
                      args.playpen, 'run']
            report_ids = itertools.count()
            def run(grants, command):
                # A missing report from this invocation must fail even after a passing run.
                report_path = pathlib.Path(temp) / ('report-' + str(next(report_ids)) + '.json')
                options = [item for grant in grants for item in ('--allow', grant)]
                p = subprocess.run(prefix + ['--report', report_path] + options + ['--'] + command, capture_output=True, timeout=20)
                try:
                    report = json.loads(report_path.read_text())
                except (OSError, ValueError) as exc:
                    raise AssertionError(f'missing report: {exc}; stderr={p.stderr!r}') from exc
                assert report['outcome'] == 'ran' and report['startup_evidence'] == 'exec_and_exit', (p.stderr, report)
                assert report['exit_code'] == p.returncode, (p.returncode, report)
                assert report['dropped'] is not None, report
                return p, report['dropped']
            def dropped(summary, address, proto, port):
                return any(d['address'] == address and d['protocol'] == proto and d['port'] == port and d['packets'] > 0 for d in summary['destinations'])
            for both in (True, False):
                requests.clear()
                grants = [A + ':8080/tcp'] + ([B + ':8080/tcp'] if both else [])
                p, drops = run(grants, ['curl', '-q', '-sS', '--noproxy', '*', '--location', '--max-time', '4', f'http://{A}:8080/start'])
                print('redirect', both, 'requests', requests, 'drops', drops, flush=True)
                assert requests == ([(A, '/start'), (B, '/final')] if both else [(A, '/start')])
                assert (p.returncode == 0) == both
                if both:
                    assert p.stdout == b'peer-ok' and drops['packets'] == 0
                else:
                    assert dropped(drops, B, 'tcp', 8080)
            for addr in (A, V6):
                host = addr if addr == A else '[' + addr + ']'
                first, second = host + ':8090/udp', host + ':8091/udp'
                for both in (True, False):
                    seen.clear()
                    p, drops = run([first] + ([second] if both else []), [args.playpen, 'probe', 'reach', '--try', first, '--try', second])
                    values = [json.loads(line) for line in p.stdout.splitlines()]
                    print('udp', addr, both, 'receiver', seen, 'drops', drops, flush=True)
                    assert p.returncode == 0 and [v['reached'] for v in values] == [True, both]
                    assert seen == ([(addr, 8090), (addr, 8091)] if both else [(addr, 8090)])
                    assert (drops['packets'] == 0) == both
                    if not both:
                        assert dropped(drops, addr, 'udp', 8091)
            requests.clear()
            p, drops = run(['[' + V6 + ']:8080/tcp'], ['curl', '-q', '-g', '-sS', '--noproxy', '*', '--max-time', '4', f'http://[{V6}]:8080/final'])
            print('ipv6-http', requests, 'drops', drops, flush=True)
            assert p.returncode == 0 and p.stdout == b'peer-ok' and requests == [(V6, '/final')] and drops['packets'] == 0
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for sock in sockets:
            sock.close()
    print('EXECUTED: routed-peer', flush=True)
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--playpen', required=True)
    parser.add_argument('--inner', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--parent-net', help=argparse.SUPPRESS)
    parser.add_argument('--uid', help=argparse.SUPPRESS)
    parser.add_argument('--gid', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inner:
        return inner(args)
    for tool in ('ip', 'unshare', 'curl', 'nft', 'pasta'):
        if not shutil.which(tool):
            return unsupported(tool + ' is unavailable')
    preflight = subprocess.run(['unshare', '--user', '--map-root-user', '--net', 'true'], capture_output=True, text=True)
    if preflight.returncode:
        return unsupported('cannot create isolated user/network namespace: ' + preflight.stderr.strip())
    binary = pathlib.Path(args.playpen).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return unsupported('playpen binary is unavailable')
    cmd = ['unshare', '--user', '--map-root-user', '--net', sys.executable, str(pathlib.Path(__file__).resolve()),
           '--inner', '--playpen', str(binary), '--parent-net', os.readlink('/proc/self/ns/net'),
           '--uid', str(os.getuid()), '--gid', str(os.getgid())]
    child = subprocess.Popen(cmd, start_new_session=True)
    try:
        return child.wait(timeout=120)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        print('FAILED: routed peer fixture timed out', flush=True)
        return 1

if __name__ == '__main__':
    if not __debug__:
        print('FAILED: Python assertions are disabled', flush=True)
        sys.exit(1)
    try:
        sys.exit(main())
    except Exception as exc:
        print(f'FAILED: {type(exc).__name__}: {exc}', flush=True)
        sys.exit(1)
