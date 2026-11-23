#!/usr/bin/env python3
"""Socket family probe for the table in docs/DESIGN.md ("Socket families").

Run it inside playpen, in a disposable guest: `sweep` calls socket() for every
address family, and a family whose module is not loaded can make the kernel
load it. Do not run `sweep` on a machine whose module set must not change.

  sweep [--families 1,2,...]   one JSON line per family: what socket() did,
                               and which modules appeared in /proc/modules
  vsock-listen PORT            accept AF_VSOCK streams, print the peer, reply
                               (PORT 4294967295: any; the port is printed)
  vsock-connect CID PORT       connect an AF_VSOCK stream, print the outcome
  vhost-guest PORT             act as a guest through /dev/vhost-vsock and
                               connect to the host (CID 2) at PORT
  vsock-mode                   print /proc/sys/net/vsock/* or "absent"
  with-mode MODE CMD...        run CMD in a user and mount namespace of its
                               own, where a tmpfs over /proc/sys gives
                               /proc/sys/net/vsock/ns_mode the text MODE
                               (for the test of playpen's refusal)
  qrtr-listen PORT             receive one AF_QIPCRTR datagram on the local node
  qrtr-send PORT               send one AF_QIPCRTR datagram to the local node
"""
import argparse
import ctypes
import errno
import fcntl
import json
import mmap
import os
import select
import socket
import struct
import sys

# Extra (type, protocol) pairs per family, beyond types 1-5 with protocol 0.
EXTRA = {
    15: [(3, 2)],  # AF_KEY, PF_KEY_V2
    16: [(3, p) for p in range(32)],  # AF_NETLINK, every protocol
    17: [(3, 0x0300)],  # AF_PACKET, ETH_P_ALL
    24: [(1, 0), (1, 1), (1, 2)],  # AF_PPPOX: PPPoE, L2TP, PPTP
    29: [(3, 1), (2, 2), (2, 6), (2, 7)],  # AF_CAN: raw, BCM, ISO-TP, J1939
    31: [(3, 1), (5, 2), (1, 3), (3, 4), (3, 5), (3, 6), (5, 8)],  # Bluetooth
    33: [(2, 2), (2, 10)],  # AF_RXRPC over IPv4, IPv6
    34: [(2, 1)],  # AF_ISDN
    35: [(5, 2)],  # AF_PHONET pipe
    39: [(5, 1), (1, 1)],  # AF_NFC LLCP
    43: [(1, 1)],  # AF_SMC over IPv6
}
PEER_TIMEOUT = 5


def modules():
    with open('/proc/modules') as f:
        return {line.split()[0] for line in f}


def sweep(args):
    families = ([int(x) for x in args.families.split(',')] if args.families
                else range(args.max + 1))
    for fam in families:
        before = modules()
        created, errors = [], {}
        for typ, proto in dict.fromkeys([(t, 0) for t in range(1, 6)] + EXTRA.get(fam, [])):
            try:
                socket.socket(fam, typ, proto).close()
                created.append([typ, proto])
            except OSError as e:
                errors.setdefault(errno.errorcode.get(e.errno, str(e.errno)), []).append([typ, proto])
        print(json.dumps({'family': fam, 'created': created,
                          'errors': {k: len(v) for k, v in errors.items()},
                          'loaded': sorted(modules() - before)}), flush=True)


def vsock_listen(args):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.bind((socket.VMADDR_CID_ANY, args.port))
    s.listen()
    s.settimeout(args.timeout)
    print(f'listening port={s.getsockname()[1]}', flush=True)
    for _ in range(args.count):
        try:
            c, (cid, port) = s.accept()
        except TimeoutError:
            print('no connection', flush=True)
            return
        c.settimeout(PEER_TIMEOUT)
        data = c.recv(64)
        print(f'accepted cid={cid} port={port} data={data.decode(errors="replace")}', flush=True)
        c.sendall(b'pong')
        c.close()


def vsock_connect(args):
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.settimeout(args.timeout)
    try:
        s.connect((args.cid, args.port))
        s.sendall(b'ping')
        print(f'connected reply={s.recv(64).decode(errors="replace")}', flush=True)
    except TimeoutError:
        print('error timeout', flush=True)
    except OSError as e:
        print('error ' + errno.errorcode.get(e.errno, str(e.errno)), flush=True)


def ioc(direction, nr, size):
    return direction << 30 | size << 16 | 0xAF << 8 | nr


W, R = 1, 2
SET_OWNER, GET_FEATURES, SET_FEATURES = ioc(0, 1, 0), ioc(R, 0, 8), ioc(W, 0, 8)
SET_MEM_TABLE, SET_NUM, SET_ADDR = ioc(W, 3, 8), ioc(W, 0x10, 8), ioc(W, 0x11, 40)
SET_BASE, SET_KICK, SET_CALL = ioc(W, 0x12, 8), ioc(W, 0x20, 8), ioc(W, 0x21, 8)
SET_CID, SET_RUNNING = ioc(W, 0x60, 8), ioc(W, 0x61, 4)
QSIZE, BUF = 8, 4096
HDR = struct.Struct('<QQIIIHHIII')  # struct virtio_vsock_hdr
OP_NAMES = {1: 'request', 2: 'response', 3: 'rst', 4: 'shutdown', 5: 'rw', 6: 'credit_update'}


class Queue:
    """One split virtqueue inside the shared mapping, at offset base."""

    def __init__(self, mem, addr, base):
        self.mem, self.base, self.addr = mem, base, addr
        self.desc, self.avail, self.used = base, base + 16 * QSIZE, base + 1024
        self.next_avail = self.last_used = 0

    def add(self, desc, buf_off, length, write):
        struct.pack_into('<QIHH', self.mem, self.desc + 16 * desc, self.addr + buf_off, length, 2 if write else 0, 0)
        struct.pack_into('<H', self.mem, self.avail + 4 + 2 * (self.next_avail % QSIZE), desc)
        self.next_avail += 1
        struct.pack_into('<H', self.mem, self.avail + 2, self.next_avail & 0xFFFF)

    def take_used(self):
        """Return the next used descriptor index, or None."""
        if self.last_used == struct.unpack_from('<H', self.mem, self.used + 2)[0]:
            return None
        head = struct.unpack_from('<I', self.mem, self.used + 4 + 8 * (self.last_used % QSIZE))[0]
        self.last_used = (self.last_used + 1) & 0xFFFF
        return head


def vhost_guest(args):
    """Speak virtio-vsock to the host kernel through /dev/vhost-vsock."""
    fd = os.open('/dev/vhost-vsock', os.O_RDWR)
    print('opened /dev/vhost-vsock', flush=True)
    size = 1 << 20
    mem = mmap.mmap(-1, size)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
    fcntl.ioctl(fd, SET_OWNER)
    features = struct.unpack('<Q', fcntl.ioctl(fd, GET_FEATURES, bytes(8)))[0]
    fcntl.ioctl(fd, SET_FEATURES, struct.pack('<Q', features & (1 << 32)))
    fcntl.ioctl(fd, SET_MEM_TABLE, struct.pack('<IIQQQQ', 1, 0, addr, size, addr, 0))
    rx, tx = Queue(mem, addr, 0), Queue(mem, addr, 4096)
    kicks, calls = [os.eventfd(0) for _ in (rx, tx)], [os.eventfd(0) for _ in (rx, tx)]
    for index, q in enumerate((rx, tx)):
        fcntl.ioctl(fd, SET_NUM, struct.pack('<II', index, QSIZE))
        fcntl.ioctl(fd, SET_ADDR, struct.pack('<IIQQQQ', index, 0, addr + q.desc, addr + q.used, addr + q.avail, 0))
        fcntl.ioctl(fd, SET_BASE, struct.pack('<II', index, 0))
        fcntl.ioctl(fd, SET_KICK, struct.pack('<Ii', index, kicks[index]))
        fcntl.ioctl(fd, SET_CALL, struct.pack('<Ii', index, calls[index]))
    rx_bufs = [16384 + BUF * i for i in range(QSIZE)]
    for desc, off in enumerate(rx_bufs):
        rx.add(desc, off, BUF, write=True)
    fcntl.ioctl(fd, SET_CID, struct.pack('<Q', args.guest_cid))
    fcntl.ioctl(fd, SET_RUNNING, struct.pack('<i', 1))
    os.eventfd_write(kicks[0], 1)
    tx_off, sent = 16384 + BUF * QSIZE, 0

    def send(op, payload=b'', flags=0):
        nonlocal sent
        desc = sent % QSIZE
        off = tx_off + BUF * desc
        sent += 1
        HDR.pack_into(mem, off, args.guest_cid, 2, 50000, args.port, len(payload), 1, op, flags, 65536, 0)
        mem[off + HDR.size:off + HDR.size + len(payload)] = payload
        tx.add(desc, off, HDR.size + len(payload), write=False)
        os.eventfd_write(kicks[1], 1)

    poll = select.poll()
    poll.register(calls[0], select.POLLIN)

    def receive():
        while True:
            head = rx.take_used()
            if head is None:
                if not poll.poll(args.timeout * 1000):
                    return None, b''
                os.eventfd_read(calls[0])
                continue
            off = rx_bufs[head]
            hdr = HDR.unpack_from(mem, off)
            data = bytes(mem[off + HDR.size:off + HDR.size + hdr[4]])
            rx.add(head, off, BUF, write=True)
            os.eventfd_write(kicks[0], 1)
            if hdr[6] != 6:  # skip credit updates
                return OP_NAMES.get(hdr[6], str(hdr[6])), data

    send(1)
    op, _ = receive()
    print(f'guest cid={args.guest_cid} request to cid=2 port={args.port}: {op or "no reply"}', flush=True)
    if op == 'response':
        send(5, b'ping')
        op, data = receive()
        print(f'reply {op}: {data.decode(errors="replace")}', flush=True)
        send(4, flags=3)


def qrtr_listen(args):
    s = socket.socket(socket.AF_QIPCRTR, socket.SOCK_DGRAM)
    node = s.getsockname()[0]
    s.bind((node, args.port))
    s.settimeout(args.timeout)
    print(f'listening node={node} port={args.port}', flush=True)
    try:
        data, peer = s.recvfrom(64)
        print(f'received from={peer} data={data.decode(errors="replace")}', flush=True)
    except TimeoutError:
        print('nothing received', flush=True)


def qrtr_send(args):
    s = socket.socket(socket.AF_QIPCRTR, socket.SOCK_DGRAM)
    node = s.getsockname()[0]
    s.sendto(b'ping', (node, args.port))
    print(f'sent to node={node} port={args.port}', flush=True)


def vsock_mode(_args):
    base = '/proc/sys/net/vsock'
    if not os.path.isdir(base):
        print('absent', flush=True)
        return
    for name in sorted(os.listdir(base)):
        with open(os.path.join(base, name)) as f:
            print(f'{name}={f.read().strip()}', flush=True)


def with_mode(args):
    """Exec the command where /proc/sys/net/vsock/ns_mode reads args.mode.

    The command keeps the caller's uid and gid (mapped to themselves) and has
    no capabilities once it runs. The tmpfs hides the rest of /proc/sys.
    """
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
    for path, text in (('/proc/self/setgroups', 'deny'), ('/proc/self/uid_map', f'{uid} {uid} 1'),
                       ('/proc/self/gid_map', f'{gid} {gid} 1')):
        with open(path, 'w') as f:
            f.write(text)
    libc = ctypes.CDLL(None, use_errno=True)
    ms_rec, ms_private = 0x4000, 1 << 18
    for source, target, fstype, flags in ((None, b'/', None, ms_rec | ms_private),
                                          (b'none', b'/proc/sys', b'tmpfs', 0)):
        if libc.mount(source, target, fstype, flags, None) != 0:
            e = ctypes.get_errno()
            raise OSError(e, os.strerror(e), target.decode())
    os.makedirs('/proc/sys/net/vsock')
    for name in ('ns_mode', 'child_ns_mode'):
        with open(f'/proc/sys/net/vsock/{name}', 'w') as f:
            f.write(args.mode + '\n')
    os.execvp(args.command[0], args.command)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('sweep')
    s.add_argument('--families')
    s.add_argument('--max', type=int, default=63)
    s = sub.add_parser('vsock-listen')
    s.add_argument('port', type=int)
    s.add_argument('--count', type=int, default=1)
    s.add_argument('--timeout', type=float, default=30)
    s = sub.add_parser('vsock-connect')
    s.add_argument('cid', type=int)
    s.add_argument('port', type=int)
    s.add_argument('--timeout', type=float, default=5)
    s = sub.add_parser('vhost-guest')
    s.add_argument('port', type=int)
    s.add_argument('--guest-cid', type=int, default=42)
    s.add_argument('--timeout', type=int, default=5)
    sub.add_parser('vsock-mode')
    s = sub.add_parser('with-mode')
    s.add_argument('mode')
    s.add_argument('command', nargs=argparse.REMAINDER)
    s = sub.add_parser('qrtr-listen')
    s.add_argument('port', type=int)
    s.add_argument('--timeout', type=float, default=10)
    s = sub.add_parser('qrtr-send')
    s.add_argument('port', type=int)
    args = p.parse_args()
    {'sweep': sweep, 'vsock-listen': vsock_listen, 'vsock-connect': vsock_connect,
     'vhost-guest': vhost_guest, 'vsock-mode': vsock_mode, 'with-mode': with_mode,
     'qrtr-listen': qrtr_listen, 'qrtr-send': qrtr_send}[args.cmd](args)


if __name__ == '__main__':
    try:
        main()
    except OSError as e:
        print('error ' + errno.errorcode.get(e.errno, str(e.errno)) + ': ' + str(e), flush=True)
        sys.exit(1)
