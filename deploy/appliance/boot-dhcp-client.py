#!/usr/bin/env python3
"""Minimal DHCPv4 client for the boot test (the appliance has none).

Usage: boot-dhcp-client.py INTERFACE
Runs DISCOVER/OFFER/REQUEST/ACK on INTERFACE (no address needed) and prints
the result as JSON: address, server, router, dns, domain, lease, options.
Exits 1 if no ACK arrives. Test tooling only; not shipped in the image.
"""
import json
import os
import random
import socket
import struct
import sys
import time

IFACE = sys.argv[1]
MAC = bytes.fromhex(open(f"/sys/class/net/{IFACE}/address").read().strip().replace(":", ""))
XID = random.getrandbits(32)
MAGIC = b"\x63\x82\x53\x63"


def packet(msg_type, extra=b""):
    # op, htype, hlen, hops, xid, secs, flags (broadcast), ciaddr, yiaddr,
    # siaddr, giaddr, chaddr(16), sname(64), file(128)
    head = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, XID, 0, 0x8000,
                       b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4, MAC + b"\0" * 10, b"", b"")
    opts = bytes([53, 1, msg_type]) + extra + bytes([55, 6, 1, 3, 6, 15, 51, 66, 255])
    return head + MAGIC + opts


def parse(data):
    if len(data) < 240 or data[236:240] != MAGIC or struct.unpack("!I", data[4:8])[0] != XID:
        return None
    out = {"yiaddr": socket.inet_ntoa(data[16:20]), "opts": {}}
    i = 240
    while i < len(data) and data[i] != 255:
        if data[i] == 0:
            i += 1
            continue
        code, n = data[i], data[i + 1]
        out["opts"][code] = data[i + 2:i + 2 + n]
        i += 2 + n
    return out


def exchange(sock, pkt, want):
    end = time.time() + 6
    while time.time() < end:
        sock.sendto(pkt, ("255.255.255.255", 67))
        sock.settimeout(2)
        try:
            while True:
                data, _ = sock.recvfrom(4096)
                r = parse(data)
                if r and r["opts"].get(53, b"\0")[0] == want:
                    return r
        except socket.timeout:
            continue
    return None


def ips(b):
    return [socket.inet_ntoa(b[i:i + 4]) for i in range(0, len(b), 4)]


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, IFACE.encode())
s.bind(("0.0.0.0", 68))

offer = exchange(s, packet(1), 2)  # DISCOVER -> OFFER
if not offer:
    print(json.dumps({"error": "no offer"}))
    sys.exit(1)
server = offer["opts"][54]
req = bytes([50, 4]) + socket.inet_aton(offer["yiaddr"]) + bytes([54, 4]) + server
ack = exchange(s, packet(3, req), 5)  # REQUEST -> ACK
if not ack:
    print(json.dumps({"error": "no ack", "offered": offer["yiaddr"]}))
    sys.exit(1)
o = ack["opts"]
print(json.dumps({
    "address": ack["yiaddr"],
    "server": socket.inet_ntoa(o[54]),
    "router": ips(o.get(3, b"")),
    "dns": ips(o.get(6, b"")),
    "domain": o.get(15, b"").decode(errors="replace"),
    "lease": struct.unpack("!I", o[51])[0] if 51 in o else 0,
    "tftp": o.get(66, b"").decode(errors="replace"),
}))
