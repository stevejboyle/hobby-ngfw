#!/usr/bin/env python3
"""SNMP reachability probe for the boot test (test tooling; not shipped).

  boot-snmp-probe.py HOST COMMUNITY

Sends one SNMPv2c GetRequest for sysUpTime.0 to HOST:161 and prints
"answered" if any SNMP reply comes back within 3 seconds, else "timeout".
Run inside a test namespace on the appliance to check that SNMP can't be
reached from a dataplane interface (the appliance has no SNMP client).
Standard library only.
"""
import socket
import sys


def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + body


def integer(v):
    return tlv(0x02, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def oid(dotted):
    parts = [int(p) for p in dotted.strip(".").split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, out)


def get_request(community, request_id=0x5B1):
    varbind = tlv(0x30, oid("1.3.6.1.2.1.1.3.0") + tlv(0x05, b""))
    pdu = tlv(0xA0, integer(request_id) + integer(0) + integer(0) + tlv(0x30, varbind))
    return tlv(0x30, integer(1) + tlv(0x04, community.encode()) + pdu)


def main():
    host, community = sys.argv[1], sys.argv[2]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(get_request(community), (host, 161))
    try:
        data, _ = s.recvfrom(4096)
    except (socket.timeout, ConnectionRefusedError, OSError):
        print("timeout")
        return
    print("answered" if data[:1] == b"\x30" else "timeout")


if __name__ == "__main__":
    main()
