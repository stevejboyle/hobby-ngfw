#!/usr/bin/env python3
"""App Identification test traffic for the boot test (test tooling; not shipped).

  boot-appid-traffic.py server          listen on 443/tcp, 80/tcp, 22/tcp, 53/udp
  boot-appid-traffic.py client SERVER   one connection of each kind to SERVER

The client makes traffic nDPI recognises from its first packets:
  - TLS ClientHello with SNI www.youtube.com (443)  -> YouTube
  - HTTP request with Host: www.netflix.com (80)     -> Netflix
  - SSH version exchange (22)                        -> SSH
  - DNS query for www.wikipedia.org (53/udp)         -> DNS
No certificates are needed: the TLS "server" just reads the ClientHello.
"""
import socket
import ssl
import struct
import sys
import threading


def serve_tcp(port, greet=b"", reply=b""):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(3)
            if greet:
                c.sendall(greet)
            c.recv(4096)
            if reply:
                c.sendall(reply)
        except OSError:
            pass
        finally:
            c.close()


def serve_dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    while True:
        q, addr = s.recvfrom(512)
        if len(q) < 12:
            continue
        # Answer with the question echoed and no records (NXDOMAIN).
        tid, flags = struct.unpack("!HH", q[:4])
        s.sendto(struct.pack("!HHHHHH", tid, 0x8183, 1, 0, 0, 0) + q[12:], addr)


def server():
    for port, greet, reply in [
        (443, b"", b""),
        (80, b"", b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"),
        (22, b"SSH-2.0-OpenSSH_9.9\r\n", b""),
    ]:
        threading.Thread(target=serve_tcp, args=(port, greet, reply), daemon=True).start()
    serve_dns()


def client(host):
    results = {}
    # TLS: only the ClientHello matters; the handshake then fails, as expected.
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=3) as s:
            try:
                ctx.wrap_socket(s, server_hostname="www.youtube.com")
            except (ssl.SSLError, OSError):
                pass
        results["tls"] = "sent"
    except OSError as e:
        results["tls"] = str(e)
    try:
        with socket.create_connection((host, 80), timeout=3) as s:
            s.sendall(b"GET / HTTP/1.1\r\nHost: www.netflix.com\r\nUser-Agent: sjb-test\r\nAccept: */*\r\n\r\n")
            results["http"] = s.recv(100).split(b"\r\n")[0].decode()
    except OSError as e:
        results["http"] = str(e)
    try:
        with socket.create_connection((host, 22), timeout=3) as s:
            banner = s.recv(100)
            s.sendall(b"SSH-2.0-OpenSSH_9.9\r\n")
            results["ssh"] = banner.strip().decode()
    except OSError as e:
        results["ssh"] = str(e)
    try:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3)
        name = b"".join(bytes([len(p)]) + p for p in b"www.wikipedia.org".split(b".")) + b"\0"
        u.sendto(struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1), (host, 53))
        r, _ = u.recvfrom(512)
        results["dns"] = "answered" if r[:2] == b"\x12\x34" else "bad answer"
    except OSError as e:
        results["dns"] = str(e)
    print(results)


if __name__ == "__main__":
    if sys.argv[1:2] == ["server"]:
        server()
    elif sys.argv[1:2] == ["client"] and len(sys.argv) == 3:
        client(sys.argv[2])
    else:
        sys.exit(__doc__)
