#!/usr/bin/env python3
"""Test harness only: a syslog receiver for the log forwarding gate.
UDP, TCP and TLS (octet-counted frames, RFC 6587/5425) on the given
ports; each message is appended as one line to DIR/<transport>.log.
usage: syslog-sink.py DIR UDP_PORT TCP_PORT TLS_PORT CERT KEY"""
import os, socket, ssl, sys, threading

d, udp_port, tcp_port, tls_port, cert, key = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5], sys.argv[6]
lock = threading.Lock()

def write(name, msg):
    with lock, open(os.path.join(d, name + ".log"), "a") as f:
        f.write(msg.replace("\n", "\\n") + "\n")

def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", udp_port))
    while True:
        data, _ = s.recvfrom(65535)
        write("udp", data.decode(errors="replace"))

def frames(conn, name):
    buf = b""
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            return
        buf += chunk
        while b" " in buf:
            n, rest = buf.split(b" ", 1)
            if not n.isdigit():
                write(name, "BAD FRAME " + buf[:40].decode(errors="replace"))
                return
            if len(rest) < int(n):
                break
            write(name, rest[: int(n)].decode(errors="replace"))
            buf = rest[int(n):]

def stream(port, name, ctx=None):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    while True:
        c, _ = s.accept()
        try:
            if ctx:
                c = ctx.wrap_socket(c, server_side=True)
        except (ssl.SSLError, OSError):
            c.close()
            continue
        threading.Thread(target=frames, args=(c, name), daemon=True).start()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
threading.Thread(target=udp, daemon=True).start()
threading.Thread(target=stream, args=(tcp_port, "tcp"), daemon=True).start()
stream(tls_port, "tls", ctx)
