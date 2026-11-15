#!/usr/bin/env python3
"""IPS test traffic for the boot test (test tooling; not shipped).

  boot-ips-traffic.py server                  HTTP on 8080 (/uid answers like `id` run as
                                              root) and a line echo server on 9099
  boot-ips-traffic.py client SERVER SRC PATH  GET http://SERVER:8080/PATH from address SRC
  boot-ips-traffic.py raw SERVER SRC TEXT     send TEXT as the connection's first bytes to
                                              port 8080 (not HTTP: nothing to classify yet);
                                              prints "passed" if any answer comes, else "blocked"
  boot-ips-traffic.py stream SERVER SRC N     send N lines to the echo server, one at a time;
                                              prints how many came back before it stalled

The client prints the HTTP status, or "blocked" when no answer comes in time
(the IPS dropped the request or its reply). /uid's body matches the ET Open
signature 2100498 (GPL ATTACK_RESPONSE id check returned root); paths with
SJB-IPS-TEST-<LEVEL> match SJB-OS's test signatures.
"""
import http.server
import socket
import socketserver
import sys
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"uid=0(root) gid=0(root) groups=0(root)\n" if self.path == "/uid" else b"Welcome through the border.\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def client(server, src, path):
    s = socket.socket()
    s.settimeout(6)
    try:
        s.bind((src, 0))
        s.connect((server, 8080))
        s.sendall(f"GET /{path} HTTP/1.1\r\nHost: {server}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data or len(data) < 40:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\r\n", 1)[0].decode(errors="replace")
        print(line.split(" ")[1] if line.startswith("HTTP/") else "blocked")
    except OSError:
        print("blocked")
    finally:
        s.close()


def raw(server, src, text):
    s = socket.socket()
    s.settimeout(6)
    try:
        s.bind((src, 0))
        s.connect((server, 8080))
        s.sendall(text.encode() + b"\r\n\r\n")
        print("passed" if s.recv(4096) else "blocked")
    except OSError:
        print("blocked")
    finally:
        s.close()


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(256)
            if not d:
                return
            self.request.sendall(d)


def stream(server, src, n):
    s = socket.socket()
    s.settimeout(3)
    got = 0
    try:
        s.bind((src, 0))
        s.connect((server, 9099))
        for i in range(int(n)):
            s.sendall(b"line %d\n" % i)
            if not s.recv(256):
                break
            got += 1
    except OSError:
        pass
    finally:
        s.close()
    print(got)


if __name__ == "__main__":
    if sys.argv[1] == "server":
        es = socketserver.ThreadingTCPServer(("0.0.0.0", 9099), Echo)
        es.daemon_threads = True
        threading.Thread(target=es.serve_forever, daemon=True).start()
        http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
    elif sys.argv[1] == "raw":
        raw(*sys.argv[2:5])
    elif sys.argv[1] == "stream":
        stream(*sys.argv[2:5])
    else:
        client(*sys.argv[2:5])
