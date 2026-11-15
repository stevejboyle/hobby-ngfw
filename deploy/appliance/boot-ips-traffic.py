#!/usr/bin/env python3
"""IPS test traffic for the boot test (test tooling; not shipped).

  boot-ips-traffic.py server                  HTTP on 8080: /uid answers like `id` run as root
  boot-ips-traffic.py client SERVER SRC PATH  GET http://SERVER:8080/PATH from address SRC

The client prints the HTTP status, or "blocked" when no answer comes in time
(the IPS dropped the request or its reply). /uid's body matches the ET Open
signature 2100498 (GPL ATTACK_RESPONSE id check returned root); paths with
SJB-IPS-TEST-<LEVEL> match SJB-OS's test signatures.
"""
import http.server
import socket
import sys


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


if __name__ == "__main__":
    if sys.argv[1] == "server":
        http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
    else:
        client(*sys.argv[2:5])
