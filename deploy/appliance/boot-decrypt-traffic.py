#!/usr/bin/env python3
"""TLS decryption test traffic for the boot test (test tooling; not shipped).

  boot-decrypt-traffic.py server DIR           HTTPS on 443; a certificate per server
                                               name from DIR/<name>.crt|key; answers
                                               "seen from ADDR path PATH"
  boot-decrypt-traffic.py client NAME ADDR CA PATH
                                               GET https://NAME/PATH at ADDR trusting
                                               the CA file; prints the answer and
                                               "| issuer: CN", or ERROR: reason, or
                                               "blocked" when no answer comes
"""
import http.server
import socket
import socketserver
import ssl
import sys

NAMES = ["shop.example", "www.bank.example", "app.example", "bad.example"]


def server(d):
    ctxs = {}
    for n in NAMES:
        c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        c.load_cert_chain(f"{d}/{n}.crt", f"{d}/{n}.key")
        ctxs[n] = c
    base = ctxs["shop.example"]

    def pick(s, name, _):
        s.context = ctxs.get(name, base)

    base.sni_callback = pick

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = f"seen from {self.client_address[0]} path {self.path}\n".encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
        daemon_threads = True
        allow_reuse_address = True

    s = S(("0.0.0.0", 443), H)
    s.socket = base.wrap_socket(s.socket, server_side=True)
    s.serve_forever()


def client(name, addr, ca, path):
    ctx = ssl.create_default_context(cafile=ca)
    try:
        with socket.create_connection((addr, 443), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=name) as s:
                issuer = dict(x[0] for x in s.getpeercert()["issuer"]).get("commonName", "?")
                s.sendall(f"GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
                data = b""
                try:
                    while chunk := s.recv(4096):
                        data += chunk
                except (socket.timeout, TimeoutError):
                    pass
                if not data:
                    print("blocked")
                    return
                print(data.decode(errors="replace").split("\r\n\r\n", 1)[-1].strip(), "| issuer:", issuer)
    except Exception as e:  # noqa: BLE001 (test tooling: report any failure)
        print("ERROR:", type(e).__name__, e)


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server(sys.argv[2])
    else:
        client(*sys.argv[2:6])
