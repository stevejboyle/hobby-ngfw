#!/usr/bin/env bash
# TLS decryption gate: ngfwd, tlsd and the cleartext loop in the namespace
# lab. A client in users makes HTTPS connections to a server in internet
# (which answers with the address it saw, so a connection through tlsd shows
# the firewall's); the gate checks what tlsd decided, what crossed the
# forward chain, that the security rules still decide, exclusions, pinned
# clients, bad server certificates and fail-open.
#
# Linux only; needs root, nft, conntrack, python3 and openssl. Binaries from
# $BIN (./bin), built for this machine. MODE=observe checks observe mode
# (0.9.9-r04); the default checks decryption.
set -uo pipefail

BIN=${BIN:-./bin}
MODE=${MODE:-decrypt}
WORK=$(mktemp -d)
SOCK=$WORK/ngfwd.sock
FAILS=0
PIDS=()
TLSD_PID=

cleanup() {
	for p in "${PIDS[@]}" $TLSD_PID; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	nsenter --net=/run/netns/ngfw-fw ./deploy/appliance/rootfs/usr/local/sbin/sjb-decrypt-net down >/dev/null 2>&1
	./lab/topology.sh down >/dev/null
	if ((FAILS > 0)); then
		echo "--- ngfwd log ---"; tail -40 "$WORK/ngfwd.log" 2>/dev/null
		echo "--- tlsd log ---"; tail -40 "$WORK/tlsd.log" 2>/dev/null
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
fw() { "$BIN/fwctl" -socket "$SOCK" "$@"; }
in_fw() { ip netns exec ngfw-fw "$@"; }
# nsenter keeps the mount namespace, so the loop's namespaces (bind mounts
# under /run/netns) made here are seen by tlsd.
in_fw_net() { nsenter --net=/run/netns/ngfw-fw "$@"; }

id sjb-tls >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sjb-tls
./lab/topology.sh up >/dev/null
ip -n ngfw-inet addr add 203.0.113.11/24 dev eth0 # a server the rules deny
in_fw_net ./deploy/appliance/rootfs/usr/local/sbin/sjb-decrypt-net up >/dev/null || { fail "loop setup"; exit 1; }

# --- test PKI: a "public" root the firewall trusts, and server certificates --
cd "$WORK"
openssl_cert() { # NAME DAYS-BACK DAYS-VALID SIGNER(ca|self)
	local n=$1
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$n.key" -subj "/CN=$n" -out "$n.csr" 2>/dev/null
	printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$n" >"$n.ext"
	if [[ $4 == self ]]; then
		openssl x509 -req -in "$n.csr" -signkey "$n.key" -days "$3" -extfile "$n.ext" -out "$n.crt" 2>/dev/null
	else
		openssl x509 -req -in "$n.csr" -CA testca.crt -CAkey testca.key -CAcreateserial -days "$3" -extfile "$n.ext" -out "$n.crt" 2>/dev/null
		if [[ $2 != 0 ]]; then # expired: back-date by re-signing with a fixed past window
			openssl x509 -req -in "$n.csr" -CA testca.crt -CAkey testca.key -CAcreateserial -not_before 20200101000000Z -not_after 20200201000000Z \
				-extfile "$n.ext" -out "$n.crt" 2>/dev/null
		fi
	fi
}
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout testca.key -subj "/CN=Lab Public Root" \
	-days 30 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -out testca.crt 2>/dev/null
for n in shop.example www.bank.example app.example; do openssl_cert $n 0 30 ca; done
openssl_cert old.example 1 30 ca
openssl_cert bad.example 0 30 self
cd - >/dev/null

# --- the server: HTTPS on 443 with a certificate per server name ------------
cat >"$WORK/server.py" <<'EOF'
import http.server, socketserver, ssl, sys
w = sys.argv[1]
ctxs = {}
for n in ["shop.example", "www.bank.example", "app.example", "old.example", "bad.example"]:
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    c.load_cert_chain(f"{w}/{n}.crt", f"{w}/{n}.key")
    ctxs[n] = c
base = ctxs["shop.example"]
base.sni_callback = lambda s, name, _: setattr(s, "context", ctxs.get(name, base)) or None
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"seen from {self.client_address[0]} path {self.path}\n".encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
class S(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
s = S(("0.0.0.0", 443), H)
s.socket = base.wrap_socket(s.socket, server_side=True)
s.serve_forever()
EOF
ip netns exec ngfw-inet python3 "$WORK/server.py" "$WORK" >/dev/null 2>&1 &
PIDS+=($!)

# client NAME ADDR CA-FILE PATH: GET https://NAME/PATH at ADDR, trusting
# CA-FILE; prints the answer, or ERROR: reason.
cat >"$WORK/client.py" <<'EOF'
import socket, ssl, sys
name, addr, ca, path = sys.argv[1:5]
ctx = ssl.create_default_context(cafile=ca)
try:
    with socket.create_connection((addr, 443), timeout=6) as raw:
        with ctx.wrap_socket(raw, server_hostname=name) as s:
            issuer = dict(x[0] for x in s.getpeercert()["issuer"]).get("commonName", "?")
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
            data = b""
            while chunk := s.recv(4096):
                data += chunk
            print(data.decode(errors="replace").split("\r\n\r\n", 1)[-1].strip(), "| issuer:", issuer)
except Exception as e:
    print("ERROR:", type(e).__name__, e)
EOF
client() { ip netns exec ngfw-users python3 "$WORK/client.py" "$@"; }

# --- ngfwd and tlsd -----------------------------------------------------------
in_fw "$BIN/ngfwd" -state "$WORK/state" -socket "$SOCK" -users "$WORK/users.json" -roles "$WORK/roles.json" -web-users "$WORK/web-users" -unix-accounts=false -ips-dir "" -frr "" -kea "" -ip "" \
	-tlsd "$BIN/tlsd" -decryption-ca "$WORK/ca" -decryption-policy "$WORK/policy.json" -tlsd-socket "$WORK/tlsd.sock" \
	>>"$WORK/ngfwd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do fw status >/dev/null 2>&1 && break; sleep 0.1; done

start_tlsd() {
	nsenter --net=/run/netns/ngfw-fw env SSL_CERT_FILE="$WORK/testca.crt" "$BIN/tlsd" -policy "$WORK/policy.json" -ca "$WORK/ca" \
		-learned "$WORK/learned.json" -status "$WORK/tlsd.sock" -builtin ./deploy/appliance/rootfs/usr/share/sjb-os/decryption-exclusions.txt \
		>>"$WORK/tlsd.log" 2>&1 &
	TLSD_PID=$!
	for _ in $(seq 50); do [[ -S $WORK/tlsd.sock ]] && break; sleep 0.1; done
	sleep 2.5 # ngfwd's health check fills decrypt_ready
}

SYSTEM_MODE=""
[[ $MODE == observe ]] && SYSTEM_MODE="  decryption: observe"
cat >"$WORK/fw.yaml" <<EOF
system:
  hostname: fw-lab
$SYSTEM_MODE
zones:
  - name: users
  - name: internet
interfaces:
  - name: veth-users
    zone: users
    address: 10.10.1.1/24
  - name: veth-inet
    zone: internet
    address: 203.0.113.1/24
addresses:
  - name: denied-server
    cidr: 203.0.113.11
services:
  - name: https
    protocol: tcp
    ports: "443"
decryption_exclusions:
  - name: lab-bank
    domains: [bank.example]
decryption_rules:
  - name: users-out
    from: [users]
    to: [internet]
    service: [https]
    action: decrypt
rules:
  - name: no-denied-server
    from: [users]
    to: [internet]
    destination: [denied-server]
    action: reset
  - name: web-out
    from: [users]
    to: [internet]
    service: [https]
    action: allow
EOF
fw load "$WORK/fw.yaml" >/dev/null && fw commit -m decryption >/dev/null || { fail "commit"; exit 1; }
fw shell -c "request decryption ca generate" >/dev/null 2>&1 || fail "generate the CA"
fw shell -c "show decryption ca" | sed -n '/BEGIN CERT/,/END CERT/p' >"$WORK/sjb-ca.crt"
grep -q "BEGIN CERTIFICATE" "$WORK/sjb-ca.crt" && pass "decryption CA generated; its certificate shown by show decryption ca" || fail "CA certificate"
[[ $(stat -c %a "$WORK/ca/ca.key") == 600 ]] && pass "CA key is mode 600" || fail "CA key mode $(stat -c %a "$WORK/ca/ca.key")"
start_tlsd

# Count plaintext HTTP crossing the forward chain on the loop (what App
# Identification and the IPS see).
in_fw nft -f - <<'EOF'
table ip gate {
	chain count {
		type filter hook forward priority filter - 20; policy accept;
		iifname "sjbd-c" tcp dport 443 @ih,0,32 0x47455420 counter comment "plaintext GET on the loop"
		iifname "sjbd-c" tcp dport 443 counter comment "loop"
	}
}
EOF
plaintext() { in_fw nft list chain ip gate count | awk '/plaintext GET/ {for (i=1;i<=NF;i++) if ($i=="packets") print $(i+1)}'; }
looped() { in_fw nft list chain ip gate count | awk '/comment "loop"/ {for (i=1;i<=NF;i++) if ($i=="packets") print $(i+1)}'; }
lastlog() { grep '^ngfw-decrypt ' "$WORK/tlsd.log" | tail -1; }

sd=$(fw shell -c "show decryption")
grep -qE "state +(DECRYPTING|OBSERVING)" <<<"$sd" && pass "show decryption: $(awk '/^state/ {print $2}' <<<"$sd")" || fail "show decryption: $(grep state <<<"$sd")"

if [[ $MODE == observe ]]; then
	out=$(client shop.example 203.0.113.10 "$WORK/testca.crt" /observed)
	[[ $out == *"seen from 203.0.113.1 "*"issuer: Lab Public Root"* ]] && pass "observe: through tlsd, real certificate ($out)" || fail "observe: $out"
	lastlog | grep -q '"decision":"would-decrypt"' && pass "observe: logged would-decrypt" || fail "observe log: $(lastlog)"
	(($(plaintext) == 0 && $(looped) > 0)) && pass "observe: loop carried only ciphertext" || fail "observe: plaintext $(plaintext) looped $(looped)"
else
	out=$(client shop.example 203.0.113.10 "$WORK/sjb-ca.crt" /SJB-IPS-TEST-CRITICAL)
	[[ $out == *"seen from 203.0.113.1 path /SJB-IPS-TEST-CRITICAL"*"issuer: SJB-OS Decryption CA"* ]] && pass "decrypted: client trusts the SJB-OS CA ($out)" || fail "decrypt: $out"
	lastlog | grep -q '"decision":"decrypted".*"server_name":"shop.example"' && pass "decryption log: decrypted shop.example" || fail "log: $(lastlog)"
	(($(plaintext) > 0)) && pass "plaintext request crossed the forward chain ($(plaintext) packet)" || fail "no plaintext on the loop"

	out=$(client www.bank.example 203.0.113.10 "$WORK/testca.crt" /)
	[[ $out == *"issuer: Lab Public Root"* ]] && pass "excluded name keeps the server's own certificate" || fail "exclusion: $out"
	lastlog | grep -q '"decision":"excluded"' && pass "logged excluded" || fail "log: $(lastlog)"

	out=$(client app.example 203.0.113.10 "$WORK/testca.crt" /)
	[[ $out == ERROR* ]] && lastlog | grep -q '"decision":"learned"' && pass "client rejecting the certificate is learned ($out)" || fail "pinned 1st: $out $(lastlog)"
	out=$(client app.example 203.0.113.10 "$WORK/testca.crt" /)
	[[ $out == *"issuer: Lab Public Root"* ]] && pass "learned server passes through after" || fail "pinned 2nd: $out"
	grep -q app.example <<<"$(fw shell -c 'show decryption learned')" && pass "show decryption learned lists it" || fail "learned list"

	cat "$WORK/sjb-ca.crt" "$WORK/ca/untrusted.crt" >"$WORK/both.crt"
	out=$(client bad.example 203.0.113.10 "$WORK/both.crt" /)
	[[ $out == *"issuer: SJB-OS Untrusted"* ]] && pass "bad server certificate re-signed with the untrusted CA" || fail "bad cert: $out"
	out=$(client old.example 203.0.113.10 "$WORK/sjb-ca.crt" /)
	[[ $out == ERROR* ]] && pass "expired server certificate: a client trusting only the SJB-OS CA refuses it" || fail "expired: $out"

	out=$(client shop.example 203.0.113.11 "$WORK/sjb-ca.crt" /)
	[[ $out == ERROR* ]] && lastlog | grep -q '"decision":"blocked".*security rules' && pass "the security rules still deny decrypted traffic" || fail "deny: $out $(lastlog)"

	out=$(ip netns exec ngfw-users python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1); s.sendto(b"x", ("203.0.113.10", 443)); print("sent")')
	grep -qE 'packets [1-9].*quic' <<<"$(in_fw nft list chain inet ngfw decrypt)" && pass "QUIC dropped for decrypted traffic" || fail "QUIC not dropped"
fi

# --- fail-open ---------------------------------------------------------------
kill $TLSD_PID; wait $TLSD_PID 2>/dev/null; TLSD_PID=
sleep 3
out=$(client shop.example 203.0.113.10 "$WORK/testca.crt" /direct)
[[ $out == *"seen from 10.10.1.10 path /direct"* ]] && pass "tlsd down: traffic passes undecrypted (fail-open)" || fail "fail-open: $out"
grep -q "UNAVAILABLE" <<<"$(fw shell -c 'show decryption')" && pass "show decryption says unavailable" || fail "state while down"
start_tlsd
out=$(client shop.example 203.0.113.10 "$WORK/testca.crt" /back)
[[ $out == *"seen from 203.0.113.1 "* ]] || [[ $MODE != observe && $out == ERROR* ]] && pass "tlsd back: connections handed to it again" || fail "back: $out"

# --- decryption off ------------------------------------------------------------
sed -i 's/^  hostname: fw-lab/  hostname: fw-lab\n  decryption: "off"/; /^  decryption: observe/d' "$WORK/fw.yaml"
fw load "$WORK/fw.yaml" >/dev/null && fw commit -m off >/dev/null
grep -q "chain decrypt " <<<"$(in_fw nft list table inet ngfw)" && fail "decrypt chain still there" || pass "decryption off: no hand-over chain"

echo
((FAILS == 0)) && echo "decryption gate: all checks passed" || echo "decryption gate: $FAILS failed"
exit $((FAILS > 0))
