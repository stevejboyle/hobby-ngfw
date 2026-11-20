#!/usr/bin/env bash
# NAT gate: publishing an inside server. ngfw-users (10.10.1.10) plays the
# server, ngfw-inet (203.0.113.10) the internet client.
#   - port forward on the firewall's own outside address (203.0.113.1:8080
#     to the server's port 80): closed until an allow rule naming the
#     server's inside address lets it in, with a commit warning meanwhile;
#     other ports stay closed; the counter shows the connections
#   - 1:1 static NAT 203.0.113.20 <-> 10.10.1.10: the address goes on the
#     outside interface (labelled), every allowed port reaches the server,
#     and the server's own outbound traffic leaves from 203.0.113.20
#     (bidirectional), or from the outside address with bidirectional off;
#     removing the entry removes the address
#   - the port forward on the own address doesn't catch the static address
# Linux only; needs root, nft, conntrack, curl and python3. Binaries from $BIN (./bin).
set -uo pipefail

BIN=${BIN:-./bin}
WORK=$(mktemp -d)
SOCK=$WORK/ngfwd.sock
FAILS=0
PIDS=()

cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	./lab/topology.sh down >/dev/null
	(( FAILS > 0 )) && { echo "--- ngfwd log ---"; cat "$WORK/ngfwd.log" 2>/dev/null; }
	rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
check() { # check DESCRIPTION COMMAND...
	local d=$1; shift
	if "$@"; then pass "$d"; else fail "$d"; fi
}
fw() { "$BIN/fwctl" -socket "$SOCK" "$@"; }
in_fw() { ip netns exec ngfw-fw "$@"; }
api() { curl -s --unix-socket "$SOCK" "http://ngfwd$1"; }

# from_inet URL: the page body, or nothing when it doesn't connect.
from_inet() { ip netns exec ngfw-inet curl -4 -s -m 3 "$1" 2>/dev/null; }
# outbound_source: the address the internet sees the server's new
# connection come from.
outbound_source() { ip netns exec ngfw-users python3 -c '
import socket
s = socket.create_connection(("203.0.113.10", 7000), timeout=3)
print(s.recv(64).decode().strip())' 2>/dev/null; }

# --- configs ------------------------------------------------------------------
cat >"$WORK/head.yaml" <<'EOF'
system:
  hostname: fw-lab
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
  - name: users-net
    cidr: 10.10.1.0/24
  - name: server
    cidr: 10.10.1.10
  - name: server-public
    cidr: 203.0.113.20
services:
  - name: web
    protocol: tcp
    ports: "80"
EOF
NAT_FWD='nat:
  - name: users-out
    type: masquerade
    from: [users]
    to: [internet]
  - name: web-fwd
    type: port-forward
    interface: veth-inet
    protocol: tcp
    public_port: "8080"
    server: server
    server_port: "80"'
STATIC='  - name: one-to-one
    type: static
    interface: veth-inet
    public_address: server-public
    server: server'
RULES_OUT='rules:
  - name: users-out
    from: [users]
    to: [internet]
    action: allow'
RULE_IN='  - name: web-in
    from: [internet]
    to: [users]
    destination: [server]
    service: [web]
    action: allow
    log: true'
config() { # config NAME PARTS...: head.yaml plus the parts, one per line
	local f=$WORK/$1.yaml; shift
	{ cat "$WORK/head.yaml"; printf '%s\n' "$@"; } >"$f"
	echo "$f"
}
COMMIT_OUT=
commit() { # commit FILE MESSAGE: output (warnings) in COMMIT_OUT
	fw load "$1" >/dev/null || { fail "load $2"; return; }
	COMMIT_OUT=$(fw commit -m "$2" 2>&1) || fail "commit $2: $COMMIT_OUT"
}

# --- run ----------------------------------------------------------------------
./lab/topology.sh up >/dev/null
mkdir -p "$WORK/www" && echo "sjb-nat-gate" >"$WORK/www/index.html"
ip netns exec ngfw-users python3 -m http.server 80 --bind 0.0.0.0 --directory "$WORK/www" >/dev/null 2>&1 &
PIDS+=($!)
# Tells each client the address it came from.
ip netns exec ngfw-inet python3 -c '
import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall((self.client_address[0] + "\n").encode())
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
S(("203.0.113.10", 7000), H).serve_forever()' >/dev/null 2>&1 &
PIDS+=($!)
ip netns exec ngfw-fw "$BIN/ngfwd" -state "$WORK/state" -socket "$SOCK" -users "$WORK/users.json" -roles "$WORK/roles.json" -web-users "$WORK/web-users" -unix-accounts=false -ips-dir "" >>"$WORK/ngfwd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do fw status >/dev/null 2>&1 && break; sleep 0.1; done
sleep 1

# 1. Port forward without an allow rule: translated, but the rules drop it.
commit "$(config fwd-only "$NAT_FWD" "$RULES_OUT")" "port forward, no allow rule"
check "commit warns that no allow rule lets web-fwd in" grep -q 'nat "web-fwd": no allow rule' <<<"$COMMIT_OUT"
check "port forward without an allow rule: closed" test -z "$(from_inet http://203.0.113.1:8080/)"

# 2. With the allow rule (the server's inside address): open.
commit "$(config fwd "$NAT_FWD" "$RULES_OUT" "$RULE_IN")" "allow web-in"
check "allow rule present: no warning" bash -c '! grep -q "no allow rule" <<<"$1"' _ "$COMMIT_OUT"
check "203.0.113.1:8080 reaches the server's port 80" test "$(from_inet http://203.0.113.1:8080/)" = sjb-nat-gate
check "another port on the outside address stays closed" test -z "$(from_inet http://203.0.113.1:8081/)"
check "the server's own port 80 isn't published on the outside address" test -z "$(from_inet http://203.0.113.1:80/)"
hits=$(api /v1/nat | python3 -c 'import json,sys; print(next(e["hits"] for e in json.load(sys.stdin) if e["name"] == "web-fwd"))')
check "show nat counts web-fwd's connections ($hits)" test "${hits:-0}" -ge 1
check "the server sees no static NAT yet: outbound from the outside address" test "$(outbound_source)" = 203.0.113.1

# 3. Static NAT, bidirectional (the default).
commit "$(config static "$NAT_FWD" "$STATIC" "$RULES_OUT" "$RULE_IN")" "static NAT"
sleep 1
check "203.0.113.20 is on veth-inet with label veth-inet:nat" bash -c 'ip -n ngfw-fw -4 addr show dev veth-inet | grep -q "203.0.113.20/32 .*veth-inet:nat"'
check "203.0.113.20:80 reaches the server" test "$(from_inet http://203.0.113.20/)" = sjb-nat-gate
check "the own-address port forward doesn't catch 203.0.113.20:8080" test -z "$(from_inet http://203.0.113.20:8080/)"
check "203.0.113.1:8080 still reaches the server" test "$(from_inet http://203.0.113.1:8080/)" = sjb-nat-gate
src=$(outbound_source)
check "bidirectional: the server's outbound traffic leaves from 203.0.113.20 (seen: $src)" test "$src" = 203.0.113.20

# 4. Bidirectional off: inbound still works, outbound is masqueraded.
STATIC_OFF="$STATIC
    bidirectional: \"off\""
commit "$(config static-off "$NAT_FWD" "$STATIC_OFF" "$RULES_OUT" "$RULE_IN")" "static NAT, bidirectional off"
check "bidirectional off: 203.0.113.20:80 still reaches the server" test "$(from_inet http://203.0.113.20/)" = sjb-nat-gate
src=$(outbound_source)
check "bidirectional off: outbound leaves from the outside address (seen: $src)" test "$src" = 203.0.113.1

# 5. Removing the static entry removes its address.
commit "$(config fwd2 "$NAT_FWD" "$RULES_OUT" "$RULE_IN")" "remove static NAT"
sleep 1
check "static entry removed: 203.0.113.20 is off veth-inet" bash -c '! ip -n ngfw-fw -4 addr show dev veth-inet | grep -q 203.0.113.20'
check "203.0.113.20 no longer answers" test -z "$(from_inet http://203.0.113.20/)"
check "the interface's own address is untouched" bash -c 'ip -n ngfw-fw -4 addr show dev veth-inet | grep -q "203.0.113.1/24"'

echo
if (( FAILS > 0 )); then echo "NAT GATE: $FAILS check(s) failed"; exit 1; fi
echo "NAT GATE: all checks passed"
