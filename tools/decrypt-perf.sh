#!/usr/bin/env bash
# TLS decryption throughput, measured in the namespace lab: one HTTPS
# download (SIZE MB, default 200) and PARALLEL concurrent ones (default 8),
# straight through (no decryption rule), through tlsd in observe mode, and
# decrypted; plus tlsd's memory. Development tooling, not shipped: the
# numbers describe the machine it runs on, not a VMware VM; run it on a
# Linux host (or in a privileged container) like the lab gates.
#
# Needs root, nft, conntrack, openssl, curl, python3 and nsenter. Binaries
# from $BIN (./bin).
#   tools/decrypt-perf.sh [SIZE-MB] [PARALLEL]
set -uo pipefail
BIN=${BIN:-./bin}
SIZE=${1:-200}
PAR=${2:-8}
WORK=$(mktemp -d)
SOCK=$WORK/ngfwd.sock
PIDS=()
cleanup() {
	for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	nsenter --net=/run/netns/ngfw-fw ./deploy/appliance/rootfs/usr/local/sbin/sjb-decrypt-net down >/dev/null 2>&1
	./lab/topology.sh down >/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT
fw() { "$BIN/fwctl" -socket "$SOCK" "$@"; }

id sjb-tls >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sjb-tls
./lab/topology.sh up >/dev/null
nsenter --net=/run/netns/ngfw-fw ./deploy/appliance/rootfs/usr/local/sbin/sjb-decrypt-net up >/dev/null

cd "$WORK"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -subj "/CN=Perf Root" -days 2 \
	-addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -out ca.crt 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout srv.key -subj "/CN=perf.example" -out srv.csr 2>/dev/null
printf 'subjectAltName=DNS:perf.example\n' >srv.ext
openssl x509 -req -in srv.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile srv.ext -out srv.crt 2>/dev/null
mkdir www && head -c $((SIZE << 20)) /dev/urandom >www/blob
cd - >/dev/null
# A threaded HTTPS file server (python; its own speed is part of every row).
cat >"$WORK/srv.py" <<'EOF'
import http.server, socketserver, ssl, sys, os
os.chdir(sys.argv[1] + "/www")
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(sys.argv[1] + "/srv.crt", sys.argv[1] + "/srv.key")
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True; allow_reuse_address = True
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
s = S(("0.0.0.0", 443), H); s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
EOF
ip netns exec ngfw-inet python3 "$WORK/srv.py" "$WORK" >/dev/null 2>&1 &
PIDS+=($!)

ip netns exec ngfw-fw "$BIN/ngfwd" -state "$WORK/state" -socket "$SOCK" -ips-dir "" -frr "" -kea "" -ip "" \
	-tlsd "$BIN/tlsd" -decryption-ca "$WORK/sjbca" -decryption-policy "$WORK/policy.json" -tlsd-socket "$WORK/tlsd.sock" >"$WORK/ngfwd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do fw status >/dev/null 2>&1 && break; sleep 0.1; done
nsenter --net=/run/netns/ngfw-fw env SSL_CERT_FILE="$WORK/ca.crt" "$BIN/tlsd" -policy "$WORK/policy.json" -ca "$WORK/sjbca" \
	-learned "$WORK/learned.json" -status "$WORK/tlsd.sock" -builtin /dev/null >"$WORK/tlsd.log" 2>&1 &
TLSD=$!
PIDS+=($TLSD)

config() { # config off|observe|on
	cat >"$WORK/fw.yaml" <<EOF
system:
  hostname: perf
  decryption: "$1"
zones: [{name: users}, {name: internet}]
interfaces:
  - {name: veth-users, zone: users, address: 10.10.1.1/24}
  - {name: veth-inet, zone: internet, address: 203.0.113.1/24}
services: [{name: https, protocol: tcp, ports: "443"}]
decryption_rules: [{name: all, from: [users], to: [internet], service: [https], action: decrypt}]
rules: [{name: web, from: [users], to: [internet], service: [https], action: allow}]
EOF
	fw load "$WORK/fw.yaml" >/dev/null && fw commit -m "$1" >/dev/null
	sleep 3
}
config off
fw shell -c "request decryption ca generate" >/dev/null
fw shell -c "show decryption ca" | sed -n '/BEGIN CERT/,/END CERT/p' >"$WORK/sjbca.pem"
cat "$WORK/ca.crt" "$WORK/sjbca.pem" >"$WORK/trust.pem"

get() { # one download; prints Mbit/s
	ip netns exec ngfw-users curl -s --cacert "$WORK/trust.pem" --resolve perf.example:443:203.0.113.10 \
		-o /dev/null -w '%{speed_download}\n' https://perf.example/blob | awk '{printf "%.0f", $1 * 8 / 1e6}'
}
many() { # PAR concurrent downloads; prints aggregate Mbit/s
	local t0 t1 pids=()
	t0=$(date +%s.%N)
	for _ in $(seq "$PAR"); do
		ip netns exec ngfw-users curl -s --cacert "$WORK/trust.pem" --resolve perf.example:443:203.0.113.10 -o /dev/null https://perf.example/blob &
		pids+=($!)
	done
	wait "${pids[@]}"
	t1=$(date +%s.%N)
	awk -v s="$SIZE" -v n="$PAR" -v a="$t0" -v b="$t1" 'BEGIN {printf "%.0f", s * n * 8 * 1.048576 / (b - a)}'
}
rss() { awk '/VmHWM/ {printf "%.0f", $2 / 1024}' /proc/$TLSD/status; }

printf '%-34s %12s %16s\n' "path" "1 download" "$PAR at once"
printf '%-34s %12s %16s\n' "----" "----------" "-----------"
for mode in off observe on; do
	config "$mode"
	label=$([[ $mode == off ]] && echo "straight through (no decryption)" || ([[ $mode == observe ]] && echo "through tlsd, observe" || echo "decrypted"))
	one=$(get)
	all=$(many)
	printf '%-34s %8s Mbit/s %12s Mbit/s\n' "$label" "$one" "$all"
done
echo
echo "tlsd peak memory: $(rss) MB; cores: $(nproc); $(uname -m)"
echo "tlsd's decisions: $(grep -o '"decision":"[a-z-]*"' "$WORK/tlsd.log" | sort | uniq -c | tr -s ' ' | tr '\n' ',')"
