#!/usr/bin/env bash
# Log forwarding gate: ngfwd sends the logs to syslog servers in the
# internet namespace (UDP, TCP and TLS) and keeps its place in the journal.
# With test country and AS databases, entries carry the destination's
# country and AS, forwarded (JSON, CEF) and in the Logs views.
#   - each server gets the log types it asks for, RFC 5424 framed, in JSON
#     or CEF; TLS checks the server's certificate against the configured CA
#   - a server in the (missing) management VRF shows an error, not a hang
#   - records written while ngfwd is down arrive after it restarts (the
#     TLS connection too: ngfwd connects after its start-up conntrack flush)
#   - forwarding survives a policy commit's conntrack flush
#   - a test message reaches a server; removing the servers stops forwarding
#   - a config backup made with the CLI restores to the same config
# The lab has no journal: lab/fake-journalctl.py replays $LOGFWD_FEED.
# Linux only; needs root, python3 and openssl. Binaries from $BIN (./bin).
set -uo pipefail

BIN=${BIN:-./bin}
WORK=$(mktemp -d)
chmod 755 "$WORK"
SOCK=$WORK/ngfwd.sock
FAILS=0
PIDS=()
NGFWD=
export LOGFWD_FEED=$WORK/feed.jsonl
SINK=$WORK/sink
mkdir -p "$SINK"

cleanup() {
	for p in "${PIDS[@]}" $NGFWD; do kill "$p" 2>/dev/null; done
	wait 2>/dev/null
	./lab/topology.sh down >/dev/null
	(( FAILS > 0 )) && { echo "--- ngfwd log ---"; cat "$WORK/ngfwd.log" 2>/dev/null; for f in "$SINK"/*.log; do echo "--- $f ---"; cat "$f"; done; }
	rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
check() { local d=$1; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
fw() { "$BIN/fwctl" -socket "$SOCK" "$@"; }
commit() { fw load "$1" >/dev/null && fw commit -m "$2" >/dev/null 2>&1 || fail "commit $2"; }
lines() { local c; c=$(grep -c -- "$2" "$SINK/$1.log" 2>/dev/null); echo "${c:-0}"; }
wait_for() { # wait_for FILE PATTERN COUNT
	for _ in $(seq 50); do (( $(lines "$1" "$2") >= $3 )) && return 0; sleep 0.1; done
	return 1
}
n=0
record() { # record JSON-FIELDS: appends a journal record with a fresh cursor
	n=$((n + 1))
	printf '{"__CURSOR":"c%d","__REALTIME_TIMESTAMP":"%d000000",%s}\n' "$n" "$(date +%s)" "$1" >>"$LOGFWD_FEED"
}
start_ngfwd() {
	ip netns exec ngfw-fw "$BIN/ngfwd" -state "$WORK/state" -socket "$SOCK" -users "$WORK/users.json" -roles "$WORK/roles.json" \
		-web-users "$WORK/web-users" -unix-accounts=false -ips-dir "" -journalctl "$PWD/lab/fake-journalctl.py" \
		-root "$WORK/root" -geoip-dir "$WORK/geoip" >>"$WORK/ngfwd.log" 2>&1 &
	NGFWD=$!
	for _ in $(seq 50); do fw status >/dev/null 2>&1 && break; sleep 0.1; done
}

# --- the syslog servers --------------------------------------------------------
(cd "$WORK" && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ca.key -out ca.crt \
	-subj "/CN=lab log CA" -days 2 2>/dev/null &&
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout siem.key -out siem.csr -subj "/CN=siem.lab" 2>/dev/null &&
	printf 'subjectAltName=DNS:siem.lab\nextendedKeyUsage=serverAuth\n' >ext &&
	openssl x509 -req -in siem.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile ext -out siem.crt 2>/dev/null) ||
	{ echo "openssl failed"; exit 1; }
./lab/topology.sh up >/dev/null
ip netns exec ngfw-inet python3 -I "$PWD/lab/syslog-sink.py" "$SINK" 5514 5515 6514 "$WORK/siem.crt" "$WORK/siem.key" &
PIDS+=($!)
sleep 0.5

{
	cat <<'EOF2'
system:
  hostname: fw-lab
zones:
  - name: users
  - name: internet
interfaces:
  - name: veth-users
    zone: users
  - name: veth-inet
    zone: internet
rules:
  - name: web-out
    from: [users]
    to: [internet]
    action: allow
log_servers:
  - name: all-udp
    address: 203.0.113.10
    port: 5514
    transport: udp
    vrf: default
  - name: threats-cef
    address: 203.0.113.10
    port: 5515
    transport: tcp
    format: cef
    types: [threat]
    vrf: default
  - name: system-tls
    address: 203.0.113.10
    transport: tls
    types: [system]
    vrf: default
    server_name: siem.lab
    ca: |
EOF2
	sed 's/^/      /' "$WORK/ca.crt"
	cat <<'EOF2'
  - name: mgmt-only
    address: 192.0.2.99
    transport: udp
EOF2
} >"$WORK/fwd.yaml"
sed '/^log_servers:/,$d' "$WORK/fwd.yaml" >"$WORK/none.yaml"

# --- run ----------------------------------------------------------------------
start_ngfwd
commit "$WORK/fwd.yaml" "four log servers"
# Test country and AS databases: the internet side is CN, AS4134.
printf '203.0.113.0,203.0.113.255,CN\n' >"$WORK/geo.csv"
printf '203.0.113.0,203.0.113.255,4134,"Lab Telecom"\n' >"$WORK/asn.csv"
fw geoip import "$WORK/geo.csv" >/dev/null && fw geoip import "$WORK/asn.csv" >/dev/null || fail "geoip import"
sleep 1
record '"_TRANSPORT":"kernel","MESSAGE":"ngfw web-out allow IN=veth-users OUT=veth-inet SRC=10.10.1.10 DST=203.0.113.10 LEN=60 TTL=64 PROTO=TCP SPT=40000 DPT=443 SYN"'
record '"_SYSTEMD_UNIT":"ngfwd.service","MESSAGE":"ngfw-threat {\"rule\":\"web-out\",\"profile\":\"default\",\"action\":\"block\",\"severity\":\"critical\",\"sid\":9900001,\"signature\":\"SJB-OS test signature\",\"proto\":\"tcp\",\"src\":\"10.10.1.10\",\"dst\":\"203.0.113.10\"}"'
record '"_SYSTEMD_UNIT":"sjb-tlsd.service","MESSAGE":"ngfw-decrypt {\"rule\":\"d1\",\"decision\":\"decrypted\",\"server_name\":\"example.com\",\"src\":\"10.10.1.10\",\"dst\":\"203.0.113.10\"}"'
record '"_SYSTEMD_UNIT":"ngfwd.service","MESSAGE":"time=x level=INFO msg=\"gate system line\" by=gate"'
record '"_TRANSPORT":"kernel","MESSAGE":"e1000: unrelated kernel line"'

check "udp, all logs: traffic, threat, decryption and system arrive" bash -c "
	$(declare -f lines wait_for); SINK=$SINK
	wait_for udp ' TRAFFIC - {\"log\":\"traffic\"' 1 && wait_for udp ' THREAT - ' 1 && wait_for udp ' DECRYPT - ' 1 && wait_for udp 'gate system line' 1"
check "udp: RFC 5424 header (local0.info traffic: <134>1, app sjb-os, MSGID TRAFFIC)" grep -q '^<134>1 [0-9T:.Z-]* [^ ]* sjb-os - TRAFFIC - ' "$SINK/udp.log"
check "udp: traffic entries get zones" grep -q '"from":"users","to":"internet"' "$SINK/udp.log"
check "udp: unrelated kernel lines are not forwarded" bash -c "! grep -q e1000 $SINK/udp.log"
check "udp JSON: the destination's country and AS, none for the private source" bash -c "
	grep TRAFFIC $SINK/udp.log | grep -q '\"dst_country\":\"CN\",\"dst_asn\":4134,\"dst_as_org\":\"Lab Telecom\"' && ! grep TRAFFIC $SINK/udp.log | grep -q src_country"
check "tcp, CEF, threats only: one CEF threat, octet-counted" bash -c "
	$(declare -f lines wait_for); SINK=$SINK
	wait_for tcp 'CEF:0|SJB Consulting|SJB-OS|[^|]*|9900001|SJB-OS test signature|10|' 1 && (( \$(wc -l <$SINK/tcp.log) == 1 ))"
check "CEF: sjbDstCountry, sjbDstAsn and sjbDstAsOrg on the threat" grep -q 'sjbDstCountry=CN sjbDstAsn=4134 sjbDstAsOrg=Lab Telecom' "$SINK/tcp.log"
lv=$(fw shell <<<"show log traffic columns src,dst,dst_country,dst_asn where dst_country = CN" 2>&1)
check "show log traffic where dst_country = CN: the entry, with AS4134 Lab Telecom" grep -q '203.0.113.10 .*CN .*AS4134 Lab Telecom' <<<"$lv"
fw shell <<<"show log traffic where src_country = CN" >"$WORK/lv2.txt" 2>&1
check "show log traffic where src_country = CN: nothing (the source is private)" bash -c "! grep -q 203.0.113.10 $WORK/lv2.txt"
check "show log threat where asn = 4134 and org ~ lab: the threat" grep -q 9900001 <<<"$(fw shell <<<'show log threat where asn = 4134 and org ~ lab' 2>&1)"
check "tls with the lab CA: system lines only" bash -c "
	$(declare -f lines wait_for); SINK=$SINK
	wait_for tls 'gate system line' 1 && ! grep -q -e TRAFFIC -e THREAT $SINK/tls.log"
st=$(fw shell <<<"show log-forwarding" 2>&1)
check "show log-forwarding: the udp server sent 4+" bash -c "grep -E '^all-udp .* connected .* ([4-9]|[1-9][0-9]+) ' <<<'$st' >/dev/null"
check "show log-forwarding: a server in the missing management VRF shows its error" bash -c "grep -q 'mgmt-only: last error' <<<'$st'"

# Records written while ngfwd is down arrive after it restarts.
sleep 1.5 # the journal position is saved every second
kill $NGFWD; wait $NGFWD 2>/dev/null
record '"_SYSTEMD_UNIT":"ssh.service","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"written while ngfwd was down"'
start_ngfwd
check "restart: the record written while ngfwd was down arrives (journal cursor kept)" bash -c "
	$(declare -f lines wait_for); SINK=$SINK; wait_for udp 'written while ngfwd was down' 1"
check "restart: nothing is sent twice" bash -c "(( \$(grep -c 'gate system line' $SINK/udp.log) == 1 ))"

fw shell <<<"request log-forwarding test system-tls" >/dev/null 2>&1
check "request log-forwarding test reaches the TLS server" bash -c "
	$(declare -f lines wait_for); SINK=$SINK; wait_for tls 'border check passed' 1"

# A commit that changes the policy flushes conntrack: the TLS connection
# keeps delivering (conntrack picks it up again from the firewall's side).
sed 's/  - name: web-out/  - name: web-out2/' "$WORK/fwd.yaml" >"$WORK/fwd2.yaml"
commit "$WORK/fwd2.yaml" "policy change"
record '"_SYSTEMD_UNIT":"ngfwd.service","MESSAGE":"time=x level=INFO msg=\"after the policy change\""'
check "policy change (conntrack flushed): the TLS server still gets system lines" bash -c "
	$(declare -f lines wait_for); SINK=$SINK; wait_for tls 'after the policy change' 1"

# A wrong CA: the TLS server is refused.
sed -i 's/server_name: siem.lab/server_name: other.lab/' "$WORK/fwd.yaml"
commit "$WORK/fwd.yaml" "wrong server name"
record '"_SYSTEMD_UNIT":"ngfwd.service","MESSAGE":"time=x level=INFO msg=\"after the name change\""'
sleep 2
check "tls: a certificate for another name is refused (nothing delivered, error shown)" bash -c "
	! grep -q 'after the name change' $SINK/tls.log && fw() { \"$BIN/fwctl\" -socket \"$SOCK\" \"\$@\"; }; fw shell <<<'show log-forwarding' | grep -q 'system-tls: last error.*certificate'"

# Backup round trip through the CLI.
fw shell <<<"request backup export" 2>/dev/null | sed 's/^.*> //' | sed -n '/^SJB-OS backup/,/END SJB-OS/p' >"$WORK/backup.txt"
check "request backup export prints an armoured backup" grep -q -- '-----END SJB-OS BACKUP-----' "$WORK/backup.txt"
out=$( { echo "request backup restore"; cat "$WORK/backup.txt"; } | fw shell 2>&1)
check "request backup restore of the running config: nothing to commit" grep -q "same as the running config" <<<"$out"

# Removing the servers stops forwarding.
commit "$WORK/none.yaml" "no log servers"
before=$(cat "$SINK"/udp.log | wc -l)
record '"_SYSTEMD_UNIT":"ngfwd.service","MESSAGE":"time=x level=INFO msg=\"after removal\""'
sleep 1
check "no servers: nothing more is sent" bash -c "(( \$(cat $SINK/udp.log | wc -l) == $before ))"
check "no servers: show log-forwarding says so" bash -c "fw() { \"$BIN/fwctl\" -socket \"$SOCK\" \"\$@\"; }; fw shell <<<'show log-forwarding' | grep -q 'no log servers'"

echo
if (( FAILS > 0 )); then echo "LOG FORWARDING GATE: $FAILS check(s) failed"; exit 1; fi
echo "LOG FORWARDING GATE: all checks passed"
