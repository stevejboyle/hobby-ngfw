#!/usr/bin/env bash
# policy-test.sh: check that SJB-OS enforces the best-practice policy
# (examples/best-practice.yaml), from a Linux client VM in the inside zone.
# One file; copy it to the VM and run it.
#
#   ./policy-test.sh                         everything
#   ./policy-test.sh -D 192.168.1.97,192.168.1.98
#                                            your approved DNS resolvers (default:
#                                            the template's Quad9 and Cloudflare ones)
#   ./policy-test.sh -L 192.168.1.1          a LAN host with an HTTPS page that a
#                                            no-decrypt rule covers: checks it isn't
#                                            decrypted
#   ./policy-test.sh -x bank.example         also check NAME (one of your own
#                                            exclusions) isn't decrypted; repeat
#   ./policy-test.sh -C ca.crt               the decryption CA, to recognise an
#                                            imported one
#   ./policy-test.sh -I 198.51.100.7:443     inbound only, from a client OUTSIDE
#                                            the firewall: a published server
#                                            (port forward) answers on its public
#                                            address and port, and nothing else on
#                                            that address does; repeat for more
#   ./policy-test.sh -l                      list the checks, send nothing
#
# What it checks, each against a working control so a failure is evidence:
#   - allowed: web, DNS to the approved resolvers, NTP, mail submission and
#     IMAPS, ping
#   - the outbound allow-list: other TCP ports stay closed, tested against
#     portquiz.net, which answers on every port (a connection there is a hole
#     in the policy, not a down server); DNS to other resolvers and DNS over
#     TLS don't get through
#   - risky applications on allowed ports: DNS over HTTPS, VPN and remote-
#     control vendors (reported, not failed, when they get through: App
#     Identification names these by their own traffic, which a test can only
#     approximate)
#   - the IPS: SJB-OS's test signatures over HTTP, and over HTTPS once
#     decrypted
#   - TLS decryption: ordinary sites decrypted, excluded ones not, bad
#     certificates blocked, QUIC blocked
#
# Not checked from here: inbound (run again with -I from a client outside) and
# quarantine (tag this VM with the tag API, run again: everything should
# fail; untag it afterwards).
#
# Results: ok, FAIL (the policy isn't doing what it should), skip (couldn't
# tell; the note says what to look at). Exit status is non-zero when
# anything failed. Afterwards: 'show log traffic', 'show log threat' and
# 'show log decryption' on the firewall show each decision.
#
# Everything is IPv4: SJB-OS is IPv4-only, so a client's IPv6 would go
# around it. Needs bash, curl, openssl, awk and timeout. dig (or python3) for DNS, python3
# for NTP, ping for ICMP; their checks are skipped when missing.
set -u

DNS_OK="9.9.9.9,149.112.112.112,1.1.1.2,1.0.0.2"
LAN_HOST="" CA_FILE="" LIST=0
EXTRA_EXCL=()
INBOUND=()
while getopts "D:L:x:C:I:lh" o; do
	case $o in
	D) DNS_OK=$OPTARG ;;
	L) LAN_HOST=$OPTARG ;;
	x) EXTRA_EXCL+=("$OPTARG") ;;
	C) CA_FILE=$OPTARG ;;
	I) INBOUND+=("$OPTARG") ;;
	l) LIST=1 ;;
	*) sed -n '2,51p' "$0"; exit 0 ;;
	esac
done
IFS=',' read -r -a RESOLVERS <<<"$DNS_OK"
[[ -z $CA_FILE && -r /usr/local/share/ca-certificates/sjb-os-decryption-ca.crt ]] &&
	CA_FILE=/usr/local/share/ca-certificates/sjb-os-decryption-ca.crt

# Ports the allow-list must keep closed (allowed: 80, 443, 53, 123, 465, 587, 993).
BLOCKED_PORTS=(22 23 25 110 143 445 1433 3306 3389 5900 6667 8080 8443)
OTHER_RESOLVERS=(8.8.8.8 1.1.1.1)
DECRYPT_SITES=(www.example.com en.wikipedia.org github.com)
# Built-in exclusions and the template's own.
EXCLUDED_SITES=(www.chase.com www.irs.gov www.apple.com login.microsoftonline.com www.zoom.us www.dropbox.com accounts.google.com)
BAD_CERT_SITES=(expired.badssl.com self-signed.badssl.com wrong.host.badssl.com)
RISKY_SITES=("NordVPN|https://nordvpn.com/" "Psiphon|https://psiphon.ca/" "TeamViewer|https://www.teamviewer.com/" "AnyDesk|https://anydesk.com/")

# Ports a published address must not answer on (besides its own port).
INBOUND_CLOSED=(22 23 445 3389 8080)

if [[ $LIST == 1 && ${#INBOUND[@]} -gt 0 ]]; then
	echo "inbound, from outside: each of ${INBOUND[*]} answers; TCP ${INBOUND_CLOSED[*]} and the next port up don't"
	exit 0
fi
if [[ $LIST == 1 ]]; then
	echo "allowed: http/https, DNS to ${RESOLVERS[*]}, NTP (pool.ntp.org), SMTP 587 and 465, IMAPS 993, ping 1.1.1.1"
	echo "allow-list, must stay closed: TCP ${BLOCKED_PORTS[*]} (portquiz.net); DNS to ${OTHER_RESOLVERS[*]}; DNS over TLS (1.1.1.1:853)"
	echo "risky applications: DNS over HTTPS (cloudflare-dns.com, dns.google); ${RISKY_SITES[*]%%|*}"
	echo "IPS: SJB-IPS-TEST-CRITICAL and -MINOR over HTTP and (decrypted) HTTPS"
	echo "decryption: decrypted ${DECRYPT_SITES[*]}; not decrypted ${EXCLUDED_SITES[*]} ${EXTRA_EXCL[*]} ${LAN_HOST}"
	echo "  bad certificates blocked: ${BAD_CERT_SITES[*]}; QUIC blocked"
	exit 0
fi

have() { command -v "$1" >/dev/null 2>&1; }
for t in curl openssl timeout; do have "$t" || { echo "needs $t" >&2; exit 2; }; done
PY=$(command -v python3 || true)
UA="Mozilla/5.0 (X11; Linux x86_64) sjb-policy-test"

ok=0 bad=0 skip=0
result() { # name status detail
	case $2 in
	ok) ok=$((ok + 1)); printf '  %-38s %-5s %s\n' "$1" ok "$3" ;;
	skip) skip=$((skip + 1)); printf '  %-38s %-5s %s\n' "$1" skip "$3" ;;
	*) bad=$((bad + 1)); printf '  %-38s %-5s %s\n' "$1" FAIL "$3" ;;
	esac
}

# http_code URL [curl args]: prints the HTTP status; returns curl's exit code.
http_code() {
	local url=$1; shift
	curl -4 -s -o /dev/null -m 10 -A "$UA" -w '%{http_code}' "$@" "$url" 2>/dev/null
}
answered() { [[ $1 =~ ^[1-5][0-9][0-9]$ ]]; }

# tcp HOST PORT: open, refused (reset) or timeout (dropped). curl reports
# whether the TCP connection opened, even when what answers isn't HTTP.
tcp() {
	local t rc
	t=$(curl -4 -s -o /dev/null --connect-timeout 5 -m 6 -w '%{time_connect}' "http://$1:$2/" 2>/dev/null)
	rc=$?
	if awk -v t="${t:-0}" 'BEGIN { exit !(t > 0) }'; then echo open
	elif [[ $rc == 7 ]]; then echo refused
	else echo timeout; fi
}

# dnsq SERVER NAME: answer, none or skip.
dnsq() {
	if have dig; then
		# +short still prints ";;" error lines (refused, unreachable, timed
		# out) on stdout: an answer needs exit 0 and a line that isn't one.
		local out
		if out=$(dig -4 +time=3 +tries=1 +short @"$1" "$2" A 2>/dev/null) && grep -qv '^;' <<<"$out"; then echo answer; else echo none; fi
	elif [[ -n $PY ]]; then
		"$PY" - "$1" "$2" 2>/dev/null <<'EOF' && echo answer || echo none
import os, socket, struct, sys
server, name = sys.argv[1], sys.argv[2]
q = struct.pack("!HHHHHH", int.from_bytes(os.urandom(2), "big"), 0x0100, 1, 0, 0, 0)
q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, (server, 53)); r = s.recvfrom(512)[0]
sys.exit(0 if struct.unpack("!H", r[6:8])[0] > 0 else 1)
EOF
	else
		echo skip
	fi
}

# ---------------------------------------------------------------- inbound (-I)
# Run from outside: published servers answer on their public address and
# port; nothing else on that address gets through (default deny inbound).
if [[ ${#INBOUND[@]} -gt 0 ]]; then
	echo "inbound (published servers):"
	for hp in "${INBOUND[@]}"; do
		ip=${hp%:*} port=${hp##*:}
		if [[ ! $ip =~ ^[0-9.]+$ || ! $port =~ ^[0-9]+$ ]]; then
			echo "-I wants ADDRESS:PORT, got $hp" >&2; exit 2
		fi
		st=$(tcp "$ip" "$port")
		if [[ $st == open ]]; then result "published $ip:$port" ok "answers"
		else result "published $ip:$port" FAIL "$st: check the port forward, the allow rule (it names the server's inside address) and the server itself"; fi
		for p in "${INBOUND_CLOSED[@]}" $((port + 1)); do
			[[ $p == "$port" ]] && continue
			st=$(tcp "$ip" "$p")
			if [[ $st == open ]]; then result "closed $ip:$p" FAIL "open: something besides the published port gets in"
			else result "closed $ip:$p" ok "$st"; fi
		done
	done
	echo
	echo "done: $ok ok, $bad failed, $skip skipped"
	echo "On the firewall: 'show nat' (connections per entry), 'show log traffic'."
	((bad == 0))
	exit
fi

# ---------------------------------------------------------------- TLS helpers

CA_SUBJECT=""
[[ -n $CA_FILE ]] && CA_SUBJECT=$(openssl x509 -in "$CA_FILE" -noout -subject 2>/dev/null | sed 's/^subject= *//')

# peer HOST[:PORT] [SNI|-]: one handshake; sets P_ISSUER. 1 when no certificate came back.
peer() {
	local sni=${2:-${1%:*}} out cert target=$1
	[[ $target == *:* ]] || target=$target:443
	local -a sn=(-servername "$sni")
	[[ $sni == - ]] && sn=(-noservername)
	P_ISSUER=""
	out=$(timeout 12 openssl s_client -4 -connect "$target" "${sn[@]}" </dev/null 2>/dev/null)
	cert=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' <<<"$out")
	[[ -n $cert ]] || return 1
	P_ISSUER=$(openssl x509 -noout -issuer <<<"$cert" 2>/dev/null | sed 's/^issuer= *//')
}
kind() {
	case $1 in
	*"SJB-OS Untrusted"*) echo untrusted ;;
	*"SJB-OS Decryption CA"*) echo ours ;;
	*) if [[ -n $CA_SUBJECT && $1 == "$CA_SUBJECT" ]]; then echo ours; else echo real; fi ;;
	esac
}
cn() { sed -n 's/.*CN *= *\([^,/]*\).*/\1/p' <<<"$1" | head -1; }

# ---------------------------------------------------------------- checks

DECRYPTING=no
CONTROL=no

setup() {
	local code rc
	code=$(http_code https://www.example.com/); rc=$?
	if answered "$code"; then CONTROL=yes; result "control: HTTPS to www.example.com" ok "HTTP $code"
	elif [[ $rc == 60 ]]; then result "control: HTTPS to www.example.com" FAIL "certificate not trusted: install the decryption CA on this VM"
	else result "control: HTTPS to www.example.com" FAIL "curl $rc: no web access, most checks below are inconclusive"; fi
	if peer www.example.com; then
		if [[ $(kind "$P_ISSUER") == ours ]]; then DECRYPTING=yes; result "decryption is on" ok "issuer: $(cn "$P_ISSUER")"
		else result "decryption is on" FAIL "not decrypted (issuer: $(cn "$P_ISSUER")): check the decryption rule covers this VM and system decryption is on"; fi
	else
		result "decryption is on" skip "no TLS answer from www.example.com"
	fi
}

allowed() {
	local code r h
	code=$(http_code http://example.com/); answered "$code" && result "web: HTTP" ok "HTTP $code" || result "web: HTTP" FAIL "no answer from http://example.com/"
	code=$(http_code https://en.wikipedia.org/); answered "$code" && result "web: HTTPS" ok "HTTP $code" || result "web: HTTPS" FAIL "no answer from https://en.wikipedia.org/"
	for h in "${RESOLVERS[@]}"; do
		r=$(dnsq "$h" example.com)
		case $r in answer) result "DNS to approved $h" ok "answered" ;; skip) result "DNS" skip "no dig or python3"; break ;; *) result "DNS to approved $h" FAIL "no answer: approved resolvers must work (-D to set yours)" ;; esac
	done
	if [[ -n $PY ]]; then
		"$PY" - 2>/dev/null <<'EOF' && result "NTP (pool.ntp.org)" ok "answered" || result "NTP (pool.ntp.org)" FAIL "no answer"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(b"\x1b" + 47 * b"\0", ("pool.ntp.org", 123)); s.recvfrom(64)
EOF
	else
		result "NTP" skip "no python3"
	fi
	if [[ $(tcp smtp.gmail.com 587) == open ]]; then result "mail submission (smtp.gmail.com:587)" ok "connects"
	else result "mail submission (smtp.gmail.com:587)" FAIL "no connection"; fi
	peer smtp.gmail.com:465 && result "mail submission (smtp.gmail.com:465)" ok "TLS handshake" || result "mail submission (smtp.gmail.com:465)" FAIL "no TLS answer"
	peer imap.gmail.com:993 && result "IMAPS (imap.gmail.com:993)" ok "TLS handshake" || result "IMAPS (imap.gmail.com:993)" FAIL "no TLS answer"
	if have ping; then
		ping -4 -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 || ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1 && result "ping 1.1.1.1" ok "replies" || result "ping 1.1.1.1" FAIL "no reply"
	else
		result "ping" skip "no ping"
	fi
}

allow_list() {
	local p s r anyok=no
	# portquiz.net answers on every TCP port: a connection that fails on a
	# blocked port, while port 80 works, was stopped by the firewall.
	if [[ $(tcp portquiz.net 80) != open ]]; then
		result "TCP allow-list (portquiz.net)" skip "control port 80 unreachable; can't test other ports"
	else
		for p in "${BLOCKED_PORTS[@]}"; do
			s=$(tcp portquiz.net "$p")
			case $s in
			open) result "TCP $p closed" FAIL "OPEN: the policy lets port $p out" ;;
			timeout) result "TCP $p closed" ok "dropped" ;;
			*) result "TCP $p closed" ok "reset" ;;
			esac
		done
	fi
	for p in "${RESOLVERS[@]}"; do [[ $(dnsq "$p" example.com) == answer ]] && anyok=yes; done
	for r in "${OTHER_RESOLVERS[@]}"; do
		if [[ $anyok != yes ]]; then result "DNS to $r blocked" skip "no approved resolver answers either; inconclusive"; continue; fi
		case $(dnsq "$r" example.com) in
		answer) result "DNS to $r blocked" FAIL "ANSWERED: DNS gets around the approved resolvers" ;;
		skip) result "DNS to $r blocked" skip "no dig or python3" ;;
		*) result "DNS to $r blocked" ok "no answer, approved resolvers work" ;;
		esac
	done
	if [[ $CONTROL != yes ]]; then
		result "DNS over TLS (1.1.1.1:853) blocked" skip "HTTPS control failed; inconclusive"
	else
		case $(tcp 1.1.1.1 853) in
		open) result "DNS over TLS (1.1.1.1:853) blocked" FAIL "OPEN: encrypted DNS gets around the approved resolvers" ;;
		*) result "DNS over TLS (1.1.1.1:853) blocked" ok "no connection, other HTTPS works" ;;
		esac
	fi
}

# curl_why RC: what a curl exit status means, for notes.
curl_why() {
	case $1 in
	0) echo "finished without an HTTP status" ;;
	2 | 48) echo "this curl lacks an option the check needs" ;;
	3) echo "malformed URL" ;;
	5 | 6) echo "couldn't resolve the name" ;;
	7) echo "connection refused" ;;
	28) echo "timed out" ;;
	35) echo "TLS handshake failed" ;;
	52) echo "empty reply" ;;
	55 | 56) echo "connection reset" ;;
	58 | 59 | 77) echo "local TLS setup failed" ;;
	60) echo "certificate not trusted" ;;
	*) echo "curl error" ;;
	esac
}
# fw_stopped RC: curl's exit looks like the firewall cutting the connection
# (refused, dropped, or reset during the handshake or the request). Name
# lookups, certificates, missing options and other local or request errors
# say nothing about the policy.
fw_stopped() { case $1 in 7 | 28 | 35 | 52 | 55 | 56) return 0 ;; *) return 1 ;; esac; }

# risky_check LABEL doh|site URL [curl args]: a DoH query must not be
# answered (FAIL if it is). A vendor's website is only the vendor's site,
# not its app's traffic, so its being reachable is a skip. Only a failure
# that looks like the firewall cutting the connection counts as ok, and
# even then the traffic log is what says which rule did it.
risky_check() {
	local label=$1 what=$2 url=$3 code rc; shift 3
	code=$(http_code "$url" "$@"); rc=$?
	if answered "$code"; then
		if [[ $what == doh ]]; then result "$label" FAIL "ANSWERED (HTTP $code): encrypted DNS gets around the approved resolvers"
		else result "$label" skip "reachable (HTTP $code): the block applies to the app's own traffic; check 'show app'"; fi
	elif fw_stopped "$rc"; then
		result "$label" ok "stopped (curl $rc, $(curl_why "$rc")), other HTTPS works; traffic log should show block-risky-apps"
	else
		result "$label" skip "curl $rc ($(curl_why "$rc")): not a sign of a firewall block; inconclusive"
	fi
}

risky() {
	local name url e
	if [[ $CONTROL != yes ]]; then result "risky applications" skip "HTTPS control failed; inconclusive"; return; fi
	risky_check "DNS over HTTPS (Cloudflare) blocked" doh "https://cloudflare-dns.com/dns-query?name=example.com&type=A" -H "accept: application/dns-json"
	risky_check "DNS over HTTPS (Google) blocked" doh "https://dns.google/resolve?name=example.com&type=A"
	for e in "${RISKY_SITES[@]}"; do
		name=${e%%|*} url=${e#*|}
		risky_check "$name site" site "$url"
	done
}

# ips_block LABEL URL: a request carrying a critical test string must fail
# while the same site works before and after.
ips_block() {
	local label=$1 url=$2 base=${2%/*}/ code rc before after
	before=$(http_code "$base")
	if ! answered "$before"; then result "$label" skip "control $base failed; inconclusive"; return; fi
	code=$(http_code "$url"); rc=$?
	if answered "$code"; then result "$label" FAIL "passed (HTTP $code): is there an IPS profile on the allow rule?"; return; fi
	after=$(http_code "$base")
	case $rc in
	28 | 52 | 55 | 56)
		if answered "$after"; then result "$label" ok "blocked (curl $rc), controls fine; threat log should show SID 9900001"
		else result "$label" skip "control failed afterwards; inconclusive"; fi ;;
	*) result "$label" skip "curl $rc: not the signature of an IPS drop; check the threat log" ;;
	esac
}

ips() {
	local code
	ips_block "IPS over HTTP, critical" "http://example.com/SJB-IPS-TEST-CRITICAL"
	code=$(http_code http://example.com/SJB-IPS-TEST-MINOR)
	answered "$code" && result "IPS over HTTP, minor" ok "passed (HTTP $code); threat log should show SID 9900003 as alert" ||
		result "IPS over HTTP, minor" FAIL "no answer: minor should alert, not block"
	if [[ $DECRYPTING == yes ]]; then
		ips_block "IPS inside HTTPS, critical" "https://www.example.com/SJB-IPS-TEST-CRITICAL"
	else
		result "IPS inside HTTPS, critical" skip "decryption isn't on for this VM"
	fi
}

decryption() {
	local h code
	if [[ $DECRYPTING != yes ]]; then result "decryption checks" skip "decryption isn't on for this VM"; return; fi
	for h in "${DECRYPT_SITES[@]}"; do
		if ! peer "$h"; then result "decrypt $h" FAIL "no TLS answer"; continue; fi
		case $(kind "$P_ISSUER") in
		ours) result "decrypt $h" ok "decrypted" ;;
		*) result "decrypt $h" FAIL "not decrypted (issuer: $(cn "$P_ISSUER"))" ;;
		esac
	done
	for h in "${EXCLUDED_SITES[@]}" "${EXTRA_EXCL[@]}" "${LAN_HOST}"; do
		[[ -n $h ]] || continue
		if ! peer "$h"; then result "exclude $h" skip "no TLS answer"; continue; fi
		case $(kind "$P_ISSUER") in
		real) result "exclude $h" ok "not decrypted (issuer: $(cn "$P_ISSUER"))" ;;
		ours) result "exclude $h" FAIL "DECRYPTED, but it should be excluded" ;;
		*) result "exclude $h" FAIL "re-signed with the untrusted CA" ;;
		esac
	done
	# badssl.com's own site has a good certificate: if it works and the bad
	# ones don't, the firewall blocked them.
	if ! peer badssl.com; then
		result "bad certificates blocked" skip "badssl.com unreachable; inconclusive"
	else
		for h in "${BAD_CERT_SITES[@]}"; do
			if ! peer "$h"; then result "bad cert $h blocked" ok "blocked, badssl.com itself works; decryption log should say so"; continue; fi
			case $(kind "$P_ISSUER") in
			untrusted) result "bad cert $h blocked" FAIL "warned instead (profile bad-certificate warn): best practice blocks" ;;
			ours) result "bad cert $h blocked" FAIL "re-signed with the TRUSTED CA: the bad certificate was hidden" ;;
			*) result "bad cert $h blocked" FAIL "passed through undecrypted (issuer: $(cn "$P_ISSUER"))" ;;
			esac
		done
	fi
	if curl -V 2>/dev/null | grep -q HTTP3; then
		code=$(http_code https://www.google.com/ --http3-only)
		if answered "$code"; then result "QUIC blocked" FAIL "QUIC answered (HTTP $code): profile allow_quic should be false"
		else
			code=$(http_code https://www.google.com/)
			answered "$code" && result "QUIC blocked" ok "no QUIC answer, HTTPS works" || result "QUIC blocked" skip "HTTPS to www.google.com fails too; inconclusive"
		fi
	else
		result "QUIC blocked" skip "this curl has no HTTP/3"
	fi
}

# tools/harness-test.sh sources this file for its functions only.
[[ ${SJB_HARNESS_SOURCE:-} == 1 ]] && return 0

echo "Setup:"; setup
echo "Allowed:"; allowed
echo "Outbound allow-list:"; allow_list
echo "Risky applications on allowed ports:"; risky
echo "IPS:"; ips
echo "TLS decryption:"; decryption
echo "  (Not checked here: inbound, run with -I from outside; and quarantine: tag this VM's address"
echo "   'quarantine' with the tag API and run again; everything should fail.)"
echo
echo "done: $ok ok, $bad failed, $skip skipped"
echo "On the firewall: 'show log traffic', 'show log threat', 'show log decryption'."
((bad == 0))
