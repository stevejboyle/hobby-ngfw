#!/usr/bin/env bash
# lab-test.sh: check the SJB-OS DMZ lab (examples/lab-dmz-bgp.yaml: inside, a
# DMZ web server, eBGP upstream) from each side. One file; copy it
# to each machine and run it there with its role.
#
#   ./lab-test.sh -r inside      the inside client (DHCP on VLAN 150): its lease,
#                                the firewall from inside, the DMZ web server, and
#                                the whole outbound policy (web, approved DNS, NTP,
#                                mail, ping, the allow-list, risky applications,
#                                the IPS, TLS decryption)
#   ./lab-test.sh -r dmz         the DMZ web server (VLAN 151): its address, its
#                                own web server, the firewall from the DMZ, DMZ
#                                outbound (open, not decrypted), and that inside
#                                stays out of reach
#   ./lab-test.sh -r outside     a machine on the home LAN or wifi, routed through
#                                the upstream router: web to the DMZ allowed and
#                                inspected, nothing else to the DMZ, inside not
#                                reachable, the firewall's outside address closed
#
# Options:
#   -w ADDRESS   the DMZ web server (default 192.168.151.10)
#   -c ADDRESS   the inside client's address, for the dmz and outside roles'
#                "inside is out of reach" checks (the inside role prints it)
#   -D A,B       approved DNS resolvers (default 192.168.1.97,192.168.1.98)
#   -L HOST      a home-LAN host with an HTTPS page: inside checks it isn't
#                decrypted (rule never-decrypt-home-lan)
#   -x NAME      also check NAME (one of your exclusions) isn't decrypted; repeat
#   -C ca.crt    the decryption CA, to recognise an imported one
#   -l           list the role's checks, send nothing
#
# Each check is judged against a working control where it can be, so a
# failure is evidence. Results: ok, FAIL (the policy isn't doing what it
# should), skip (couldn't tell; the note says what to look at). Exit status
# is non-zero when anything failed. Afterwards, on the firewall:
# 'show log traffic', 'show log threat', 'show log decryption'.
#
# Needs bash, curl, openssl, awk, timeout and ip (not for -r outside, which
# also runs on a Mac); dig (or python3) for DNS, python3 for NTP, ping for
# ICMP; their checks are skipped when missing.
set -u

ROLE="" WEB=192.168.151.10 CLIENT=""
DNS_OK="192.168.1.97,192.168.1.98"
LAN_HOST="" CA_FILE="" LIST=0
EXTRA_EXCL=()
while getopts "r:w:c:D:L:x:C:lh" o; do
	case $o in
	r) ROLE=$OPTARG ;;
	w) WEB=$OPTARG ;;
	c) CLIENT=$OPTARG ;;
	D) DNS_OK=$OPTARG ;;
	L) LAN_HOST=$OPTARG ;;
	x) EXTRA_EXCL+=("$OPTARG") ;;
	C) CA_FILE=$OPTARG ;;
	l) LIST=1 ;;
	*) awk 'NR > 1 && /^#/ { print; next } NR > 1 { exit }' "$0"; exit 0 ;;
	esac
done
case $ROLE in inside | dmz | outside) ;; *) echo "usage: $0 -r inside|dmz|outside [options] (-h for help)" >&2; exit 2 ;; esac
IFS=',' read -r -a RESOLVERS <<<"$DNS_OK"
[[ -z $CA_FILE && -r /usr/local/share/ca-certificates/sjb-os-decryption-ca.crt ]] &&
	CA_FILE=/usr/local/share/ca-certificates/sjb-os-decryption-ca.crt
for a in "$WEB" "$CLIENT"; do
	[[ -z $a || $a =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "not an IPv4 address: $a" >&2; exit 2; }
done

# The lab (examples/lab-dmz-bgp.yaml and the running config merged with it).
FW_INSIDE=192.168.150.1 FW_DMZ=192.168.151.1 FW_OUTSIDE=192.168.149.254
DHCP_FIRST=101 DHCP_LAST=199 DOMAIN=sboyle.internal
# Ports nothing but web may reach on the DMZ server from outside.
DMZ_CLOSED=(21 22 23 3306 3389 8080)

# Ports the allow-list must keep closed (allowed: 80, 443, 53, 123, 465, 587, 993).
BLOCKED_PORTS=(22 23 25 110 143 445 1433 3306 3389 5900 6667 8080 8443)
OTHER_RESOLVERS=(8.8.8.8 1.1.1.1)
DECRYPT_SITES=(www.example.com en.wikipedia.org github.com)
# Built-in exclusions and the template's own.
EXCLUDED_SITES=(www.chase.com www.irs.gov www.apple.com login.microsoftonline.com www.zoom.us www.dropbox.com accounts.google.com)
BAD_CERT_SITES=(expired.badssl.com self-signed.badssl.com wrong.host.badssl.com)
RISKY_SITES=("NordVPN|https://nordvpn.com/" "Psiphon|https://psiphon.ca/" "TeamViewer|https://www.teamviewer.com/" "AnyDesk|https://anydesk.com/")

if [[ $LIST == 1 ]]; then
	case $ROLE in
	inside)
		echo "lease: address in 192.168.150.$DHCP_FIRST-$DHCP_LAST, gateway $FW_INSIDE, DNS ${RESOLVERS[*]}, domain $DOMAIN"
		echo "firewall: ping $FW_INSIDE, $FW_DMZ, $FW_OUTSIDE; TCP 22 and 443 on each closed"
		echo "DMZ: ping $WEB; its web page over HTTP (and HTTPS if served), not decrypted; no IPS on inside-to-dmz"
		echo "outbound (as before): web, DNS to ${RESOLVERS[*]}, NTP, SMTP 587/465, IMAPS 993, ping 1.1.1.1"
		echo "  allow-list, must stay closed: TCP ${BLOCKED_PORTS[*]} (portquiz.net); DNS to ${OTHER_RESOLVERS[*]}; DNS over TLS"
		echo "  risky applications: DNS over HTTPS; ${RISKY_SITES[*]%%|*}"
		echo "  IPS: SJB-IPS-TEST-CRITICAL and -MINOR over HTTP and (decrypted) HTTPS"
		echo "  decryption: decrypted ${DECRYPT_SITES[*]}; not decrypted ${EXCLUDED_SITES[*]} ${EXTRA_EXCL[*]+${EXTRA_EXCL[*]}} ${LAN_HOST}; bad certificates blocked; QUIC blocked" ;;
	dmz)
		echo "address in 192.168.151.0/24, gateway $FW_DMZ; this server's own web page"
		echo "firewall: ping $FW_DMZ; TCP 22 and 443 closed"
		echo "inside out of reach: ping and TCP 22 to ${CLIENT:-(the client, -c)}"
		echo "outbound open: HTTP, HTTPS (not decrypted), DNS to 8.8.8.8, TCP 8080 (portquiz.net), ping 1.1.1.1" ;;
	outside)
		echo "DMZ web: $WEB over HTTP (and HTTPS if served); IPS: -CRITICAL blocked, -MINOR passed"
		echo "DMZ closed: TCP ${DMZ_CLOSED[*]} to $WEB dropped; ping $WEB no reply"
		echo "inside out of reach: ping $FW_INSIDE${CLIENT:+, ping and TCP 22 to $CLIENT}"
		echo "firewall outside: ping $FW_OUTSIDE; TCP 22 and 443 closed" ;;
	esac
	exit 0
fi

have() { command -v "$1" >/dev/null 2>&1; }
# macOS has no timeout(1): use coreutils' gtimeout, or perl.
if ! have timeout; then
	if have gtimeout; then timeout() { gtimeout "$@"; }
	elif have perl; then timeout() { perl -e 'alarm shift; exec @ARGV' "$@"; }
	fi
fi
for t in curl openssl timeout; do have "$t" || { echo "needs $t" >&2; exit 2; }; done
PY=$(command -v python3 || true)
UA="Mozilla/5.0 (X11; Linux x86_64) sjb-lab-test"

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

risky() {
	local code name url
	if [[ $CONTROL != yes ]]; then result "risky applications" skip "HTTPS control failed; inconclusive"; return; fi
	code=$(http_code "https://cloudflare-dns.com/dns-query?name=example.com&type=A" -H "accept: application/dns-json")
	if answered "$code"; then result "DNS over HTTPS (Cloudflare) blocked" FAIL "ANSWERED (HTTP $code): encrypted DNS gets around the approved resolvers"
	else result "DNS over HTTPS (Cloudflare) blocked" ok "no answer, other HTTPS works"; fi
	code=$(http_code "https://dns.google/resolve?name=example.com&type=A")
	if answered "$code"; then result "DNS over HTTPS (Google) blocked" FAIL "ANSWERED (HTTP $code): encrypted DNS gets around the approved resolvers"
	else result "DNS over HTTPS (Google) blocked" ok "no answer, other HTTPS works"; fi
	for e in "${RISKY_SITES[@]}"; do
		name=${e%%|*} url=${e#*|}
		code=$(http_code "$url")
		if answered "$code"; then result "$name site" skip "reachable (HTTP $code): the block applies to the app's own traffic; check 'show app'"
		else result "$name site" ok "blocked, other HTTPS works"; fi
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
	for h in "${EXCLUDED_SITES[@]}" ${EXTRA_EXCL[@]+"${EXTRA_EXCL[@]}"} "${LAN_HOST}"; do
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


# ---------------------------------------------------------------- lab checks

[[ $ROLE == outside ]] || have ip || { echo "needs ip (iproute2)" >&2; exit 2; }

# pings ADDRESS: one reply within 3 s.
if [[ $(uname -s) == Darwin ]]; then
	pings() { ping -c 1 -t 3 "$1" >/dev/null 2>&1; } # macOS: -t is the timeout in seconds
else
	pings() { ping -4 -c 1 -W 3 "$1" >/dev/null 2>&1 || ping -c 1 -W 3 "$1" >/dev/null 2>&1; }
fi
# body URL: the page, or nothing.
body() { curl -4 -s -m 8 -A "$UA" "$1" 2>/dev/null; }
# my_addr PREFIX: this machine's address starting PREFIX (e.g. 192.168.150.).
my_addr() { ip -4 -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4}' | grep -m1 "^${1//./\\.}"; }
gateway() { ip -4 route show default 2>/dev/null | awk '{print $3; exit}'; }

# closed_by_fw LABEL HOST PORT: the firewall must drop it (a timeout). A reset
# means something answered, so the firewall let it through.
closed_by_fw() {
	case $(tcp "$2" "$3") in
	timeout) result "$1" ok "dropped" ;;
	refused) result "$1" FAIL "reset: it got past the firewall to $2 (nothing listens on $3)" ;;
	*) result "$1" FAIL "OPEN: $2:$3 answered" ;;
	esac
}
# fw_closed HOST: the firewall's own address answers ping, nothing else.
fw_closed() {
	if have ping; then
		if pings "$1"; then LAB_OK=yes; result "ping firewall $1" ok "replies"
		else result "ping firewall $1" FAIL "no reply: zones may ping the firewall"; fi
	fi
	local p
	[[ $LAB_OK == yes ]] || { result "firewall $1: TCP 22, 443 closed" skip "the firewall doesn't answer ping either; inconclusive"; return; }
	for p in 22 443; do
		[[ $(tcp "$1" "$p") == open ]] && result "firewall $1:$p closed" FAIL "OPEN: only ping should reach the firewall from a zone" ||
			result "firewall $1:$p closed" ok "no connection"
	done
}
# LAB_OK: something on the lab answers from here (the control for "out of
# reach" checks: with no route at all, everything would look unreachable).
LAB_OK=no
unreachable() { # LABEL HOST
	have ping || { result "$1" skip "no ping"; return; }
	[[ $LAB_OK == yes ]] || { result "$1" skip "nothing on the lab answers from here either; inconclusive"; return; }
	pings "$2" && result "$1" FAIL "REPLIED: $2 is reachable from here" || result "$1" ok "no reply"
}
WEB_OK=no
web_page() { # LABEL-PREFIX; sets WEB_OK, the control for the DMZ's closed ports
	local code
	code=$(http_code "http://$WEB/")
	if answered "$code"; then WEB_OK=yes; result "$1 HTTP $WEB" ok "HTTP $code"
	else result "$1 HTTP $WEB" FAIL "no answer: check the server's address (-w), the rule and the route"; fi
	if peer "$WEB:443" -; then
		[[ $(kind "$P_ISSUER") == ours ]] && result "$1 HTTPS $WEB not decrypted" FAIL "decrypted: no decryption rule covers the DMZ" ||
			result "$1 HTTPS $WEB not decrypted" ok "issuer: $(cn "$P_ISSUER")"
	else
		result "$1 HTTPS $WEB" skip "no TLS answer: the server may not serve HTTPS"
	fi
}

lease_inside() {
	local a gw dns dom last
	a=$(my_addr 192.168.150.)
	if [[ -z $a ]]; then result "address on VLAN 150" FAIL "no 192.168.150.x address: is this VM on the VLAN 150 port group, and did DHCP answer?"; return; fi
	last=${a##*.}
	((last >= DHCP_FIRST && last <= DHCP_LAST)) && result "DHCP address $a" ok "in the server's range" ||
		result "DHCP address $a" FAIL "outside .$DHCP_FIRST-.$DHCP_LAST: static, or not from SJB-OS's DHCP server"
	CLIENT_SELF=$a
	gw=$(gateway)
	[[ $gw == "$FW_INSIDE" ]] && result "default gateway" ok "$gw" || result "default gateway" FAIL "${gw:-none}, want $FW_INSIDE"
	if have resolvectl; then dns=$(resolvectl dns 2>/dev/null); dom=$(resolvectl domain 2>/dev/null)
	else dns=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null); dom=$(awk '/^(search|domain)/' /etc/resolv.conf 2>/dev/null); fi
	local r missing=""
	for r in "${RESOLVERS[@]}"; do grep -qw "${r//./\\.}" <<<"$dns" || missing+=" $r"; done
	if [[ -z $missing ]]; then result "DNS servers from DHCP" ok "${RESOLVERS[*]}"
	elif grep -q 127.0.0.53 <<<"$dns"; then result "DNS servers from DHCP" skip "only the local resolver (127.0.0.53) is visible; install resolvectl"
	else result "DNS servers from DHCP" FAIL "missing$missing"; fi
	grep -qw "$DOMAIN" <<<"$dom" && result "domain from DHCP" ok "$DOMAIN" || result "domain from DHCP" FAIL "no $DOMAIN in the search domains"
}

dmz_from_inside() {
	have ping && { pings "$WEB" && result "ping DMZ $WEB" ok "replies" || result "ping DMZ $WEB" FAIL "no reply: inside may reach the DMZ"; }
	web_page "DMZ:"
	local code
	code=$(http_code "http://$WEB/SJB-IPS-TEST-CRITICAL")
	answered "$code" && result "DMZ: no IPS on inside-to-dmz" ok "test string passed (HTTP $code), as designed" ||
		result "DMZ: no IPS on inside-to-dmz" skip "no answer; if a profile was added to inside-to-dmz, that's expected"
}

dmz_self() {
	local a gw code
	a=$(my_addr 192.168.151.)
	[[ -n $a ]] && result "address on VLAN 151" ok "$a" || result "address on VLAN 151" FAIL "no 192.168.151.x address: is this VM on the VLAN 151 port group?"
	[[ -n $a && $a != "$WEB" ]] && result "this is the web server ($WEB)" skip "this machine is $a; pass -w $a if it's the web server"
	gw=$(gateway)
	[[ $gw == "$FW_DMZ" ]] && result "default gateway" ok "$gw" || result "default gateway" FAIL "${gw:-none}, want $FW_DMZ"
	code=$(http_code http://127.0.0.1/)
	answered "$code" && result "local web server" ok "HTTP $code" || result "local web server" FAIL "nothing on 127.0.0.1:80: start Apache or nginx"
}

dmz_outbound() {
	local code
	code=$(http_code http://example.com/); answered "$code" && result "out: HTTP" ok "HTTP $code" || result "out: HTTP" FAIL "no answer: dmz-out allows the DMZ out"
	code=$(http_code https://www.example.com/); answered "$code" && result "out: HTTPS" ok "HTTP $code" || result "out: HTTPS" FAIL "no answer (curl: certificate trouble means decryption, which shouldn't apply)"
	if peer www.example.com; then
		[[ $(kind "$P_ISSUER") == ours ]] && result "out: HTTPS not decrypted" FAIL "decrypted: decryption covers inside only" ||
			result "out: HTTPS not decrypted" ok "issuer: $(cn "$P_ISSUER")"
	fi
	case $(dnsq 8.8.8.8 example.com) in
	answer) result "out: DNS to 8.8.8.8" ok "answered (the DMZ isn't held to the approved resolvers)" ;;
	skip) result "out: DNS to 8.8.8.8" skip "no dig or python3" ;;
	*) result "out: DNS to 8.8.8.8" FAIL "no answer: dmz-out allows any destination" ;;
	esac
	[[ $(tcp portquiz.net 8080) == open ]] && result "out: TCP 8080 (portquiz.net)" ok "connects (no allow-list for the DMZ)" ||
		result "out: TCP 8080 (portquiz.net)" FAIL "no connection: dmz-out allows any port"
	have ping && { pings 1.1.1.1 && result "out: ping 1.1.1.1" ok "replies" || result "out: ping 1.1.1.1" FAIL "no reply"; }
}

inside_out_of_reach() { # from the DMZ or outside
	if [[ -z $CLIENT ]]; then result "inside client out of reach" skip "pass -c with the inside client's address (the inside role prints it)"; return; fi
	unreachable "inside client $CLIENT: ping" "$CLIENT"
	[[ $LAB_OK == yes ]] || { result "inside client $CLIENT: TCP 22" skip "inconclusive, as above"; return; }
	[[ $(tcp "$CLIENT" 22) == timeout ]] && result "inside client $CLIENT: TCP 22" ok "dropped" ||
		result "inside client $CLIENT: TCP 22" FAIL "got an answer: inside should be unreachable from here"
}

dmz_from_outside() {
	web_page "DMZ web:"
	ips_block "DMZ web: IPS, critical" "http://$WEB/SJB-IPS-TEST-CRITICAL"
	local code p
	code=$(http_code "http://$WEB/SJB-IPS-TEST-MINOR")
	answered "$code" && result "DMZ web: IPS, minor" ok "passed (HTTP $code); threat log: SID 9900003 alert" ||
		result "DMZ web: IPS, minor" FAIL "no answer: the enterprise profile alerts on minor, it doesn't block"
	if [[ $WEB_OK == yes ]]; then
		for p in "${DMZ_CLOSED[@]}"; do closed_by_fw "DMZ $WEB:$p closed" "$WEB" "$p"; done
		unreachable "DMZ $WEB: ping" "$WEB"
	else
		result "DMZ $WEB: other ports closed" skip "the web page doesn't answer either; inconclusive"
	fi
}

# ---------------------------------------------------------------- run

echo "SJB-OS lab test, role $ROLE"
case $ROLE in
inside)
	CLIENT_SELF=""
	echo "Lease:"; lease_inside
	echo "Firewall from inside:"; for h in "$FW_INSIDE" "$FW_DMZ" "$FW_OUTSIDE"; do fw_closed "$h"; done
	echo "DMZ from inside:"; dmz_from_inside
	echo "Setup:"; setup
	echo "Allowed:"; allowed
	echo "Outbound allow-list:"; allow_list
	echo "Risky applications on allowed ports:"; risky
	echo "IPS:"; ips
	echo "TLS decryption:"; decryption
	[[ -n $CLIENT_SELF ]] && echo "  (For the dmz and outside roles: -c $CLIENT_SELF)"
	echo "  (Not checked here: quarantine. Tag this VM's address 'quarantine' with the tag API"
	echo "   and run again: everything should fail; untag it afterwards.)" ;;
dmz)
	echo "This server:"; dmz_self
	echo "Firewall from the DMZ:"; fw_closed "$FW_DMZ"
	echo "Inside is out of reach:"; inside_out_of_reach
	echo "Outbound:"; dmz_outbound ;;
outside)
	echo "Firewall's outside address:"; fw_closed "$FW_OUTSIDE"
	echo "DMZ from outside:"; dmz_from_outside
	echo "Inside is out of reach:"; unreachable "inside gateway $FW_INSIDE: ping" "$FW_INSIDE"; inside_out_of_reach ;;
esac
echo
echo "done: $ok ok, $bad failed, $skip skipped"
((bad == 0))
