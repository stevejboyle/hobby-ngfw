#!/usr/bin/env bash
# fw-traffic-test.sh: exercise SJB-OS App Identification and IPS from a Linux test VM
# behind the firewall. One file; copy it to the VM and run it.
#
#   ./fw-traffic-test.sh             App Identification traffic, then IPS triggers
#   ./fw-traffic-test.sh -a          App Identification traffic only
#   ./fw-traffic-test.sh -i          IPS triggers only
#   ./fw-traffic-test.sh -r 3        three rounds
#   ./fw-traffic-test.sh -d 9.9.9.9  DNS server for the DNS tests (default 1.1.1.1)
#   ./fw-traffic-test.sh -l          list what it would do, send nothing
#
# Everything is harmless: page fetches, DNS lookups, TLS handshakes and
# protocol greetings. The IPS triggers are requests that merely LOOK like
# something: SJB-OS's own test strings, DNS lookups of long-sinkholed
# malware kill-switch domains, scanner user-agent strings sent to
# example.com. Nothing is attacked and nothing is downloaded.
#
# Before you run it:
#   - The VM's traffic must match an allow rule with an IPS profile
#     (e.g. inside-out with ips-profile default), or no IPS test fires.
#   - The default profile blocks critical and major, alerts on minor and
#     IGNORES informational. To see the informational ones in the threat
#     log too, use a profile with informational alert, e.g.
#       set ips-profile lab critical block major block minor alert informational alert
#   - Turn on Log for that rule to get traffic-log end entries per app.
#
# Afterwards: Logs -> Threats (or `show log threat`) right away; App Identification
# counts a connection when it ENDS, so give Security -> Applications (or
# `show app`) 2-3 minutes. The dashboard's Activity charts update each minute.
#
# Needs bash and curl. dig, openssl, ssh-keyscan, git and python3 are used
# when present; their tests are skipped when not.
set -u

ROUNDS=1 LIST=0 DO_APPID=1 DO_IPS=1 DNS=1.1.1.1
while getopts "r:d:ailh" o; do
	case $o in
	r) ROUNDS=$OPTARG ;;
	d) DNS=$OPTARG ;;
	a) DO_IPS=0 ;;
	i) DO_APPID=0 ;;
	l) LIST=1 ;;
	*) sed -n '2,32p' "$0"; exit 0 ;;
	esac
done

have() { command -v "$1" >/dev/null 2>&1; }
have curl || { echo "needs curl" >&2; exit 1; }
PY=$(command -v python3 || true)
UA="Mozilla/5.0 (X11; Linux x86_64) sjb-fw-test"

ok=0 bad=0 skip=0
row() { printf '  %-34s %-8s %s\n' "$1" "$2" "$3"; }
result() { # name status detail
	case $2 in
	ok) ok=$((ok + 1)); row "$1" ok "$3" ;;
	skip) skip=$((skip + 1)); row "$1" skip "$3" ;;
	*) bad=$((bad + 1)); row "$1" FAIL "$3" ;;
	esac
}

# ---------------------------------------------------------------- App Identification

# HTTPS: nDPI names the app from the TLS server name.
HTTPS_APPS=(
	"YouTube|https://www.youtube.com/"
	"Netflix|https://www.netflix.com/"
	"Facebook|https://www.facebook.com/"
	"Instagram|https://www.instagram.com/"
	"WhatsApp|https://web.whatsapp.com/"
	"TikTok|https://www.tiktok.com/"
	"Twitter/X|https://x.com/"
	"LinkedIn|https://www.linkedin.com/"
	"Reddit|https://www.reddit.com/"
	"Pinterest|https://www.pinterest.com/"
	"Wikipedia|https://en.wikipedia.org/"
	"Amazon|https://www.amazon.com/"
	"Apple|https://www.apple.com/"
	"iCloud|https://www.icloud.com/"
	"Microsoft|https://www.microsoft.com/"
	"Teams|https://teams.microsoft.com/"
	"Outlook/Office365|https://outlook.office.com/"
	"OneDrive|https://onedrive.live.com/"
	"Bing|https://www.bing.com/"
	"Zoom|https://zoom.us/"
	"Webex|https://www.webex.com/"
	"Slack|https://slack.com/"
	"Telegram|https://web.telegram.org/"
	"Signal|https://signal.org/"
	"Spotify|https://open.spotify.com/"
	"Dropbox|https://www.dropbox.com/"
	"GitHub|https://github.com/"
	"Google|https://www.google.com/"
	"Gmail|https://mail.google.com/"
	"Google Drive|https://drive.google.com/"
	"Yahoo|https://www.yahoo.com/"
	"DuckDuckGo|https://duckduckgo.com/"
	"Cloudflare|https://www.cloudflare.com/"
	"Twitch|https://www.twitch.tv/"
	"Discord|https://discord.com/"
	"Steam|https://store.steampowered.com/"
	"ChatGPT|https://chatgpt.com/"
)

# Plain HTTP: nDPI reads the Host header.
HTTP_APPS=(
	"HTTP (neverssl.com)|http://neverssl.com/"
	"HTTP (example.com)|http://example.com/"
	"Ubuntu archive (HTTP)|http://archive.ubuntu.com/ubuntu/"
	"Debian mirror (HTTP)|http://deb.debian.org/debian/"
)

fetch() { # name url [extra curl args]: ok on any HTTP answer
	local name=$1 url=$2 code; shift 2
	code=$(curl -s -o /dev/null -m 10 -A "$UA" -w '%{http_code}' "$@" "$url" 2>/dev/null)
	if [[ $code =~ ^[1-5][0-9][0-9]$ ]]; then result "$name" ok "HTTP $code"; else result "$name" fail "no response"; fi
}

# dnsq NAME: one A query to $DNS; prints "answer" or "none".
dnsq() {
	if have dig; then
		dig +time=3 +tries=1 @"$DNS" "$1" A >/dev/null 2>&1 && echo answer || echo none
	elif [[ -n $PY ]]; then
		"$PY" - "$DNS" "$1" 2>/dev/null <<'EOF' && echo answer || echo none
import os, socket, struct, sys
server, name = sys.argv[1], sys.argv[2]
q = struct.pack("!HHHHHH", int.from_bytes(os.urandom(2), "big"), 0x0100, 1, 0, 0, 0)
q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, (server, 53)); s.recvfrom(512)
EOF
	else
		echo skip
	fi
}

appid_dns() {
	local n r
	for n in www.youtube.com www.netflix.com github.com zoom.us; do
		r=$(dnsq "$n")
		case $r in answer) result "DNS $n" ok "@$DNS" ;; skip) result "DNS" skip "no dig or python3"; return ;; *) result "DNS $n" fail "@$DNS" ;; esac
	done
	fetch "DNS over HTTPS (Cloudflare)" "https://cloudflare-dns.com/dns-query?name=example.com&type=A" -H "accept: application/dns-json"
	if have openssl; then
		if timeout 8 openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com </dev/null >/dev/null 2>&1; then
			result "DNS over TLS (853)" ok "handshake"; else result "DNS over TLS (853)" fail ""; fi
	else
		result "DNS over TLS (853)" skip "no openssl"
	fi
}

appid_quic() {
	if curl -V 2>/dev/null | grep -q HTTP3; then
		fetch "QUIC / HTTP3 (Google)" "https://www.google.com/" --http3-only
		fetch "QUIC / HTTP3 (YouTube)" "https://www.youtube.com/" --http3-only
	else
		result "QUIC / HTTP3" skip "this curl has no HTTP/3"
	fi
}

appid_udp() {
	if [[ -z $PY ]]; then
		result "NTP / STUN / BitTorrent" skip "no python3"
		return
	fi
	# NTP: one SNTP client request.
	"$PY" - 2>/dev/null <<'EOF' && result "NTP (pool.ntp.org)" ok "" || result "NTP (pool.ntp.org)" fail ""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
s.sendto(b"\x1b" + 47 * b"\0", ("pool.ntp.org", 123)); s.recvfrom(64)
EOF
	# STUN: a binding request, as WebRTC, Teams and Zoom calls start with.
	"$PY" - 2>/dev/null <<'EOF' && result "STUN (Google)" ok "" || result "STUN (Google)" fail ""
import os, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
s.sendto(struct.pack("!HHI", 0x0001, 0, 0x2112A442) + os.urandom(12), ("stun.l.google.com", 19302)); s.recvfrom(512)
EOF
	# BitTorrent: one DHT "ping" to the public bootstrap node (no torrent,
	# no download). A rule denying BitTorrent makes this one fail.
	"$PY" - 2>/dev/null <<'EOF' && result "BitTorrent DHT ping" ok "" || result "BitTorrent DHT ping" fail "no answer (expected if a rule blocks BitTorrent)"
import os, socket
msg = b"d1:ad2:id20:" + os.urandom(20) + b"e1:q4:ping1:t2:aa1:y1:qe"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
s.sendto(msg, ("router.bittorrent.com", 6881)); s.recvfrom(1024)
EOF
}

appid_tcp() {
	if have ssh-keyscan; then
		if timeout 10 ssh-keyscan -T 5 github.com >/dev/null 2>&1; then result "SSH (github.com:22)" ok "key exchange only"; else result "SSH (github.com:22)" fail ""; fi
	else
		result "SSH" skip "no ssh-keyscan"
	fi
	if timeout 8 bash -c 'exec 3<>/dev/tcp/smtp.gmail.com/587; read -r -t 5 l <&3; echo QUIT >&3; [[ $l == 220* ]]' 2>/dev/null; then
		result "SMTP (gmail:587)" ok "greeting"; else result "SMTP (gmail:587)" fail ""; fi
	if have openssl; then
		if timeout 8 openssl s_client -connect imap.gmail.com:993 -servername imap.gmail.com </dev/null >/dev/null 2>&1; then
			result "IMAPS (gmail:993)" ok "handshake"; else result "IMAPS (gmail:993)" fail ""; fi
	fi
	if have git; then
		if timeout 15 git ls-remote https://github.com/git/git HEAD >/dev/null 2>&1; then result "git over HTTPS" ok "refs only"; else result "git over HTTPS" fail ""; fi
	fi
}

run_appid() {
	echo "App Identification, HTTPS (TLS server name):"
	for e in "${HTTPS_APPS[@]}"; do fetch "${e%%|*}" "${e#*|}"; done
	echo "App Identification, HTTP (Host header):"
	for e in "${HTTP_APPS[@]}"; do fetch "${e%%|*}" "${e#*|}"; done
	echo "App Identification, DNS:"; appid_dns
	echo "App Identification, QUIC:"; appid_quic
	echo "App Identification, UDP:"; appid_udp
	echo "App Identification, TCP:"; appid_tcp
}

# ---------------------------------------------------------------- IPS
#
# Each trigger lists the signature it should match, its severity and what
# the built-in default profile does with it (critical/major block, minor
# alert, informational ignore). "blocked" means no answer came back; for
# DNS, "no answer" can also be a slow or missing name server.

# kind|label|target|SID|severity|signature
IPS_TESTS=(
	"http|SJB test, critical|SJB-IPS-TEST-CRITICAL|9900001|critical|SJB-OS IPS test signature"
	"http|SJB test, major|SJB-IPS-TEST-MAJOR|9900002|major|SJB-OS IPS test signature"
	"http|SJB test, minor|SJB-IPS-TEST-MINOR|9900003|minor|SJB-OS IPS test signature"
	"http|SJB test, informational|SJB-IPS-TEST-INFO|9900004|informational|SJB-OS IPS test signature"
	"dns|WannaCry variant kill switch|ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com|2024293|critical|ET MALWARE Possible WannaCry DNS Lookup 2"
	"dns|WannaCry kill switch|iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com|2024291|major|ET MALWARE Possible WannaCry DNS Lookup 1"
	"dns|Reverse proxy service|sjb-fw-test.serveo.net|2027942|major|ET INFO DNS Query to a Reverse Proxy Service Observed"
	"dns|Hex-only duckdns name|5b1a2c3d4e5f.duckdns.org|2033959|major|ET HUNTING DNS Lookup for 8+ hexadecimal only duckdns domain"
	"tls12|Telegram API certificate|api.telegram.org|2029322|minor|ET HUNTING Telegram API Certificate Observed"
	"dns|External IP lookup (DNS)|www.ifconfig.me|2063062|informational|ET INFO External IP Lookup Domain (ifconfig .me) in DNS Lookup"
	"dns|Interactsh callback domain|sjb-fw-test.interact.sh|2034198|informational|ET INFO Interactsh Domain in DNS Lookup"
	"dns|dnslog.cn domain|sjb-fw-test.dnslog.cn|2034669|informational|ET INFO dnslog .cn Observed in DNS Query"
	"ua|Python-urllib user agent|Python-urllib/3.11|2013031|informational|ET INFO Python-urllib/ Suspicious User Agent"
	"ua|Masscan user agent|masscan/1.3 (https://github.com/robertdavidgraham/masscan)|2017615|informational|ET SCAN NETWORK Outgoing Masscan detected"
	"uid|id check returned root|http://testmyids.com/|2100498|informational|GPL ATTACK_RESPONSE id check returned root"
)

expect() { # severity -> what the default profile does
	case $1 in critical | major) echo blocked ;; minor) echo "passes, logged" ;; *) echo "passes, not logged" ;; esac
}

ips_one() { # kind label target sid severity
	local kind=$1 label=$2 target=$3 sid=$4 sev=$5 got code
	case $kind in
	http)
		code=$(curl -s -o /dev/null -m 8 -A "$UA" -w '%{http_code}' "http://example.com/$target" 2>/dev/null)
		[[ $code =~ ^[1-5][0-9][0-9]$ ]] && got="passed (HTTP $code)" || got=blocked ;;
	ua)
		code=$(curl -s -o /dev/null -m 8 -A "$target" -w '%{http_code}' "http://example.com/" 2>/dev/null)
		[[ $code =~ ^[1-5][0-9][0-9]$ ]] && got="passed (HTTP $code)" || got=blocked ;;
	uid)
		code=$(curl -s -o /dev/null -m 8 -A "$UA" -w '%{http_code}' "$target" 2>/dev/null)
		[[ $code =~ ^[1-5][0-9][0-9]$ ]] && got="passed (HTTP $code)" || got="blocked or site down" ;;
	dns)
		case $(dnsq "$target") in answer) got="passed (answered)" ;; skip) result "$label" skip "no dig or python3"; return ;; *) got="no answer" ;; esac ;;
	tls12)
		code=$(curl -s -o /dev/null -m 8 --tlsv1.2 --tls-max 1.2 -A "$UA" -w '%{http_code}' "https://$target/" 2>/dev/null)
		[[ $code =~ ^[1-5][0-9][0-9]$ ]] && got="passed (HTTP $code)" || got=blocked ;;
	esac
	ok=$((ok + 1))
	printf '  %-30s %-13s %-8s %-22s default: %s\n' "$label" "$sev" "$sid" "$got" "$(expect "$sev")"
}

run_ips() {
	echo "IPS triggers (label, severity, SID, what happened, what the default profile does):"
	for e in "${IPS_TESTS[@]}"; do
		IFS='|' read -r kind label target sid sev _ <<<"$e"
		ips_one "$kind" "$label" "$target" "$sid" "$sev"
	done
	echo "  (Suricata's whole set loads only when a rule uses a profile; if every"
	echo "   line passed, check that this VM's traffic hits such a rule and that"
	echo "   'show ips' says the engine is running.)"
}

# ---------------------------------------------------------------- main

if [[ $LIST == 1 ]]; then
	if [[ $DO_APPID == 1 ]]; then
		echo "App Identification, HTTPS:"; printf '  %s\n' "${HTTPS_APPS[@]%%|*}"
		echo "App Identification, HTTP:";  printf '  %s\n' "${HTTP_APPS[@]%%|*}"
		echo "App Identification, other: DNS, DNS over HTTPS and TLS, QUIC/HTTP3, NTP, STUN,"
		echo "  BitTorrent DHT ping, SSH, SMTP, IMAPS, git over HTTPS"
	fi
	if [[ $DO_IPS == 1 ]]; then
		echo "IPS (label | target | SID | severity | signature):"
		for e in "${IPS_TESTS[@]}"; do
			IFS='|' read -r _ label target sid sev msg <<<"$e"
			printf '  %s | %s | %s | %s | %s\n' "$label" "$target" "$sid" "$sev" "$msg"
		done
	fi
	exit 0
fi

for ((r = 1; r <= ROUNDS; r++)); do
	echo "== round $r of $ROUNDS =="
	[[ $DO_APPID == 1 ]] && run_appid
	[[ $DO_IPS == 1 ]] && run_ips
done

echo
echo "done: $ok ok, $bad failed, $skip skipped"
[[ $DO_IPS == 1 ]] && echo "Threats: Logs -> Threats or 'show log threat' (informational ones only if the profile alerts on them)."
[[ $DO_APPID == 1 ]] && echo "Applications: wait 2-3 minutes, then Security -> Applications or 'show app'."
exit 0
