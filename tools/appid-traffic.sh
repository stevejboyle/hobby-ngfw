#!/usr/bin/env bash
# appid-traffic.sh: make a spread of real application traffic from a Linux
# machine behind a SJB-OS firewall, to exercise App Identification.
#
#   ./appid-traffic.sh            one round of everything
#   ./appid-traffic.sh -r 3       three rounds
#   ./appid-traffic.sh -l         list what it does, send nothing
#
# Everything is a short, harmless request (a page fetch, a DNS lookup, a
# TLS handshake, a protocol greeting). Needs bash and curl; dig, openssl,
# ssh-keyscan and python3 are used when present and their tests skipped
# when not.
#
# App Identification counts a connection when it ENDS: TCP connections linger in
# TIME_WAIT for about 2 minutes, UDP ones until they time out (30-120 s).
# So check the firewall's Applications page (Security menu) (or `show app`) 2-3 minutes after a run.
# For per-connection detail, turn on Log for the rule this traffic matches;
# the traffic log then gets an end entry per connection with its app.
set -u

ROUNDS=1
LIST=0
while getopts "r:lh" o; do
	case $o in
	r) ROUNDS=$OPTARG ;;
	l) LIST=1 ;;
	*) sed -n '2,18p' "$0"; exit 0 ;;
	esac
done

have() { command -v "$1" >/dev/null 2>&1; }
have curl || { echo "needs curl" >&2; exit 1; }
PY=$(command -v python3 || true)

ok=0 bad=0 skip=0
result() { # name status detail
	case $2 in
	ok) ok=$((ok + 1)); printf '  %-28s ok    %s\n' "$1" "$3" ;;
	skip) skip=$((skip + 1)); printf '  %-28s skip  %s\n' "$1" "$3" ;;
	*) bad=$((bad + 1)); printf '  %-28s FAIL  %s\n' "$1" "$3" ;;
	esac
}

# TLS/HTTPS by server name: nDPI names the app from the SNI.
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
	"Wikipedia|https://en.wikipedia.org/"
	"Amazon|https://www.amazon.com/"
	"Apple|https://www.apple.com/"
	"Microsoft|https://www.microsoft.com/"
	"Teams|https://teams.microsoft.com/"
	"Outlook/Office365|https://outlook.office.com/"
	"Zoom|https://zoom.us/"
	"Slack|https://slack.com/"
	"Spotify|https://open.spotify.com/"
	"Dropbox|https://www.dropbox.com/"
	"GitHub|https://github.com/"
	"Google|https://www.google.com/"
	"Gmail|https://mail.google.com/"
	"Google Drive|https://drive.google.com/"
	"Cloudflare|https://www.cloudflare.com/"
	"Twitch|https://www.twitch.tv/"
	"Discord|https://discord.com/"
	"Steam|https://store.steampowered.com/"
)

# Plain HTTP: nDPI reads the Host header.
HTTP_APPS=(
	"HTTP (neverssl)|http://neverssl.com/"
	"HTTP (example.com)|http://example.com/"
	"Ubuntu archive (HTTP)|http://archive.ubuntu.com/ubuntu/"
)

if [[ $LIST == 1 ]]; then
	echo "HTTPS (TLS server name):"; printf '  %s\n' "${HTTPS_APPS[@]%%|*}"
	echo "HTTP (Host header):";      printf '  %s\n' "${HTTP_APPS[@]%%|*}"
	echo "Other: DNS (UDP 53), DNS over TLS (853), DNS over HTTPS, QUIC/HTTP3,"
	echo "       NTP, STUN, SSH, SMTP, IMAPS, git over HTTPS, BitTorrent DHT ping"
	exit 0
fi

fetch() { # name url [extra curl args]
	local name=$1 url=$2; shift 2
	local code
	code=$(curl -s -o /dev/null -m 10 -A "Mozilla/5.0 (X11; Linux x86_64) appid-test" -w '%{http_code}' "$@" "$url" 2>/dev/null)
	if [[ $code =~ ^[1-5][0-9][0-9]$ ]]; then result "$name" ok "HTTP $code"; else result "$name" fail "no response"; fi
}

dns_tests() {
	if have dig; then
		for n in www.youtube.com www.netflix.com github.com; do
			if dig +time=3 +tries=1 +short @1.1.1.1 "$n" A >/dev/null 2>&1; then result "DNS $n (@1.1.1.1)" ok ""; else result "DNS $n" fail ""; fi
		done
		if dig +time=3 +tries=1 +short @8.8.8.8 example.com A >/dev/null 2>&1; then result "DNS (@8.8.8.8)" ok ""; else result "DNS (@8.8.8.8)" fail ""; fi
	elif [[ -n $PY ]]; then
		"$PY" - 2>/dev/null <<'EOF' && result "DNS (@1.1.1.1, python)" ok "" || result "DNS (@1.1.1.1)" fail ""
import socket, struct
q = struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + b"\x07youtube\x03com\x00" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(q, ("1.1.1.1", 53)); s.recvfrom(512)
EOF
	else
		result "DNS" skip "no dig or python3"
	fi
	# DNS over HTTPS (JSON API).
	fetch "DNS over HTTPS (Cloudflare)" "https://cloudflare-dns.com/dns-query?name=example.com&type=A" -H "accept: application/dns-json"
	# DNS over TLS: just the TLS handshake on 853.
	if have openssl; then
		if timeout 8 openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com </dev/null >/dev/null 2>&1; then
			result "DNS over TLS (853)" ok ""; else result "DNS over TLS (853)" fail ""; fi
	else
		result "DNS over TLS (853)" skip "no openssl"
	fi
}

quic_test() {
	if curl -V 2>/dev/null | grep -q HTTP3; then
		fetch "QUIC / HTTP3 (Google)" "https://www.google.com/" --http3-only
		fetch "QUIC / HTTP3 (YouTube)" "https://www.youtube.com/" --http3-only
	else
		result "QUIC / HTTP3" skip "this curl has no HTTP/3"
	fi
}

udp_tests() {
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
	# STUN: a binding request, as WebRTC/Teams/Zoom calls start with.
	"$PY" - 2>/dev/null <<'EOF' && result "STUN (Google)" ok "" || result "STUN (Google)" fail ""
import os, socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
s.sendto(struct.pack("!HHI", 0x0001, 0, 0x2112A442) + os.urandom(12), ("stun.l.google.com", 19302)); s.recvfrom(512)
EOF
	# BitTorrent: a single DHT "ping" to the public bootstrap node (no
	# torrent, no download; just the protocol's hello).
	"$PY" - 2>/dev/null <<'EOF' && result "BitTorrent DHT ping" ok "" || result "BitTorrent DHT ping" fail "no answer (often blocked; the request still counts)"
import os, socket
nid = os.urandom(20)
msg = b"d1:ad2:id20:" + nid + b"e1:q4:ping1:t2:aa1:y1:qe"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(4)
s.sendto(msg, ("router.bittorrent.com", 6881)); s.recvfrom(1024)
EOF
}

tcp_tests() {
	# SSH: the version exchange (no login).
	if have ssh-keyscan; then
		if timeout 10 ssh-keyscan -T 5 github.com >/dev/null 2>&1; then result "SSH (github.com:22)" ok "key exchange only"; else result "SSH (github.com:22)" fail ""; fi
	else
		result "SSH" skip "no ssh-keyscan"
	fi
	# SMTP: read the server's greeting, say QUIT.
	if timeout 8 bash -c 'exec 3<>/dev/tcp/smtp.gmail.com/587; read -r -t 5 l <&3; echo QUIT >&3; [[ $l == 220* ]]' 2>/dev/null; then
		result "SMTP (gmail:587)" ok "greeting"; else result "SMTP (gmail:587)" fail ""; fi
	# IMAPS: TLS handshake on 993.
	if have openssl; then
		if timeout 8 openssl s_client -connect imap.gmail.com:993 -servername imap.gmail.com </dev/null >/dev/null 2>&1; then
			result "IMAPS (gmail:993)" ok ""; else result "IMAPS (gmail:993)" fail ""; fi
	fi
	# git over HTTPS: the ref advertisement only.
	if have git; then
		if timeout 15 git ls-remote https://github.com/git/git HEAD >/dev/null 2>&1; then result "git over HTTPS" ok ""; else result "git over HTTPS" fail ""; fi
	fi
}

for ((r = 1; r <= ROUNDS; r++)); do
	echo "== round $r of $ROUNDS =="
	echo "HTTPS (TLS server name):"
	for e in "${HTTPS_APPS[@]}"; do fetch "${e%%|*}" "${e#*|}"; done
	echo "HTTP:"
	for e in "${HTTP_APPS[@]}"; do fetch "${e%%|*}" "${e#*|}"; done
	echo "DNS:"; dns_tests
	echo "QUIC:"; quic_test
	echo "UDP:"; udp_tests
	echo "TCP:"; tcp_tests
done

echo
echo "done: $ok ok, $bad failed, $skip skipped"
echo "Give App Identification 2-3 minutes, then look at Security → Applications or run 'show app'."
