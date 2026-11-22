#!/usr/bin/env bash
# harness-test.sh: checks the test harnesses' own verdicts (policy-test.sh
# and lab-test.sh), offline. curl is replaced by a stub that answers each URL
# with a chosen HTTP status and exit code, so the cases that can't be staged
# on a real network are repeatable: a certificate failure, a name that
# doesn't resolve, a curl without an option, a reset, a timeout.
#
#   tools/harness-test.sh        (make harness-test)
#
# It checks that only failures that look like the firewall cutting a
# connection count as a block, that an answer is still a FAIL (DNS over
# HTTPS) or a skip (vendor sites), and that the IPS checks keep their
# verdicts.
set -u
cd "$(dirname "$0")/.." || exit 2

STUB=$(mktemp -d)
trap 'rm -rf "$STUB"' EXIT
TABLE=$STUB/table
# The stub: the URL is curl's last argument; the first table line whose
# pattern it contains gives the status to print and the exit code.
cat >"$STUB/curl" <<'EOF'
#!/usr/bin/env bash
url=${!#}
while read -r pat code rc; do
	[[ -n $pat && $url == *"$pat"* ]] && { printf '%s' "$code"; exit "$rc"; }
done <"$FAKE_CURL_TABLE"
printf 200; exit 0
EOF
printf '#!/bin/sh\nexit 1\n' >"$STUB/openssl"
printf '#!/bin/sh\nshift; exec "$@"\n' >"$STUB/timeout"
printf '#!/bin/sh\nexit 0\n' >"$STUB/ip"
chmod +x "$STUB/curl" "$STUB/openssl" "$STUB/timeout" "$STUB/ip"
export PATH="$STUB:$PATH" FAKE_CURL_TABLE=$TABLE

pass=0 fail=0
# table LINES...: what the stub answers ("pattern status exit").
table() { printf '%s\n' "$@" >"$TABLE"; }
# expect DESC WANT GOT
expect() {
	if [[ $3 == "$2" ]]; then pass=$((pass + 1))
	else fail=$((fail + 1)); printf '  FAIL %s: want %s, got %s\n' "$1" "$2" "${3:-nothing}"; fi
}
# verdict LABEL: the status the harness gave LABEL in the last run.
verdict() { awk -F'|' -v l="$1" '$2 == l { print $1; exit }' "$STUB/out"; }

DOH_CF="DNS over HTTPS (Cloudflare) blocked"
DOH_G="DNS over HTTPS (Google) blocked"

run_suite() { # SCRIPT [args]
	local script=$1; shift
	rm -f "$STUB/count"
	(
		# Load the functions only; nothing runs, nothing is sent.
		OPTIND=1
		export SJB_HARNESS_SOURCE=1
		# shellcheck disable=SC1090
		source "$script" "$@"
		# shellcheck disable=SC2329 # called by the harness functions
		result() { printf '%s|%s\n' "$2" "$1"; }

		# risky CASE STATUS EXIT: every risky URL answers the same way.
		risky_case() {
			table "cloudflare-dns.com $1 $2" "dns.google $1 $2" "nordvpn.com $1 $2" \
				"psiphon.ca $1 $2" "teamviewer.com $1 $2" "anydesk.com $1 $2"
			CONTROL=yes risky >"$STUB/out"
		}
		echo "== $script"
		for rc in 60 6 2 48 3 0; do
			risky_case 000 "$rc"
			expect "curl $rc: Cloudflare DoH" skip "$(verdict "$DOH_CF")"
			expect "curl $rc: Google DoH" skip "$(verdict "$DOH_G")"
			expect "curl $rc: NordVPN site" skip "$(verdict "NordVPN site")"
		done
		for rc in 7 28 35 52 55 56; do
			risky_case 000 "$rc"
			expect "curl $rc: Cloudflare DoH" ok "$(verdict "$DOH_CF")"
			expect "curl $rc: AnyDesk site" ok "$(verdict "AnyDesk site")"
		done
		risky_case 200 0
		expect "answered: Cloudflare DoH" FAIL "$(verdict "$DOH_CF")"
		expect "answered: Google DoH" FAIL "$(verdict "$DOH_G")"
		expect "answered: TeamViewer site" skip "$(verdict "TeamViewer site")"
		risky_case 403 0
		expect "HTTP 403: Google DoH" FAIL "$(verdict "$DOH_G")"
		expect "HTTP 403: Psiphon site" skip "$(verdict "Psiphon site")"
		# A certificate failure must not pass even with the control working.
		table "cloudflare-dns.com 000 60" "dns.google 000 56"
		CONTROL=yes risky >"$STUB/out"
		expect "mixed: Cloudflare curl 60" skip "$(verdict "$DOH_CF")"
		expect "mixed: Google curl 56" ok "$(verdict "$DOH_G")"
		CONTROL=no risky >"$STUB/out"
		expect "control failed" skip "$(verdict "risky applications")"

		# IPS: the base page, the test string, then the base page again.
		L="IPS case"
		table "SJB-IPS-TEST-CRITICAL 000 56"
		ips_block "$L" "http://example.com/SJB-IPS-TEST-CRITICAL" >"$STUB/out"
		expect "IPS reset, controls fine" ok "$(verdict "$L")"
		table "SJB-IPS-TEST-CRITICAL 000 28"
		ips_block "$L" "http://example.com/SJB-IPS-TEST-CRITICAL" >"$STUB/out"
		expect "IPS timeout, controls fine" ok "$(verdict "$L")"
		table "SJB-IPS-TEST-CRITICAL 200 0"
		ips_block "$L" "http://example.com/SJB-IPS-TEST-CRITICAL" >"$STUB/out"
		expect "IPS test string answered" FAIL "$(verdict "$L")"
		table "SJB-IPS-TEST-CRITICAL 000 60"
		ips_block "$L" "https://www.example.com/SJB-IPS-TEST-CRITICAL" >"$STUB/out"
		expect "IPS certificate failure" skip "$(verdict "$L")"
		table "SJB-IPS-TEST-CRITICAL 000 6"
		ips_block "$L" "http://example.com/SJB-IPS-TEST-CRITICAL" >"$STUB/out"
		expect "IPS name not resolved" skip "$(verdict "$L")"
		table "example.com 000 7"
		ips_block "$L" "http://example.com/SJB-IPS-TEST-CRITICAL" >"$STUB/out"
		expect "IPS control down" skip "$(verdict "$L")"
		table "SJB-IPS-TEST-MINOR 200 0"
		ips >"$STUB/out"
		expect "IPS minor answered" ok "$(verdict "IPS over HTTP, minor")"
		table "SJB-IPS-TEST-MINOR 000 56"
		ips >"$STUB/out"
		expect "IPS minor cut" FAIL "$(verdict "IPS over HTTP, minor")"

		echo "$pass $fail" >"$STUB/count"
	)
	if [[ ! -s $STUB/count ]]; then
		fail=$((fail + 1)); echo "  FAIL $script: stopped before its checks ran"; return
	fi
	read -r p f <"$STUB/count"
	pass=$p fail=$f
}

run_suite tools/policy-test.sh
run_suite tools/lab-test.sh -r inside
echo "harness-test: $pass passed, $fail failed"
((fail == 0))
