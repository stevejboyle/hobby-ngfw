#!/usr/bin/env bash
# ips-test.sh: check a SJB-OS IPS profile from a machine behind the
# firewall. It sends one HTTP request per severity containing SJB-OS's
# test signature text (SJB-IPS-TEST-CRITICAL, -MAJOR, -MINOR, -INFO) and
# reports whether the firewall blocked it. Harmless: an ordinary page fetch.
#
#   ./ips-test.sh                 http://example.com/
#   ./ips-test.sh http://HOST/    another web server reached through the firewall
#
# Under the default profile, critical and major are blocked, minor passes
# (and is logged), informational passes silently. The rule this traffic
# matches must have an IPS profile; see Logs -> Threats afterwards.
set -u
URL=${1:-http://example.com/}
URL=${URL%/}/
command -v curl >/dev/null || { echo "needs curl" >&2; exit 1; }
for level in CRITICAL MAJOR MINOR INFO; do
	code=$(curl -s -o /dev/null -m 8 -w '%{http_code}' "${URL}SJB-IPS-TEST-$level" 2>/dev/null)
	if [[ $code =~ ^[1-5][0-9][0-9]$ ]]; then
		printf '  %-14s passed   (HTTP %s)\n' "$level" "$code"
	else
		printf '  %-14s blocked  (no response within 8 s)\n' "$level"
	fi
done
echo "See Logs -> Threats on the firewall for what matched."
