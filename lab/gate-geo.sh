#!/usr/bin/env bash
# Geo-blocking gate: rules by country, with a test country database.
# ngfw-users (10.10.1.10) serves a web page; ngfw-inet is the internet,
# with two addresses that the test database puts in two countries:
#   203.0.113.10  -> CN
#   198.51.100.10 -> US (routed through 203.0.113.10)
# Checks:
#   - a rule naming a country before there is a database: a commit warning
#     and an empty set (the deny rule matches nothing)
#   - fwctl geoip import: the running ruleset gets the ranges with no new
#     revision; geoip lookup and status
#   - deny country:CN: CN blocked, US through
#   - source-negate: deny everything except country:US: CN blocked, US
#     through
#   - a database refresh while traffic flows: no allowed connection fails,
#     no blocked one gets through
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
# get FROM: the page from the server, from one of the internet addresses.
get() { ip netns exec ngfw-inet curl -4 -s -m 3 --interface "$1" http://10.10.1.10/ 2>/dev/null; }
revisions() { fw revisions | grep -c '"n":'; }

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
  - name: server
    cidr: 10.10.1.10
services:
  - name: web
    protocol: tcp
    ports: "80"
rules:
EOF
WEB_IN='  - name: web-in
    from: [internet]
    to: [users]
    destination: [server]
    service: [web]
    action: allow'
DENY_CN='  - name: deny-cn
    from: [internet]
    source: [country:CN]
    action: deny'
US_ONLY='  - name: us-only
    from: [internet]
    source: [country:US]
    source_negate: true
    action: deny'
config() { # config NAME PARTS...
	local f=$WORK/$1.yaml; shift
	{ cat "$WORK/head.yaml"; printf '%s\n' "$@"; } >"$f"
	echo "$f"
}
COMMIT_OUT=
commit() {
	fw load "$1" >/dev/null || { fail "load $2"; return; }
	COMMIT_OUT=$(fw commit -m "$2" 2>&1) || fail "commit $2: $COMMIT_OUT"
}
# The test database (DB-IP's CSV format).
printf '203.0.113.0,203.0.113.255,CN\n198.51.100.0,198.51.100.255,US\n' >"$WORK/test-db.csv"

# --- run ----------------------------------------------------------------------
./lab/topology.sh up >/dev/null
ip -n ngfw-inet addr add 198.51.100.10/32 dev eth0
in_fw ip route add 198.51.100.0/24 via 203.0.113.10
mkdir -p "$WORK/www" && echo "sjb-geo-gate" >"$WORK/www/index.html"
ip netns exec ngfw-users python3 -m http.server 80 --bind 0.0.0.0 --directory "$WORK/www" >/dev/null 2>&1 &
PIDS+=($!)
in_fw "$BIN/ngfwd" -state "$WORK/state" -socket "$SOCK" -users "$WORK/users.json" -roles "$WORK/roles.json" -web-users "$WORK/web-users" \
	-unix-accounts=false -ips-dir "" -root "$WORK/root" -geoip-dir "$WORK/geoip" >>"$WORK/ngfwd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do fw status >/dev/null 2>&1 && break; sleep 0.1; done
sleep 1

# 1. A country rule before there is a database.
commit "$(config deny-cn "$DENY_CN" "$WEB_IN")" "deny CN, no database yet"
check "commit warns there is no country database yet" grep -q 'country:CN: there is no country database yet' <<<"$COMMIT_OUT"
check "without a database the CN set is empty, so CN gets through" test "$(get 203.0.113.10)" = sjb-geo-gate

# 2. Import: the running ruleset gets the ranges, no new revision.
before=$(revisions)
out=$(fw geoip import "$WORK/test-db.csv" 2>&1)
check "fwctl geoip import: CN in use with its range" grep -Eq 'CN +China +1 ranges' <<<"$out"
check "the import made no new revision" test "$(revisions)" = "$before"
check "the CN set holds 203.0.113.0/24" grep -q '203.0.113.0/24' <<<"$(in_fw nft list set inet ngfw geo_cn)"
check "geoip lookup 203.0.113.77: CN" grep -q 'CN (China)' <<<"$(fw geoip lookup 203.0.113.77)"
check "geoip lookup 10.10.1.10: no country" grep -q 'no country' <<<"$(fw geoip lookup 10.10.1.10)"

# 3. deny country:CN.
check "deny country:CN: CN blocked" test -z "$(get 203.0.113.10)"
check "deny country:CN: US gets through" test "$(get 198.51.100.10)" = sjb-geo-gate

# 4. Everything except the US denied (source-negate).
commit "$(config us-only "$US_ONLY" "$WEB_IN")" "everything but the US denied"
check "negated rule: one nft rule excluding the US set" grep -q 'ip saddr != @geo_us .* drop comment "rule:us-only"' <<<"$(in_fw nft list chain inet ngfw forward)"
check "US only: US gets through" test "$(get 198.51.100.10)" = sjb-geo-gate
check "US only: CN blocked" test -z "$(get 203.0.113.10)"

# 5. Refreshes while traffic flows: allowed requests never fail, blocked
# ones never get through.
ok=0 bad=0 leak=0
before=$(revisions) # after step 4's commit
( for _ in $(seq 6); do fw geoip import "$WORK/test-db.csv" >/dev/null 2>&1; sleep 0.3; done ) &
refresher=$!
for _ in $(seq 40); do
	[[ $(get 198.51.100.10) == sjb-geo-gate ]] && ok=$((ok + 1)) || bad=$((bad + 1))
	[[ -n $(get 203.0.113.10) ]] && leak=$((leak + 1))
done
wait "$refresher"
check "6 refreshes during 40 requests from each side: $ok allowed, $bad failed, $leak leaked" test "$bad" = 0 -a "$leak" = 0
check "still no new revision after the refreshes" test "$(revisions)" = "$before"

echo
if (( FAILS > 0 )); then echo "GEO GATE: $FAILS check(s) failed"; exit 1; fi
echo "GEO GATE: all checks passed"
