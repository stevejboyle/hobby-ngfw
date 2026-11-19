#!/usr/bin/env bash
# Phase 1 gate: commit, tag API (REST and XML user-ID), rollback, commit
# confirmed and restart recovery, end to end in the namespace lab.
# Linux only; needs root, nft, conntrack, python3 and curl. Binaries from $BIN (./bin).
set -uo pipefail

BIN=${BIN:-./bin}
WORK=$(mktemp -d)
SOCK=$WORK/ngfwd.sock
API=http://127.0.0.1:8080
USER_IP=10.10.1.10
FAILS=0
NGFWD_PID=
WEB_PID=

cleanup() {
	[[ -n $NGFWD_PID ]] && kill "$NGFWD_PID" 2>/dev/null
	[[ -n $WEB_PID ]] && kill "$WEB_PID" 2>/dev/null
	[[ -n ${FWSVC_PID:-} ]] && kill "$FWSVC_PID" 2>/dev/null
	wait 2>/dev/null
	./lab/topology.sh down >/dev/null
	if (( FAILS > 0 )); then
		echo "--- ngfwd log ---"
		cat "$WORK/ngfwd.log" 2>/dev/null
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }

fw() { "$BIN/fwctl" -socket "$SOCK" "$@"; }
in_fw() { ip netns exec ngfw-fw "$@"; }
can_ping() { ip netns exec ngfw-users ping -c 1 -W 1 203.0.113.10 >/dev/null 2>&1; }
can_web() { ip netns exec ngfw-users timeout 2 bash -c 'exec 3<>/dev/tcp/203.0.113.10/80' 2>/dev/null; }

expect() { # expect ok|blocked DESCRIPTION CHECK
	local want=$1 desc=$2; shift 2
	if "$@"; then got=ok; else got=blocked; fi
	if [[ $got == "$want" ]]; then pass "$desc ($got)"; else fail "$desc (want $want, got $got)"; fi
}

start_ngfwd() {
	# Call ip directly, not the in_fw function: backgrounding a function
	# forks a subshell, and $! would be its PID instead of ngfwd's.
	ip netns exec ngfw-fw "$BIN/ngfwd" -state "$WORK/state" -socket "$SOCK" -users "$WORK/users.json" -roles "$WORK/roles.json" -web-users "$WORK/web-users" -unix-accounts=false \
		-api-listen 127.0.0.1:8080 -api-keys "$WORK/keys" >>"$WORK/ngfwd.log" 2>&1 &
	NGFWD_PID=$!
	for _ in $(seq 50); do
		fw status >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	fail "ngfwd did not start"
	exit 1
}

ms() { date +%s%3N; }

api_json() { # api_json PATH BODY -> prints HTTP code
	in_fw curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $KEY" \
		-H 'Content-Type: application/json' -d "$2" "$API$1"
}

pan_uid() { # pan_uid register|unregister IP TAG -> prints HTTP code
	local inner="<entry ip=\"$2\"><tag><member timeout=\"300\">$3</member></tag></entry>"
	local cmd="<uid-message><version>2.0</version><type>update</type><payload><$1>$inner</$1></payload></uid-message>"
	in_fw curl -s -o /dev/null -w '%{http_code}' --data-urlencode "type=user-id" \
		--data-urlencode "key=$KEY" --data-urlencode "cmd=$cmd" "$API/api/"
}

# --- setup -------------------------------------------------------------------
./lab/topology.sh up
KEY=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
echo "gate-test tags:read,tags:write $KEY" >"$WORK/keys"
sed '/- name: allow-web/,$d' examples/lab.yaml >"$WORK/no-web.yaml"
ip netns exec ngfw-inet python3 -m http.server 80 --bind 203.0.113.10 >"$WORK/web.log" 2>&1 &
WEB_PID=$!
# A service on the firewall itself, to check zones can't reach it.
ip netns exec ngfw-fw python3 -m http.server 2222 --bind 10.10.1.1 >/dev/null 2>&1 &
FWSVC_PID=$!
sleep 1
start_ngfwd

# --- 1. default deny before any commit -----------------------------------------
expect blocked "no config: forward default-deny" can_ping

# --- 2. first commit ------------------------------------------------------------
fw load examples/lab.yaml >/dev/null && fw commit -m "lab" >/dev/null || fail "commit lab.yaml"
expect ok "rev 1: ping allowed" can_ping
expect ok "rev 1: web allowed" can_web
ip netns exec ngfw-users curl -s -m 2 -o /dev/null http://203.0.113.10/
if grep -q '^203\.0\.113\.1 ' "$WORK/web.log"; then pass "NAT: server sees the firewall's outside address"
else fail "NAT: server did not see 203.0.113.1 ($(tail -1 "$WORK/web.log"))"; fi
can_fw_ping() { ip netns exec ngfw-users ping -c 1 -W 1 10.10.1.1 >/dev/null 2>&1; }
can_fw_svc() { ip netns exec ngfw-users timeout 2 bash -c 'exec 3<>/dev/tcp/10.10.1.1/2222' 2>/dev/null; }
expect ok "users zone can ping the firewall" can_fw_ping
expect blocked "users zone cannot reach services on the firewall" can_fw_svc

# --- 3. tag API (REST): block a host in under 1 second ---------------------------
# Hold a TCP session open first; quarantining the host must clear it.
ip netns exec ngfw-users bash -c 'exec 3<>/dev/tcp/203.0.113.10/80; sleep 20' 2>/dev/null &
HOLD_PID=$!
sleep 0.5
tcp_sessions() { in_fw conntrack -L -p tcp -s "$USER_IP" 2>/dev/null | grep -c ESTABLISHED; }
[[ $(tcp_sessions) -ge 1 ]] && pass "open TCP session tracked before quarantine" || fail "no TCP session to test with"
t0=$(ms)
code=$(api_json /api/v1/tags/register "{\"ip\":\"$USER_IP\",\"tags\":[\"quarantine\"],\"ttl\":300}")
t1=$(ms)
[[ $code == 200 ]] || fail "REST register returned $code"
expect blocked "REST register quarantine" can_ping
elapsed=$((t1 - t0))
if (( elapsed < 1000 )); then pass "tag API applied in ${elapsed} ms (< 1000)"; else fail "tag API took ${elapsed} ms"; fi
[[ $(tcp_sessions) -eq 0 ]] && pass "quarantine cleared the host's open TCP session" || fail "TCP session survived quarantine"
kill "$HOLD_PID" 2>/dev/null

code=$(in_fw curl -s -o /dev/null -w '%{http_code}' -d "{\"ip\":\"$USER_IP\",\"tags\":[\"x\"]}" "$API/api/v1/tags/register")
[[ $code == 401 ]] && pass "REST without key rejected (401)" || fail "REST without key returned $code"

code=$(api_json /api/v1/tags/unregister "{\"ip\":\"$USER_IP\",\"tags\":[\"quarantine\"]}")
[[ $code == 200 ]] || fail "REST unregister returned $code"
expect ok "REST unregister quarantine" can_ping

# --- 4. tag API (XML user-ID uid-message) ---------------------------------------
code=$(pan_uid register "$USER_IP" quarantine)
[[ $code == 200 ]] || fail "XML user-ID register returned $code"
expect blocked "XML user-ID register quarantine" can_ping
code=$(pan_uid unregister "$USER_IP" quarantine)
[[ $code == 200 ]] || fail "XML user-ID unregister returned $code"
expect ok "XML user-ID unregister quarantine" can_ping

# --- 5. commit and rollback -----------------------------------------------------
fw load "$WORK/no-web.yaml" >/dev/null && fw commit -m "drop web" >/dev/null || fail "commit no-web"
expect blocked "rev 2 (no allow-web): web" can_web
expect ok "rev 2: ping still allowed" can_ping
fw rollback 1 >/dev/null || fail "rollback 1"
expect ok "rollback to rev 1: web restored" can_web

# --- 6. commit confirmed, not confirmed -> automatic rollback ---------------------
fw load "$WORK/no-web.yaml" >/dev/null && fw commit -m "risky" -confirm 3s >/dev/null || fail "commit confirmed"
expect blocked "unconfirmed commit active: web" can_web
sleep 4
expect ok "auto-rollback after 3s: web restored" can_web

# --- 7. restart recovery: ruleset and tags come back -----------------------------
api_json /api/v1/tags/register "{\"ip\":\"$USER_IP\",\"tags\":[\"quarantine\"],\"ttl\":300}" >/dev/null
kill "$NGFWD_PID"; wait "$NGFWD_PID" 2>/dev/null
in_fw nft flush ruleset
expect ok "ruleset flushed while ngfwd down (sanity)" can_ping
start_ngfwd
kill -0 "$NGFWD_PID" 2>/dev/null && pass "ngfwd restarted" || fail "ngfwd died after restart"
expect blocked "after restart: quarantine registration restored" can_ping
api_json /api/v1/tags/unregister "{\"ip\":\"$USER_IP\",\"tags\":[\"quarantine\"]}" >/dev/null
expect ok "after restart: running rules restored (web)" can_web

echo
if (( FAILS > 0 )); then echo "GATE 1: $FAILS check(s) failed"; exit 1; fi
echo "GATE 1: all checks passed"
