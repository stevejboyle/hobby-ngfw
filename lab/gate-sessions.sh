#!/usr/bin/env bash
# Sessions gate: established connections across policy commits. A commit
# that changes the policy resets conntrack, so every existing connection is
# re-evaluated against the new rules on its next packet: it can't keep a
# verdict, or a ct mark (rule position, IPS tag), from the old policy.
# Covers rule insertion, reordering, deletion, an IPS-profile change, a
# manual rollback and an automatic rollback.
# Linux only; needs root, nft, conntrack and python3. Binaries from $BIN (./bin).
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
fw() { "$BIN/fwctl" -socket "$SOCK" "$@"; }
in_fw() { ip netns exec ngfw-fw "$@"; }

# --- configs ------------------------------------------------------------------
# rules_<name> are rule lists; config NAME writes the full config with them.
head_yaml() {
	cat <<'EOF'
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
  - name: users-net
    cidr: 10.10.1.0/24
services:
  - name: web
    protocol: tcp
    ports: "80"
  - name: alt
    protocol: tcp
    ports: "8080"
  - name: extra
    protocol: tcp
    ports: "9090"
EOF
}
rule() { # rule NAME SERVICE ACTION [ips_profile]
	printf '  - name: %s\n    from: [users]\n    to: [internet]\n    service: [%s]\n    action: %s\n' "$1" "$2" "$3"
	[[ -n ${4:-} ]] && printf '    ips_profile: %s\n' "$4"
	return 0
}
config() { # config FILE RULE-SPEC... (each spec "name service action [profile]")
	local f=$WORK/$1.yaml; shift
	{ head_yaml; echo "rules:"; for spec in "$@"; do rule $spec; done; } >"$f"
	echo "$f"
}
commit() { # commit FILE MESSAGE [-confirm D]
	local f=$1 m=$2; shift 2
	fw load "$f" >/dev/null && fw commit -m "$m" "$@" >/dev/null || fail "commit $m"
}

# --- sessions -----------------------------------------------------------------
# A session is a TCP connection from users to the echo server that sends a
# line every 0.2 s; its file holds the time of the last echo.
cat >"$WORK/echo.py" <<'EOF'
import socketserver, sys
class H(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            d = self.request.recv(64)
            if not d:
                return
            self.request.sendall(d)
class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
S(("203.0.113.10", int(sys.argv[1])), H).serve_forever()
EOF
cat >"$WORK/client.py" <<'EOF'
import socket, sys, time
port, out = int(sys.argv[1]), sys.argv[2]
s = socket.create_connection(("203.0.113.10", port), timeout=3)
s.settimeout(0.5)
while True:
    try:
        s.sendall(b"x\n")
        if s.recv(64):
            open(out, "w").write(str(time.time()))
    except (socket.timeout, BlockingIOError):
        pass
    except OSError:
        sys.exit(0)  # reset or closed: the session is over
    time.sleep(0.2)
EOF

session() { # session NAME PORT: start a session; NAME's file tracks it
	rm -f "$WORK/s-$1"
	ip netns exec ngfw-users python3 "$WORK/client.py" "$2" "$WORK/s-$1" >/dev/null 2>&1 &
	PIDS+=($!)
	sleep 1.5
}
alive() { # alive NAME: an echo came back in the last 1.2 s (waits 2 s first)
	sleep 2
	[[ -f $WORK/s-$1 ]] && python3 -c "import sys,time; sys.exit(0 if time.time()-float(open('$WORK/s-$1').read()) < 1.2 else 1)"
}
expect() { # expect alive|dead DESCRIPTION NAME
	if alive "$3"; then got=alive; else got=dead; fi
	[[ $got == "$1" ]] && pass "$2 ($got)" || fail "$2 (want $1, got $got)"
}
rulebits() { # rulebits PORT: rule position bits (mark >> 16) of the session's ct entry
	local m
	m=$(in_fw conntrack -L -p tcp --dport "$1" 2>/dev/null | grep -o 'mark=[0-9]*' | head -1 | cut -d= -f2)
	echo $(( ${m:-0} >> 16 ))
}

# --- run ----------------------------------------------------------------------
./lab/topology.sh up >/dev/null
in_fw sysctl -qw net.netfilter.nf_conntrack_tcp_loose=1
for port in 80 8080 9090; do
	ip netns exec ngfw-inet python3 "$WORK/echo.py" "$port" >/dev/null 2>&1 &
	PIDS+=($!)
done
# -ips-dir "": no IPS engine here. Rules with a profile still queue to it,
# with bypass, so traffic flows and the ct mark shows the IPS tag.
ip netns exec ngfw-fw "$BIN/ngfwd" -state "$WORK/state" -socket "$SOCK" -ips-dir "" >>"$WORK/ngfwd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do fw status >/dev/null 2>&1 && break; sleep 0.1; done

BASE=$(config base "allow-web web allow" "allow-alt alt allow")
commit "$BASE" base
session web1 80
session alt1 8080
expect alive "base: web session" web1
expect alive "base: alt session" alt1

# 1. Insertion: a deny above the allow cuts the established web session;
# the alt session (its rule moved down a place) carries on.
INSERT=$(config insert "deny-web web deny" "allow-web web allow" "allow-alt alt allow")
commit "$INSERT" "insert deny-web above allow-web"
expect dead "insertion: established web session re-evaluated and denied" web1
expect alive "insertion: alt session still allowed by its moved rule" alt1

# 2. Manual rollback to base: allowed again; and a session the base policy
# doesn't allow, set up under a newer revision, is cut by the rollback.
EXTRA=$(config extra "allow-web web allow" "allow-alt alt allow" "allow-extra extra allow")
commit "$EXTRA" "allow extra"
session extra1 9090
expect alive "extra allowed: session on 9090" extra1
fw rollback 1 >/dev/null || fail "rollback 1"
expect dead "manual rollback to base: 9090 session re-evaluated and denied" extra1
session web2 80
expect alive "manual rollback to base: new web session" web2

# 3. Reorder: deny-alt below allow-alt lets alt through; moved above, it cuts it.
BELOW=$(config below "allow-web web allow" "allow-alt alt allow" "deny-alt alt deny")
commit "$BELOW" "deny-alt below allow-alt"
session alt2 8080
expect alive "deny-alt below allow-alt: alt session" alt2
ABOVE=$(config above "allow-web web allow" "deny-alt alt deny" "allow-alt alt allow")
commit "$ABOVE" "move deny-alt above allow-alt"
expect dead "reorder: established alt session re-evaluated and denied" alt2

# 4. Deletion: removing the allow rule cuts its sessions.
commit "$BASE" base
session alt3 8080
expect alive "base again: alt session" alt3
NOALT=$(config noalt "allow-web web allow")
commit "$NOALT" "delete allow-alt"
expect dead "deletion: established alt session re-evaluated and denied" alt3

# 5. IPS-profile change: the established session picks up the rule's tag,
# so the IPS would inspect it from its next packet (no stale, untagged mark).
commit "$BASE" base
session alt4 8080
expect alive "base: alt session, no IPS" alt4
[[ $(rulebits 8080) == 0 ]] && pass "no IPS profile: the session carries no rule tag" || fail "untagged expected, rule bits $(rulebits 8080)"
IPS=$(config ips "allow-web web allow" "allow-alt alt allow default")
commit "$IPS" "allow-alt gets ips_profile default"
expect alive "IPS profile added: alt session still allowed" alt4
[[ $(rulebits 8080) == 2 ]] && pass "IPS profile added: the established session now carries allow-alt's tag (position 2)" ||
	fail "rule bits after the IPS change: $(rulebits 8080), want 2"
IPSMOVED=$(config ipsmoved "deny-none extra deny" "allow-web web allow" "allow-alt alt allow default")
commit "$IPSMOVED" "rule inserted above: allow-alt moves to position 3"
expect alive "rule inserted above: alt session still allowed" alt4
[[ $(rulebits 8080) == 3 ]] && pass "rule moved: the established session's tag follows it (position 3)" ||
	fail "rule bits after the move: $(rulebits 8080), want 3"

# 6. Automatic rollback: a session allowed only by the unconfirmed revision
# is cut when it rolls back.
commit "$BASE" base
commit "$EXTRA" "allow extra, unconfirmed" -confirm 7s
session extra2 9090
expect alive "unconfirmed revision: 9090 session" extra2
sleep 4 # past the 7 s deadline
expect dead "automatic rollback: 9090 session re-evaluated and denied" extra2
session web3 80
expect alive "after automatic rollback: new web session" web3

# A commit that changes nothing in the policy leaves sessions alone.
session alt5 8080
commit "$BASE" "same policy again"
expect alive "unchanged policy: alt session untouched" alt5

echo
if (( FAILS > 0 )); then echo "SESSIONS GATE: $FAILS check(s) failed"; exit 1; fi
echo "SESSIONS GATE: all checks passed"
