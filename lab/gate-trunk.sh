#!/usr/bin/env bash
# Trunk gate: an interface with no zone that carries VLANs. veth-users
# becomes a trunk with VLAN 150 (zone users); ngfw-users talks tagged on
# eth0.150 and, for the checks, untagged on eth0 too.
#   - with veth-users in a zone, untagged traffic works (the baseline)
#   - as a trunk: tagged traffic reaches the firewall and the internet;
#     untagged traffic reaches neither, even with an allow-everything rule;
#     the drop counters show it
#   - in a zone again, untagged works again
# Linux only; needs root, nft, conntrack and ping. Binaries from $BIN (./bin).
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
check() { local d=$1; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
fw() { "$BIN/fwctl" -socket "$SOCK" "$@"; }
users() { ip netns exec ngfw-users "$@"; }
reach() { users ping -c 1 -W 1 "$@" >/dev/null 2>&1; }
commit() { fw load "$1" >/dev/null && fw commit -m "$2" >/dev/null 2>&1 || fail "commit $2"; }

config() { # config FILE TRUNK(yes|no)
	{
		cat <<'EOF'
system:
  hostname: fw-lab
zones:
  - name: users
  - name: internet
interfaces:
  - name: veth-inet
    zone: internet
    address: 203.0.113.1/24
  - name: veth-users.150
    zone: users
    address: 10.10.150.1/24
EOF
		if [[ $2 == yes ]]; then
			printf '  - name: veth-users\n'
		else
			printf '  - name: veth-users\n    zone: users\n'
		fi
		cat <<'EOF'
nat:
  - name: out
    type: masquerade
    from: [users]
    to: [internet]
rules:
  - name: everything
    action: allow
EOF
	} >"$WORK/$1.yaml"
	echo "$WORK/$1.yaml"
}

# --- run ----------------------------------------------------------------------
./lab/topology.sh up >/dev/null
ip -n ngfw-inet addr add 203.0.113.11/24 dev eth0
users ip link add link eth0 name eth0.150 type vlan id 150
users ip addr add 10.10.150.10/24 dev eth0.150
users ip link set eth0.150 up
# 203.0.113.10 tagged (VLAN 150), 203.0.113.11 untagged.
users ip route add 203.0.113.10/32 via 10.10.150.1 dev eth0.150
users ip route add 203.0.113.11/32 via 10.10.1.1 dev eth0

ip netns exec ngfw-fw "$BIN/ngfwd" -state "$WORK/state" -socket "$SOCK" -users "$WORK/users.json" -roles "$WORK/roles.json" -web-users "$WORK/web-users" -unix-accounts=false -ips-dir "" >>"$WORK/ngfwd.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 50); do fw status >/dev/null 2>&1 && break; sleep 0.1; done

# 1. Baseline: veth-users in zone users.
commit "$(config zoned no)" "veth-users in a zone"
sleep 1
check "zoned: VLAN 150 created with 10.10.150.1" bash -c 'ip -n ngfw-fw -4 addr show dev veth-users.150 | grep -q 10.10.150.1/24'
check "zoned: untagged ping to the firewall answers" reach 10.10.1.1
check "zoned: untagged traffic reaches the internet" reach 203.0.113.11

# 2. Trunk: no zone.
commit "$(config trunk yes)" "veth-users a trunk"
check "trunk: the ruleset drops untagged traffic on veth-users" bash -c 'ip netns exec ngfw-fw nft list table inet ngfw | grep -q "iifname \"veth-users\" counter .*drop comment \"trunk: untagged\""'
check "trunk: tagged ping to the firewall (10.10.150.1) answers" reach 10.10.150.1
check "trunk: tagged traffic reaches the internet" reach 203.0.113.10
check "trunk: untagged ping to the firewall gets no answer" bash -c '! ip netns exec ngfw-users ping -c 1 -W 1 10.10.1.1 >/dev/null 2>&1'
check "trunk: untagged traffic doesn't reach the internet, even with an allow-everything rule" bash -c '! ip netns exec ngfw-users ping -c 1 -W 1 203.0.113.11 >/dev/null 2>&1'
drops=$(ip netns exec ngfw-fw nft list chain inet ngfw forward | awk '/iifname "veth-users" counter/ {for (i=1;i<=NF;i++) if ($i=="packets") print $(i+1)}')
check "trunk: the forward drop counter shows the untagged packets ($drops)" test "${drops:-0}" -ge 1

# 3. Back in a zone: untagged works again.
commit "$(config zoned2 no)" "veth-users in a zone again"
check "zoned again: no trunk drop in the ruleset" bash -c '! ip netns exec ngfw-fw nft list table inet ngfw | grep -q "trunk: untagged"'
check "zoned again: untagged traffic reaches the internet" reach 203.0.113.11

echo
if (( FAILS > 0 )); then echo "TRUNK GATE: $FAILS check(s) failed"; exit 1; fi
echo "TRUNK GATE: all checks passed"
