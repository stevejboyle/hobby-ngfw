#!/usr/bin/env bash
# Network-namespace lab: a firewall namespace between "users" and "internet".
#
#   ngfw-users (10.10.1.10) --veth-users-- ngfw-fw --veth-inet-- ngfw-inet (203.0.113.10)
#
# Interface names inside ngfw-fw match examples/basic.yaml.
# Linux only; needs root. Usage: topology.sh up|down|status
set -euo pipefail

FW=ngfw-fw
USERS=ngfw-users
INET=ngfw-inet

up() {
	down quiet
	for ns in "$FW" "$USERS" "$INET"; do
		ip netns add "$ns"
		ip -n "$ns" link set lo up
	done

	ip link add veth-users netns "$FW" type veth peer name eth0 netns "$USERS"
	ip link add veth-inet netns "$FW" type veth peer name eth0 netns "$INET"

	ip -n "$FW" addr add 10.10.1.1/24 dev veth-users
	ip -n "$FW" addr add 203.0.113.1/24 dev veth-inet
	ip -n "$FW" link set veth-users up
	ip -n "$FW" link set veth-inet up
	ip netns exec "$FW" sysctl -qw net.ipv4.ip_forward=1

	ip -n "$USERS" addr add 10.10.1.10/24 dev eth0
	ip -n "$USERS" link set eth0 up
	ip -n "$USERS" route add default via 10.10.1.1

	ip -n "$INET" addr add 203.0.113.10/24 dev eth0
	ip -n "$INET" link set eth0 up
	ip -n "$INET" route add default via 203.0.113.1

	echo "lab up: $USERS -> $FW -> $INET"
}

down() {
	for ns in "$FW" "$USERS" "$INET"; do
		ip netns del "$ns" 2>/dev/null || true
	done
	[[ "${1:-}" == quiet ]] || echo "lab down"
}

status() {
	ip netns list | grep -E "^ngfw-" || echo "lab not running"
}

case "${1:-}" in
	up) up ;;
	down) down ;;
	status) status ;;
	*) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
