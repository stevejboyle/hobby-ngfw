#!/usr/bin/env bash
# Smoke test: traffic crosses the firewall namespace in both directions.
# Phase 0 has no policy loaded, so everything should pass.
set -euo pipefail

fail=0
check() {
	local desc=$1; shift
	if "$@" >/dev/null 2>&1; then
		echo "PASS  $desc"
	else
		echo "FAIL  $desc"
		fail=1
	fi
}

check "users -> fw gateway"   ip netns exec ngfw-users ping -c 2 -W 1 10.10.1.1
check "users -> internet host" ip netns exec ngfw-users ping -c 2 -W 1 203.0.113.10
check "internet -> users host" ip netns exec ngfw-inet ping -c 2 -W 1 10.10.1.10

exit "$fail"
