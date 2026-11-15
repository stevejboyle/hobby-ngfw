#!/usr/bin/env bash
# Validate the FRR configs SJB-OS generates (the golden files) with the
# appliance's FRR, as root: vtysh -C must accept each one silently (any
# output means it skipped or complained about something), and must reject
# the malformed sample, so a broken check can't pass unnoticed.
# Run inside Debian 13 (the appliance's FRR), e.g.:
#   docker run --rm -v "$PWD":/src:ro -w /src debian:trixie lab/check-frr.sh
set -uo pipefail
if ! command -v vtysh >/dev/null; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null && apt-get install -y -qq --no-install-recommends frr >/dev/null 2>&1
fi
[[ $(id -u) == 0 ]] || { echo "run as root: vtysh can't read its own config otherwise"; exit 2; }
fails=0
n=0
for f in internal/frr/testdata/*.conf; do
	n=$((n + 1))
	out=$(vtysh -C -f "$f" 2>&1)
	rc=$?
	if (( rc != 0 )) || [[ -n $out ]]; then
		echo "FAIL  $f (exit $rc): $out"
		fails=$((fails + 1))
	else
		echo "ok    $f"
	fi
done
(( n > 0 )) || { echo "FAIL  no FRR configs found to check"; exit 1; }
for f in internal/frr/testdata/invalid/*.conf; do
	if vtysh -C -f "$f" >/dev/null 2>&1; then
		echo "FAIL  $f was accepted: the validation isn't checking"
		fails=$((fails + 1))
	else
		echo "ok    $f rejected, as it should be"
	fi
done
(( fails == 0 )) && echo "FRR configs: all valid" || { echo "FRR configs: $fails problem(s)"; exit 1; }
