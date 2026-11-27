.PHONY: build test validate lab-up lab-down lab-status lab-smoke lab-gate1 lab-gate-sessions lab-gate-decrypt lab-gate-nat lab-gate-trunk lab-gate-logfwd lab-gate-users lab-gate-geo harness-test clean

build:
	go build -o bin/ ./cmd/...

test:
	go vet ./...
	go test -race ./...

# The client test harnesses' own verdicts, offline (curl stubbed).
harness-test:
	./tools/harness-test.sh

validate: build
	./bin/fwctl validate examples/*.yaml

# Lab targets: Linux only, run as root.
lab-up:
	./lab/topology.sh up

lab-down:
	./lab/topology.sh down

lab-status:
	./lab/topology.sh status

lab-smoke:
	./lab/smoke.sh

# Phase 1 gate: needs `make build` first (as your user), then run as root.
lab-gate1:
	./lab/gate1.sh

# Sessions gate: established connections across policy commits (insertion,
# reorder, deletion, IPS-profile change, manual and automatic rollback).
lab-gate-sessions:
	./lab/gate-sessions.sh

# TLS decryption gate: ngfwd, tlsd and the cleartext loop (needs openssl).
# MODE=observe checks observe mode.
lab-gate-decrypt:
	./lab/gate-decrypt.sh

# NAT gate: port forwarding and 1:1 static NAT (publishing a server).
lab-gate-nat:
	./lab/gate-nat.sh

# Trunk gate: an interface with no zone carries VLANs and drops untagged traffic.
lab-gate-trunk:
	./lab/gate-trunk.sh

# Log forwarding gate: UDP, TCP and TLS syslog servers, JSON and CEF, the
# journal position across restarts, and a CLI backup round trip (needs
# python3 and openssl).
lab-gate-logfwd:
	./lab/gate-logfwd.sh

# Geo-blocking gate: country rules, negation and database refreshes, with a
# test country database.
lab-gate-geo:
	./lab/gate-geo.sh

# Users and roles on a real Debian system. It creates accounts and rewrites
# PAM, so it runs in a throwaway container (Docker; Linux binaries in bin/).
lab-gate-users:
	docker run --rm --privileged -v "$$PWD":/src:ro -w /src debian:trixie bash -c \
	  'apt-get update -qq && apt-get install -y -qq openssh-server pamtester procps >/dev/null && ./lab/gate-users.sh'


clean:
	rm -rf bin
