.PHONY: build test validate lab-up lab-down lab-status lab-smoke lab-gate1 lab-gate-sessions clean

build:
	go build -o bin/ ./cmd/...

test:
	go vet ./...
	go test -race ./...

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

clean:
	rm -rf bin
