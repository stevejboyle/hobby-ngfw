//go:build !linux

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// tlsd runs only on the appliance (Linux); these let it build elsewhere.

var errLinux = errors.New("tlsd needs Linux (tproxy, network namespaces)")

func listenTransparent(ns string, port int) (net.Listener, error) { return nil, errLinux }

func dialLoop(ctx context.Context, ns string, client, server netip.AddrPort, dscp int) (net.Conn, error) {
	return nil, errLinux
}

func socketMark(c net.Conn) (uint32, error) { return 0, errLinux }

func reset(c net.Conn) { c.Close() }

var loopTimeout = 5 * time.Second
