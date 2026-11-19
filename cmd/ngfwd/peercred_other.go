//go:build !linux

package main

import (
	"net"
	"os"
)

// peerUID on development hosts (macOS): the socket is 0600 and owned by
// the user running ngfwd, so only that user can connect.
func peerUID(net.Conn) (int, error) { return os.Getuid(), nil }
