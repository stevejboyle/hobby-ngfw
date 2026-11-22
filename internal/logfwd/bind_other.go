//go:build !linux

package logfwd

import "syscall"

// bindToDevice is a no-op off Linux (development builds only).
func bindToDevice(string) func(network, address string, c syscall.RawConn) error {
	return nil
}
