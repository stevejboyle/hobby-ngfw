package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"time"
)

const ipTransparent = 19 // IP_TRANSPARENT

// inNetns runs fn with the calling goroutine's thread in the network
// namespace at path (sockets created there stay there). If the thread
// can't be switched back it is left locked, and Go retires it when the
// goroutine ends, so no other goroutine ever runs in the wrong namespace.
func inNetns(path string, fn func() error) error {
	runtime.LockOSThread()
	orig, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer orig.Close()
	target, err := os.Open(path)
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer target.Close()
	if err := setns(target); err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("entering %s: %w", path, err)
	}
	ferr := fn()
	if err := setns(orig); err != nil {
		return fmt.Errorf("leaving %s: %w (thread retired)", path, err)
	}
	runtime.UnlockOSThread()
	return ferr
}

func setns(f *os.File) error {
	if _, _, e := syscall.RawSyscall(sysSetns, f.Fd(), syscall.CLONE_NEWNET, 0); e != 0 {
		return e
	}
	return nil
}

// transparent lets a socket bind and accept addresses that aren't the
// firewall's own (tproxy).
func transparent(tos int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, ipTransparent, 1); serr != nil {
				return
			}
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); serr != nil {
				return
			}
			if tos > 0 {
				serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}

// listenTransparent listens on port for connections to any address, in the
// network namespace at ns ("" = tlsd's own).
func listenTransparent(ns string, port int) (net.Listener, error) {
	var ln net.Listener
	listen := func() error {
		var err error
		lc := net.ListenConfig{Control: transparent(0)}
		ln, err = lc.Listen(context.Background(), "tcp4", fmt.Sprintf("0.0.0.0:%d", port))
		return err
	}
	if ns == "" {
		return ln, listen()
	}
	return ln, inNetns(ns, listen)
}

// dialLoop opens the loop leg in the client-half namespace: from the
// client's own address and port to the server, DSCP-marked with the
// client's zone, so the forward chain sees the original connection.
func dialLoop(ctx context.Context, ns string, client, server netip.AddrPort, dscp int) (net.Conn, error) {
	var c net.Conn
	err := inNetns(ns, func() error {
		d := net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(client), Control: transparent(dscp << 2), Timeout: loopTimeout}
		var err error
		c, err = d.DialContext(ctx, "tcp4", server.String())
		return err
	})
	return c, err
}

// socketMark reads the mark the kernel gave an accepted connection (the
// SYN's, with net.ipv4.tcp_fwmark_accept).
func socketMark(c net.Conn) (uint32, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, fmt.Errorf("no socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var mark int
	var gerr error
	if err := raw.Control(func(fd uintptr) { mark, gerr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK) }); err != nil {
		return 0, err
	}
	return uint32(mark), gerr
}

// reset closes a TCP connection with a reset instead of a FIN.
func reset(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetLinger(0)
	}
	c.Close()
}

var loopTimeout = 5 * time.Second
