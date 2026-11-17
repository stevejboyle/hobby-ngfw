package main

import "syscall"

// setHostname sets the running system's hostname (the UTS name).
func setHostname(name string) error { return syscall.Sethostname([]byte(name)) }
