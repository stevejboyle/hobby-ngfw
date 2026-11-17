//go:build !linux

package main

import "errors"

func setHostname(string) error { return errors.New("setting the hostname is supported on Linux only") }
