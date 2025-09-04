//go:build !linux

package netbind

import "syscall"

// ControlBindToDevice is a no-op on non-Linux platforms.
func ControlBindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
    return func(network, address string, c syscall.RawConn) error { return nil }
}

