//go:build linux

package netbind

import (
    "golang.org/x/sys/unix"
    "syscall"
)

// ControlBindToDevice returns a net.Dialer.Control function that binds the
// socket to the specified network interface (Linux only). On other platforms,
// this is a no-op (see bind_other.go).
func ControlBindToDevice(iface string) func(network, address string, c syscall.RawConn) error {
    return func(network, address string, c syscall.RawConn) error {
        if iface == "" {
            return nil
        }
        var ctrlErr error
        if err := c.Control(func(fd uintptr) {
            ctrlErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
        }); err != nil {
            return err
        }
        return ctrlErr
    }
}

