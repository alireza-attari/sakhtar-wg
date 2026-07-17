//go:build linux

package main

import (
	"context"
	"net"
	"syscall"
	"time"
)

func dialMarkedContext(ctx context.Context, network, addr string, mark int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if mark != 0 {
		d.Control = func(_, _ string, rc syscall.RawConn) error {
			var serr error
			if err := rc.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	return d.DialContext(ctx, network, addr)
}
