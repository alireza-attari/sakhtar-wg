//go:build !linux

package main

import (
	"context"
	"errors"
	"net"
	"time"
)

var errMarkedDialUnsupported = errors.New("SO_MARK is only supported on Linux")

func dialMarkedContext(ctx context.Context, network, addr string, mark int, timeout time.Duration) (net.Conn, error) {
	if mark != 0 {
		return nil, errMarkedDialUnsupported
	}
	return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, addr)
}
