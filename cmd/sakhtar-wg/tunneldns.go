package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	proxydial "github.com/alireza-attari/sakhtar-wg/internal/proxy"
)

type markedDialFunc func(context.Context, string, string, int, time.Duration) (net.Conn, error)

// tunnelResolver resolves through one egress mark, querying each server over
// UDP and, when UDP times out, over TCP to the same server.
//
// Go's resolver retries over TCP only on a truncated reply, never on a timeout,
// and under a single context deadline it makes one UDP attempt. A path that
// drops most UDP to a resolver therefore took a tunnel's DNS down completely:
// OpenDNS answered 4-8 of 20 UDP queries from wg18's exit and 20 of 20 over
// TCP. Each server gets a slice of the budget, split between UDP and TCP.
type tunnelResolver struct {
	udp     []*net.Resolver
	tcp     []*net.Resolver
	timeout time.Duration
	slice   func(remaining time.Duration, attemptsLeft int) time.Duration
}

func newTunnelResolver(dial markedDialFunc, servers []string, mark int, timeout time.Duration) *tunnelResolver {
	r := &tunnelResolver{timeout: timeout, slice: proxydial.BudgetSlice}
	for _, server := range servers {
		r.udp = append(r.udp, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dial(ctx, network, server, mark, timeout)
			},
		})
		// A stream conn makes the Go resolver frame every exchange as DNS over TCP.
		r.tcp = append(r.tcp, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dial(ctx, "tcp", server, mark, timeout)
			},
		})
	}
	return r
}

// LookupNetIP asks for IPv4 records only: the tunnels route IPv4 alone, and an
// AAAA reply lost on a lossy path would hold the whole lookup until its slice
// ran out.
func (r *tunnelResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if network == "ip" {
		network = "ip4"
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	var errs []error
	for i := range r.udp {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		serverCtx, cancelServer := r.sliceOf(ctx, len(r.udp)-i)
		addrs, err := r.lookupServer(serverCtx, i, network, host)
		cancelServer()
		if err == nil || isDNSNotFound(err) {
			return addrs, err
		}
		errs = append(errs, err)
	}
	if len(errs) == 1 {
		return nil, errs[0]
	}
	return nil, errors.Join(errs...)
}

func (r *tunnelResolver) lookupServer(ctx context.Context, server int, network, host string) ([]netip.Addr, error) {
	udpCtx, cancel := r.sliceOf(ctx, 2)
	addrs, err := r.udp[server].LookupNetIP(udpCtx, network, host)
	cancel()
	if err == nil || !isDNSTimeout(err) || ctx.Err() != nil {
		return addrs, err
	}
	return r.tcp[server].LookupNetIP(ctx, network, host)
}

func (r *tunnelResolver) sliceOf(ctx context.Context, attemptsLeft int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, r.slice(time.Until(deadline), attemptsLeft))
}

func isDNSTimeout(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsTimeout || errors.Is(err, context.DeadlineExceeded)
}

func isDNSNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
