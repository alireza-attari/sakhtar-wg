// Package proxy contains policy-neutral address selection and bounded retry
// primitives used by the SNI/HTTP proxy.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
)

type AddressFamilyStrategy string

const (
	IPv4First  AddressFamilyStrategy = "ipv4_first"
	IPv6First  AddressFamilyStrategy = "ipv6_first"
	Interleave AddressFamilyStrategy = "interleave"
)

func (s AddressFamilyStrategy) Valid() bool {
	return s == IPv4First || s == IPv6First || s == Interleave
}

type AddressSelector interface {
	Select([]netip.Addr, func(netip.Addr) bool) []netip.Addr
}

// RotatingSelector de-duplicates and policy-filters candidates, then rotates
// the starting point on every call. This avoids permanently pinning traffic to
// element zero while retaining deterministic behavior under tests.
type RotatingSelector struct {
	Strategy    AddressFamilyStrategy
	MaxAttempts int
	cursor      atomic.Uint64
}

func (s *RotatingSelector) Select(input []netip.Addr, allowed func(netip.Addr) bool) []netip.Addr {
	if s.MaxAttempts <= 0 {
		return nil
	}
	seen := make(map[netip.Addr]struct{}, len(input))
	v4 := make([]netip.Addr, 0, len(input))
	v6 := make([]netip.Addr, 0, len(input))
	for _, addr := range input {
		if !addr.IsValid() || addr.Zone() != "" {
			continue
		}
		addr = addr.Unmap()
		if allowed != nil && !allowed(addr) {
			continue
		}
		if _, duplicate := seen[addr]; duplicate {
			continue
		}
		seen[addr] = struct{}{}
		if addr.Is4() {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	sequence := s.cursor.Add(1) - 1
	rotate(v4, sequence)
	rotate(v6, sequence)
	ordered := make([]netip.Addr, 0, len(v4)+len(v6))
	switch s.Strategy {
	case IPv6First:
		ordered = append(ordered, v6...)
		ordered = append(ordered, v4...)
	case Interleave:
		first, second := v6, v4
		if sequence%2 == 1 {
			first, second = second, first
		}
		for len(first) > 0 || len(second) > 0 {
			if len(first) > 0 {
				ordered = append(ordered, first[0])
				first = first[1:]
			}
			if len(second) > 0 {
				ordered = append(ordered, second[0])
				second = second[1:]
			}
		}
	default:
		ordered = append(ordered, v4...)
		ordered = append(ordered, v6...)
	}
	if len(ordered) > s.MaxAttempts {
		ordered = ordered[:s.MaxAttempts]
	}
	return ordered
}

func rotate(addrs []netip.Addr, sequence uint64) {
	if len(addrs) < 2 {
		return
	}
	start := int(sequence % uint64(len(addrs)))
	reverse(addrs[:start])
	reverse(addrs[start:])
	reverse(addrs)
}

func reverse(addrs []netip.Addr) {
	for left, right := 0, len(addrs)-1; left < right; left, right = left+1, right-1 {
		addrs[left], addrs[right] = addrs[right], addrs[left]
	}
}

type DialFunc func(context.Context, string, string) (net.Conn, error)

type ConnectMetrics struct {
	successDirect atomic.Uint64
	failureDirect atomic.Uint64
	successMarked atomic.Uint64
	failureMarked atomic.Uint64
}

func (m *ConnectMetrics) record(success, marked bool) {
	switch {
	case success && marked:
		m.successMarked.Add(1)
	case success:
		m.successDirect.Add(1)
	case marked:
		m.failureMarked.Add(1)
	default:
		m.failureDirect.Add(1)
	}
}

func (m *ConnectMetrics) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"success|direct": m.successDirect.Load(),
		"failure|direct": m.failureDirect.Load(),
		"success|marked": m.successMarked.Load(),
		"failure|marked": m.failureMarked.Load(),
	}
}

// DialCandidates retries only the already validated IP literals supplied by
// the selector. The caller owns ctx's total deadline; no attempt receives a new
// budget. The returned count is useful for bounded observability and tests.
func DialCandidates(ctx context.Context, candidates []netip.Addr, port string, attemptCap int, marked bool, dial DialFunc, metrics *ConnectMetrics) (net.Conn, int, error) {
	if attemptCap <= 0 {
		return nil, 0, errors.New("proxy: connect attempt cap must be greater than zero")
	}
	if dial == nil {
		return nil, 0, errors.New("proxy: nil dial function")
	}
	if len(candidates) > attemptCap {
		candidates = candidates[:attemptCap]
	}
	errs := make([]error, 0, len(candidates))
	attempts := 0
	for i, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		address := net.JoinHostPort(candidate.String(), port)
		attempts++
		conn, err := dial(ctx, "tcp", address)
		if err == nil {
			if metrics != nil {
				metrics.record(true, marked)
			}
			return conn, i + 1, nil
		}
		if metrics != nil {
			metrics.record(false, marked)
		}
		errs = append(errs, fmt.Errorf("%s: %w", address, err))
	}
	if len(errs) == 0 {
		return nil, 0, errors.New("proxy: no dialable addresses")
	}
	return nil, attempts, errors.Join(errs...)
}
