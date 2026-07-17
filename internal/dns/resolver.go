package dns

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// NetResolver adapts net.Resolver to the typed Resolver contract. net.Resolver
// does not expose record TTLs, so LocalTTL is explicitly a local cache policy,
// not an authoritative DNS TTL.
type NetResolver struct {
	Resolver *net.Resolver
	LocalTTL time.Duration
	Clock    Clock
}

func (r *NetResolver) Resolve(ctx context.Context, query Query) (Result, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	network := "ip"
	switch query.Family {
	case FamilyIPv4:
		network = "ip4"
	case FamilyIPv6:
		network = "ip6"
	}
	addrs, err := resolver.LookupNetIP(ctx, network, query.Host)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return Result{RCode: RCodeNXDOMAIN}, nil
		}
		return Result{}, err
	}
	if len(addrs) == 0 {
		return Result{RCode: RCodeNODATA}, nil
	}
	clock := r.Clock
	if clock == nil {
		clock = realClock{}
	}
	result := Result{RCode: RCodeSuccess, ExpiresAt: clock.Now().Add(r.LocalTTL), Addrs: make([]netip.Addr, 0, len(addrs))}
	result.Addrs = append(result.Addrs, addrs...)
	return result, nil
}
