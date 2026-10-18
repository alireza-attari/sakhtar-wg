package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"
)

// IPLookuper is the part of net.Resolver NetResolver uses, so a resolver with
// its own transport policy can stand in for it.
type IPLookuper interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// NetResolver adapts net.Resolver to the typed Resolver contract. net.Resolver
// does not expose record TTLs, so LocalTTL is explicitly a local cache policy,
// not an authoritative DNS TTL.
type NetResolver struct {
	Resolver IPLookuper
	LocalTTL time.Duration
	Clock    Clock
}

func (r *NetResolver) Resolve(ctx context.Context, query Query) (Result, error) {
	var resolver IPLookuper = net.DefaultResolver
	if r.Resolver != nil {
		resolver = r.Resolver
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
		if dnsErr := (*net.DNSError)(nil); errors.As(err, &dnsErr) && dnsErr.IsNotFound {
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
