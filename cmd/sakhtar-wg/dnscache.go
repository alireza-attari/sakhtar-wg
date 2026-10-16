package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	resolvercache "github.com/alireza-attari/sakhtar-wg/internal/dns"
	proxydial "github.com/alireza-attari/sakhtar-wg/internal/proxy"
)

var errCachedFail = errors.New("cached authoritative negative DNS answer")

const (
	dnsNegTTL   = defaultDNSNegativeTTL * time.Second
	dnsMaxStale = defaultDNSStaleWindow * time.Second
)

// dnsCache is the main-package adapter around the pure bounded cache. The
// adapter remains intentionally small so callers outside the proxy can migrate
// without reintroducing net.IP or cache-key construction.
type dnsCache struct {
	cache      *resolvercache.Cache
	generation uint64
	resolverID string
	// egressNames maps a tunnel's fwmark to its configured name, so cache keys
	// and the resolution metrics carry the tunnel an answer was fetched through
	// rather than an opaque mark number.
	egressNames map[int]string
	now         func() time.Time
}

type dnsCacheClock struct{ cache *dnsCache }

func (c dnsCacheClock) Now() time.Time {
	if c.cache.now != nil {
		return c.cache.now()
	}
	return time.Now()
}

func newDNSCache(posTTL time.Duration) *dnsCache {
	return newDNSCacheWithPolicy(resolvercache.Policy{
		PositiveCapacity:    defaultDNSPositiveCapacity,
		NegativeCapacity:    defaultDNSNegativeCapacity,
		MaxPending:          defaultDNSMaxPending,
		MinPositiveTTL:      time.Second,
		MaxPositiveTTL:      posTTL,
		NegativeTTL:         defaultDNSNegativeTTL * time.Second,
		TransientFailureTTL: defaultDNSTransientTTL * time.Second,
		StaleWindow:         defaultDNSStaleWindow * time.Second,
		StalePolicy:         resolvercache.StaleTransient,
		ResolverTimeout:     defaultDNSResolverTimeout * time.Second,
	}, 1, "legacy", nil)
}

func newDNSCacheForConfig(c *Config, generation uint64) *dnsCache {
	positiveCapacity := positiveOr(c.Proxy.DNSPositiveCapacity, defaultDNSPositiveCapacity)
	negativeCapacity := positiveOr(c.Proxy.DNSNegativeCapacity, defaultDNSNegativeCapacity)
	maxPending := positiveOr(c.Proxy.DNSMaxPending, defaultDNSMaxPending)
	minPositiveTTL := positiveOr(c.Proxy.DNSMinPositiveTTL, defaultDNSMinPositiveTTL)
	maxPositiveTTL := positiveOr(c.Proxy.DNSMaxPositiveTTL, defaultDNSMaxPositiveTTL)
	negativeTTL := positiveOr(c.Proxy.DNSNegativeTTL, defaultDNSNegativeTTL)
	transientTTL := positiveOr(c.Proxy.DNSTransientFailureTTL, defaultDNSTransientTTL)
	staleWindow := c.Proxy.DNSStaleWindow
	if staleWindow == 0 {
		staleWindow = defaultDNSStaleWindow
	}
	stalePolicy := c.Proxy.DNSStalePolicy
	if stalePolicy == "" {
		stalePolicy = string(resolvercache.StaleTransient)
	}
	resolverTimeout := positiveOr(c.Proxy.DNSResolverTimeout, defaultDNSResolverTimeout)
	return newDNSCacheWithPolicy(resolvercache.Policy{
		PositiveCapacity:    positiveCapacity,
		NegativeCapacity:    negativeCapacity,
		MaxPending:          maxPending,
		MinPositiveTTL:      time.Duration(minPositiveTTL) * time.Second,
		MaxPositiveTTL:      time.Duration(maxPositiveTTL) * time.Second,
		NegativeTTL:         time.Duration(negativeTTL) * time.Second,
		TransientFailureTTL: time.Duration(transientTTL) * time.Second,
		StaleWindow:         time.Duration(staleWindow) * time.Second,
		StalePolicy:         resolvercache.StalePolicy(stalePolicy),
		ResolverTimeout:     time.Duration(resolverTimeout) * time.Second,
	}, generation, c.Proxy.Resolver, tunnelNamesByMark(c))
}

func positiveOr(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

// tunnelNamesByMark indexes the configured tunnels by fwmark. Marks are unique
// per tunnel (config validation enforces it), so this is a total mapping.
func tunnelNamesByMark(c *Config) map[int]string {
	names := make(map[int]string, len(c.Tunnels))
	for _, tunnel := range c.Tunnels {
		names[tunnel.Fwmark] = tunnel.Name
	}
	return names
}

func newDNSCacheWithPolicy(policy resolvercache.Policy, generation uint64, resolverID string, egressNames map[int]string) *dnsCache {
	if policy.MaxPositiveTTL < policy.MinPositiveTTL {
		policy.MaxPositiveTTL = policy.MinPositiveTTL
	}
	adapter := &dnsCache{generation: generation, resolverID: resolverID, egressNames: egressNames, now: time.Now}
	cache, err := resolvercache.NewCache(policy, dnsCacheClock{cache: adapter})
	if err != nil {
		panic(err) // validated configuration and constants make this unreachable
	}
	adapter.cache = cache
	return adapter
}

// resolveFn is retained for focused compatibility tests and non-proxy callers.
type resolveFn func(context.Context, string) ([]net.IP, error)

func (c *dnsCache) lookup(ctx context.Context, mark int, host string, resolve resolveFn) ([]net.IP, error) {
	result, err := c.resolve(ctx, mark, host, resolvercache.ResolverFunc(func(resolveCtx context.Context, query resolvercache.Query) (resolvercache.Result, error) {
		ips, resolveErr := resolve(resolveCtx, query.Host)
		if resolveErr != nil {
			return resolvercache.Result{}, resolveErr
		}
		addrs := make([]netip.Addr, 0, len(ips))
		for _, ip := range ips {
			if addr, ok := netip.AddrFromSlice(ip); ok {
				addrs = append(addrs, addr)
			}
		}
		return resolvercache.Result{Addrs: addrs, ExpiresAt: c.now().Add(time.Hour), RCode: resolvercache.RCodeSuccess}, nil
	}))
	if err != nil {
		return nil, err
	}
	if result.RCode != resolvercache.RCodeSuccess {
		return nil, errCachedFail
	}
	ips := make([]net.IP, 0, len(result.Addrs))
	for _, addr := range result.Addrs {
		bytes := addr.AsSlice()
		ips = append(ips, append(net.IP(nil), bytes...))
	}
	return ips, nil
}

func (c *dnsCache) resolve(ctx context.Context, mark int, host string, resolver resolvercache.Resolver) (resolvercache.Result, error) {
	return c.cache.Resolve(ctx, c.query(mark, host), resolver)
}

// invalidate drops the cached answer for host on this egress. The dial path
// calls it when every address the answer produced failed to connect, so the
// next connection re-resolves instead of re-dialing a dead address for the rest
// of the TTL.
func (c *dnsCache) invalidate(mark int, host string) {
	c.cache.Invalidate(c.query(mark, host))
}

func (c *dnsCache) query(mark int, host string) resolvercache.Query {
	egress := c.egressName(mark)
	return resolvercache.Query{
		Host:       host,
		Family:     resolvercache.FamilyAny,
		Egress:     egress,
		Resolver:   c.resolverID,
		Generation: c.generation,
	}
}

// egressName is the tunnel's name when one is configured for the mark, and the
// mark itself otherwise so an unmapped egress is still distinguishable.
func (c *dnsCache) egressName(mark int) string {
	if mark == 0 {
		return proxydial.DirectEgress
	}
	if name, ok := c.egressNames[mark]; ok && name != "" {
		return name
	}
	return "mark-" + strconv.Itoa(mark)
}

func (c *dnsCache) metrics() resolvercache.MetricsSnapshot { return c.cache.Metrics() }
