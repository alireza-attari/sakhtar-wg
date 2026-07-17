package dns

import (
	"context"
	"errors"
	"hash/fnv"
	"net/netip"
	"sync"
	"time"
)

const defaultShardCount = 16

type cacheEntry struct {
	result     Result
	err        error
	stale      Result
	staleUntil time.Time
}

func (e cacheEntry) class() int {
	if e.result.RCode == RCodeSuccess {
		return classPositive
	}
	return classNegative
}

type cacheShard struct {
	mu          sync.Mutex
	entries     map[key]cacheEntry
	counts      [classKinds]int
	positiveCap int
	negativeCap int
}

func (s *cacheShard) capacity(class int) int {
	if class == classPositive {
		return s.positiveCap
	}
	return s.negativeCap
}

type flight struct {
	done       chan struct{}
	result     Result
	err        error
	stale      Result
	serveStale bool
}

// Cache is a fixed-capacity sharded cache. Capacity accounting and pending
// resolution accounting are independent hard limits.
type Cache struct {
	policy   Policy
	clock    Clock
	shards   []cacheShard
	flightMu sync.Mutex
	flights  map[key]*flight
	metrics  metrics
}

func NewCache(policy Policy, clock Clock) (*Cache, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = realClock{}
	}
	shardCount := min(defaultShardCount, policy.PositiveCapacity, policy.NegativeCapacity)
	c := &Cache{
		policy:  policy,
		clock:   clock,
		shards:  make([]cacheShard, shardCount),
		flights: make(map[key]*flight),
	}
	for i := range c.shards {
		c.shards[i] = cacheShard{
			entries:     make(map[key]cacheEntry),
			positiveCap: distributedCapacity(policy.PositiveCapacity, shardCount, i),
			negativeCap: distributedCapacity(policy.NegativeCapacity, shardCount, i),
		}
	}
	return c, nil
}

func distributedCapacity(total, shards, index int) int {
	capacity := total / shards
	if index < total%shards {
		capacity++
	}
	return capacity
}

func (c *Cache) Metrics() MetricsSnapshot { return c.metrics.snapshot() }

func (c *Cache) Resolve(ctx context.Context, query Query, resolver Resolver) (Result, error) {
	if resolver == nil {
		return Result{}, errors.New("dns: nil resolver")
	}
	k, err := makeKey(query)
	if err != nil {
		return Result{}, err
	}
	now := c.clock.Now()
	entry, found := c.takeEntry(k, now)
	if found {
		switch entry.result.RCode {
		case RCodeSuccess:
			c.metrics.requests[requestHit].Add(1)
			return entry.result.clone(), nil
		case RCodeNXDOMAIN, RCodeNODATA:
			c.metrics.requests[requestNegative].Add(1)
			return entry.result.clone(), nil
		case RCodeTransient:
			if c.canServeStale(entry, now) {
				c.metrics.requests[requestStale].Add(1)
				return entry.stale.clone(), nil
			}
			c.metrics.requests[requestNegative].Add(1)
			return entry.result.clone(), entry.err
		}
	}

	var stale Result
	var staleUntil time.Time
	if entry.result.RCode == RCodeSuccess && now.Before(entry.staleUntil) {
		stale, staleUntil = entry.result.clone(), entry.staleUntil
	} else if entry.result.RCode == RCodeTransient && c.canServeStale(entry, now) {
		stale, staleUntil = entry.stale.clone(), entry.staleUntil
		f, startErr := c.startFlight(k, query, resolver, stale, staleUntil, true)
		if startErr != nil {
			return Result{}, startErr
		}
		if f != nil {
			select {
			case <-f.done:
				return f.result.clone(), f.err
			default:
			}
			c.metrics.requests[requestRefresh].Add(1)
			c.metrics.requests[requestStale].Add(1)
			return stale.clone(), nil
		}
	}

	c.metrics.requests[requestMiss].Add(1)
	f, err := c.startFlight(k, query, resolver, stale, staleUntil, false)
	if err != nil {
		return Result{}, err
	}
	select {
	case <-f.done:
		return f.result.clone(), f.err
	default:
	}
	if f.serveStale && len(f.stale.Addrs) > 0 {
		c.metrics.requests[requestStale].Add(1)
		return f.stale.clone(), nil
	}
	return waitForFlight(ctx, f)
}

// takeEntry returns fresh entries with found=true. Expired entries are removed
// immediately, but returned with found=false so a bounded stale candidate can
// accompany the next resolver operation.
func (c *Cache) takeEntry(k key, now time.Time) (cacheEntry, bool) {
	shard := c.shardFor(k)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, ok := shard.entries[k]
	if !ok {
		return cacheEntry{}, false
	}
	if now.Before(entry.result.ExpiresAt) {
		return entry, true
	}
	// A transient backoff entry with an eligible last-good answer remains as a
	// stale marker while its background refresh is in flight. It is bounded by
	// the negative-entry capacity and is replaced by the refresh result.
	if entry.result.RCode == RCodeTransient && c.canServeStale(entry, now) {
		return entry, false
	}
	c.deleteLocked(shard, k, entry)
	return entry, false
}

func (c *Cache) canServeStale(entry cacheEntry, now time.Time) bool {
	return c.policy.StalePolicy == StaleTransient && len(entry.stale.Addrs) > 0 && now.Before(entry.staleUntil)
}

func (c *Cache) startFlight(k key, query Query, resolver Resolver, stale Result, staleUntil time.Time, serveStale bool) (*flight, error) {
	c.flightMu.Lock()
	if existing := c.flights[k]; existing != nil {
		c.flightMu.Unlock()
		return existing, nil
	}
	// A previous flight may have populated the cache after this caller observed
	// a miss but before it acquired flightMu. Re-check while flight creation is
	// serialized so that scheduling gap cannot launch a duplicate resolution.
	if entry, ok := c.peekFresh(k, c.clock.Now()); ok {
		f := &flight{done: make(chan struct{})}
		switch {
		case entry.result.RCode == RCodeTransient && c.canServeStale(entry, c.clock.Now()):
			f.result = entry.stale.clone()
		case entry.result.RCode == RCodeTransient:
			f.result, f.err = entry.result.clone(), entry.err
		default:
			f.result = entry.result.clone()
		}
		close(f.done)
		c.flightMu.Unlock()
		return f, nil
	}
	if len(c.flights) >= c.policy.MaxPending {
		c.metrics.rejected.Add(1)
		c.metrics.requests[requestRejected].Add(1)
		c.flightMu.Unlock()
		return nil, ErrPendingLimit
	}
	f := &flight{done: make(chan struct{}), stale: stale.clone(), serveStale: serveStale}
	c.flights[k] = f
	c.metrics.pending.Add(1)
	c.flightMu.Unlock()

	go c.runFlight(k, query, resolver, stale, staleUntil, f)
	return f, nil
}

func (c *Cache) peekFresh(k key, now time.Time) (cacheEntry, bool) {
	shard := c.shardFor(k)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, ok := shard.entries[k]
	return entry, ok && now.Before(entry.result.ExpiresAt)
}

func (c *Cache) runFlight(k key, query Query, resolver Resolver, stale Result, staleUntil time.Time, f *flight) {
	started := time.Now()
	resolveCtx, cancel := context.WithTimeout(context.Background(), c.policy.ResolverTimeout)
	result, err := callResolver(resolveCtx, resolver, query)
	cancel()
	now := c.clock.Now()
	result, err = c.normalizeResult(result, err, now)
	c.metrics.recordResolution(result.RCode, query.Egress != "" && query.Egress != "direct", time.Since(started))

	entry := cacheEntry{result: result.clone(), err: err}
	if result.RCode == RCodeSuccess {
		entry.staleUntil = result.ExpiresAt.Add(c.policy.StaleWindow)
	} else if result.RCode == RCodeTransient && len(stale.Addrs) > 0 && now.Before(staleUntil) {
		entry.stale = stale.clone()
		entry.staleUntil = staleUntil
	}
	c.insert(k, entry, now)

	if result.RCode == RCodeTransient && c.canServeStale(entry, now) {
		f.result = entry.stale.clone()
		f.err = nil
		c.metrics.requests[requestStale].Add(1)
	} else {
		f.result = result.clone()
		f.err = err
	}
	c.flightMu.Lock()
	delete(c.flights, k)
	c.metrics.pending.Add(-1)
	close(f.done)
	c.flightMu.Unlock()
}

func callResolver(ctx context.Context, resolver Resolver, query Query) (result Result, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = Result{}
			err = errors.New("resolver panicked")
		}
	}()
	return resolver.Resolve(ctx, query)
}

func waitForFlight(ctx context.Context, f *flight) (Result, error) {
	select {
	case <-ctx.Done():
		return Result{}, ctx.Err()
	case <-f.done:
		return f.result.clone(), f.err
	}
}

func (c *Cache) normalizeResult(result Result, err error, now time.Time) (Result, error) {
	if err != nil {
		return Result{RCode: RCodeTransient, ExpiresAt: now.Add(c.policy.TransientFailureTTL)}, &ResolveError{Err: err}
	}
	result.Addrs = normalizeAddrs(result.Addrs)
	if result.RCode == RCodeSuccess && len(result.Addrs) == 0 {
		result.RCode = RCodeNODATA
	}
	switch result.RCode {
	case RCodeSuccess:
		ttl := result.ExpiresAt.Sub(now)
		if ttl < c.policy.MinPositiveTTL {
			ttl = c.policy.MinPositiveTTL
		}
		if ttl > c.policy.MaxPositiveTTL {
			ttl = c.policy.MaxPositiveTTL
		}
		result.ExpiresAt = now.Add(ttl)
		return result, nil
	case RCodeNXDOMAIN, RCodeNODATA:
		result.Addrs = nil
		result.ExpiresAt = now.Add(c.policy.NegativeTTL)
		return result, nil
	default:
		return Result{RCode: RCodeTransient, ExpiresAt: now.Add(c.policy.TransientFailureTTL)}, &ResolveError{Err: errors.New("resolver returned invalid response class")}
	}
}

func normalizeAddrs(input []netip.Addr) []netip.Addr {
	result := make([]netip.Addr, 0, len(input))
	seen := make(map[netip.Addr]struct{}, len(input))
	for _, addr := range input {
		if !addr.IsValid() || addr.Zone() != "" {
			continue
		}
		addr = addr.Unmap()
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		result = append(result, addr)
	}
	return result
}

func (c *Cache) insert(k key, entry cacheEntry, now time.Time) {
	shard := c.shardFor(k)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	c.sweepLocked(shard, now, 4)
	if previous, ok := shard.entries[k]; ok {
		c.deleteLocked(shard, k, previous)
	}
	class := entry.class()
	if shard.counts[class] >= shard.capacity(class) {
		for victimKey, victim := range shard.entries {
			if victim.class() == class {
				c.deleteLocked(shard, victimKey, victim)
				c.metrics.evictions[class].Add(1)
				break
			}
		}
	}
	shard.entries[k] = entry
	shard.counts[class]++
	c.metrics.entries[class].Add(1)
}

func (c *Cache) sweepLocked(shard *cacheShard, now time.Time, limit int) {
	for k, entry := range shard.entries {
		if limit == 0 {
			return
		}
		limit--
		if !now.Before(entry.result.ExpiresAt) && !now.Before(entry.staleUntil) {
			c.deleteLocked(shard, k, entry)
		}
	}
}

func (c *Cache) deleteLocked(shard *cacheShard, k key, entry cacheEntry) {
	delete(shard.entries, k)
	class := entry.class()
	shard.counts[class]--
	c.metrics.entries[class].Add(-1)
}

func (c *Cache) shardFor(k key) *cacheShard {
	h := fnv.New64a()
	_, _ = h.Write([]byte(k.host))
	_, _ = h.Write([]byte{byte(k.family)})
	_, _ = h.Write([]byte(k.egress))
	_, _ = h.Write([]byte(k.resolver))
	var generation [8]byte
	for i := range generation {
		generation[i] = byte(k.generation >> (i * 8))
	}
	_, _ = h.Write(generation[:])
	return &c.shards[h.Sum64()%uint64(len(c.shards))]
}
