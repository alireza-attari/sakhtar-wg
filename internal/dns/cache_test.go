package dns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func testPolicy() Policy {
	return Policy{
		PositiveCapacity:    8,
		NegativeCapacity:    4,
		MaxPending:          2,
		MinPositiveTTL:      time.Second,
		MaxPositiveTTL:      time.Minute,
		NegativeTTL:         10 * time.Second,
		TransientFailureTTL: 2 * time.Second,
		StaleWindow:         time.Minute,
		StalePolicy:         StaleTransient,
		ResolverTimeout:     time.Second,
	}
}

func newTestCache(t testing.TB, policy Policy, clock Clock) *Cache {
	t.Helper()
	cache, err := NewCache(policy, clock)
	if err != nil {
		t.Fatal(err)
	}
	return cache
}

func positiveResolver(clock Clock, calls *atomic.Int32) Resolver {
	return ResolverFunc(func(context.Context, Query) (Result, error) {
		if calls != nil {
			calls.Add(1)
		}
		return Result{
			Addrs:     []netip.Addr{netip.MustParseAddr("192.0.2.10")},
			ExpiresAt: clock.Now().Add(5 * time.Second),
			RCode:     RCodeSuccess,
		}, nil
	})
}

func query(host string) Query {
	return Query{Host: host, Family: FamilyAny, Egress: "direct", Resolver: "system", Generation: 1}
}

func TestCacheCapacityAndEviction(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestCache(t, testPolicy(), clock)
	resolver := positiveResolver(clock, nil)
	for i := 0; i < 200; i++ {
		if _, err := cache.Resolve(context.Background(), query(fmt.Sprintf("%d.example", i)), resolver); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 100; i++ {
		q := query(fmt.Sprintf("negative-%d.example", i))
		if _, err := cache.Resolve(context.Background(), q, ResolverFunc(func(context.Context, Query) (Result, error) {
			return Result{RCode: RCodeNODATA}, nil
		})); err != nil {
			t.Fatal(err)
		}
	}
	stats := cache.Metrics()
	if stats.EntriesPositive > 8 || stats.EntriesNegative > 4 {
		t.Fatalf("cache exceeded capacity: %+v", stats)
	}
	if stats.EvictionsPositive == 0 || stats.EvictionsNegative == 0 {
		t.Fatalf("expected bounded eviction counters, got %+v", stats)
	}
}

func TestCacheExpiry(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	policy := testPolicy()
	policy.StalePolicy = StaleNever
	cache := newTestCache(t, policy, clock)
	var calls atomic.Int32
	resolver := positiveResolver(clock, &calls)
	if _, err := cache.Resolve(context.Background(), query("expiry.example"), resolver); err != nil {
		t.Fatal(err)
	}
	clock.Advance(6 * time.Second)
	if _, err := cache.Resolve(context.Background(), query("expiry.example"), resolver); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("resolver calls = %d, want 2", calls.Load())
	}
}

func TestCacheStaleRules(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestCache(t, testPolicy(), clock)
	q := query("stale.example")
	if _, err := cache.Resolve(context.Background(), q, positiveResolver(clock, nil)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(6 * time.Second)
	stale, err := cache.Resolve(context.Background(), q, ResolverFunc(func(context.Context, Query) (Result, error) {
		return Result{}, errors.New("temporary resolver outage")
	}))
	if err != nil || len(stale.Addrs) != 1 {
		t.Fatalf("transient stale result = %+v, %v", stale, err)
	}

	// An authoritative negative answer replaces, rather than overlays, stale.
	authoritative := query("authoritative.example")
	if _, err := cache.Resolve(context.Background(), authoritative, positiveResolver(clock, nil)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(6 * time.Second)
	negative, err := cache.Resolve(context.Background(), authoritative, ResolverFunc(func(context.Context, Query) (Result, error) {
		return Result{RCode: RCodeNXDOMAIN}, nil
	}))
	if err != nil || negative.RCode != RCodeNXDOMAIN || len(negative.Addrs) != 0 {
		t.Fatalf("authoritative result = %+v, %v", negative, err)
	}
	again, err := cache.Resolve(context.Background(), authoritative, positiveResolver(clock, nil))
	if err != nil || again.RCode != RCodeNXDOMAIN {
		t.Fatalf("fresh authoritative negative was not retained: %+v, %v", again, err)
	}
}

func TestCacheStaleBackgroundRefreshSingleFlight(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestCache(t, testPolicy(), clock)
	q := query("refresh.example")
	if _, err := cache.Resolve(context.Background(), q, positiveResolver(clock, nil)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(6 * time.Second)
	if _, err := cache.Resolve(context.Background(), q, ResolverFunc(func(context.Context, Query) (Result, error) {
		return Result{}, errors.New("temporary resolver outage")
	})); err != nil {
		t.Fatal(err)
	}
	clock.Advance(3 * time.Second)

	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	var refreshes atomic.Int32
	refresh := ResolverFunc(func(context.Context, Query) (Result, error) {
		if refreshes.Add(1) == 1 {
			close(started)
		}
		<-release
		return Result{Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.11")}, ExpiresAt: clock.Now().Add(time.Minute), RCode: RCodeSuccess}, nil
	})

	const waiters = 24
	results := make(chan error, waiters)
	for range waiters {
		go func() {
			result, err := cache.Resolve(context.Background(), q, refresh)
			if err == nil && (len(result.Addrs) != 1 || result.Addrs[0].String() != "192.0.2.10") {
				err = fmt.Errorf("background waiter got %+v", result)
			}
			results <- err
		}()
	}
	<-started
	for range waiters {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("stale waiter blocked on background refresh")
		}
	}
	if refreshes.Load() != 1 {
		t.Fatalf("background refreshes = %d, want 1", refreshes.Load())
	}
}

func TestWaiterCancellationDoesNotCancelResolution(t *testing.T) {
	cache := newTestCache(t, testPolicy(), realClock{})
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	resolver := ResolverFunc(func(ctx context.Context, _ Query) (Result, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		select {
		case <-release:
			return Result{Addrs: []netip.Addr{netip.MustParseAddr("198.51.100.7")}, ExpiresAt: time.Now().Add(time.Minute), RCode: RCodeSuccess}, nil
		case <-ctx.Done():
			return Result{}, ctx.Err()
		}
	})
	firstCtx, cancelFirst := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() {
		_, err := cache.Resolve(firstCtx, query("waiters.example"), resolver)
		firstDone <- err
	}()
	<-started
	secondDone := make(chan error, 1)
	go func() {
		_, err := cache.Resolve(context.Background(), query("waiters.example"), resolver)
		secondDone <- err
	}()
	cancelFirst()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first waiter error = %v", err)
	}
	close(release)
	if err := <-secondDone; err != nil {
		t.Fatalf("second waiter error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("resolver calls = %d, want 1", calls.Load())
	}
}

func TestPendingLimit(t *testing.T) {
	policy := testPolicy()
	policy.MaxPending = 1
	cache := newTestCache(t, policy, realClock{})
	started := make(chan struct{})
	release := make(chan struct{})
	resolver := ResolverFunc(func(context.Context, Query) (Result, error) {
		select {
		case <-started:
		default:
			close(started)
		}
		<-release
		return Result{Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.1")}, ExpiresAt: time.Now().Add(time.Minute), RCode: RCodeSuccess}, nil
	})
	done := make(chan error, 1)
	go func() {
		_, err := cache.Resolve(context.Background(), query("one.example"), resolver)
		done <- err
	}()
	<-started
	if _, err := cache.Resolve(context.Background(), query("two.example"), resolver); !errors.Is(err, ErrPendingLimit) {
		t.Fatalf("second key error = %v, want pending limit", err)
	}
	if stats := cache.Metrics(); stats.Pending != 1 || stats.RejectedPending != 1 {
		t.Fatalf("pending metrics = %+v", stats)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGenerationAndResultCopies(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newTestCache(t, testPolicy(), clock)
	var calls atomic.Int32
	resolver := positiveResolver(clock, &calls)
	first, err := cache.Resolve(context.Background(), query("generation.example"), resolver)
	if err != nil {
		t.Fatal(err)
	}
	first.Addrs[0] = netip.MustParseAddr("127.0.0.1")
	second, err := cache.Resolve(context.Background(), query("generation.example"), resolver)
	if err != nil {
		t.Fatal(err)
	}
	if second.Addrs[0].IsLoopback() {
		t.Fatal("caller mutated cached address slice")
	}
	q2 := query("generation.example")
	q2.Generation = 2
	if _, err := cache.Resolve(context.Background(), q2, resolver); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("resolver calls = %d, want distinct generations", calls.Load())
	}
}

func FuzzDNSMessage(f *testing.F) {
	f.Add([]byte{0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte("not a DNS message"))
	f.Fuzz(func(t *testing.T, wire []byte) {
		// This exercises x/net's defensive wire parser only. Runtime resolution
		// deliberately remains on net.Resolver until the DNS ADR is revisited.
		var parser dnsmessage.Parser
		if _, err := parser.Start(wire); err != nil {
			return
		}
		for {
			if _, err := parser.Question(); err != nil {
				break
			}
		}
		_ = parser.SkipAllAnswers()
		_ = parser.SkipAllAuthorities()
		_ = parser.SkipAllAdditionals()
	})
}

func BenchmarkCacheHit(b *testing.B) {
	policy := testPolicy()
	cache := newTestCache(b, policy, realClock{})
	resolver := benchmarkResolver()
	if _, err := cache.Resolve(context.Background(), query("bench.example"), resolver); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := cache.Resolve(context.Background(), query("bench.example"), resolver); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCacheMiss(b *testing.B) {
	policy := testPolicy()
	policy.PositiveCapacity = 4096
	policy.NegativeCapacity = 1024
	cache := newTestCache(b, policy, realClock{})
	resolver := benchmarkResolver()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := cache.Resolve(context.Background(), query(fmt.Sprintf("miss-%d.example", i)), resolver); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkResolver() Resolver {
	return ResolverFunc(func(context.Context, Query) (Result, error) {
		return Result{Addrs: []netip.Addr{netip.MustParseAddr("1.1.1.1")}, ExpiresAt: time.Now().Add(time.Minute), RCode: RCodeSuccess}, nil
	})
}
