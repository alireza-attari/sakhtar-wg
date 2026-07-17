package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestDNSCacheStateTransitions(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newDNSCache(time.Minute)
	cache.now = clock.Now
	var calls int
	answer := []net.IP{net.ParseIP("192.0.2.10")}
	resolve := func(context.Context, string) ([]net.IP, error) {
		calls++
		return answer, nil
	}

	for range 2 {
		ips, err := cache.lookup(context.Background(), 51, "example.com", resolve)
		if err != nil || len(ips) != 1 || !ips[0].Equal(answer[0]) {
			t.Fatalf("lookup = %v, %v", ips, err)
		}
	}
	if calls != 1 {
		t.Fatalf("fresh resolver calls = %d", calls)
	}

	clock.Advance(time.Minute + time.Second)
	resolverDown := func(context.Context, string) ([]net.IP, error) {
		calls++
		return nil, errors.New("resolver down")
	}
	ips, err := cache.lookup(context.Background(), 51, "example.com", resolverDown)
	if err != nil || len(ips) != 1 {
		t.Fatalf("stale-on-error = %v, %v", ips, err)
	}

	clock.Advance(dnsMaxStale)
	if _, err := cache.lookup(context.Background(), 51, "example.com", resolverDown); err == nil {
		t.Fatal("expected failure after stale horizon")
	}
	before := calls
	if _, err := cache.lookup(context.Background(), 51, "example.com", resolve); err == nil {
		t.Fatal("expected cached transient failure")
	}
	if calls != before {
		t.Fatalf("negative cache called resolver: %d -> %d", before, calls)
	}

	clock.Advance(dnsNegTTL + time.Second)
	if _, err := cache.lookup(context.Background(), 51, "example.com", resolve); err != nil {
		t.Fatal(err)
	}
	if calls != before+1 {
		t.Fatalf("post-negative calls = %d", calls)
	}

	// The egress mark is part of the key.
	if _, err := cache.lookup(context.Background(), 52, "example.com", resolve); err != nil {
		t.Fatal(err)
	}
	if calls != before+2 {
		t.Fatalf("per-mark calls = %d", calls)
	}
}

func TestDNSCacheCollapsesConcurrentMisses(t *testing.T) {
	cache := newDNSCache(time.Minute)
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	resolve := func(context.Context, string) ([]net.IP, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return []net.IP{net.ParseIP("198.51.100.1")}, nil
	}

	const workers = 24
	var wg sync.WaitGroup
	wg.Add(workers)
	errs := make(chan error, workers)
	for range workers {
		go func() {
			defer wg.Done()
			_, err := cache.lookup(context.Background(), 51, "burst.example", resolve)
			errs <- err
		}()
	}
	<-started
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls = %d", got)
	}
}

func TestReloadCreatesNewDNSGeneration(t *testing.T) {
	cfg, err := parseConfig([]byte(validConfigYAML()))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(cfg, nil)
	before := server.rt.Load()
	if _, err := before.dns.lookup(context.Background(), 0, "generation.example", func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}); err != nil {
		t.Fatal(err)
	}
	server.Reload(cfg, nil)
	after := server.rt.Load()
	if before.dns == after.dns || before.dns.generation == after.dns.generation {
		t.Fatalf("reload reused DNS cache generation: before=%d after=%d", before.dns.generation, after.dns.generation)
	}
	if stats := after.dns.metrics(); stats.EntriesPositive != 0 || stats.EntriesNegative != 0 {
		t.Fatalf("new DNS generation inherited entries: %+v", stats)
	}
}
