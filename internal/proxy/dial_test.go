package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestAddressRotationAndMixedPolicy(t *testing.T) {
	selector := &RotatingSelector{Strategy: Interleave, MaxAttempts: 3}
	input := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("8.8.8.8"),
	}
	allowed := func(addr netip.Addr) bool { return !addr.IsPrivate() && !addr.IsLoopback() }
	first := selector.Select(input, allowed)
	second := selector.Select(input, allowed)
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("selection lengths = %d, %d", len(first), len(second))
	}
	for _, candidate := range append(first, second...) {
		if candidate.String() == "10.0.0.1" {
			t.Fatal("policy-denied address survived selection")
		}
	}
	if first[0] == second[0] {
		t.Fatalf("selector remained pinned to %s", first[0])
	}
}

func TestDialBudgetAndRetryCap(t *testing.T) {
	candidates := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
	}
	var calls int
	var peer net.Conn
	metrics := &ConnectMetrics{}
	conn, attempts, err := DialCandidates(context.Background(), candidates, "443", 2, "wgt0", func(context.Context, string, string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("first failed")
		}
		client, server := net.Pipe()
		peer = server
		return client, nil
	}, metrics)
	if err != nil || attempts != 2 || calls != 2 {
		t.Fatalf("retry = attempts %d calls %d err %v", attempts, calls, err)
	}
	_ = conn.Close()
	_ = peer.Close()
	// Attempts are attributed to the egress that carried them, not just to
	// "marked": an aggregate cannot show which tunnel is dropping connections.
	if got := metrics.Snapshot(); got["failure|marked|wgt0"] != 1 || got["success|marked|wgt0"] != 1 {
		t.Fatalf("connect metrics = %v", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	calls = 0
	_, attempts, err = DialCandidates(ctx, candidates, "443", 3, DirectEgress, func(ctx context.Context, _, _ string) (net.Conn, error) {
		calls++
		<-ctx.Done()
		return nil, ctx.Err()
	}, nil)
	if err == nil || attempts != 1 || calls != 1 {
		t.Fatalf("deadline retry = attempts %d calls %d err %v", attempts, calls, err)
	}
}

func BenchmarkSelectAddress(b *testing.B) {
	selector := &RotatingSelector{Strategy: Interleave, MaxAttempts: 4}
	input := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("2001:4860:4860::8888"),
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = selector.Select(input, nil)
	}
}

func BenchmarkResolveAndDial(b *testing.B) {
	candidates := []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		client, peer := net.Pipe()
		conn, _, err := DialCandidates(context.Background(), candidates, "443", 1, DirectEgress, func(context.Context, string, string) (net.Conn, error) {
			return client, nil
		}, nil)
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
		_ = peer.Close()
	}
}

func TestAttemptTimeoutSlicesRemainingBudget(t *testing.T) {
	for _, tc := range []struct {
		name         string
		remaining    time.Duration
		attemptsLeft int
		want         time.Duration
	}{
		{"even slice", 10 * time.Second, 4, 2500 * time.Millisecond},
		{"last attempt takes the rest", 3 * time.Second, 1, 3 * time.Second},
		{"slice floored at one SYN retransmission", 2 * time.Second, 4, time.Second},
		{"floor never exceeds the budget", 400 * time.Millisecond, 4, 400 * time.Millisecond},
		{"exhausted budget", 0, 3, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := attemptTimeout(tc.remaining, tc.attemptsLeft); got != tc.want {
				t.Fatalf("attemptTimeout(%s, %d) = %s, want %s", tc.remaining, tc.attemptsLeft, got, tc.want)
			}
		})
	}
}

// One blackholed candidate must not spend the whole dial budget: before the
// slicing, a SYN into a dead path held the first attempt until the shared
// deadline and the reachable second address was never tried.
func TestBlackholedCandidateLeavesBudgetForTheNext(t *testing.T) {
	previous := minAttemptTimeout
	minAttemptTimeout = 10 * time.Millisecond
	t.Cleanup(func() { minAttemptTimeout = previous })

	candidates := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	for _, tc := range []struct {
		name      string
		blackhole map[string]bool
		wantErr   bool
		attempts  int
	}{
		{"first blackholed, second answers", map[string]bool{"192.0.2.1:443": true}, false, 2},
		{"both blackholed exhaust the budget", map[string]bool{"192.0.2.1:443": true, "192.0.2.2:443": true}, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
			defer cancel()
			var peer net.Conn
			conn, attempts, err := DialCandidates(ctx, candidates, "443", 4, "wg0", func(attemptCtx context.Context, _, address string) (net.Conn, error) {
				if tc.blackhole[address] {
					<-attemptCtx.Done()
					return nil, attemptCtx.Err()
				}
				client, server := net.Pipe()
				peer = server
				return client, nil
			}, nil)
			if (err != nil) != tc.wantErr || attempts != tc.attempts {
				t.Fatalf("attempts = %d, err = %v; want attempts %d, error %t", attempts, err, tc.attempts, tc.wantErr)
			}
			if conn != nil {
				_ = conn.Close()
				_ = peer.Close()
			}
		})
	}
}
