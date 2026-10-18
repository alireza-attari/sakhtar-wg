package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	resolvercache "github.com/alireza-attari/sakhtar-wg/internal/dns"
	internalhealth "github.com/alireza-attari/sakhtar-wg/internal/health"
)

func testProxyConfig(maximum, perSource int) *Config {
	return &Config{Proxy: Proxy{
		HTTPListen:              "127.0.0.1:0",
		Default:                 "direct",
		Resolver:                ResolverList{"1.1.1.1:53"},
		DNSCacheTTL:             300,
		MaxConnections:          maximum,
		MaxConnectionsPerSource: perSource,
		HandshakeTimeout:        30,
		DialTimeout:             1,
		ShutdownGrace:           1,
		MaxClientHelloBytes:     defaultMaxClientHelloBytes,
		MaxHTTPHeaderBytes:      defaultMaxHTTPHeaderBytes,
	}}
}

func serverAddress(t *testing.T, srv *Server) string {
	t.Helper()
	srv.listenersMu.Lock()
	defer srv.listenersMu.Unlock()
	if len(srv.listeners) != 1 {
		t.Fatalf("listeners = %d", len(srv.listeners))
	}
	return srv.listeners[0].Addr().String()
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition did not become true before timeout")
}

func countOpenFDs() int {
	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir("/proc/self/fd")
		if err == nil {
			return len(entries)
		}
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &limit); err != nil {
		return -1
	}
	maximum := limit.Cur
	if maximum > 65536 {
		maximum = 65536
	}
	count := 0
	for fd := uint64(0); fd < maximum; fd++ {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			count++
		}
	}
	return count
}

func TestAdmission(t *testing.T) {
	srv := NewServer(testProxyConfig(2, 0), nil)
	if err := srv.Start(testProxyConfig(2, 0)); err != nil {
		t.Fatal(err)
	}
	address := serverAddress(t, srv)
	clients := make([]net.Conn, 0, 3)
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, conn)
	}
	waitFor(t, time.Second, func() bool { return srv.admission.activeCount() == 2 })
	capGoroutines, capFDs := runtime.NumGoroutine(), countOpenFDs()

	excess, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = excess.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := excess.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess connection remained open")
	}
	_ = excess.Close()
	key := rejectionKey{Protocol: protocolHTTP, Reason: reasonOverload, ListenerClass: classLocal}
	waitFor(t, time.Second, func() bool { return srv.rejectionSnapshot()[key] == 1 })
	afterGoroutines, afterFDs := runtime.NumGoroutine(), countOpenFDs()
	if afterGoroutines > capGoroutines+2 {
		t.Fatalf("goroutines grew above admission cap: at-cap=%d after-overload=%d", capGoroutines, afterGoroutines)
	}
	if capFDs >= 0 && afterFDs > capFDs+1 {
		t.Fatalf("file descriptors grew above admission cap: at-cap=%d after-overload=%d", capFDs, afterFDs)
	}

	_ = clients[0].Close()
	waitFor(t, time.Second, func() bool { return srv.admission.activeCount() == 1 })
	replacement, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clients = append(clients, replacement)
	waitFor(t, time.Second, func() bool { return srv.admission.activeCount() == 2 })
	for _, conn := range clients {
		_ = conn.Close()
	}
	if forced := srv.Stop(); forced != 0 {
		t.Fatalf("graceful stop force-closed %d sessions", forced)
	}
	t.Logf("load evidence: max_connections=2 at_cap_goroutines=%d overload_goroutines=%d at_cap_fds=%d overload_fds=%d overload_rejections=1 capacity_reused=true", capGoroutines, afterGoroutines, capFDs, afterFDs)
}

func TestAdmissionChurnReturnsGoroutinesAndFDsToBaseline(t *testing.T) {
	cfg := testProxyConfig(8, 0)
	srv := NewServer(cfg, nil)
	if err := srv.Start(cfg); err != nil {
		t.Fatal(err)
	}
	address := serverAddress(t, srv)
	baselineGoroutines, baselineFDs := runtime.NumGoroutine(), countOpenFDs()
	for i := 0; i < 250; i++ {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("malformed\r\n\r\n"))
		_ = conn.Close()
	}
	waitFor(t, 3*time.Second, func() bool { return srv.admission.activeCount() == 0 })
	runtime.GC()
	waitFor(t, 3*time.Second, func() bool {
		fds := countOpenFDs()
		return runtime.NumGoroutine() <= baselineGoroutines && (baselineFDs < 0 || fds <= baselineFDs)
	})
	afterGoroutines, afterFDs := runtime.NumGoroutine(), countOpenFDs()
	if afterGoroutines > baselineGoroutines {
		t.Fatalf("goroutines grew after churn: before=%d after=%d", baselineGoroutines, afterGoroutines)
	}
	if baselineFDs >= 0 && afterFDs > baselineFDs {
		t.Fatalf("file descriptors grew after churn: before=%d after=%d", baselineFDs, afterFDs)
	}
	if forced := srv.Stop(); forced != 0 {
		t.Fatalf("stop force-closed %d sessions", forced)
	}
}

func TestSourceACLBeforeParsing(t *testing.T) {
	cfg := testProxyConfig(2, 0)
	cfg.Proxy.AllowedSourceCIDRs = []string{"10.0.0.0/8"}
	srv := NewServer(cfg, nil)
	if err := srv.Start(cfg); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp", serverAddress(t, srv), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("unauthorized source remained open")
	}
	key := rejectionKey{Protocol: protocolHTTP, Reason: reasonSourceDenied, ListenerClass: classLocal}
	waitFor(t, time.Second, func() bool { return srv.rejectionSnapshot()[key] == 1 })
	if active := srv.admission.activeCount(); active != 0 {
		t.Fatalf("unauthorized source reached admission: active=%d", active)
	}
	_ = client.Close()
	if forced := srv.Stop(); forced != 0 {
		t.Fatalf("stop force-closed %d sessions", forced)
	}
}

func TestDestinationPolicyRejectsBeforeDial(t *testing.T) {
	cfg := testProxyConfig(2, 0)
	srv := NewServer(cfg, nil)
	var dialed atomic.Bool
	srv.dial = func(context.Context, string, string, int, time.Duration) (net.Conn, error) {
		dialed.Store(true)
		return nil, io.ErrClosedPipe
	}
	if err := srv.Start(cfg); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp", serverAddress(t, srv), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("denied destination remained open")
	}
	key := rejectionKey{Protocol: protocolHTTP, Reason: reasonDestinationDenied, ListenerClass: classLocal}
	waitFor(t, time.Second, func() bool { return srv.rejectionSnapshot()[key] == 1 })
	if dialed.Load() {
		t.Fatal("denied destination reached dialer")
	}
	_ = client.Close()
	if forced := srv.Stop(); forced != 0 {
		t.Fatalf("stop force-closed %d sessions", forced)
	}
}

func TestAdmissionPerSource(t *testing.T) {
	cfg := testProxyConfig(3, 1)
	srv := NewServer(cfg, nil)
	if err := srv.Start(cfg); err != nil {
		t.Fatal(err)
	}
	address := serverAddress(t, srv)
	first, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return srv.admission.activeCount() == 1 })
	second, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	_, readErr := second.Read(make([]byte, 1))
	_ = second.Close()
	if readErr == nil {
		t.Fatal("per-source excess connection remained open")
	}
	if srv.admission.activeCount() != 1 {
		t.Fatalf("active sessions = %d, want 1", srv.admission.activeCount())
	}
	_ = first.Close()
	if forced := srv.Stop(); forced != 0 {
		t.Fatalf("graceful stop force-closed %d sessions", forced)
	}
}

func TestGracefulDrain(t *testing.T) {
	cfg := testProxyConfig(1, 0)
	srv := NewServer(cfg, nil)
	srv.rt.Load().shutdownGrace = 50 * time.Millisecond
	if err := srv.Start(cfg); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp", serverAddress(t, srv), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return srv.admission.activeCount() == 1 })
	started := time.Now()
	forced := srv.Stop()
	if forced != 1 {
		t.Fatalf("forced sessions = %d, want 1", forced)
	}
	if elapsed := time.Since(started); elapsed < 40*time.Millisecond || elapsed > 500*time.Millisecond {
		t.Fatalf("shutdown elapsed %s, want bounded grace", elapsed)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("forced session's client socket remained open")
	}
	_ = client.Close()
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, _ := listener.AcceptTCP()
		accepted <- conn
	}()
	peer, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	proxy := <-accepted
	_ = listener.Close()
	return proxy, peer
}

func TestConnectionSessionHalfCloseAndAccounting(t *testing.T) {
	client, clientPeer := tcpPair(t)
	backend, backendPeer := tcpPair(t)
	resultCh := make(chan connectionSessionResult, 1)
	go func() {
		resultCh <- runConnectionSession(context.Background(), client, backend, []byte("hello"), 0)
	}()
	prefix := make([]byte, 5)
	if _, err := io.ReadFull(backendPeer, prefix); err != nil || string(prefix) != "hello" {
		t.Fatalf("backend prefix = %q, %v", prefix, err)
	}
	_ = clientPeer.CloseWrite()
	if _, err := backendPeer.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	_ = backendPeer.CloseWrite()
	response, err := io.ReadAll(clientPeer)
	if err != nil || string(response) != "world" {
		t.Fatalf("client response = %q, %v", response, err)
	}
	result := <-resultCh
	if result.Outcome != "completed" || result.ClientBytes != 5 || result.BackendBytes != 5 || result.Duration <= 0 {
		t.Fatalf("session result = %+v", result)
	}
	_ = clientPeer.Close()
	_ = backendPeer.Close()
}

func TestConnectionSessionIdleTimeout(t *testing.T) {
	client, clientPeer := net.Pipe()
	backend, backendPeer := net.Pipe()
	started := time.Now()
	result := runConnectionSession(context.Background(), client, backend, nil, 30*time.Millisecond)
	if result.Outcome != "error" || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("idle session result = %+v after %s", result, time.Since(started))
	}
	_ = clientPeer.Close()
	_ = backendPeer.Close()
}

func TestReloadDoesNotInterruptActiveSession(t *testing.T) {
	cfg := testProxyConfig(2, 0)
	srv := NewServer(cfg, nil)
	backendReady := make(chan net.Conn, 1)
	srv.dial = func(context.Context, string, string, int, time.Duration) (net.Conn, error) {
		proxySide, backendSide := net.Pipe()
		backendReady <- backendSide
		return proxySide, nil
	}
	if err := srv.Start(cfg); err != nil {
		t.Fatal(err)
	}
	client, err := net.DialTimeout("tcp", serverAddress(t, srv), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := []byte("GET / HTTP/1.1\r\nHost: 8.8.8.8\r\n\r\n")
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	backend := <-backendReady
	forwarded := make([]byte, len(request))
	if _, err := io.ReadFull(backend, forwarded); err != nil {
		t.Fatal(err)
	}
	before := srv.Generation()
	srv.Reload(cfg, nil)
	if after := srv.Generation(); after <= before {
		t.Fatalf("generation did not advance: before=%d after=%d", before, after)
	}
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if _, err := backend.Write(response); err != nil {
		t.Fatalf("active backend write after reload: %v", err)
	}
	_ = backend.Close()
	got, err := io.ReadAll(client)
	if err != nil || string(got) != string(response) {
		t.Fatalf("response after reload = %q, %v", got, err)
	}
	_ = client.Close()
	if forced := srv.Stop(); forced != 0 {
		t.Fatalf("stop force-closed %d sessions", forced)
	}
}

// A cached answer whose addresses all fail to connect must not survive its TTL:
// a single-address answer leaves the dialer nothing to fall back to, so keeping
// it would blackhole every later connection to that host until it expired.
func TestDialFailureInvalidatesCachedAnswer(t *testing.T) {
	const mark = 0x99
	cfg := testProxyConfig(4, 0)
	cfg.Tunnels = []Tunnel{{Name: "wgt0", Fwmark: mark}}
	cfg.Proxy.Rules = []Rule{{Via: "wgt0", Suffixes: []string{"pinned.example"}}}

	srv := NewServer(cfg, nil)
	var resolves atomic.Int32
	srv.rt.Load().resolvers[mark] = resolvercache.ResolverFunc(func(context.Context, resolvercache.Query) (resolvercache.Result, error) {
		resolves.Add(1)
		return resolvercache.Result{
			Addrs:     []netip.Addr{netip.MustParseAddr("93.184.216.34")},
			ExpiresAt: time.Now().Add(5 * time.Minute),
			RCode:     resolvercache.RCodeSuccess,
		}, nil
	})
	srv.dial = func(context.Context, string, string, int, time.Duration) (net.Conn, error) {
		return nil, io.ErrClosedPipe
	}
	if err := srv.Start(cfg); err != nil {
		t.Fatal(err)
	}
	defer srv.Stop()

	address := serverAddress(t, srv)
	request := func() {
		t.Helper()
		client, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: pinned.example\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Read(make([]byte, 1)); err == nil {
			t.Fatal("failed backend left the client session open")
		}
	}

	request()
	waitFor(t, 2*time.Second, func() bool { return resolves.Load() == 1 })
	waitFor(t, 2*time.Second, func() bool { return srv.rt.Load().dns.metrics().EvictionsPositive == 1 })

	// Well inside the 300s TTL: without the invalidation this would be a cache hit.
	request()
	waitFor(t, 2*time.Second, func() bool { return resolves.Load() == 2 })
}

// 10.10.34.36 is what Iran's resolvers answer for a blocked name. The policy
// denies it, and it must not stay cached: on 2026-10-18 a poisoned YouTube
// answer through wg18 kept denying YouTube for the rest of its TTL.
func TestDeniedAnswerIsNotCached(t *testing.T) {
	const mark = 0x99
	for _, tc := range []struct {
		name        string
		answer      []string
		wantDenied  bool
		wantResolve int32
	}{
		{"poisoned private answer re-resolves", []string{"10.10.34.36"}, true, 2},
		{"loopback answer re-resolves", []string{"127.0.0.1"}, true, 2},
		{"mixed answer keeps its public address cached", []string{"10.10.34.36", "93.184.216.34"}, false, 1},
		{"public answer stays cached", []string{"93.184.216.34"}, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testProxyConfig(4, 0)
			cfg.Tunnels = []Tunnel{{Name: "wg18", Fwmark: mark}}
			srv := NewServer(cfg, nil)
			rt := srv.rt.Load()
			var resolves atomic.Int32
			rt.resolvers[mark] = resolvercache.ResolverFunc(func(context.Context, resolvercache.Query) (resolvercache.Result, error) {
				resolves.Add(1)
				addrs := make([]netip.Addr, 0, len(tc.answer))
				for _, raw := range tc.answer {
					addrs = append(addrs, netip.MustParseAddr(raw))
				}
				return resolvercache.Result{Addrs: addrs, ExpiresAt: time.Now().Add(5 * time.Minute), RCode: resolvercache.RCodeSuccess}, nil
			})
			for range 2 {
				candidates, err := srv.backendCandidates(context.Background(), "www.youtube.com", false, mark, rt, map[netip.Addr]struct{}{})
				if denied := errors.Is(err, errDestinationDenied); denied != tc.wantDenied {
					t.Fatalf("candidates = %v, err = %v; denied = %t, want %t", candidates, err, denied, tc.wantDenied)
				}
			}
			if got := resolves.Load(); got != tc.wantResolve {
				t.Fatalf("resolves = %d, want %d", got, tc.wantResolve)
			}
		})
	}
}

// The tunnels are IPv4-only, so an IPv6 candidate on a marked egress can only
// burn a budget slice. Direct egress keeps both families.
func TestMarkedEgressDialsIPv4Only(t *testing.T) {
	const mark = 0x99
	for _, tc := range []struct {
		name        string
		mark        int
		host        string
		isIP        bool
		answer      []string
		want        []string
		wantErr     error
		wantResolve int32
	}{
		{name: "marked keeps only IPv4", mark: mark, host: "dual.example", answer: []string{"2606:4700::1", "93.184.216.34"}, want: []string{"93.184.216.34"}, wantResolve: 1},
		{name: "marked IPv6-only answer stays cached", mark: mark, host: "v6.example", answer: []string{"2606:4700::1"}, wantErr: errNoIPv4Candidate, wantResolve: 1},
		{name: "marked IPv6 literal", mark: mark, host: "2606:4700::1", isIP: true, wantErr: errNoIPv4Candidate},
		{name: "direct keeps IPv6", mark: 0, host: "v6.example", answer: []string{"2606:4700::1"}, want: []string{"2606:4700::1"}, wantResolve: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testProxyConfig(4, 0)
			cfg.Tunnels = []Tunnel{{Name: "wg0", Fwmark: mark}}
			srv := NewServer(cfg, nil)
			rt := srv.rt.Load()
			var resolves atomic.Int32
			rt.resolvers[tc.mark] = resolvercache.ResolverFunc(func(context.Context, resolvercache.Query) (resolvercache.Result, error) {
				resolves.Add(1)
				addrs := make([]netip.Addr, 0, len(tc.answer))
				for _, raw := range tc.answer {
					addrs = append(addrs, netip.MustParseAddr(raw))
				}
				return resolvercache.Result{Addrs: addrs, ExpiresAt: time.Now().Add(5 * time.Minute), RCode: resolvercache.RCodeSuccess}, nil
			})
			for range 2 {
				candidates, err := srv.backendCandidates(context.Background(), tc.host, tc.isIP, tc.mark, rt, map[netip.Addr]struct{}{})
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				got := make([]string, 0, len(candidates))
				for _, candidate := range candidates {
					got = append(got, candidate.String())
				}
				if !slices.Equal(got, tc.want) {
					t.Fatalf("candidates = %v, want %v", got, tc.want)
				}
			}
			if got := resolves.Load(); got != tc.wantResolve {
				t.Fatalf("resolves = %d, want %d", got, tc.wantResolve)
			}
		})
	}
}

// A connection used to read one mark and give up when that egress failed, so a
// dead or poisoned group member failed every connection routed to it while the
// next member could have carried them.
func TestDialFailsOverToNextGroupMember(t *testing.T) {
	const wg0, wg18, wgtr = 51, 52018, 52090
	const public, poisoned = "93.184.216.34", "10.10.34.36"
	errConnRefused := errors.New("connection refused")
	for _, tc := range []struct {
		name       string
		answers    map[int]string
		dialErr    map[int]error
		wantMark   int
		wantDialed []int
		wantDenied bool
	}{
		{name: "healthy first member is the only one dialed", answers: map[int]string{wg0: public, wg18: public}, wantMark: wg0, wantDialed: []int{wg0}},
		{name: "dial error moves to the next member", answers: map[int]string{wg0: public, wg18: public}, dialErr: map[int]error{wg0: errConnRefused}, wantMark: wg18, wantDialed: []int{wg0, wg18}},
		{name: "poisoned answer moves to the next member", answers: map[int]string{wg0: poisoned, wg18: public}, wantMark: wg18, wantDialed: []int{wg18}},
		{name: "skips two failing members", answers: map[int]string{wg0: poisoned, wg18: public, wgtr: public}, dialErr: map[int]error{wg18: errConnRefused}, wantMark: wgtr, wantDialed: []int{wg18, wgtr}},
		{name: "every member denied is a denial", answers: map[int]string{wg0: poisoned, wg18: poisoned, wgtr: poisoned}, wantDenied: true},
		{name: "any dial error makes it a dial error", answers: map[int]string{wg0: poisoned, wg18: public, wgtr: poisoned}, dialErr: map[int]error{wg18: errConnRefused}, wantDialed: []int{wg18}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testProxyConfig(4, 0)
			cfg.Tunnels = []Tunnel{{Name: "wg0", Fwmark: wg0}, {Name: "wg18", Fwmark: wg18}, {Name: "wgtr", Fwmark: wgtr}}
			srv := NewServer(cfg, nil)
			rt := srv.rt.Load()
			for mark, answer := range tc.answers {
				addr := netip.MustParseAddr(answer)
				rt.resolvers[mark] = resolvercache.ResolverFunc(func(context.Context, resolvercache.Query) (resolvercache.Result, error) {
					return resolvercache.Result{Addrs: []netip.Addr{addr}, ExpiresAt: time.Now().Add(5 * time.Minute), RCode: resolvercache.RCodeSuccess}, nil
				})
			}
			var dialed []int
			var peer net.Conn
			srv.dial = func(_ context.Context, _, _ string, mark int, _ time.Duration) (net.Conn, error) {
				dialed = append(dialed, mark)
				if err := tc.dialErr[mark]; err != nil {
					return nil, err
				}
				client, server := net.Pipe()
				peer = server
				return client, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := srv.dialEgresses(ctx, "www.youtube.com", false, "443", []int{wg0, wg18, wgtr}, rt, map[netip.Addr]struct{}{})
			if conn != nil {
				_ = conn.Close()
				_ = peer.Close()
			}
			if !slices.Equal(dialed, tc.wantDialed) {
				t.Fatalf("dialed marks = %v, want %v", dialed, tc.wantDialed)
			}
			switch {
			case tc.wantMark != 0 && err != nil:
				t.Fatalf("dial failed: %v", err)
			case tc.wantMark != 0 && dialed[len(dialed)-1] != tc.wantMark:
				t.Fatalf("connected through %d, want %d", dialed[len(dialed)-1], tc.wantMark)
			case tc.wantMark == 0 && err == nil:
				t.Fatal("dial succeeded, want failure")
			case tc.wantMark == 0 && errors.Is(err, errDestinationDenied) != tc.wantDenied:
				t.Fatalf("err = %v; denied = %t, want %t", err, errors.Is(err, errDestinationDenied), tc.wantDenied)
			}
		})
	}
}

func TestRouteFollowsPublishedGroupOrder(t *testing.T) {
	var active atomic.Int32
	var order atomic.Pointer[[]internalhealth.FwMark]
	ref := markRef{dyn: &active, order: &order}
	for _, tc := range []struct {
		name      string
		active    int32
		published []internalhealth.FwMark
		want      []int
	}{
		{"before the first poll", 51, nil, []int{51}},
		{"eligible members in order", 51, []internalhealth.FwMark{51, 52018}, []int{51, 52018}},
		{"after failover", 52018, []internalhealth.FwMark{52018}, []int{52018}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			active.Store(tc.active)
			if tc.published != nil {
				order.Store(&tc.published)
			}
			if got := ref.marks(); !slices.Equal(got, tc.want) {
				t.Fatalf("marks = %v, want %v", got, tc.want)
			}
		})
	}
	if got := (markRef{static: 7}).marks(); !slices.Equal(got, []int{7}) {
		t.Fatalf("static marks = %v", got)
	}
}

// A reload that moves a rule to another tunnel while a client is still sending
// its request must not dial through the router captured at accept: its tunnel
// rule may be gone, and an unruled mark leaves through the WAN.
func TestSessionRoutesWithRouterCurrentAtDial(t *testing.T) {
	const oldMark, newMark = 51, 52018
	configFor := func(via string) *Config {
		cfg := testProxyConfig(4, 0)
		cfg.Tunnels = []Tunnel{{Name: "wg0", Fwmark: oldMark}, {Name: "wg18", Fwmark: newMark}}
		cfg.Proxy.Rules = []Rule{{Via: via, Suffixes: []string{"moved.example"}}}
		return cfg
	}
	srv := NewServer(configFor("wg0"), nil)
	dialed := make(chan int, 4)
	srv.dial = func(_ context.Context, _, _ string, mark int, _ time.Duration) (net.Conn, error) {
		dialed <- mark
		return nil, io.ErrClosedPipe
	}
	captured := srv.rt.Load()
	client, server := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleHTTP(ctx, &ownedSession{client: server, cancel: cancel}, server, captured, rejectionKey{Protocol: protocolHTTP, ListenerClass: classLocal})
	}()

	srv.Reload(configFor("wg18"), nil)
	srv.rt.Load().resolvers[newMark] = resolvercache.ResolverFunc(func(context.Context, resolvercache.Query) (resolvercache.Result, error) {
		return resolvercache.Result{Addrs: []netip.Addr{netip.MustParseAddr("93.184.216.34")}, ExpiresAt: time.Now().Add(time.Minute), RCode: resolvercache.RCodeSuccess}, nil
	})
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: moved.example\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case mark := <-dialed:
		if mark != newMark {
			t.Fatalf("dialed mark %d (router captured at accept), want %d", mark, newMark)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no dial")
	}
	cancel()
	<-done
}
