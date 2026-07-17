package main

import (
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testProxyConfig(maximum, perSource int) *Config {
	return &Config{Proxy: Proxy{
		HTTPListen:              "127.0.0.1:0",
		Default:                 "direct",
		Resolver:                "1.1.1.1:53",
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
