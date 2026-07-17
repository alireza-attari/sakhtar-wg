package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	resolvercache "github.com/alireza-attari/sakhtar-wg/internal/dns"
	"github.com/alireza-attari/sakhtar-wg/internal/observability"
	proxydial "github.com/alireza-attari/sakhtar-wg/internal/proxy"
	internalrouting "github.com/alireza-attari/sakhtar-wg/internal/routing"
	lifecycle "github.com/alireza-attari/sakhtar-wg/internal/runtime"
)

const maxPeek = defaultMaxClientHelloBytes

var errDestinationDenied = errors.New("destination denied by policy")

type router struct {
	def                     markRef
	dialTimeout             time.Duration
	handshakeTimeout        time.Duration
	idleTimeout             time.Duration
	shutdownGrace           time.Duration
	maxConnections          int
	maxConnectionsPerSource int
	maxClientHelloBytes     int64
	maxHTTPHeaderBytes      int64
	sourceACL               []netip.Prefix
	destination             destinationPolicy
	suffixes                *internalrouting.SuffixMatcher[markRef]
	dns                     *dnsCache
	resolvers               map[int]resolvercache.Resolver
	selector                *proxydial.RotatingSelector
	connectAttemptCap       int
}

type markRef struct {
	static int
	dyn    *atomic.Int32
}

func (m markRef) mark() int {
	if m.dyn != nil {
		return int(m.dyn.Load())
	}
	return m.static
}

func markRefFor(c *Config, hm *HealthMonitor, via string) markRef {
	if hm != nil {
		if a := hm.Active(via); a != nil {
			return markRef{dyn: a}
		}
	}
	return markRef{static: c.markFor(via)}
}

func newRouter(c *Config, hm *HealthMonitor) *router {
	return newRouterGeneration(c, hm, 1, dialMarkedContext)
}

func newRouterGeneration(c *Config, hm *HealthMonitor, generation uint64, dial func(context.Context, string, string, int, time.Duration) (net.Conn, error)) *router {
	cache := newDNSCacheForConfig(c, generation)
	resolverTimeout := durationSeconds(c.Proxy.DNSResolverTimeout, defaultDNSResolverTimeout)
	localTTL := durationSeconds(c.Proxy.DNSCacheTTL, defaultDNSMaxPositiveTTL)
	resolverAddress := c.Proxy.Resolver
	if resolverAddress == "" {
		resolverAddress = "1.1.1.1:53"
	}
	resolvers := map[int]resolvercache.Resolver{
		0: &resolvercache.NetResolver{Resolver: net.DefaultResolver, LocalTTL: localTTL},
	}
	for _, tunnel := range c.Tunnels {
		mark := tunnel.Fwmark
		markedResolver := &net.Resolver{
			PreferGo: true,
			Dial: func(resolveCtx context.Context, network, _ string) (net.Conn, error) {
				return dial(resolveCtx, network, resolverAddress, mark, resolverTimeout)
			},
		}
		resolvers[mark] = &resolvercache.NetResolver{Resolver: markedResolver, LocalTTL: localTTL}
	}
	strategy := proxydial.AddressFamilyStrategy(c.Proxy.AddressFamilyStrategy)
	if !strategy.Valid() {
		strategy = proxydial.Interleave
	}
	attemptCap := c.Proxy.ConnectAttemptCap
	if attemptCap <= 0 {
		attemptCap = defaultConnectAttemptCap
	}
	rt := &router{
		def:                     markRefFor(c, hm, c.Proxy.Default),
		dialTimeout:             time.Duration(c.Proxy.DialTimeout) * time.Second,
		handshakeTimeout:        time.Duration(c.Proxy.HandshakeTimeout) * time.Second,
		idleTimeout:             time.Duration(c.Proxy.IdleTimeout) * time.Second,
		shutdownGrace:           time.Duration(c.Proxy.ShutdownGrace) * time.Second,
		maxConnections:          c.Proxy.MaxConnections,
		maxConnectionsPerSource: c.Proxy.MaxConnectionsPerSource,
		maxClientHelloBytes:     int64(c.Proxy.MaxClientHelloBytes),
		maxHTTPHeaderBytes:      int64(c.Proxy.MaxHTTPHeaderBytes),
		sourceACL:               compileSourceACL(c),
		destination:             newDestinationPolicy(c),
		suffixes:                internalrouting.NewSuffixMatcher[markRef](len(c.Proxy.Rules)),
		dns:                     cache,
		resolvers:               resolvers,
		selector:                &proxydial.RotatingSelector{Strategy: strategy, MaxAttempts: attemptCap},
		connectAttemptCap:       attemptCap,
	}
	for _, rule := range c.Proxy.Rules {
		ref := markRefFor(c, hm, rule.Via)
		for _, suffix := range rule.Suffixes {
			rt.suffixes.AddFirst(suffix, ref)
		}
	}
	return rt
}

func (rt *router) mark(host string) int {
	if normalized, _, err := canonicalHost(host, false); err == nil {
		host = normalized
	}
	if ref, ok := rt.suffixes.Lookup(host); ok {
		return ref.mark()
	}
	return rt.def.mark()
}

type proxyProtocol string
type listenerClass string
type rejectionReason string

const (
	protocolTLS  proxyProtocol = "tls"
	protocolHTTP proxyProtocol = "http"
	classLocal   listenerClass = "loopback"
	classNetwork listenerClass = "non_loopback"

	reasonSourceDenied      rejectionReason = "source_denied"
	reasonParseError        rejectionReason = "parse_error"
	reasonDestinationDenied rejectionReason = "destination_denied"
	reasonOverload          rejectionReason = "overload"
	reasonDialError         rejectionReason = "dial_error"
)

type rejectionKey struct {
	Protocol      proxyProtocol
	Reason        rejectionReason
	ListenerClass listenerClass
}

type sessionAggregate struct {
	Sessions      uint64
	ClientBytes   uint64
	BackendBytes  uint64
	TotalDuration time.Duration
}

type Server struct {
	rt atomic.Pointer[router]

	dial              func(context.Context, string, string, int, time.Duration) (net.Conn, error)
	self              atomic.Pointer[addressSet]
	generations       *lifecycle.Generations
	accepted          atomic.Uint64
	expectedListeners int
	connectMetrics    proxydial.ConnectMetrics

	rootCtx    context.Context
	rootCancel context.CancelFunc
	stopping   atomic.Bool

	listenersMu sync.Mutex
	listeners   []net.Listener
	acceptWG    sync.WaitGroup

	admission admissionControl

	sessionsMu sync.Mutex
	sessions   map[*ownedSession]struct{}
	sessionWG  sync.WaitGroup

	metricsMu  sync.Mutex
	rejections map[rejectionKey]uint64
	aggregates map[string]sessionAggregate
}

type addressSet struct {
	values map[netip.Addr]struct{}
}

func NewServer(c *Config, hm *HealthMonitor) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		dial:        dialMarkedContext,
		rootCtx:     ctx,
		rootCancel:  cancel,
		sessions:    make(map[*ownedSession]struct{}),
		rejections:  make(map[rejectionKey]uint64),
		aggregates:  make(map[string]sessionAggregate),
		generations: lifecycle.NewGenerations(),
	}
	if c.Proxy.HTTPSListen != "" {
		s.expectedListeners++
	}
	if c.Proxy.HTTPListen != "" {
		s.expectedListeners++
	}
	rt := newRouterGeneration(c, hm, uint64(s.generations.Active()), s.dial)
	s.rt.Store(rt)
	s.RefreshNetworkAddresses()
	return s
}

func (s *Server) Reload(c *Config, hm *HealthMonitor) {
	generation := s.generations.Advance()
	s.rt.Store(newRouterGeneration(c, hm, uint64(generation), s.dial))
	s.RefreshNetworkAddresses()
}

// RefreshNetworkAddresses re-checks every interface and bound listener. It is
// called for every config generation and is the hook for a platform network-
// change notification, so a newly assigned daemon address cannot become a
// backend destination.
func (s *Server) RefreshNetworkAddresses() {
	values := make(map[netip.Addr]struct{})
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if prefix, err := netip.ParsePrefix(addr.String()); err == nil {
			values[prefix.Addr().Unmap()] = struct{}{}
		}
	}
	s.listenersMu.Lock()
	for _, listener := range s.listeners {
		if tcp, ok := listener.Addr().(*net.TCPAddr); ok {
			if ip, valid := netip.AddrFromSlice(tcp.IP); valid && !ip.IsUnspecified() {
				values[ip.Unmap()] = struct{}{}
			}
		}
	}
	s.listenersMu.Unlock()
	s.self.Store(&addressSet{values: values})
}

func (s *Server) Start(c *Config) error {
	if c.Proxy.HTTPSListen != "" {
		if err := s.serve(c.Proxy.HTTPSListen, protocolTLS, s.handleTLS); err != nil {
			s.closeListeners()
			return err
		}
	}
	if c.Proxy.HTTPListen != "" {
		if err := s.serve(c.Proxy.HTTPListen, protocolHTTP, s.handleHTTP); err != nil {
			s.closeListeners()
			return err
		}
	}
	s.RefreshNetworkAddresses()
	return nil
}

type acceptedHandler func(context.Context, *ownedSession, net.Conn, *router, rejectionKey)

func (s *Server) serve(addr string, protocol proxyProtocol, handler acceptedHandler) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listenersMu.Lock()
	s.listeners = append(s.listeners, listener)
	s.listenersMu.Unlock()
	s.acceptWG.Add(1)
	go func() {
		defer s.acceptWG.Done()
		s.acceptLoop(listener, protocol, handler)
	}()
	log.Printf("proxy: listening on %s", addr)
	return nil
}

func listenerAddrClass(addr net.Addr) listenerClass {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if ip, valid := netip.AddrFromSlice(tcp.IP); valid && ip.Unmap().IsLoopback() {
			return classLocal
		}
	}
	return classNetwork
}

func (s *Server) acceptLoop(listener net.Listener, protocol proxyProtocol, handler acceptedHandler) {
	var delay time.Duration
	labels := rejectionKey{Protocol: protocol, ListenerClass: listenerAddrClass(listener.Addr())}
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.stopping.Load() {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay *= 2
			}
			if max := time.Second; delay > max {
				delay = max
			}
			log.Printf("proxy: accept error on %s; retrying in %s: %v", labels.ListenerClass, delay, err)
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-s.rootCtx.Done():
				timer.Stop()
				return
			}
			continue
		}
		delay = 0
		if s.stopping.Load() {
			_ = conn.Close()
			return
		}
		rt := s.rt.Load()
		source, allowed := sourceAllowed(conn.RemoteAddr(), rt.sourceACL)
		if !allowed {
			labels.Reason = reasonSourceDenied
			s.reject(labels)
			_ = conn.Close()
			continue
		}
		release, admitted := s.admission.acquire(source, rt.maxConnections, rt.maxConnectionsPerSource)
		if !admitted {
			labels.Reason = reasonOverload
			s.reject(labels)
			_ = conn.Close()
			continue
		}
		s.accepted.Add(1)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(90 * time.Second)
		}
		ctx, cancel := context.WithCancel(s.rootCtx)
		session := &ownedSession{client: conn, cancel: cancel}
		s.sessionsMu.Lock()
		s.sessions[session] = struct{}{}
		s.sessionWG.Add(1)
		s.sessionsMu.Unlock()
		go s.runAccepted(ctx, session, conn, rt, labels, handler, release)
	}
}

func (s *Server) runAccepted(ctx context.Context, session *ownedSession, conn net.Conn, rt *router, labels rejectionKey, handler acceptedHandler, release func()) {
	defer func() {
		session.close()
		release()
		s.sessionsMu.Lock()
		delete(s.sessions, session)
		s.sessionsMu.Unlock()
		s.sessionWG.Done()
	}()
	handler(ctx, session, conn, rt, labels)
}

func (s *Server) handleTLS(ctx context.Context, session *ownedSession, conn net.Conn, rt *router, labels rejectionKey) {
	_ = conn.SetReadDeadline(time.Now().Add(rt.handshakeTimeout))
	hello, prefix, err := peekClientHelloLimit(conn, rt.maxClientHelloBytes)
	if err != nil || hello.ServerName == "" {
		if ctx.Err() != nil {
			return
		}
		labels.Reason = reasonParseError
		s.reject(labels)
		return
	}
	host, isIP, err := canonicalHost(hello.ServerName, false)
	if err != nil {
		labels.Reason = reasonParseError
		s.reject(labels)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	s.pipe(ctx, session, conn, prefix, host, isIP, "443", rt, labels)
}

func (s *Server) handleHTTP(ctx context.Context, session *ownedSession, conn net.Conn, rt *router, labels rejectionKey) {
	_ = conn.SetReadDeadline(time.Now().Add(rt.handshakeTimeout))
	rawHost, prefix, err := peekHTTPHostLimit(conn, rt.maxHTTPHeaderBytes)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		labels.Reason = reasonParseError
		s.reject(labels)
		return
	}
	host, isIP, err := canonicalHost(rawHost, true)
	if err != nil {
		labels.Reason = reasonParseError
		s.reject(labels)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	s.pipe(ctx, session, conn, prefix, host, isIP, "80", rt, labels)
}

func peekHTTPHostLimit(r io.Reader, limit int64) (string, []byte, error) {
	var buffer bytes.Buffer
	limited := io.LimitReader(r, limit+1)
	request, err := http.ReadRequest(bufio.NewReader(io.TeeReader(limited, &buffer)))
	if err != nil {
		return "", nil, err
	}
	if int64(buffer.Len()) > limit {
		return "", nil, fmt.Errorf("HTTP header exceeds %d bytes", limit)
	}
	if request.Host == "" {
		return "", nil, errors.New("HTTP request has no Host header")
	}
	return request.Host, buffer.Bytes(), nil
}

func (s *Server) pipe(ctx context.Context, session *ownedSession, client net.Conn, prefix []byte, host string, isIP bool, port string, rt *router, labels rejectionKey) {
	mark := rt.mark(host)
	self := s.self.Load()
	selfValues := map[netip.Addr]struct{}{}
	if self != nil {
		selfValues = self.values
	}
	if !rt.destination.requestedHostAllowed(host, isIP, mark, selfValues) {
		labels.Reason = reasonDestinationDenied
		s.reject(labels)
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, rt.dialTimeout)
	backend, err := s.dialBackend(dialCtx, host, isIP, port, mark, rt, selfValues)
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errDestinationDenied) {
			labels.Reason = reasonDestinationDenied
		} else {
			labels.Reason = reasonDialError
		}
		s.reject(labels)
		return
	}
	session.setBackend(backend)
	result := runConnectionSession(ctx, client, backend, prefix, rt.idleTimeout)
	s.recordSession(result)
}

func (s *Server) dialBackend(ctx context.Context, host string, isIP bool, port string, mark int, rt *router, self map[netip.Addr]struct{}) (net.Conn, error) {
	candidates, err := s.backendCandidates(ctx, host, isIP, mark, rt, self)
	if err != nil {
		return nil, err
	}
	conn, _, err := proxydial.DialCandidates(ctx, candidates, port, rt.connectAttemptCap, mark != 0, func(dialCtx context.Context, network, address string) (net.Conn, error) {
		return s.dial(dialCtx, network, address, mark, rt.dialTimeout)
	}, &s.connectMetrics)
	return conn, err
}

func (s *Server) backendCandidates(ctx context.Context, host string, isIP bool, mark int, rt *router, self map[netip.Addr]struct{}) ([]netip.Addr, error) {
	if isIP {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return nil, errDestinationDenied
		}
		selected := rt.selector.Select([]netip.Addr{addr}, func(candidate netip.Addr) bool {
			return rt.destination.addressAllowed(candidate, mark, self)
		})
		if len(selected) == 0 {
			return nil, errDestinationDenied
		}
		return selected, nil
	}
	resolver := rt.resolvers[mark]
	if resolver == nil {
		return nil, fmt.Errorf("no resolver for egress mark %d", mark)
	}
	result, err := rt.dns.resolve(ctx, mark, host, resolver)
	if err != nil {
		return nil, err
	}
	if result.RCode != resolvercache.RCodeSuccess {
		return nil, fmt.Errorf("DNS %s for %s", result.RCode, host)
	}
	allowed := rt.selector.Select(result.Addrs, func(candidate netip.Addr) bool {
		return rt.destination.addressAllowed(candidate, mark, self)
	})
	if len(allowed) == 0 {
		return nil, errDestinationDenied
	}
	return allowed, nil
}

func durationSeconds(value, fallback int) time.Duration {
	if value <= 0 {
		value = fallback
	}
	return time.Duration(value) * time.Second
}

type directionResult struct {
	clientToBackend bool
	bytes           int64
	err             error
}

type connectionSessionResult struct {
	ClientBytes  uint64
	BackendBytes uint64
	Duration     time.Duration
	Outcome      string
}

func runConnectionSession(ctx context.Context, client, backend net.Conn, prefix []byte, idle time.Duration) connectionSessionResult {
	started := time.Now()
	result := connectionSessionResult{Outcome: "completed"}
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = client.Close()
			_ = backend.Close()
		})
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			closeBoth()
		case <-done:
		}
	}()
	defer func() {
		close(done)
		closeBoth()
	}()

	if len(prefix) > 0 {
		if idle > 0 {
			_ = backend.SetWriteDeadline(time.Now().Add(idle))
		}
		n, err := writeAll(backend, prefix)
		result.ClientBytes += uint64(n)
		if err != nil {
			result.Outcome = sessionOutcome(ctx, err)
			result.Duration = time.Since(started)
			return result
		}
	}

	results := make(chan directionResult, 2)
	copyOne := func(dst, src net.Conn, clientToBackend bool) {
		var count int64
		var err error
		if idle > 0 {
			count, err = io.Copy(idleWriter{Conn: dst, timeout: idle}, idleReader{Conn: src, timeout: idle})
		} else {
			count, err = io.Copy(dst, src)
		}
		if err == nil {
			closeWrite(dst)
		}
		results <- directionResult{clientToBackend: clientToBackend, bytes: count, err: err}
	}
	go copyOne(backend, client, true)
	go copyOne(client, backend, false)
	first := <-results
	if first.err != nil {
		closeBoth()
	}
	second := <-results
	for _, copied := range []directionResult{first, second} {
		if copied.clientToBackend {
			result.ClientBytes += uint64(copied.bytes)
		} else {
			result.BackendBytes += uint64(copied.bytes)
		}
		if copied.err != nil {
			result.Outcome = sessionOutcome(ctx, copied.err)
		}
	}
	result.Duration = time.Since(started)
	return result
}

func sessionOutcome(ctx context.Context, err error) string {
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "error"
}

func writeAll(writer io.Writer, data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		n, err := writer.Write(data)
		total += n
		data = data[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

type idleReader struct {
	net.Conn
	timeout time.Duration
}

func (r idleReader) Read(data []byte) (int, error) {
	_ = r.Conn.SetReadDeadline(time.Now().Add(r.timeout))
	return r.Conn.Read(data)
}

type idleWriter struct {
	net.Conn
	timeout time.Duration
}

func (w idleWriter) Write(data []byte) (int, error) {
	_ = w.Conn.SetWriteDeadline(time.Now().Add(w.timeout))
	return w.Conn.Write(data)
}

func closeWrite(conn net.Conn) {
	if halfCloser, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
	}
}

type ownedSession struct {
	mu      sync.Mutex
	client  net.Conn
	backend net.Conn
	cancel  context.CancelFunc
	closed  bool
}

func (s *ownedSession) setBackend(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = conn.Close()
		return
	}
	s.backend = conn
}

func (s *ownedSession) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	client, backend, cancel := s.client, s.backend, s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if client != nil {
		_ = client.Close()
	}
	if backend != nil {
		_ = backend.Close()
	}
}

type admissionControl struct {
	mu        sync.Mutex
	active    int
	perSource map[netip.Addr]int
}

func (a *admissionControl) acquire(source netip.Addr, maximum, perSourceMaximum int) (func(), bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if maximum <= 0 || a.active >= maximum {
		return nil, false
	}
	if a.perSource == nil {
		a.perSource = make(map[netip.Addr]int)
	}
	if perSourceMaximum > 0 && a.perSource[source] >= perSourceMaximum {
		return nil, false
	}
	a.active++
	a.perSource[source]++
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			a.active--
			a.perSource[source]--
			if a.perSource[source] == 0 {
				delete(a.perSource, source)
			}
		})
	}, true
}

func (a *admissionControl) activeCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.active
}

func (s *Server) reject(key rejectionKey) {
	s.metricsMu.Lock()
	s.rejections[key]++
	s.metricsMu.Unlock()
}

func (s *Server) rejectionSnapshot() map[rejectionKey]uint64 {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	result := make(map[rejectionKey]uint64, len(s.rejections))
	for key, count := range s.rejections {
		result[key] = count
	}
	return result
}

func (s *Server) recordSession(result connectionSessionResult) {
	s.metricsMu.Lock()
	aggregate := s.aggregates[result.Outcome]
	aggregate.Sessions++
	aggregate.ClientBytes += result.ClientBytes
	aggregate.BackendBytes += result.BackendBytes
	aggregate.TotalDuration += result.Duration
	s.aggregates[result.Outcome] = aggregate
	s.metricsMu.Unlock()
}

func (s *Server) Generation() lifecycle.Generation {
	if s == nil || s.generations == nil {
		return 0
	}
	return s.generations.Active()
}

func (s *Server) ListenersReady() bool {
	if s == nil {
		return false
	}
	s.listenersMu.Lock()
	defer s.listenersMu.Unlock()
	return !s.stopping.Load() && len(s.listeners) == s.expectedListeners
}

// Observe copies already-aggregated, bounded proxy and DNS counters into the
// management registry. It never inspects hostnames, client addresses, or
// destinations and runs only when management state is collected.
func (s *Server) Observe(registry *observability.Registry) {
	if s == nil || registry == nil {
		return
	}
	snapshot := observability.ProxySnapshot{
		Active: int64(s.admission.activeCount()), Accepted: s.accepted.Load(),
		Rejected: map[string]uint64{}, Completed: map[string]uint64{},
		DurationSeconds: map[string]float64{}, ClientBytes: map[string]uint64{}, BackendBytes: map[string]uint64{},
		ConnectAttempts: s.connectMetrics.Snapshot(),
	}
	s.metricsMu.Lock()
	for key, total := range s.rejections {
		snapshot.Rejected[string(key.Protocol)+"|"+string(key.Reason)+"|"+string(key.ListenerClass)] = total
	}
	for outcome, aggregate := range s.aggregates {
		if outcome != "completed" && outcome != "canceled" && outcome != "error" {
			outcome = "other"
		}
		snapshot.Completed[outcome] += aggregate.Sessions
		snapshot.DurationSeconds[outcome] += aggregate.TotalDuration.Seconds()
		snapshot.ClientBytes[outcome] += aggregate.ClientBytes
		snapshot.BackendBytes[outcome] += aggregate.BackendBytes
	}
	s.metricsMu.Unlock()
	registry.SetProxy(snapshot)
	if rt := s.rt.Load(); rt != nil && rt.dns != nil {
		stats := rt.dns.metrics()
		dnsSnapshot := observability.DNSSnapshot{
			EntriesPositive: stats.EntriesPositive, EntriesNegative: stats.EntriesNegative,
			EvictionsPositive: stats.EvictionsPositive, EvictionsNegative: stats.EvictionsNegative,
			Pending: stats.Pending, RejectedPending: stats.RejectedPending, Requests: stats.Requests,
			Resolutions: map[string]observability.DNSResolution{},
		}
		for key, value := range stats.Resolutions {
			dnsSnapshot.Resolutions[key] = observability.DNSResolution{Count: value.Count, DurationSeconds: value.TotalDuration.Seconds()}
		}
		registry.SetDNS(dnsSnapshot)
	}
}

func (s *Server) closeListeners() {
	s.listenersMu.Lock()
	listeners := append([]net.Listener(nil), s.listeners...)
	s.listenersMu.Unlock()
	for _, listener := range listeners {
		_ = listener.Close()
	}
}

// Stop closes admission, waits for registered sessions, and force-closes the
// bounded remainder when shutdown_grace expires. It returns the number forced.
func (s *Server) Stop() int {
	if !s.stopping.CompareAndSwap(false, true) {
		return 0
	}
	defer s.logMetricSummary()
	s.closeListeners()
	s.acceptWG.Wait()

	drained := make(chan struct{})
	go func() {
		s.sessionWG.Wait()
		close(drained)
	}()
	grace := s.rt.Load().shutdownGrace
	if grace <= 0 {
		grace = time.Duration(defaultShutdownGrace) * time.Second
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-drained:
		s.rootCancel()
		return 0
	case <-timer.C:
	}

	s.sessionsMu.Lock()
	remaining := make([]*ownedSession, 0, len(s.sessions))
	for session := range s.sessions {
		remaining = append(remaining, session)
	}
	s.sessionsMu.Unlock()
	s.rootCancel()
	for _, session := range remaining {
		session.close()
	}
	<-drained
	if len(remaining) > 0 {
		log.Printf("proxy: shutdown grace exceeded; force-closed %d session(s)", len(remaining))
	}
	return len(remaining)
}

func (s *Server) logMetricSummary() {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	for key, total := range s.rejections {
		log.Printf("proxy: rejections protocol=%s reason=%s listener=%s total=%d", key.Protocol, key.Reason, key.ListenerClass, total)
	}
	for outcome, aggregate := range s.aggregates {
		log.Printf("proxy: sessions outcome=%s total=%d client_bytes=%d backend_bytes=%d total_duration=%s", outcome, aggregate.Sessions, aggregate.ClientBytes, aggregate.BackendBytes, aggregate.TotalDuration)
	}
	if rt := s.rt.Load(); rt != nil && rt.dns != nil {
		dnsMetrics := rt.dns.metrics()
		log.Printf("dns: cache entries_positive=%d entries_negative=%d evictions_positive=%d evictions_negative=%d pending=%d rejected_pending=%d",
			dnsMetrics.EntriesPositive, dnsMetrics.EntriesNegative, dnsMetrics.EvictionsPositive, dnsMetrics.EvictionsNegative, dnsMetrics.Pending, dnsMetrics.RejectedPending)
		for _, result := range []string{"hit", "miss", "stale", "negative", "refresh", "rejection"} {
			log.Printf("dns: requests result=%s total=%d", result, dnsMetrics.Requests[result])
		}
		for _, class := range []string{"direct", "marked"} {
			for _, outcome := range []string{"positive", "nxdomain", "nodata", "transient"} {
				resolution := dnsMetrics.Resolutions[outcome+"|"+class]
				log.Printf("dns: resolutions outcome=%s egress_class=%s total=%d total_duration=%s", outcome, class, resolution.Count, resolution.TotalDuration)
			}
		}
	}
	connectMetrics := s.connectMetrics.Snapshot()
	for _, class := range []string{"direct", "marked"} {
		for _, outcome := range []string{"success", "failure"} {
			log.Printf("proxy: backend_connect_attempts outcome=%s egress_class=%s total=%d", outcome, class, connectMetrics[outcome+"|"+class])
		}
	}
}

func peekClientHelloLimit(r io.Reader, limit int64) (*tls.ClientHelloInfo, []byte, error) {
	var buffer bytes.Buffer
	hello, err := readClientHelloLimit(io.TeeReader(io.LimitReader(r, limit+1), &buffer), limit)
	if err != nil {
		return nil, nil, err
	}
	if int64(buffer.Len()) > limit {
		return nil, nil, fmt.Errorf("ClientHello exceeds %d bytes", limit)
	}
	return hello, buffer.Bytes(), nil
}

func readClientHelloLimit(r io.Reader, limit int64) (*tls.ClientHelloInfo, error) {
	r = io.LimitReader(r, limit+1)
	var hello *tls.ClientHelloInfo
	err := tls.Server(readOnlyConn{reader: r}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			captured := *argHello
			hello = &captured
			return nil, nil
		},
	}).HandshakeContext(context.Background())
	if hello == nil {
		return nil, err
	}
	return hello, nil
}

type readOnlyConn struct{ reader io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                     { return nil }
func (readOnlyConn) LocalAddr() net.Addr              { return nil }
func (readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error { return nil }
