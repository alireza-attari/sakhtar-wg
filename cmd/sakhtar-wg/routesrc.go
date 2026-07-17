package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alireza-attari/sakhtar-wg/internal/observability"
	proxydial "github.com/alireza-attari/sakhtar-wg/internal/proxy"
	internalroutesource "github.com/alireza-attari/sakhtar-wg/internal/routesource"
)

const (
	routeCacheDir  = "/var/lib/sakhtar-wg"
	routeCacheFile = "routes.json"
	fetchTimeout   = 30 * time.Second
	maxSourceBytes = 8 << 20 // cap a source response so a huge/hostile body can't OOM us
)

// RouteUpdater periodically fetches every tunnel's RouteSources and produces a
// config whose tunnel Routes are the union of the static routes and the fetched
// CIDRs. It NEVER mutates kernel state itself: it sends the merged config to
// applyCh and the main loop applies it on its own goroutine, so all
// netlink/wgctrl mutation stays single-threaded and never races a SIGHUP reload.
//
// A fetch failure keeps the source's last good set (in memory and in a disk
// cache), so a transient upstream outage — or a daemon restart during one —
// never withdraws working routes.
type RouteUpdater struct {
	mu      sync.Mutex
	base    *Config             // static config from file; replaced on SIGHUP
	fetched map[string][]string // source name -> last good CIDRs
	applyCh chan<- *Config
	refresh time.Duration
	trigger chan struct{}
	pf      *PfSyncer // optional pfSense OpenVPN local-network mirror
	pfFrom  string    // tunnel whose routes feed pfSync
	metrics *observability.Registry
}

func hasRouteSources(c *Config) bool {
	for _, t := range c.Tunnels {
		if len(t.RouteSources) > 0 {
			return true
		}
	}
	return false
}

func needsRouteUpdater(c *Config) bool { return hasRouteSources(c) || c.PfSync.Enabled }

func NewRouteUpdater(base *Config, applyCh chan<- *Config, registries ...*observability.Registry) *RouteUpdater {
	u := &RouteUpdater{
		base:    base,
		fetched: map[string][]string{},
		applyCh: applyCh,
		refresh: time.Duration(base.RouteRefresh) * time.Second,
		trigger: make(chan struct{}, 1),
	}
	if len(registries) > 0 {
		u.metrics = registries[0]
	}
	if base.PfSync.Enabled {
		u.pf = NewPfSyncer(base.PfSync, u.metrics)
		u.pfFrom = base.PfSync.FromTunnel
	}
	u.loadCache()
	return u
}

// mirrorToPfSense pushes the given tunnel's current effective routes to pfSense
// (best-effort; only applies when the aggregated set changed).
func (u *RouteUpdater) mirrorToPfSense(ctx context.Context) {
	u.mu.Lock()
	defer u.mu.Unlock()
	pf, pfFrom := u.pf, u.pfFrom
	if pf == nil {
		return
	}
	merged := u.mergeBaseLocked(u.base)
	for _, t := range merged.Tunnels {
		if t.Name == pfFrom {
			pf.Reconcile(ctx, t.Routes)
			return
		}
	}
}

// SetBase swaps in a new static config (after SIGHUP) and schedules an immediate
// re-fetch, so newly added or removed sources take effect promptly.
func (u *RouteUpdater) SetBase(base *Config) {
	u.mu.Lock()
	pfChanged := u.base == nil || !reflect.DeepEqual(u.base.PfSync, base.PfSync)
	u.base = base
	u.refresh = time.Duration(base.RouteRefresh) * time.Second
	if base.PfSync.Enabled {
		if u.pf == nil || pfChanged {
			u.pf = NewPfSyncer(base.PfSync, u.metrics)
		}
		u.pfFrom = base.PfSync.FromTunnel
	} else {
		u.pf = nil
		u.pfFrom = ""
	}
	u.mu.Unlock()
	select {
	case u.trigger <- struct{}{}:
	default:
	}
}

// Merge returns a copy of the current base config with each tunnel's Routes set
// to the sorted, de-duplicated union of its static routes and the last-good
// fetched CIDRs of its sources.
func (u *RouteUpdater) Merge() *Config {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.mergeBaseLocked(u.base)
}

// MergeBase previews a candidate config with current last-good source data
// without changing the updater. A failed reload cannot leak candidate state
// into a later route refresh.
func (u *RouteUpdater) MergeBase(base *Config) *Config {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.mergeBaseLocked(base)
}

func (u *RouteUpdater) mergeBaseLocked(base *Config) *Config {
	out := *base
	out.Tunnels = make([]Tunnel, len(base.Tunnels))
	for i, t := range base.Tunnels {
		nt := t
		set := map[string]struct{}{}
		var merged []string
		add := func(c string) {
			if _, ok := set[c]; !ok {
				set[c] = struct{}{}
				merged = append(merged, c)
			}
		}
		for _, c := range t.Routes {
			if n, ok := normalizeIPv4CIDR(c); ok {
				add(n)
			}
		}
		for _, s := range t.RouteSources {
			for _, c := range u.fetched[s.Name] {
				add(c)
			}
		}
		sort.Strings(merged)
		nt.Routes = merged
		out.Tunnels[i] = nt
	}
	return &out
}

// Run drives the update loop until ctx is cancelled. It applies the cached set
// immediately (so a restart mid-outage keeps routes), then fetches live and on
// every refresh tick / trigger.
func (u *RouteUpdater) Run(ctx context.Context) {
	u.send(ctx, u.Merge())
	u.cycle(ctx)
	t := time.NewTicker(u.refreshInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			u.cycle(ctx)
		case <-u.trigger:
			u.cycle(ctx)
		}
		t.Reset(u.refreshInterval())
	}
}

func (u *RouteUpdater) refreshInterval() time.Duration {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.refresh <= 0 {
		return 6 * time.Hour
	}
	return u.refresh
}

// cycle fetches every source once, updates the last-good sets, and pushes a
// freshly merged config to the main loop.
func (u *RouteUpdater) cycle(ctx context.Context) {
	u.mu.Lock()
	base := u.base
	u.mu.Unlock()

	seen := map[string]bool{}
	changed := false
	for _, t := range base.Tunnels {
		for _, s := range t.RouteSources {
			if seen[s.Name] {
				continue
			}
			seen[s.Name] = true
			cidrs, err := u.fetchSource(ctx, base, s)
			if err != nil {
				u.mu.Lock()
				have := len(u.fetched[s.Name])
				u.mu.Unlock()
				log.Printf("routesrc %s: fetch failed: %v (keeping %d last-good)", s.Name, err, have)
				if u.metrics != nil {
					u.metrics.SetRouteSource(observability.RouteSourceSnapshot{Name: s.Name, LastOutcome: "failure", PrefixCount: have, LastError: err.Error()})
				}
				continue
			}
			cidrs = sortDedup(cidrs)
			u.mu.Lock()
			if !equalStrings(u.fetched[s.Name], cidrs) {
				u.fetched[s.Name] = cidrs
				changed = true
			}
			u.mu.Unlock()
			log.Printf("routesrc %s: %d IPv4 CIDRs", s.Name, len(cidrs))
			if u.metrics != nil {
				u.metrics.SetRouteSource(observability.RouteSourceSnapshot{Name: s.Name, LastSuccess: time.Now().UTC(), LastOutcome: "success", PrefixCount: len(cidrs)})
			}
		}
	}
	if changed {
		u.saveCache()
	}
	u.send(ctx, u.Merge())
	u.mirrorToPfSense(ctx)
}

func (u *RouteUpdater) send(ctx context.Context, cfg *Config) {
	select {
	case u.applyCh <- cfg:
	case <-ctx.Done():
	}
}

// fetchSource fetches and parses one source, egressing per src.Via.
func (u *RouteUpdater) fetchSource(ctx context.Context, base *Config, src RouteSource) ([]string, error) {
	client := u.httpClient(base, src.Via)
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sakhtar-wg/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := readBounded(resp.Body, maxSourceBytes)
	if err != nil {
		return nil, fmt.Errorf("source body: %w", err)
	}
	switch src.Format {
	case "cidr-lines":
		return parseCIDRLines(body)
	case "ripe-prefixes":
		return parseRIPEPrefixes(body)
	default:
		return nil, fmt.Errorf("unknown format %q", src.Format)
	}
}

// httpClient builds a client whose connections egress "direct" (system routing)
// or THROUGH a tunnel (via != "direct"): for the tunnel case it resolves the
// host's real IPv4 with the clean upstream resolver over the tunnel and stamps
// SO_MARK so the connection follows the tunnel's policy route — mirroring how
// the SNI proxy reaches a filtered backend, avoiding any AdGuard rewrite loop.
func (u *RouteUpdater) httpClient(base *Config, via string) *http.Client {
	mark := base.markFor(via)
	resolver := base.Proxy.Resolver
	if resolver == "" {
		resolver = "1.1.1.1:53"
	}
	resolverTimeout := durationSeconds(base.Proxy.DNSResolverTimeout, defaultDNSResolverTimeout)
	attemptCap := positiveOr(base.Proxy.ConnectAttemptCap, defaultConnectAttemptCap)
	strategy := proxydial.AddressFamilyStrategy(base.Proxy.AddressFamilyStrategy)
	if !strategy.Valid() {
		strategy = proxydial.Interleave
	}
	selector := &proxydial.RotatingSelector{Strategy: strategy, MaxAttempts: attemptCap}
	destination := newDestinationPolicy(base)
	noSelfAddresses := map[netip.Addr]struct{}{}
	markedResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, dnsNet, _ string) (net.Conn, error) {
			return dialMarkedContext(ctx, dnsNet, resolver, mark, resolverTimeout)
		},
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if mark == 0 {
				// Direct configured route sources retain net.Dialer's standard
				// hostname resolution and Happy Eyeballs behavior.
				return (&net.Dialer{Timeout: fetchTimeout}).DialContext(ctx, network, addr)
			}
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if parsed, parseErr := netip.ParseAddr(host); parseErr == nil {
				if !destination.addressAllowed(parsed, mark, noSelfAddresses) {
					return nil, errDestinationDenied
				}
				return dialMarkedContext(ctx, network, addr, mark, fetchTimeout)
			}
			resolveCtx, cancel := context.WithTimeout(ctx, resolverTimeout)
			addrs, err := markedResolver.LookupNetIP(resolveCtx, "ip", host)
			cancel()
			if err != nil {
				return nil, err
			}
			candidates := selector.Select(addrs, func(candidate netip.Addr) bool {
				return destination.addressAllowed(candidate, mark, noSelfAddresses)
			})
			if len(candidates) == 0 {
				return nil, errDestinationDenied
			}
			conn, _, err := proxydial.DialCandidates(ctx, candidates, port, attemptCap, true, func(dialCtx context.Context, dialNetwork, dialAddress string) (net.Conn, error) {
				return dialMarkedContext(dialCtx, dialNetwork, dialAddress, mark, fetchTimeout)
			}, nil)
			return conn, err
		},
	}
	return &http.Client{Transport: tr, Timeout: fetchTimeout}
}

// --- parsers ---

// parseCIDRLines reads a plain-text list of one CIDR (or bare IP) per line,
// ignoring blanks and '#' comments and trailing fields. IPv6 entries are
// skipped (the L3 path and pfSense chain are IPv4).
func parseCIDRLines(b []byte) ([]string, error) {
	if len(b) > maxSourceBytes {
		return nil, fmt.Errorf("CIDR source exceeds %d bytes", maxSourceBytes)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexAny(line, " \t,;"); i >= 0 {
			line = line[:i]
		}
		if c, ok := normalizeIPv4CIDR(line); ok {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 CIDRs parsed")
	}
	return out, nil
}

// parseRIPEPrefixes reads RIPEstat announced-prefixes JSON
// (data.prefixes[].prefix), keeping IPv4 entries.
func parseRIPEPrefixes(b []byte) ([]string, error) {
	if len(b) > maxSourceBytes {
		return nil, fmt.Errorf("RIPE source exceeds %d bytes", maxSourceBytes)
	}
	var doc struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range doc.Data.Prefixes {
		if c, ok := normalizeIPv4CIDR(p.Prefix); ok {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no IPv4 prefixes in RIPE data")
	}
	return out, nil
}

// normalizeIPv4CIDR canonicalises an IPv4 CIDR (or bare IP -> /32) and rejects
// IPv6. Returns the masked network string, e.g. "1.2.0.0/16".
func normalizeIPv4CIDR(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			return "", false
		}
		return ip.To4().String() + "/32", true
	}
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil || ip.To4() == nil {
		return "", false
	}
	return ipnet.String(), true
}

// --- disk cache ---

func (u *RouteUpdater) cachePath() string { return filepath.Join(routeCacheDir, routeCacheFile) }

func (u *RouteUpdater) loadCache() {
	b, err := os.ReadFile(u.cachePath())
	if err != nil {
		return
	}
	var m map[string][]string
	if err := json.Unmarshal(b, &m); err != nil {
		log.Printf("routesrc: ignoring bad cache: %v", err)
		return
	}
	for k, v := range m {
		u.fetched[k] = sortDedup(v)
	}
	log.Printf("routesrc: loaded cached routes for %d source(s)", len(m))
}

func (u *RouteUpdater) saveCache() {
	u.mu.Lock()
	snapshot := make(map[string][]string, len(u.fetched))
	for k, v := range u.fetched {
		snapshot[k] = v
	}
	u.mu.Unlock()
	b, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(routeCacheDir, 0o700); err != nil {
		log.Printf("routesrc: cache dir: %v", err)
		return
	}
	if err := os.Chmod(routeCacheDir, 0o700); err != nil {
		log.Printf("routesrc: secure cache dir: %v", err)
		return
	}
	tmp := u.cachePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("routesrc: write cache: %v", err)
		return
	}
	if err := os.Rename(tmp, u.cachePath()); err != nil {
		log.Printf("routesrc: replace cache: %v", err)
	}
}

// --- small helpers ---

func sortDedup(in []string) []string {
	return internalroutesource.MergeDedup(in)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
