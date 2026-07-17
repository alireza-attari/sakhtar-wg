package main

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	kernelstate "github.com/alireza-attari/sakhtar-wg/internal/kernel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

const maxConfigBytes = 1 << 20

const (
	defaultMaxConnections              = 1024
	defaultHandshakeTimeout            = 5
	defaultShutdownGrace               = 10
	defaultMaxClientHelloBytes         = 64 << 10
	defaultMaxHTTPHeaderBytes          = 64 << 10
	defaultDNSPositiveCapacity         = 4096
	defaultDNSNegativeCapacity         = 1024
	defaultDNSMaxPending               = 128
	defaultDNSMinPositiveTTL           = 5
	defaultDNSMaxPositiveTTL           = 300
	defaultDNSNegativeTTL              = 20
	defaultDNSTransientTTL             = 2
	defaultDNSStaleWindow              = 3600
	defaultDNSResolverTimeout          = 5
	defaultConnectAttemptCap           = 4
	defaultManagementReadHeaderTimeout = 5
	defaultManagementWriteTimeout      = 10
	defaultManagementIdleTimeout       = 30
	defaultManagementShutdownTimeout   = 5
	defaultManagementMaxHeaderBytes    = 16 << 10
	maxConfiguredConnections           = 1 << 20
	maxConfiguredProtocolBytes         = 256 << 10
	maxDNSCapacity                     = 1 << 20
	maxConnectAttemptCap               = 64
)

const maxDurationSeconds = int64(math.MaxInt64) / int64(time.Second)

var interfaceNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var operationalNameRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// Config is the whole sakhtar-wg configuration: a set of WireGuard tunnels, the
// SNI/HTTP proxy that steers selected hostnames into them, and an optional L3
// gateway that forwards routed client traffic out the tunnels.
type Config struct {
	Tunnels []Tunnel `yaml:"tunnels"`
	// Groups are failover sets of tunnels. A proxy rule (or the default) may
	// target a group name instead of a single tunnel; the health monitor keeps
	// the group pointed at its first member with a fresh WireGuard handshake.
	Groups  []Group `yaml:"groups"`
	Proxy   Proxy   `yaml:"proxy"`
	Gateway Gateway `yaml:"gateway"`
	// RouteRefresh is how often (seconds) tunnel RouteSources are re-fetched.
	// 0 => 21600 (6h). Ignored if no tunnel declares a route source.
	RouteRefresh int `yaml:"route_refresh"`
	// HealthInterval is how often (seconds) group members' handshakes are polled
	// for failover. 0 => 10. Ignored if no group is defined.
	HealthInterval int `yaml:"health_interval"`
	// PfSync optionally mirrors a tunnel's routes into a pfSense OpenVPN server's
	// "IPv4 Local Network(s)" via the REST API, so split-tunnel VPN clients route
	// the bypassed ranges into the VPN automatically. Runs on the route refresh.
	PfSync PfSync `yaml:"pfsync"`
	// Management serves bounded operational endpoints. It defaults to loopback
	// and never accepts a wildcard/non-loopback TCP address.
	Management Management `yaml:"management"`
	// HealthProbe is an optional independent reachability check through one
	// marked egress. It never probes a customer-requested destination.
	HealthProbe HealthProbe `yaml:"health_probe"`
}

type HealthProbe struct {
	Enabled       bool   `yaml:"enabled"`
	Endpoint      string `yaml:"endpoint"`
	Via           string `yaml:"via"`
	Interval      int    `yaml:"interval"`
	Timeout       int    `yaml:"timeout"`
	JitterPercent int    `yaml:"jitter_percent"`
	MaxConcurrent int    `yaml:"max_concurrent"`
}

type Management struct {
	Disabled          bool   `yaml:"disabled"`
	Listen            string `yaml:"listen"` // loopback host:port or unix:/absolute/path
	ReadHeaderTimeout int    `yaml:"read_header_timeout"`
	WriteTimeout      int    `yaml:"write_timeout"`
	IdleTimeout       int    `yaml:"idle_timeout"`
	ShutdownTimeout   int    `yaml:"shutdown_timeout"`
	MaxHeaderBytes    int    `yaml:"max_header_bytes"`
	Pprof             bool   `yaml:"pprof"`
}

// PfSync configures the optional pfSense OpenVPN local-network mirror.
//
// It pushes over SSH to a locked-down forced-command key (not the REST API: the
// RESTAPI package 500s on a CARP-VIP-bound OpenVPN server). The far end only ever
// updates one server's local_network + openvpn_resync — never the filter/NAT.
type PfSync struct {
	Enabled      bool     `yaml:"enabled"`
	SSHHost      string   `yaml:"ssh_host"`      // pfSense LAN IP, e.g. 10.0.0.1
	SSHPort      int      `yaml:"ssh_port"`      // 0 => 22
	SSHUser      string   `yaml:"ssh_user"`      // e.g. admin
	SSHKey       string   `yaml:"ssh_key"`       // path to the private key (chmod 600)
	KnownHosts   string   `yaml:"known_hosts"`   // path to a pinned known_hosts file
	FromTunnel   string   `yaml:"from_tunnel"`   // push this tunnel's effective routes
	KeepNetworks []string `yaml:"keep_networks"` // always retained, e.g. the LAN
}

// Group is a failover set of tunnels sharing one logical egress name. A proxy
// rule (or proxy.default) can route to the group name; the health monitor keeps
// it pointed at the first member whose handshake is fresh, so a dead upstream
// fails over without a reload or any per-connection cost.
type Group struct {
	Name         string   `yaml:"name"`          // referenced by proxy.rules[].via / proxy.default
	Members      []string `yaml:"members"`       // tunnel names, in preference order (primary first)
	HealthyAfter int      `yaml:"healthy_after"` // handshake age (s) still counted healthy; 0 => 180
}

// Gateway turns the box into an L3 forwarder: traffic from ClientCIDRs (e.g. the
// OpenVPN pool) destined to a tunnel's Routes is forwarded out that tunnel with
// NAT. Enables ip_forward and installs the masquerade/forward rules.
type Gateway struct {
	Enabled     bool     `yaml:"enabled"`
	ClientCIDRs []string `yaml:"client_cidrs"` // source subnets allowed to be forwarded
	// ListListen, if set (e.g. ":8088"), serves the union of every tunnel's
	// Routes as a plain-text CIDR list — one per line — for a pfSense URL Table
	// alias to pull. The list is the single source of truth; pfSense caches it in
	// a kernel pf table and a routing change never edits pfSense config.
	ListListen string `yaml:"list_listen"`
}

// Tunnel is one kernel WireGuard interface with a single upstream peer.
//
// Fwmark is the routing selector, not the WireGuard device firewall-mark: the
// proxy stamps SO_MARK=Fwmark on sockets it wants to send through this tunnel,
// an `ip rule fwmark Fwmark lookup Table` sends them to Table, and Table holds
// a single `default dev <Name>`. Unmarked traffic never touches the tunnel, so
// the box's own egress (updates, DNS, management) stays on the main table.
type Tunnel struct {
	Name          string `yaml:"name"`           // interface name, e.g. wg0
	PrivateKey    string `yaml:"private_key"`    // base64, 32 bytes
	Address       string `yaml:"address"`        // CIDR assigned to the interface, e.g. 10.200.0.2/32
	MTU           int    `yaml:"mtu"`            // 0 => 1420 default
	Fwmark        int    `yaml:"fwmark"`         // routing mark; must be unique and non-zero
	FwmarkMask    uint32 `yaml:"fwmark_mask"`    // 0 => exact 0xffffffff mask
	Table         int    `yaml:"table"`          // routing table id; 0 => same as Fwmark
	RulePriority  int    `yaml:"rule_priority"`  // 0 => 31000 + tunnel index
	AdoptExisting bool   `yaml:"adopt_existing"` // opt-in adoption after strict conflict checks
	// Routes are destination CIDRs sent out this tunnel at L3 (main routing
	// table). This is the "by IP" path for applications that dial address
	// literals and therefore bypass hostname routing.
	// Static routes here are a permanent floor; RouteSources are merged on top.
	Routes []string `yaml:"routes"`
	// RouteSources are external CIDR lists fetched periodically and merged into
	// this tunnel's effective routes. A fetch failure keeps the last good set;
	// the union of static and sourced routes is routed and served on the list
	// listener.
	RouteSources []RouteSource `yaml:"route_sources"`
	Peer         Peer          `yaml:"peer"`
}

// RouteSource is one periodically-fetched CIDR list feeding a tunnel's routes.
type RouteSource struct {
	Name   string `yaml:"name"`   // unique label, used in logs and the disk cache
	URL    string `yaml:"url"`    // http(s) endpoint to fetch
	Format string `yaml:"format"` // "cidr-lines" | "ripe-prefixes"
	// Via selects how the fetch itself egresses: a tunnel name (dial + resolve
	// THROUGH that tunnel, for a source that is itself filtered, e.g. Telegram)
	// or "direct". Empty => "direct".
	Via string `yaml:"via"`
}

// Peer is the single upstream WireGuard endpoint of a Tunnel.
type Peer struct {
	PublicKey  string   `yaml:"public_key"`  // base64, 32 bytes
	Endpoint   string   `yaml:"endpoint"`    // host:port, resolved at (re)configure time
	AllowedIPs []string `yaml:"allowed_ips"` // empty => 0.0.0.0/0
	Keepalive  int      `yaml:"keepalive"`   // seconds; 0 => disabled (25 recommended behind NAT)
}

// Proxy is the SNI (TLS :443) + Host (HTTP :80) splicing proxy.
type Proxy struct {
	HTTPSListen string `yaml:"https_listen"` // e.g. :443, "" => disabled
	HTTPListen  string `yaml:"http_listen"`  // e.g. :80,  "" => disabled
	Default     string `yaml:"default"`      // tunnel name or "direct"; empty => direct
	// AllowedSourceCIDRs is mandatory for any wildcard or non-loopback proxy
	// listener. An empty list on loopback listeners means loopback clients only.
	AllowedSourceCIDRs      []string          `yaml:"allowed_source_cidrs"`
	MaxConnections          int               `yaml:"max_connections"`            // 0 => 1024
	MaxConnectionsPerSource int               `yaml:"max_connections_per_source"` // 0 => disabled
	HandshakeTimeout        int               `yaml:"handshake_timeout"`          // seconds; 0 => 5
	DialTimeout             int               `yaml:"dial_timeout"`               // total resolve+dial seconds; 0 => 10
	IdleTimeout             int               `yaml:"idle_timeout"`               // seconds; 0 => disabled
	ShutdownGrace           int               `yaml:"shutdown_grace"`             // seconds; 0 => 10
	MaxClientHelloBytes     int               `yaml:"max_client_hello_bytes"`     // 0 => 64 KiB
	MaxHTTPHeaderBytes      int               `yaml:"max_http_header_bytes"`      // 0 => 64 KiB
	DestinationPolicy       DestinationPolicy `yaml:"destination_policy"`
	// Resolver is the upstream DNS used to resolve a tunnelled backend's real
	// address, queried THROUGH that tunnel. It must not be the rewriting resolver
	// (AdGuard) that points the domain back at this proxy, or the proxy would dial
	// itself. host:port; empty => 1.1.1.1:53.
	Resolver string `yaml:"resolver"`
	// DNSCacheTTL is the local positive lifetime used because net.Resolver does
	// not expose authoritative record TTLs. It is clamped by the min/max policy.
	DNSCacheTTL            int    `yaml:"dns_cache_ttl"`
	DNSPositiveCapacity    int    `yaml:"dns_positive_capacity"`
	DNSNegativeCapacity    int    `yaml:"dns_negative_capacity"`
	DNSMaxPending          int    `yaml:"dns_max_pending"`
	DNSMinPositiveTTL      int    `yaml:"dns_min_positive_ttl"`
	DNSMaxPositiveTTL      int    `yaml:"dns_max_positive_ttl"`
	DNSNegativeTTL         int    `yaml:"dns_negative_ttl"`
	DNSTransientFailureTTL int    `yaml:"dns_transient_failure_ttl"`
	DNSStaleWindow         int    `yaml:"dns_stale_window"`
	DNSStalePolicy         string `yaml:"dns_stale_policy"` // "transient" | "never"
	DNSResolverTimeout     int    `yaml:"dns_resolver_timeout"`
	AddressFamilyStrategy  string `yaml:"address_family_strategy"` // "interleave" | "ipv4_first" | "ipv6_first"
	ConnectAttemptCap      int    `yaml:"connect_attempt_cap"`
	Rules                  []Rule `yaml:"rules"`
}

// DestinationPolicy contains the only exceptions to the default destination
// deny ranges. Exceptions are scoped to the actual egress: direct traffic uses
// DirectAllowCIDRs and a marked tunnel uses the entry named for that tunnel.
// Listener/self addresses, unspecified addresses, and multicast are never
// dialable even when covered by an allow CIDR.
type DestinationPolicy struct {
	DirectAllowCIDRs []string            `yaml:"direct_allow_cidrs"`
	TunnelAllowCIDRs map[string][]string `yaml:"tunnel_allow_cidrs"`
}

// Rule maps a set of domain suffixes to an egress: a tunnel name or "direct".
type Rule struct {
	Via      string   `yaml:"via"`      // tunnel name or "direct"
	Suffixes []string `yaml:"suffixes"` // match host == s or host endsWith "."+s (case-insensitive)
}

// LoadConfig reads, parses and validates a config file.
func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := readBounded(f, maxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	c, err := parseConfig(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return c, nil
}

// parseConfig is the bounded, strict parser used by both LoadConfig and fuzz
// tests. Unknown fields, duplicate mapping keys, and trailing YAML documents
// are rejected: a typo in a network daemon config must never be silently
// ignored.
func parseConfig(raw []byte) (*Config, error) {
	if len(raw) > maxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("parse trailing YAML: %w", err)
	}
	c.normalize()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if !validSeconds(c.RouteRefresh) {
		return fmt.Errorf("route_refresh must be between 0 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.HealthInterval) {
		return fmt.Errorf("health_interval must be between 0 and %d seconds", maxDurationSeconds)
	}
	if !c.Management.Disabled {
		if strings.HasPrefix(c.Management.Listen, "unix:") {
			path := strings.TrimPrefix(c.Management.Listen, "unix:")
			if !strings.HasPrefix(path, "/") || len(path) < 2 {
				return fmt.Errorf("management.listen: Unix socket path must be absolute")
			}
		} else {
			host, _, err := net.SplitHostPort(c.Management.Listen)
			if err != nil {
				return fmt.Errorf("management.listen: %w", err)
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return fmt.Errorf("management.listen: TCP listener must use a loopback IP literal")
			}
		}
		for name, value := range map[string]int{
			"read_header_timeout": c.Management.ReadHeaderTimeout,
			"write_timeout":       c.Management.WriteTimeout,
			"idle_timeout":        c.Management.IdleTimeout,
			"shutdown_timeout":    c.Management.ShutdownTimeout,
		} {
			if !validSeconds(value) || value == 0 {
				return fmt.Errorf("management.%s must be between 1 and %d seconds", name, maxDurationSeconds)
			}
		}
		if c.Management.MaxHeaderBytes < 1024 || c.Management.MaxHeaderBytes > maxConfiguredProtocolBytes {
			return fmt.Errorf("management.max_header_bytes must be between 1024 and %d", maxConfiguredProtocolBytes)
		}
	}
	seenName := map[string]bool{}
	seenMark := map[int]string{}
	seenTable := map[int]string{}
	allocations := make([]kernelstate.Allocation, 0, len(c.Tunnels))
	type routeOwner struct {
		name   string
		prefix netip.Prefix
	}
	var gatewayRoutes []routeOwner
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if t.Name == "" {
			return fmt.Errorf("tunnel #%d: name is required", i)
		}
		if len(t.Name) > 15 || !interfaceNameRE.MatchString(t.Name) {
			return fmt.Errorf("tunnel %q: name must be 1-15 letters, digits, '.', '_' or '-'", t.Name)
		}
		if seenName[t.Name] {
			return fmt.Errorf("duplicate tunnel name %q", t.Name)
		}
		seenName[t.Name] = true
		if t.PrivateKey == "" {
			return fmt.Errorf("tunnel %q: private_key is required", t.Name)
		}
		if _, err := wgtypes.ParseKey(t.PrivateKey); err != nil {
			return fmt.Errorf("tunnel %q: private_key: %w", t.Name, err)
		}
		if t.Address == "" {
			return fmt.Errorf("tunnel %q: address is required", t.Name)
		}
		address, err := netip.ParsePrefix(t.Address)
		if err != nil || !address.Addr().Is4() {
			return fmt.Errorf("tunnel %q: address %q must be an IPv4 prefix", t.Name, t.Address)
		}
		if t.MTU < 0 {
			return fmt.Errorf("tunnel %q: mtu must be non-negative", t.Name)
		}
		if t.Fwmark <= 0 || uint64(t.Fwmark) > math.MaxUint32 {
			return fmt.Errorf("tunnel %q: fwmark must be between 1 and %d", t.Name, uint64(math.MaxUint32))
		}
		if other, ok := seenMark[t.Fwmark]; ok {
			return fmt.Errorf("tunnel %q: fwmark %d already used by %q", t.Name, t.Fwmark, other)
		}
		seenMark[t.Fwmark] = t.Name
		if t.Table <= 0 || int64(t.Table) > math.MaxInt32 {
			return fmt.Errorf("tunnel %q: table must be between 1 and %d", t.Name, int64(math.MaxInt32))
		}
		if other, ok := seenTable[t.Table]; ok {
			return fmt.Errorf("tunnel %q: table %d already used by %q", t.Name, t.Table, other)
		}
		seenTable[t.Table] = t.Name
		allocations = append(allocations, kernelstate.Allocation{
			Name: t.Name, Mark: uint32(t.Fwmark), Mask: t.FwmarkMask,
			Table: t.Table, Priority: t.RulePriority,
		})
		if t.Peer.PublicKey == "" {
			return fmt.Errorf("tunnel %q: peer.public_key is required", t.Name)
		}
		if _, err := wgtypes.ParseKey(t.Peer.PublicKey); err != nil {
			return fmt.Errorf("tunnel %q: peer.public_key: %w", t.Name, err)
		}
		if t.Peer.Endpoint == "" {
			return fmt.Errorf("tunnel %q: peer.endpoint is required", t.Name)
		}
		if err := validateHostPort(t.Peer.Endpoint, false); err != nil {
			return fmt.Errorf("tunnel %q: peer.endpoint: %w", t.Name, err)
		}
		if !validSeconds(t.Peer.Keepalive) {
			return fmt.Errorf("tunnel %q: peer.keepalive must be between 0 and %d seconds", t.Name, maxDurationSeconds)
		}
		for _, allowed := range t.Peer.AllowedIPs {
			if _, _, err := net.ParseCIDR(allowed); err != nil {
				return fmt.Errorf("tunnel %q: allowed_ips %q: %w", t.Name, allowed, err)
			}
		}
		seenRoute := map[string]bool{}
		for _, route := range t.Routes {
			prefix, err := netip.ParsePrefix(route)
			if err != nil || !prefix.Addr().Is4() {
				return fmt.Errorf("tunnel %q: route %q: must be an IPv4 prefix", t.Name, route)
			}
			canonical := prefix.Masked().String()
			if seenRoute[canonical] {
				return fmt.Errorf("tunnel %q: duplicate route %s", t.Name, canonical)
			}
			seenRoute[canonical] = true
			gatewayRoutes = append(gatewayRoutes, routeOwner{name: t.Name, prefix: prefix.Masked()})
		}
	}
	if c.HealthProbe.Enabled {
		endpoint, err := url.ParseRequestURI(c.HealthProbe.Endpoint)
		if err != nil || endpoint.Host == "" || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
			return fmt.Errorf("health_probe.endpoint must be an absolute http(s) URL")
		}
		if endpoint.User != nil {
			return fmt.Errorf("health_probe.endpoint must not contain credentials")
		}
		if !seenName[c.HealthProbe.Via] {
			return fmt.Errorf("health_probe.via %q is not a known tunnel", c.HealthProbe.Via)
		}
		if c.HealthProbe.Interval < 5 || !validSeconds(c.HealthProbe.Interval) {
			return fmt.Errorf("health_probe.interval must be at least 5 seconds")
		}
		if c.HealthProbe.Timeout < 1 || c.HealthProbe.Timeout >= c.HealthProbe.Interval {
			return fmt.Errorf("health_probe.timeout must be positive and less than health_probe.interval")
		}
		if c.HealthProbe.JitterPercent < 0 || c.HealthProbe.JitterPercent > 100 {
			return fmt.Errorf("health_probe.jitter_percent must be between 0 and 100")
		}
		if c.HealthProbe.MaxConcurrent < 1 || c.HealthProbe.MaxConcurrent > 8 {
			return fmt.Errorf("health_probe.max_concurrent must be between 1 and 8")
		}
	}
	if err := kernelstate.ValidateAllocations(allocations); err != nil {
		return err
	}
	if c.Gateway.Enabled {
		for i, route := range gatewayRoutes {
			for _, other := range gatewayRoutes[:i] {
				if route.name != other.name && route.prefix.Overlaps(other.prefix) {
					return fmt.Errorf("gateway routes %s (%s) and %s (%s) overlap across tunnels", other.prefix, other.name, route.prefix, route.name)
				}
			}
		}
	}
	seenSource := map[string]bool{}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		for _, s := range t.RouteSources {
			if s.Name == "" {
				return fmt.Errorf("tunnel %q: route source: name is required", t.Name)
			}
			if !operationalNameRE.MatchString(s.Name) {
				return fmt.Errorf("route source name %q must be 1-64 letters, digits, '.', '_' or '-'", s.Name)
			}
			if seenSource[s.Name] {
				return fmt.Errorf("duplicate route source name %q", s.Name)
			}
			seenSource[s.Name] = true
			if s.URL == "" {
				return fmt.Errorf("route source %q: url is required", s.Name)
			}
			u, err := url.ParseRequestURI(s.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("route source %q: url must be an absolute http(s) URL", s.Name)
			}
			switch s.Format {
			case "cidr-lines", "ripe-prefixes":
			default:
				return fmt.Errorf("route source %q: unknown format %q (want cidr-lines|ripe-prefixes)", s.Name, s.Format)
			}
			if s.Via != "" && s.Via != "direct" && !seenName[s.Via] {
				return fmt.Errorf("route source %q: via %q is not a known tunnel", s.Name, s.Via)
			}
		}
	}
	for _, c := range c.Gateway.ClientCIDRs {
		prefix, err := netip.ParsePrefix(c)
		if err != nil || !prefix.Addr().Is4() {
			return fmt.Errorf("gateway.client_cidrs %q: must be an IPv4 prefix", c)
		}
	}
	if c.Gateway.ListListen != "" {
		if err := validateHostPort(c.Gateway.ListListen, true); err != nil {
			return fmt.Errorf("gateway.list_listen: %w", err)
		}
	}
	if c.PfSync.Enabled {
		if c.PfSync.SSHHost == "" || c.PfSync.SSHUser == "" || c.PfSync.SSHKey == "" || c.PfSync.KnownHosts == "" {
			return fmt.Errorf("pfsync: ssh_host, ssh_user, ssh_key and known_hosts are required")
		}
		if c.PfSync.SSHPort < 0 || c.PfSync.SSHPort > 65535 {
			return fmt.Errorf("pfsync: ssh_port must be between 1 and 65535 (or 0 for default)")
		}
		if !seenName[c.PfSync.FromTunnel] {
			return fmt.Errorf("pfsync: from_tunnel %q is not a known tunnel", c.PfSync.FromTunnel)
		}
		for _, n := range c.PfSync.KeepNetworks {
			if _, _, err := net.ParseCIDR(n); err != nil {
				return fmt.Errorf("pfsync.keep_networks %q: %w", n, err)
			}
		}
	}
	seenGroup := map[string]bool{}
	for i := range c.Groups {
		g := &c.Groups[i]
		if g.Name == "" {
			return fmt.Errorf("group #%d: name is required", i)
		}
		if !operationalNameRE.MatchString(g.Name) {
			return fmt.Errorf("group name %q must be 1-64 letters, digits, '.', '_' or '-'", g.Name)
		}
		if seenName[g.Name] {
			return fmt.Errorf("group %q: name collides with a tunnel", g.Name)
		}
		if seenGroup[g.Name] {
			return fmt.Errorf("duplicate group name %q", g.Name)
		}
		seenGroup[g.Name] = true
		if len(g.Members) == 0 {
			return fmt.Errorf("group %q: at least one member is required", g.Name)
		}
		if !validSeconds(g.HealthyAfter) {
			return fmt.Errorf("group %q: healthy_after must be between 0 and %d seconds", g.Name, maxDurationSeconds)
		}
		seenMember := map[string]bool{}
		for _, m := range g.Members {
			if !seenName[m] {
				return fmt.Errorf("group %q: member %q is not a known tunnel", g.Name, m)
			}
			if seenMember[m] {
				return fmt.Errorf("group %q: duplicate member %q", g.Name, m)
			}
			seenMember[m] = true
		}
	}
	if !validSeconds(c.Proxy.DialTimeout) {
		return fmt.Errorf("proxy.dial_timeout must be between 0 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.Proxy.HandshakeTimeout) {
		return fmt.Errorf("proxy.handshake_timeout must be between 0 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.Proxy.IdleTimeout) {
		return fmt.Errorf("proxy.idle_timeout must be between 0 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.Proxy.ShutdownGrace) {
		return fmt.Errorf("proxy.shutdown_grace must be between 0 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.Proxy.DNSCacheTTL) {
		return fmt.Errorf("proxy.dns_cache_ttl must be between 0 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.Proxy.DNSMinPositiveTTL) || c.Proxy.DNSMinPositiveTTL == 0 {
		return fmt.Errorf("proxy.dns_min_positive_ttl must be between 1 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.Proxy.DNSMaxPositiveTTL) || c.Proxy.DNSMaxPositiveTTL < c.Proxy.DNSMinPositiveTTL {
		return fmt.Errorf("proxy.dns_max_positive_ttl must be between dns_min_positive_ttl and %d seconds", maxDurationSeconds)
	}
	if c.Proxy.DNSCacheTTL < c.Proxy.DNSMinPositiveTTL || c.Proxy.DNSCacheTTL > c.Proxy.DNSMaxPositiveTTL {
		return fmt.Errorf("proxy.dns_cache_ttl must be between dns_min_positive_ttl and dns_max_positive_ttl")
	}
	if !validSeconds(c.Proxy.DNSNegativeTTL) || c.Proxy.DNSNegativeTTL == 0 {
		return fmt.Errorf("proxy.dns_negative_ttl must be between 1 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.Proxy.DNSTransientFailureTTL) || c.Proxy.DNSTransientFailureTTL == 0 {
		return fmt.Errorf("proxy.dns_transient_failure_ttl must be between 1 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.Proxy.DNSStaleWindow) {
		return fmt.Errorf("proxy.dns_stale_window must be between 0 and %d seconds", maxDurationSeconds)
	}
	if !validSeconds(c.Proxy.DNSResolverTimeout) || c.Proxy.DNSResolverTimeout == 0 {
		return fmt.Errorf("proxy.dns_resolver_timeout must be between 1 and %d seconds", maxDurationSeconds)
	}
	if c.Proxy.DNSPositiveCapacity < 1 || c.Proxy.DNSPositiveCapacity > maxDNSCapacity {
		return fmt.Errorf("proxy.dns_positive_capacity must be between 1 and %d", maxDNSCapacity)
	}
	if c.Proxy.DNSNegativeCapacity < 1 || c.Proxy.DNSNegativeCapacity > maxDNSCapacity {
		return fmt.Errorf("proxy.dns_negative_capacity must be between 1 and %d", maxDNSCapacity)
	}
	if c.Proxy.DNSMaxPending < 1 || c.Proxy.DNSMaxPending > maxDNSCapacity {
		return fmt.Errorf("proxy.dns_max_pending must be between 1 and %d", maxDNSCapacity)
	}
	if c.Proxy.DNSStalePolicy != "transient" && c.Proxy.DNSStalePolicy != "never" {
		return fmt.Errorf("proxy.dns_stale_policy must be %q or %q", "transient", "never")
	}
	if c.Proxy.AddressFamilyStrategy != "interleave" && c.Proxy.AddressFamilyStrategy != "ipv4_first" && c.Proxy.AddressFamilyStrategy != "ipv6_first" {
		return fmt.Errorf("proxy.address_family_strategy must be %q, %q, or %q", "interleave", "ipv4_first", "ipv6_first")
	}
	if c.Proxy.ConnectAttemptCap < 1 || c.Proxy.ConnectAttemptCap > maxConnectAttemptCap {
		return fmt.Errorf("proxy.connect_attempt_cap must be between 1 and %d", maxConnectAttemptCap)
	}
	if c.Proxy.MaxConnections < 1 || c.Proxy.MaxConnections > maxConfiguredConnections {
		return fmt.Errorf("proxy.max_connections must be between 1 and %d", maxConfiguredConnections)
	}
	if c.Proxy.MaxConnectionsPerSource < 0 || c.Proxy.MaxConnectionsPerSource > c.Proxy.MaxConnections {
		return fmt.Errorf("proxy.max_connections_per_source must be between 0 and proxy.max_connections")
	}
	if c.Proxy.MaxClientHelloBytes < 1 || c.Proxy.MaxClientHelloBytes > maxConfiguredProtocolBytes {
		return fmt.Errorf("proxy.max_client_hello_bytes must be between 1 and %d", maxConfiguredProtocolBytes)
	}
	if c.Proxy.MaxHTTPHeaderBytes < 1 || c.Proxy.MaxHTTPHeaderBytes > maxConfiguredProtocolBytes {
		return fmt.Errorf("proxy.max_http_header_bytes must be between 1 and %d", maxConfiguredProtocolBytes)
	}
	for _, cidr := range c.Proxy.AllowedSourceCIDRs {
		if _, err := parsePolicyPrefix(cidr); err != nil {
			return fmt.Errorf("proxy.allowed_source_cidrs %q: %w", cidr, err)
		}
	}
	if c.Proxy.HTTPSListen != "" {
		if err := validateListener(c.Proxy.HTTPSListen); err != nil {
			return fmt.Errorf("proxy.https_listen: %w", err)
		}
		if listenerNeedsSourceACL(c.Proxy.HTTPSListen) && len(c.Proxy.AllowedSourceCIDRs) == 0 {
			return fmt.Errorf("proxy.https_listen %q is wildcard or non-loopback; proxy.allowed_source_cidrs is required and must be non-empty", c.Proxy.HTTPSListen)
		}
	}
	if c.Proxy.HTTPListen != "" {
		if err := validateListener(c.Proxy.HTTPListen); err != nil {
			return fmt.Errorf("proxy.http_listen: %w", err)
		}
		if listenerNeedsSourceACL(c.Proxy.HTTPListen) && len(c.Proxy.AllowedSourceCIDRs) == 0 {
			return fmt.Errorf("proxy.http_listen %q is wildcard or non-loopback; proxy.allowed_source_cidrs is required and must be non-empty", c.Proxy.HTTPListen)
		}
	}
	if err := validateHostPort(c.Proxy.Resolver, false); err != nil {
		return fmt.Errorf("proxy.resolver: %w", err)
	}
	for _, cidr := range c.Proxy.DestinationPolicy.DirectAllowCIDRs {
		if _, err := parsePolicyPrefix(cidr); err != nil {
			return fmt.Errorf("proxy.destination_policy.direct_allow_cidrs %q: %w", cidr, err)
		}
	}
	for name, cidrs := range c.Proxy.DestinationPolicy.TunnelAllowCIDRs {
		if !seenName[name] {
			return fmt.Errorf("proxy.destination_policy.tunnel_allow_cidrs %q is not a known tunnel", name)
		}
		for _, cidr := range cidrs {
			if _, err := parsePolicyPrefix(cidr); err != nil {
				return fmt.Errorf("proxy.destination_policy.tunnel_allow_cidrs[%q] %q: %w", name, cidr, err)
			}
		}
	}
	valid := func(via string) bool {
		return via == "" || via == "direct" || seenName[via] || seenGroup[via]
	}
	if !valid(c.Proxy.Default) {
		return fmt.Errorf("proxy.default %q is not a known tunnel", c.Proxy.Default)
	}
	for i, r := range c.Proxy.Rules {
		if !valid(r.Via) {
			return fmt.Errorf("proxy.rules[%d].via %q is not a known tunnel", i, r.Via)
		}
		for j, suffix := range r.Suffixes {
			normalized, isIP, err := canonicalHost(suffix, false)
			if err != nil {
				return fmt.Errorf("proxy.rules[%d].suffixes[%d] is invalid: %v", i, j, err)
			}
			if isIP {
				return fmt.Errorf("proxy.rules[%d].suffixes[%d] is invalid: IP literals cannot be routing suffixes", i, j)
			}
			c.Proxy.Rules[i].Suffixes[j] = normalized
		}
	}
	return nil
}

func (c *Config) normalize() {
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		if t.Table == 0 {
			t.Table = t.Fwmark
		}
		if t.MTU == 0 {
			t.MTU = 1420
		}
		if t.FwmarkMask == 0 {
			t.FwmarkMask = kernelstate.FullMarkMask
		}
		if t.RulePriority == 0 {
			t.RulePriority = kernelstate.RulePriorityMin + i
		}
		if len(t.Peer.AllowedIPs) == 0 {
			t.Peer.AllowedIPs = []string{"0.0.0.0/0"}
		}
		for j := range t.RouteSources {
			if t.RouteSources[j].Via == "" {
				t.RouteSources[j].Via = "direct"
			}
		}
	}
	for i := range c.Groups {
		if c.Groups[i].HealthyAfter == 0 {
			c.Groups[i].HealthyAfter = 180
		}
	}
	if c.RouteRefresh == 0 {
		c.RouteRefresh = 21600 // 6h
	}
	if c.HealthInterval == 0 {
		c.HealthInterval = 10
	}
	if c.HealthProbe.Interval == 0 {
		c.HealthProbe.Interval = 30
	}
	if c.HealthProbe.Timeout == 0 {
		c.HealthProbe.Timeout = 5
	}
	if c.HealthProbe.JitterPercent == 0 {
		c.HealthProbe.JitterPercent = 20
	}
	if c.HealthProbe.MaxConcurrent == 0 {
		c.HealthProbe.MaxConcurrent = 1
	}
	if c.Management.Listen == "" {
		c.Management.Listen = "127.0.0.1:9090"
	}
	if c.Management.ReadHeaderTimeout == 0 {
		c.Management.ReadHeaderTimeout = defaultManagementReadHeaderTimeout
	}
	if c.Management.WriteTimeout == 0 {
		c.Management.WriteTimeout = defaultManagementWriteTimeout
	}
	if c.Management.IdleTimeout == 0 {
		c.Management.IdleTimeout = defaultManagementIdleTimeout
	}
	if c.Management.ShutdownTimeout == 0 {
		c.Management.ShutdownTimeout = defaultManagementShutdownTimeout
	}
	if c.Management.MaxHeaderBytes == 0 {
		c.Management.MaxHeaderBytes = defaultManagementMaxHeaderBytes
	}
	if c.Proxy.DialTimeout == 0 {
		c.Proxy.DialTimeout = 10
	}
	if c.Proxy.HandshakeTimeout == 0 {
		c.Proxy.HandshakeTimeout = defaultHandshakeTimeout
	}
	if c.Proxy.ShutdownGrace == 0 {
		c.Proxy.ShutdownGrace = defaultShutdownGrace
	}
	if c.Proxy.MaxConnections == 0 {
		c.Proxy.MaxConnections = defaultMaxConnections
	}
	if c.Proxy.MaxClientHelloBytes == 0 {
		c.Proxy.MaxClientHelloBytes = defaultMaxClientHelloBytes
	}
	if c.Proxy.MaxHTTPHeaderBytes == 0 {
		c.Proxy.MaxHTTPHeaderBytes = defaultMaxHTTPHeaderBytes
	}
	if c.Proxy.DNSPositiveCapacity == 0 {
		c.Proxy.DNSPositiveCapacity = defaultDNSPositiveCapacity
	}
	if c.Proxy.DNSNegativeCapacity == 0 {
		c.Proxy.DNSNegativeCapacity = defaultDNSNegativeCapacity
	}
	if c.Proxy.DNSMaxPending == 0 {
		c.Proxy.DNSMaxPending = defaultDNSMaxPending
	}
	if c.Proxy.DNSMinPositiveTTL == 0 {
		c.Proxy.DNSMinPositiveTTL = defaultDNSMinPositiveTTL
	}
	if c.Proxy.DNSMaxPositiveTTL == 0 {
		c.Proxy.DNSMaxPositiveTTL = defaultDNSMaxPositiveTTL
	}
	if c.Proxy.DNSCacheTTL == 0 {
		c.Proxy.DNSCacheTTL = c.Proxy.DNSMaxPositiveTTL
	}
	if c.Proxy.DNSNegativeTTL == 0 {
		c.Proxy.DNSNegativeTTL = defaultDNSNegativeTTL
	}
	if c.Proxy.DNSTransientFailureTTL == 0 {
		c.Proxy.DNSTransientFailureTTL = defaultDNSTransientTTL
	}
	if c.Proxy.DNSStaleWindow == 0 {
		c.Proxy.DNSStaleWindow = defaultDNSStaleWindow
	}
	if c.Proxy.DNSStalePolicy == "" {
		c.Proxy.DNSStalePolicy = "transient"
	}
	if c.Proxy.DNSResolverTimeout == 0 {
		c.Proxy.DNSResolverTimeout = defaultDNSResolverTimeout
	}
	if c.Proxy.AddressFamilyStrategy == "" {
		c.Proxy.AddressFamilyStrategy = "interleave"
	}
	if c.Proxy.ConnectAttemptCap == 0 {
		c.Proxy.ConnectAttemptCap = defaultConnectAttemptCap
	}
	if c.Proxy.Default == "" {
		c.Proxy.Default = "direct"
	}
	if c.Proxy.Resolver == "" {
		c.Proxy.Resolver = "1.1.1.1:53"
	}
	for i := range c.Proxy.Rules {
		for j, s := range c.Proxy.Rules[i].Suffixes {
			c.Proxy.Rules[i].Suffixes[j] = strings.TrimPrefix(s, ".")
		}
	}
}

// markFor returns the SO_MARK to use for an egress name ("direct" => 0).
func (c *Config) markFor(via string) int {
	if via == "direct" || via == "" {
		return 0
	}
	for i := range c.Tunnels {
		if c.Tunnels[i].Name == via {
			return c.Tunnels[i].Fwmark
		}
	}
	return 0
}

func validateHostPort(addr string, emptyHostOK bool) error {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q must be host:port: %w", addr, err)
	}
	if !emptyHostOK && host == "" {
		return fmt.Errorf("%q requires a host", addr)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("%q has an invalid port", addr)
	}
	return nil
}

func validateListener(addr string) error {
	if err := validateHostPort(addr, true); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	if host == "" {
		return nil
	}
	if strings.Contains(host, "%") {
		return fmt.Errorf("%q must not contain an IPv6 zone", addr)
	}
	if _, err := netip.ParseAddr(host); err != nil {
		return fmt.Errorf("%q listener host must be an IP literal or empty wildcard", addr)
	}
	return nil
}

func listenerNeedsSourceACL(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err != nil || !ip.Unmap().IsLoopback()
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("input exceeds %d bytes", limit)
	}
	return b, nil
}

func validSeconds(seconds int) bool {
	return seconds >= 0 && int64(seconds) <= maxDurationSeconds
}
