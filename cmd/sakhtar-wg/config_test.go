package main

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestReleaseSmokeConfig(t *testing.T) {
	config, err := LoadConfig("../../testdata/release-smoke.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if config.Proxy.HTTPListen != "127.0.0.1:18080" || len(config.Tunnels) != 0 {
		t.Fatalf("smoke config = %+v", config)
	}
}

func testKey(fill byte) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string([]byte{fill}), 32)))
}

func validConfigYAML() string {
	return fmt.Sprintf(`
tunnels:
  - name: wg0
    private_key: %q
    address: 10.0.0.2/32
    fwmark: 51
    routes: [10.10.1.1/24]
    peer:
      public_key: %q
      endpoint: 192.0.2.1:51820
proxy:
  https_listen: ":443"
  allowed_source_cidrs: [10.0.0.0/8]
  resolver: 1.1.1.1:53
  rules:
    - via: wg0
      suffixes: [".Example.COM"]
`, testKey(1), testKey(2))
}

func TestParseConfigDefaultsAndNormalization(t *testing.T) {
	cfg, err := parseConfig([]byte(validConfigYAML()))
	if err != nil {
		t.Fatal(err)
	}
	tun := cfg.Tunnels[0]
	if tun.Table != 51 || tun.MTU != 1420 {
		t.Fatalf("tunnel defaults = table %d MTU %d", tun.Table, tun.MTU)
	}
	if tun.FwmarkMask != ^uint32(0) || tun.RulePriority != 31000 || tun.AdoptExisting {
		t.Fatalf("ownership defaults = mask %#x priority %d adopt %t", tun.FwmarkMask, tun.RulePriority, tun.AdoptExisting)
	}
	if got := tun.Peer.AllowedIPs; len(got) != 1 || got[0] != "0.0.0.0/0" {
		t.Fatalf("allowed IP defaults = %v", got)
	}
	if cfg.RouteRefresh != 21600 || cfg.HealthInterval != 10 {
		t.Fatalf("interval defaults = %d, %d", cfg.RouteRefresh, cfg.HealthInterval)
	}
	if cfg.Management.Listen != "127.0.0.1:9090" || cfg.Management.MaxHeaderBytes != defaultManagementMaxHeaderBytes || cfg.Management.Pprof {
		t.Fatalf("management defaults = %+v", cfg.Management)
	}
	if cfg.HealthProbe.Interval != 30 || cfg.HealthProbe.Timeout != 5 || cfg.HealthProbe.MaxConcurrent != 1 {
		t.Fatalf("health probe defaults = %+v", cfg.HealthProbe)
	}
	if cfg.Proxy.Default != "direct" || cfg.Proxy.DialTimeout != 10 || cfg.Proxy.DNSCacheTTL != 300 ||
		cfg.Proxy.MaxConnections != defaultMaxConnections || cfg.Proxy.HandshakeTimeout != defaultHandshakeTimeout ||
		cfg.Proxy.ShutdownGrace != defaultShutdownGrace || cfg.Proxy.MaxClientHelloBytes != defaultMaxClientHelloBytes ||
		cfg.Proxy.MaxHTTPHeaderBytes != defaultMaxHTTPHeaderBytes || cfg.Proxy.DNSPositiveCapacity != defaultDNSPositiveCapacity ||
		cfg.Proxy.DNSNegativeCapacity != defaultDNSNegativeCapacity || cfg.Proxy.DNSMaxPending != defaultDNSMaxPending ||
		cfg.Proxy.DNSMinPositiveTTL != defaultDNSMinPositiveTTL || cfg.Proxy.DNSMaxPositiveTTL != defaultDNSMaxPositiveTTL ||
		cfg.Proxy.DNSNegativeTTL != defaultDNSNegativeTTL || cfg.Proxy.DNSTransientFailureTTL != defaultDNSTransientTTL ||
		cfg.Proxy.DNSStaleWindow != defaultDNSStaleWindow || cfg.Proxy.DNSStalePolicy != "transient" ||
		cfg.Proxy.DNSResolverTimeout != defaultDNSResolverTimeout || cfg.Proxy.AddressFamilyStrategy != "interleave" ||
		cfg.Proxy.ConnectAttemptCap != defaultConnectAttemptCap {
		t.Fatalf("proxy defaults = %+v", cfg.Proxy)
	}
	if got := cfg.Proxy.Rules[0].Suffixes[0]; got != "example.com" {
		t.Fatalf("normalized suffix = %q", got)
	}
	if got := tun.Routes[0]; got != "10.10.1.1/24" {
		t.Fatalf("validation unexpectedly rewrote route %q", got)
	}
}

func TestParseConfigRejectsInvalidInput(t *testing.T) {
	valid := validConfigYAML()
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"unknown field", valid + "unknown_option: true\n", "field unknown_option not found"},
		{"duplicate field", valid + "proxy:\n  default: direct\n", "mapping key \"proxy\" already defined"},
		{"trailing document", valid + "---\nproxy: {}\n", "multiple YAML documents"},
		{"negative refresh", strings.Replace(valid, "tunnels:", "route_refresh: -1\ntunnels:", 1), "route_refresh must be between"},
		{"negative health interval", strings.Replace(valid, "tunnels:", "health_interval: -1\ntunnels:", 1), "health_interval must be between"},
		{"wildcard management", strings.Replace(valid, "tunnels:", "management:\n  listen: 0.0.0.0:9090\ntunnels:", 1), "loopback IP literal"},
		{"probe credentials", strings.Replace(valid, "tunnels:", "health_probe:\n  enabled: true\n  endpoint: https://user:pass@example.test/ping\n  via: wg0\n  interval: 30\n  timeout: 5\n  max_concurrent: 1\ntunnels:", 1), "must not contain credentials"},
		{"probe concurrency", strings.Replace(valid, "tunnels:", "health_probe:\n  enabled: true\n  endpoint: https://example.test/ping\n  via: wg0\n  interval: 30\n  timeout: 5\n  max_concurrent: 9\ntunnels:", 1), "max_concurrent"},
		{"bad interface name", strings.Replace(valid, "name: wg0", "name: a/b", 1), "name must be"},
		{"long interface name", strings.Replace(valid, "name: wg0", "name: wireguard-too-long", 1), "name must be"},
		{"bad private key", strings.Replace(valid, testKey(1), "not-a-key", 1), "private_key"},
		{"bad address", strings.Replace(valid, "10.0.0.2/32", "bad-cidr", 1), "address"},
		{"negative mtu", strings.Replace(valid, "fwmark: 51", "mtu: -1\n    fwmark: 51", 1), "mtu must be non-negative"},
		{"negative mark", strings.Replace(valid, "fwmark: 51", "fwmark: -1", 1), "fwmark must be between"},
		{"mask excludes mark", strings.Replace(valid, "fwmark: 51", "fwmark: 256\n    fwmark_mask: 255", 1), "does not select mark"},
		{"reserved table", strings.Replace(valid, "fwmark: 51", "fwmark: 51\n    table: 254", 1), "reserved"},
		{"rule priority outside allocation", strings.Replace(valid, "fwmark: 51", "fwmark: 51\n    rule_priority: 100", 1), "outside reserved range"},
		{"bad public key", strings.Replace(valid, testKey(2), "bad-key", 1), "peer.public_key"},
		{"bad endpoint", strings.Replace(valid, "192.0.2.1:51820", "192.0.2.1", 1), "peer.endpoint"},
		{"bad route", strings.Replace(valid, "10.10.1.1/24", "bad", 1), "route \"bad\""},
		{"bad listener", strings.Replace(valid, `https_listen: ":443"`, `https_listen: "443"`, 1), "proxy.https_listen"},
		{"bad resolver", strings.Replace(valid, "1.1.1.1:53", "1.1.1.1", 1), "proxy.resolver"},
		{"negative dial timeout", strings.Replace(valid, "resolver: 1.1.1.1:53", "resolver: 1.1.1.1:53\n  dial_timeout: -1", 1), "dial_timeout"},
		{"bad positive capacity", strings.Replace(valid, "resolver: 1.1.1.1:53", "resolver: 1.1.1.1:53\n  dns_positive_capacity: -1", 1), "dns_positive_capacity"},
		{"bad negative capacity", strings.Replace(valid, "resolver: 1.1.1.1:53", "resolver: 1.1.1.1:53\n  dns_negative_capacity: -1", 1), "dns_negative_capacity"},
		{"bad pending limit", strings.Replace(valid, "resolver: 1.1.1.1:53", "resolver: 1.1.1.1:53\n  dns_max_pending: -1", 1), "dns_max_pending"},
		{"bad TTL bounds", strings.Replace(valid, "resolver: 1.1.1.1:53", "resolver: 1.1.1.1:53\n  dns_min_positive_ttl: 60\n  dns_max_positive_ttl: 30", 1), "dns_max_positive_ttl"},
		{"bad stale policy", strings.Replace(valid, "resolver: 1.1.1.1:53", "resolver: 1.1.1.1:53\n  dns_stale_policy: always", 1), "dns_stale_policy"},
		{"bad family strategy", strings.Replace(valid, "resolver: 1.1.1.1:53", "resolver: 1.1.1.1:53\n  address_family_strategy: random", 1), "address_family_strategy"},
		{"bad connect cap", strings.Replace(valid, "resolver: 1.1.1.1:53", "resolver: 1.1.1.1:53\n  connect_attempt_cap: 65", 1), "connect_attempt_cap"},
		{"empty suffix", strings.Replace(valid, `suffixes: [".Example.COM"]`, `suffixes: ["."]`, 1), "suffixes[0] is invalid"},
		{"bad source URL", strings.Replace(valid, "peer:\n", "route_sources:\n      - name: source\n        url: file:///tmp/x\n        format: cidr-lines\n    peer:\n", 1), "absolute http(s) URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig([]byte(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestParseConfigRejectsDuplicateNamesMarksAndTables(t *testing.T) {
	base := validConfigYAML()
	second := fmt.Sprintf(`
  - name: wg1
    private_key: %q
    address: 10.0.0.3/32
    fwmark: 52
    table: 52
    peer:
      public_key: %q
      endpoint: 192.0.2.2:51820
`, testKey(3), testKey(4))
	withSecond := strings.Replace(base, "proxy:\n", second+"proxy:\n", 1)
	tests := []struct {
		name, raw, want string
	}{
		{"name", strings.Replace(withSecond, "name: wg1", "name: wg0", 1), "duplicate tunnel name"},
		{"mark", strings.Replace(withSecond, "fwmark: 52", "fwmark: 51", 1), "fwmark 51 already used"},
		{"table", strings.Replace(withSecond, "table: 52", "table: 51", 1), "table 51 already used"},
		{"priority", strings.Replace(withSecond, "table: 52", "table: 52\n    rule_priority: 31000", 1), "rule priority 31000 already used"},
		{"mark masks overlap", strings.Replace(strings.Replace(withSecond, "fwmark: 51", "fwmark: 16\n    fwmark_mask: 240", 1), "fwmark: 52", "fwmark: 17\n    fwmark_mask: 241", 1), "selectors overlap"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig([]byte(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseConfigRejectsAmbiguousGatewayPolicy(t *testing.T) {
	base := validConfigYAML()
	second := fmt.Sprintf(`
  - name: wg1
    private_key: %q
    address: 10.0.0.3/32
    fwmark: 52
    routes: [10.10.1.128/25]
    peer:
      public_key: %q
      endpoint: 192.0.2.2:51820
`, testKey(3), testKey(4))
	withSecond := strings.Replace(base, "proxy:\n", second+"proxy:\n", 1)
	tests := []struct {
		name, raw, want string
	}{
		{"overlapping destinations", withSecond + "gateway:\n  enabled: true\n  client_cidrs: [10.0.1.0/24]\n", "overlap across tunnels"},
		{"IPv6 client", base + "gateway:\n  enabled: true\n  client_cidrs: [2001:db8::/64]\n", "must be an IPv4 prefix"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig([]byte(tt.raw))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseConfigBound(t *testing.T) {
	_, err := parseConfig(make([]byte, maxConfigBytes+1))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v", err)
	}
}

func FuzzLoadConfig(f *testing.F) {
	f.Add([]byte(validConfigYAML()))
	f.Add([]byte("tunnels: ["))
	f.Add([]byte("unknown: true\n"))
	f.Add([]byte("---\n{}\n---\n{}\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = parseConfig(raw)
	})
}
