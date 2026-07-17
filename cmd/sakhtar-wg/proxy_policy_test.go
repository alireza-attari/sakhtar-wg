package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCanonicalHost(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		allowPort bool
		want      string
		wantIP    bool
		wantErr   bool
	}{
		{name: "case and root dot", raw: "API.Example.COM.", want: "api.example.com"},
		{name: "HTTP port", raw: "Example.COM:8443", allowPort: true, want: "example.com"},
		{name: "IPv4", raw: "8.8.8.8", want: "8.8.8.8", wantIP: true},
		{name: "bracketed IPv6 port", raw: "[2001:4860:4860::8888]:443", allowPort: true, want: "2001:4860:4860::8888", wantIP: true},
		{name: "valid A-label", raw: "xn--bcher-kva.example", want: "xn--bcher-kva.example"},
		{name: "Unicode rejected", raw: "bücher.example", wantErr: true},
		{name: "control rejected", raw: "example.com\n", wantErr: true},
		{name: "empty label", raw: "a..example", wantErr: true},
		{name: "multiple root dots", raw: "example.com..", wantErr: true},
		{name: "oversized label", raw: strings.Repeat("a", 64) + ".example", wantErr: true},
		{name: "legacy short IPv4", raw: "127.1", wantErr: true},
		{name: "legacy integer IPv4", raw: "2130706433", wantErr: true},
		{name: "legacy hex IPv4", raw: "0x7f000001", wantErr: true},
		{name: "bad port", raw: "example.com:0", allowPort: true, wantErr: true},
		{name: "SNI port rejected", raw: "example.com:443", wantErr: true},
		{name: "unbracketed HTTP IPv6", raw: "2001:4860::8888", allowPort: true, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, gotIP, err := canonicalHost(test.raw, test.allowPort)
			if test.wantErr {
				if err == nil {
					t.Fatalf("canonicalHost(%q) = %q, %v; want error", test.raw, got, gotIP)
				}
				return
			}
			if err != nil || got != test.want || gotIP != test.wantIP {
				t.Fatalf("canonicalHost(%q) = %q, %v, %v; want %q, %v", test.raw, got, gotIP, err, test.want, test.wantIP)
			}
		})
	}
}

func TestSourceACL(t *testing.T) {
	prefixes := mustPolicyPrefixes([]string{"10.0.0.0/8", "2001:db8:1::/48"})
	tests := []struct {
		ip      string
		allowed bool
	}{
		{ip: "10.2.3.4", allowed: true},
		{ip: "11.2.3.4", allowed: false},
		{ip: "2001:db8:1::9", allowed: true},
		{ip: "2001:db8:2::9", allowed: false},
		{ip: "::ffff:10.2.3.4", allowed: true},
		{ip: "::ffff:11.2.3.4", allowed: false},
	}
	for _, test := range tests {
		remote := &net.TCPAddr{IP: net.ParseIP(test.ip), Port: 12345}
		got, allowed := sourceAllowed(remote, prefixes)
		if allowed != test.allowed {
			t.Errorf("sourceAllowed(%s) = %s, %v; want %v", test.ip, got, allowed, test.allowed)
		}
	}
}

func TestDestinationPolicy(t *testing.T) {
	cfg := &Config{
		Tunnels: []Tunnel{{Name: "wg0", Fwmark: 51}, {Name: "wg1", Fwmark: 52}},
		Proxy: Proxy{DestinationPolicy: DestinationPolicy{
			DirectAllowCIDRs: []string{"192.168.0.0/16"},
			TunnelAllowCIDRs: map[string][]string{"wg0": {"10.0.0.0/8"}},
		}},
	}
	policy := newDestinationPolicy(cfg)
	emptySelf := map[netip.Addr]struct{}{}
	if !policy.addressAllowed(netip.MustParseAddr("8.8.8.8"), 0, emptySelf) {
		t.Fatal("public direct destination was denied")
	}
	if !policy.addressAllowed(netip.MustParseAddr("192.168.1.20"), 0, emptySelf) {
		t.Fatal("explicit direct private destination was denied")
	}
	if policy.addressAllowed(netip.MustParseAddr("10.1.2.3"), 0, emptySelf) {
		t.Fatal("direct destination inherited a tunnel exception")
	}
	if !policy.addressAllowed(netip.MustParseAddr("10.1.2.3"), 51, emptySelf) {
		t.Fatal("explicit wg0 private destination was denied")
	}
	if policy.addressAllowed(netip.MustParseAddr("10.1.2.3"), 52, emptySelf) {
		t.Fatal("wg1 destination inherited wg0 exception")
	}
	for _, raw := range []string{"127.0.0.1", "169.254.1.1", "192.0.2.1", "198.18.0.1", "2001:db8::1", "fe80::1"} {
		if policy.addressAllowed(netip.MustParseAddr(raw), 0, emptySelf) {
			t.Errorf("default-denied destination %s was allowed", raw)
		}
	}
	wideOpen := destinationPolicy{allowByMark: map[int][]netip.Prefix{0: {netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}}
	for _, raw := range []string{"0.0.0.0", "224.0.0.1", "::", "ff02::1"} {
		if wideOpen.addressAllowed(netip.MustParseAddr(raw), 0, emptySelf) {
			t.Errorf("hard-denied destination %s was allowed by a CIDR exception", raw)
		}
	}
	self := map[netip.Addr]struct{}{netip.MustParseAddr("8.8.8.8"): {}}
	if wideOpen.addressAllowed(netip.MustParseAddr("8.8.8.8"), 0, self) {
		t.Fatal("daemon self address was allowed by a CIDR exception")
	}
	if policy.addressAllowed(netip.MustParseAddr("::ffff:10.1.2.3"), 0, emptySelf) {
		t.Fatal("IPv4-mapped private destination bypassed direct policy")
	}
	for _, host := range []string{"localhost", "api.localhost", "localhost.localdomain", "printer.local", "ip6-loopback"} {
		if policy.requestedHostAllowed(host, false, 0, emptySelf) {
			t.Errorf("localhost alias %q was allowed", host)
		}
	}
}

func TestDNSRebinding(t *testing.T) {
	cfg := &Config{Proxy: Proxy{Default: "direct", DialTimeout: 1, DNSCacheTTL: 300}}
	srv := NewServer(cfg, nil)
	rt := srv.rt.Load()
	resolve := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("8.8.8.8"), net.ParseIP("::ffff:8.8.8.8")}, nil
	}
	if _, err := rt.dns.lookup(context.Background(), 0, "mixed.example", resolve); err != nil {
		t.Fatal(err)
	}
	candidates, err := srv.backendCandidates(context.Background(), "mixed.example", false, 0, rt, map[netip.Addr]struct{}{})
	if err != nil || len(candidates) != 1 || candidates[0].String() != "8.8.8.8" {
		t.Fatalf("mixed candidates = %v, %v; want only 8.8.8.8", candidates, err)
	}

	var dialed string
	var peer net.Conn
	srv.dial = func(_ context.Context, network, address string, mark int, timeout time.Duration) (net.Conn, error) {
		if network != "tcp" || mark != 0 || timeout != time.Second {
			t.Errorf("dial arguments = %q, %q, %d, %s", network, address, mark, timeout)
		}
		dialed = address
		conn, other := net.Pipe()
		peer = other
		return conn, nil
	}
	conn, err := srv.dialBackend(context.Background(), "mixed.example", false, "443", 0, rt, map[netip.Addr]struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	_ = peer.Close()
	if dialed != "8.8.8.8:443" {
		t.Fatalf("dialed %q; resolver hostname or denied answer reached dialer", dialed)
	}

	_, _ = rt.dns.lookup(context.Background(), 0, "denied.example", func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.0.1")}, nil
	})
	if _, err := srv.backendCandidates(context.Background(), "denied.example", false, 0, rt, map[netip.Addr]struct{}{}); !errors.Is(err, errDestinationDenied) {
		t.Fatalf("all-denied DNS answer error = %v", err)
	}
	if rt.destination.requestedHostAllowed("localhost", false, 0, map[netip.Addr]struct{}{}) {
		t.Fatal("localhost hostname passed requested-host policy")
	}
}

func TestProxyConfigTrustBoundary(t *testing.T) {
	wildcardWithoutACL := strings.Replace(validConfigYAML(), "  allowed_source_cidrs: [10.0.0.0/8]\n", "", 1)
	if _, err := parseConfig([]byte(wildcardWithoutACL)); err == nil || !strings.Contains(err.Error(), "proxy.allowed_source_cidrs is required") {
		t.Fatalf("wildcard listener error = %v", err)
	}
	loopback := strings.Replace(wildcardWithoutACL, `https_listen: ":443"`, `https_listen: "127.0.0.1:443"`, 1)
	if _, err := parseConfig([]byte(loopback)); err != nil {
		t.Fatalf("loopback-only config without explicit ACL: %v", err)
	}
	tests := []struct {
		name, raw, want string
	}{
		{"bad source CIDR", strings.Replace(validConfigYAML(), "10.0.0.0/8", "not-a-cidr", 1), "allowed_source_cidrs"},
		{"zero max", strings.Replace(validConfigYAML(), "  resolver:", "  max_connections: -1\n  resolver:", 1), "max_connections"},
		{"per-source above global", strings.Replace(validConfigYAML(), "  resolver:", "  max_connections: 2\n  max_connections_per_source: 3\n  resolver:", 1), "max_connections_per_source"},
		{"hello cap", strings.Replace(validConfigYAML(), "  resolver:", "  max_client_hello_bytes: 999999\n  resolver:", 1), "max_client_hello_bytes"},
		{"header cap", strings.Replace(validConfigYAML(), "  resolver:", "  max_http_header_bytes: 999999\n  resolver:", 1), "max_http_header_bytes"},
		{"unknown tunnel policy", strings.Replace(validConfigYAML(), "  resolver:", "  destination_policy:\n    tunnel_allow_cidrs:\n      missing: [10.0.0.0/8]\n  resolver:", 1), "not a known tunnel"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseConfig([]byte(test.raw)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
