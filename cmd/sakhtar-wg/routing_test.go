package main

import (
	"reflect"
	"testing"
)

func TestRouterSuffixPrecedenceAndDefault(t *testing.T) {
	cfg := &Config{
		Tunnels: []Tunnel{{Name: "wg0", Fwmark: 51}, {Name: "wg1", Fwmark: 52}},
		Proxy: Proxy{
			Default: "wg0",
			Rules: []Rule{
				{Via: "wg1", Suffixes: []string{"example.com"}},
				{Via: "direct", Suffixes: []string{"api.example.com"}},
				{Via: "wg0", Suffixes: []string{"example.com"}}, // first duplicate wins
			},
		},
	}
	rt := newRouter(cfg, nil)
	tests := map[string]int{
		"api.example.com":      0,
		"API.EXAMPLE.COM.":     0,
		"www.api.example.com":  0,
		"other.example.com":    52,
		"notexample.com":       51,
		"deep.notexample.com.": 51,
	}
	for host, want := range tests {
		if got := rt.mark(host); got != want {
			t.Errorf("mark(%q) = %d, want %d", host, got, want)
		}
	}
}

func TestPlanRouteDiff(t *testing.T) {
	got := planRouteDiff(
		[]string{"10.0.0.0/8", "192.0.2.0/24", "192.0.2.0/24"},
		[]string{"10.0.0.0/8", "203.0.113.0/24", "198.51.100.0/24"},
	)
	want := routeDiff{
		Add:    []string{"198.51.100.0/24", "203.0.113.0/24"},
		Delete: []string{"192.0.2.0/24"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diff = %#v, want %#v", got, want)
	}
	if got := planRouteDiff([]string{"10.0.0.0/8"}, []string{"10.0.0.0/8"}); len(got.Add)+len(got.Delete) != 0 {
		t.Fatalf("idempotent diff = %#v", got)
	}
}

func TestWGConfig(t *testing.T) {
	tun := Tunnel{
		Name: "wg0", PrivateKey: testKey(1),
		Peer: Peer{PublicKey: testKey(2), Endpoint: "192.0.2.1:51820", AllowedIPs: []string{"0.0.0.0/0", "10.0.0.0/8"}, Keepalive: 25},
	}
	cfg, err := wgConfig(tun)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PrivateKey == nil || !cfg.ReplacePeers || len(cfg.Peers) != 1 {
		t.Fatalf("wg config = %+v", cfg)
	}
	p := cfg.Peers[0]
	if p.Endpoint.String() != "192.0.2.1:51820" || len(p.AllowedIPs) != 2 || p.PersistentKeepaliveInterval == nil {
		t.Fatalf("peer config = %+v", p)
	}
}
