package main

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestParseCIDRLines(t *testing.T) {
	raw := []byte(`
# comment
1.2.3.4
10.1.2.3/8 trailing
192.0.2.0/24,description
2001:db8::/32
invalid
1.2.3.4/32
`)
	got, err := parseCIDRLines(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"1.2.3.4/32", "10.0.0.0/8", "192.0.2.0/24", "1.2.3.4/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("CIDRs = %v, want %v", got, want)
	}
	if _, err := parseCIDRLines([]byte("invalid\n2001:db8::/32\n")); err == nil {
		t.Fatal("expected empty parse error")
	}
}

func TestParseRIPEPrefixes(t *testing.T) {
	raw := []byte(`{"data":{"prefixes":[{"prefix":"203.0.113.4/24"},{"prefix":"2001:db8::/32"},{"prefix":"bad"}]}}`)
	got, err := parseRIPEPrefixes(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes = %v", got)
	}
	for _, raw := range [][]byte{[]byte("{"), []byte(`{"data":{"prefixes":[]}}`)} {
		if _, err := parseRIPEPrefixes(raw); err == nil {
			t.Fatalf("expected error for %q", raw)
		}
	}
}

func TestRouteUpdaterMergeDeduplicates(t *testing.T) {
	cfg := &Config{Tunnels: []Tunnel{{
		Name: "wg0", Routes: []string{"10.1.2.3/8", "192.0.2.1"},
		RouteSources: []RouteSource{{Name: "source"}},
	}}}
	u := &RouteUpdater{base: cfg, fetched: map[string][]string{"source": {"10.0.0.0/8", "203.0.113.0/24"}}}
	got := u.Merge().Tunnels[0].Routes
	want := []string{"10.0.0.0/8", "192.0.2.1/32", "203.0.113.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("merged = %v, want %v", got, want)
	}
	if cfg.Tunnels[0].Routes[0] != "10.1.2.3/8" {
		t.Fatal("Merge mutated base config")
	}
}

func TestRouteUpdaterMergeBaseDoesNotCommitCandidate(t *testing.T) {
	active := &Config{Tunnels: []Tunnel{{Name: "wg0", Routes: []string{"192.0.2.0/24"}, RouteSources: []RouteSource{{Name: "source"}}}}}
	candidate := &Config{Tunnels: []Tunnel{{Name: "wg0", Routes: []string{"198.51.100.0/24"}, RouteSources: []RouteSource{{Name: "source"}}}}}
	updater := &RouteUpdater{base: active, fetched: map[string][]string{"source": {"203.0.113.0/24"}}}
	preview := updater.MergeBase(candidate)
	if got := preview.Tunnels[0].Routes; !reflect.DeepEqual(got, []string{"198.51.100.0/24", "203.0.113.0/24"}) {
		t.Fatalf("preview routes = %v", got)
	}
	if got := updater.Merge().Tunnels[0].Routes; !reflect.DeepEqual(got, []string{"192.0.2.0/24", "203.0.113.0/24"}) {
		t.Fatalf("active routes changed = %v", got)
	}
}

func TestReadBoundedDetectsOverflow(t *testing.T) {
	if got, err := readBounded(strings.NewReader("12345"), 5); err != nil || string(got) != "12345" {
		t.Fatalf("exact limit = %q, %v", got, err)
	}
	if _, err := readBounded(strings.NewReader("123456"), 5); err == nil {
		t.Fatal("expected overflow error")
	}
	if _, err := parseCIDRLines(bytes.Repeat([]byte{'1'}, maxSourceBytes+1)); err == nil {
		t.Fatal("expected CIDR parser bound error")
	}
	if _, err := parseRIPEPrefixes(bytes.Repeat([]byte{'1'}, maxSourceBytes+1)); err == nil {
		t.Fatal("expected RIPE parser bound error")
	}
}

func TestRouteUpdaterSendHonorsCancellation(t *testing.T) {
	ch := make(chan *Config)
	u := &RouteUpdater{applyCh: ch}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u.send(ctx, &Config{})
}

func FuzzParseCIDRLines(f *testing.F) {
	f.Add([]byte("1.2.3.4\n10.0.0.0/8\n"))
	f.Add([]byte("# comment\n2001:db8::/32\n"))
	f.Add([]byte{0, 1, 2, '\n'})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseCIDRLines(data)
	})
}

func FuzzParseRIPEPrefixes(f *testing.F) {
	f.Add([]byte(`{"data":{"prefixes":[{"prefix":"192.0.2.0/24"}]}}`))
	f.Add([]byte(`{"data":{"prefixes":[]}}`))
	f.Add([]byte("{"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseRIPEPrefixes(data)
	})
}
