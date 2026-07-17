package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestAggregateIPv4(t *testing.T) {
	got := aggregateIPv4([]string{
		"10.0.0.0/25", "10.0.0.128/25", // adjacent -> /24
		"192.0.2.0/25", "192.0.2.64/26", // overlap
		"203.0.113.7/32", "bad", "2001:db8::/32",
	})
	want := []string{"10.0.0.0/24", "192.0.2.0/25", "203.0.113.7/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("aggregate = %v, want %v", got, want)
	}
	if got := aggregateIPv4([]string{"0.0.0.0/0"}); !reflect.DeepEqual(got, []string{"0.0.0.0/0"}) {
		t.Fatalf("default aggregate = %v", got)
	}
}

func TestPfSyncDesiredIncludesKeepNetworks(t *testing.T) {
	p := NewPfSyncer(PfSync{KeepNetworks: []string{"10.0.0.0/24"}})
	got := p.desired([]string{"10.0.1.0/24"})
	want := []string{"10.0.0.0/23"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("desired = %v, want %v", got, want)
	}
}

func FuzzAggregateIPv4(f *testing.F) {
	f.Add([]byte("10.0.0.0/25\n10.0.0.128/25"))
	f.Add([]byte("0.0.0.0/0\n255.255.255.255"))
	f.Add([]byte("bad\n2001:db8::/32"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxSourceBytes {
			return
		}
		_ = aggregateIPv4(strings.Split(string(data), "\n"))
	})
}
