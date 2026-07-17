package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func BenchmarkClientHelloParsing(b *testing.B) {
	fixture := clientHelloBytes(b, "api.example.com")
	b.ReportMetric(float64(len(fixture)), "fixture_bytes")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		hello, err := readClientHelloLimit(bytes.NewReader(fixture), defaultMaxClientHelloBytes)
		if err != nil || hello.ServerName != "api.example.com" {
			b.Fatalf("parse ClientHello: name=%q err=%v", hello.ServerName, err)
		}
	}
}

func BenchmarkHTTPHostParsing(b *testing.B) {
	for _, headerBytes := range []int{128, 4 << 10, 32 << 10} {
		padding := strings.Repeat("a", max(0, headerBytes-64))
		fixture := []byte("GET /path HTTP/1.1\r\nHost: api.example.com\r\nX-Pad: " + padding + "\r\n\r\n")
		b.Run(fmt.Sprintf("header_%d", len(fixture)), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				host, _, err := peekHTTPHostLimit(bytes.NewReader(fixture), defaultMaxHTTPHeaderBytes)
				if err != nil || host != "api.example.com" {
					b.Fatalf("parse HTTP Host: host=%q err=%v", host, err)
				}
			}
		})
	}
}
