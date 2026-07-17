package main

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestTLSFixtureCarriesSNI(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	captured := make(chan string, 1)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- tls.Server(server, &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			captured <- hello.ServerName
			return nil, nil
		}}).HandshakeContext(context.Background())
	}()
	if _, err := client.Write(tlsFixture("api.example.com")); err != nil {
		t.Fatal(err)
	}
	select {
	case host := <-captured:
		if host != "api.example.com" {
			t.Fatalf("SNI = %q", host)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS parser did not observe fixture")
	}
	_ = client.Close()
	<-serverDone
}

func TestPercentile(t *testing.T) {
	values := []time.Duration{10 * time.Millisecond, time.Millisecond, 5 * time.Millisecond}
	if got := percentile(values, .50); got != 5 {
		t.Fatalf("p50 = %v ms", got)
	}
}
