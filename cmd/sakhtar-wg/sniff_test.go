package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
)

func peekClientHello(r io.Reader) (*tls.ClientHelloInfo, []byte, error) {
	return peekClientHelloLimit(r, maxPeek)
}

func readClientHello(r io.Reader) (*tls.ClientHelloInfo, error) {
	return readClientHelloLimit(r, maxPeek)
}

func peekHTTPHost(r io.Reader) (string, []byte, error) {
	raw, prefix, err := peekHTTPHostLimit(r, maxPeek)
	if err != nil {
		return "", nil, err
	}
	host, _, err := canonicalHost(raw, true)
	if err != nil {
		return "", nil, err
	}
	return host, prefix, nil
}

func clientHelloBytes(t testing.TB, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tls.Client(client, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	}()
	hello, prefix, err := peekClientHello(server)
	_ = server.Close()
	_ = client.Close()
	<-done
	if err != nil {
		t.Fatalf("capture ClientHello: %v", err)
	}
	if hello.ServerName != serverName {
		t.Fatalf("SNI = %q", hello.ServerName)
	}
	return prefix
}

type chunkReader struct {
	r io.Reader
	n int
}

func (r chunkReader) Read(p []byte) (int, error) {
	if len(p) > r.n {
		p = p[:r.n]
	}
	return r.r.Read(p)
}

func TestReadClientHelloFragmented(t *testing.T) {
	data := clientHelloBytes(t, "api.example.com")
	for _, chunk := range []int{1, 2, 3, 7, 31} {
		hello, err := readClientHello(chunkReader{r: bytes.NewReader(data), n: chunk})
		if err != nil || hello.ServerName != "api.example.com" {
			t.Fatalf("chunk %d: hello=%v err=%v", chunk, hello, err)
		}
	}
}

func TestReadClientHelloMalformed(t *testing.T) {
	inputs := [][]byte{
		nil,
		{0x16, 0x03, 0x01, 0xff, 0xff},
		{0x16, 0x03, 0x01, 0, 1, 0xff},
		bytes.Repeat([]byte{0xff}, maxPeek),
	}
	for i, input := range inputs {
		if hello, err := readClientHello(bytes.NewReader(input)); err == nil || hello != nil {
			t.Errorf("case %d: hello=%v err=%v", i, hello, err)
		}
	}
}

func TestPeekHTTPHost(t *testing.T) {
	raw := "GET /path HTTP/1.1\r\nHost: Example.COM:8080\r\nX-Test: yes\r\n\r\n"
	host, prefix, err := peekHTTPHost(chunkReader{r: strings.NewReader(raw), n: 2})
	if err != nil {
		t.Fatal(err)
	}
	if host != "example.com" {
		t.Fatalf("host = %q", host)
	}
	if string(prefix) != raw {
		t.Fatalf("prefix = %q", prefix)
	}
}

func TestPeekHTTPHostMalformedAndBounded(t *testing.T) {
	for _, raw := range []string{
		"GET / HTTP/1.1\r\n\r\n",
		"not http",
		"GET / HTTP/1.1\r\nHost: x\r\nX: " + strings.Repeat("a", maxPeek) + "\r\n\r\n",
	} {
		if host, prefix, err := peekHTTPHost(strings.NewReader(raw)); err == nil || host != "" || prefix != nil {
			t.Fatalf("host=%q prefix=%d err=%v", host, len(prefix), err)
		}
	}
}

func FuzzClientHello(f *testing.F) {
	valid := clientHelloBytes(f, "fuzz.example")
	f.Add(valid)
	f.Add([]byte{0x16, 0x03, 0x01, 0xff, 0xff})
	f.Add([]byte("not tls"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readClientHello(bytes.NewReader(data))
	})
}

func FuzzHTTPHost(f *testing.F) {
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = peekHTTPHost(bytes.NewReader(data))
	})
}
