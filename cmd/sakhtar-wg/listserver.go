package main

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
)

// ListServer publishes the bypass CIDR list (the union of every tunnel's Routes)
// as plain text, for a pfSense URL Table alias to pull. It is the single source
// of truth: editing sakhtar-wg's config and reloading changes what pfSense sees on
// its next refresh — no pfSense config edit, no risk.
type ListServer struct {
	body atomic.Pointer[string]
	ln   net.Listener
}

func NewListServer(cfg *Config) *ListServer {
	s := &ListServer{}
	s.Reload(cfg)
	return s
}

// Reload rebuilds the served body from the current config (atomic swap).
func (s *ListServer) Reload(cfg *Config) {
	var b strings.Builder
	for _, t := range cfg.Tunnels {
		for _, c := range t.Routes {
			b.WriteString(c)
			b.WriteByte('\n')
		}
	}
	body := b.String()
	s.body.Store(&body)
}

func (s *ListServer) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(*s.body.Load()))
	})
	go func() { _ = http.Serve(ln, mux) }()
	log.Printf("list: serving bypass CIDRs on %s", addr)
	return nil
}

func (s *ListServer) Stop() {
	if s.ln != nil {
		_ = s.ln.Close()
	}
}
