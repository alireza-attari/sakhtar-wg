package observability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type ManagementConfig struct {
	Listen            string
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxHeaderBytes    int
	Pprof             bool
}

type Collector func()

type ManagementServer struct {
	config                       ManagementConfig
	registry                     *Registry
	collect                      Collector
	logger                       *slog.Logger
	server                       *http.Server
	listener                     net.Listener
	serveDone                    chan error
	stopOnce                     sync.Once
	previousMutexProfileFraction int
}

func NewManagementServer(config ManagementConfig, registry *Registry, collect Collector, logger *slog.Logger) (*ManagementServer, error) {
	if registry == nil {
		return nil, errors.New("management: registry is required")
	}
	if config.Listen == "" {
		config.Listen = "127.0.0.1:9090"
	}
	if config.ReadHeaderTimeout <= 0 {
		config.ReadHeaderTimeout = 5 * time.Second
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 10 * time.Second
	}
	if config.IdleTimeout <= 0 {
		config.IdleTimeout = 30 * time.Second
	}
	if config.ShutdownTimeout <= 0 {
		config.ShutdownTimeout = 5 * time.Second
	}
	if config.MaxHeaderBytes <= 0 {
		config.MaxHeaderBytes = 16 << 10
	}
	if logger == nil {
		logger = slog.Default()
	}
	if config.Pprof && !managementIsLocal(config.Listen) {
		return nil, errors.New("management: pprof requires a loopback or Unix-socket listener")
	}
	return &ManagementServer{config: config, registry: registry, collect: collect, logger: logger, serveDone: make(chan error, 1)}, nil
}

func managementIsLocal(address string) bool {
	if strings.HasPrefix(address, "unix:") {
		return strings.TrimPrefix(address, "unix:") != ""
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (m *ManagementServer) Start() error {
	if m == nil {
		return errors.New("management: nil server")
	}
	var listener net.Listener
	var err error
	if path := strings.TrimPrefix(m.config.Listen, "unix:"); path != m.config.Listen {
		if _, statErr := os.Lstat(path); statErr == nil {
			return fmt.Errorf("management: Unix socket path already exists: %s", path)
		}
		listener, err = net.Listen("unix", path)
	} else {
		listener, err = net.Listen("tcp", m.config.Listen)
	}
	if err != nil {
		return err
	}
	m.listener = listener
	mux := http.NewServeMux()
	mux.HandleFunc("/livez", m.handleLive)
	mux.HandleFunc("/readyz", m.handleReady)
	mux.HandleFunc("/metrics", m.handleMetrics)
	mux.HandleFunc("/status", m.handleStatus)
	if m.config.Pprof {
		// Profiling overhead is opt-in and the listener is constrained to a local
		// trust boundary. Restore global runtime settings during shutdown.
		runtime.SetBlockProfileRate(1)
		m.previousMutexProfileFraction = runtime.SetMutexProfileFraction(5)
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}
	m.server = &http.Server{
		Handler: mux, ReadHeaderTimeout: m.config.ReadHeaderTimeout,
		WriteTimeout: m.config.WriteTimeout, IdleTimeout: m.config.IdleTimeout,
		MaxHeaderBytes: m.config.MaxHeaderBytes,
	}
	go func() {
		err := m.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		m.serveDone <- err
	}()
	m.logger.Info("management.started", "component", "observability", "listen", listener.Addr().String(), "outcome", "success")
	return nil
}

func (m *ManagementServer) Addr() net.Addr {
	if m == nil || m.listener == nil {
		return nil
	}
	return m.listener.Addr()
}

func (m *ManagementServer) collectNow() {
	if m.collect != nil {
		m.collect()
	}
}

func requireGET(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func (m *ManagementServer) handleLive(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{\"live\":true}\n"))
}

func (m *ManagementServer) handleReady(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	m.collectNow()
	ready, reasons := m.registry.Ready()
	w.Header().Set("Content-Type", "application/json")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ready": ready, "reasons": reasons})
}

func (m *ManagementServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	m.collectNow()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m.registry.WritePrometheus(w)
}

func (m *ManagementServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	m.collectNow()
	w.Header().Set("Content-Type", "application/json")
	_ = m.registry.WriteStatus(w)
}

func (m *ManagementServer) Shutdown(ctx context.Context) error {
	if m == nil || m.server == nil {
		return nil
	}
	var shutdownErr error
	m.stopOnce.Do(func() {
		if m.config.Pprof {
			runtime.SetBlockProfileRate(0)
			runtime.SetMutexProfileFraction(m.previousMutexProfileFraction)
		}
		shutdownCtx := ctx
		var cancel context.CancelFunc
		if _, hasDeadline := ctx.Deadline(); !hasDeadline {
			shutdownCtx, cancel = context.WithTimeout(ctx, m.config.ShutdownTimeout)
			defer cancel()
		}
		shutdownErr = m.server.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			_ = m.server.Close()
		}
		select {
		case serveErr := <-m.serveDone:
			shutdownErr = errors.Join(shutdownErr, serveErr)
		case <-shutdownCtx.Done():
			shutdownErr = errors.Join(shutdownErr, shutdownCtx.Err())
		}
		m.logger.Info("management.stopped", "component", "observability", "outcome", outcome(shutdownErr))
	})
	return shutdownErr
}

func outcome(err error) string {
	if err == nil {
		return "success"
	}
	return "failure"
}
