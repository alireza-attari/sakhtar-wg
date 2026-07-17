package observability

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"
)

func startTestManagement(t *testing.T, registry *Registry) *ManagementServer {
	t.Helper()
	server, err := NewManagementServer(ManagementConfig{Listen: "127.0.0.1:0", ReadHeaderTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second, ShutdownTimeout: time.Second, MaxHeaderBytes: 4096}, registry, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })
	return server
}

func TestLivenessIgnoresDependencies(t *testing.T) {
	registry := NewRegistry()
	registry.SetComponent("kernel", true, false, "failure", context.DeadlineExceeded)
	server := startTestManagement(t, registry)
	response, err := http.Get("http://" + server.Addr().String() + "/livez")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestReadinessEndpoint(t *testing.T) {
	registry := NewRegistry()
	server := startTestManagement(t, registry)
	response, err := http.Get("http://" + server.Addr().String() + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d", response.StatusCode)
	}
	registry.SetActiveGeneration(1)
	registry.SetComponent("listeners", true, true, "ok", nil)
	response, err = http.Get("http://" + server.Addr().String() + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("ready status = %d", response.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body["ready"] != true {
		t.Fatalf("body=%v err=%v", body, err)
	}
}

func TestManagementShutdown(t *testing.T) {
	registry := NewRegistry()
	server := startTestManagement(t, registry)
	address := server.Addr().String()
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 100 * time.Millisecond}
	if response, err := client.Get("http://" + address + "/livez"); err == nil {
		response.Body.Close()
		t.Fatal("management server still accepted connections after shutdown")
	}
}

func TestPprofRequiresLocalListener(t *testing.T) {
	_, err := NewManagementServer(ManagementConfig{Listen: "0.0.0.0:9090", Pprof: true}, NewRegistry(), nil, nil)
	if err == nil {
		t.Fatal("wildcard pprof listener was accepted")
	}
}
