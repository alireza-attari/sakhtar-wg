package observability

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestRedaction(t *testing.T) {
	var output bytes.Buffer
	logger := NewJSONLogger(&output, slog.LevelDebug)
	logger.Info("config.reload_completed",
		"private_key", "super-secret",
		"url", "https://alice:password@example.test/routes",
		"host", "customer.example",
		"error", "request token=abc at https://bob:secret@example.test/path",
	)
	text := output.String()
	for _, secret := range []string{"super-secret", "alice:password", "customer.example", "token=abc", "bob:secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("secret %q leaked in %s", secret, text)
		}
	}
	if strings.Count(text, redacted) < 4 {
		t.Fatalf("expected redaction markers in %s", text)
	}
	registry := NewRegistry()
	registry.SetActiveGeneration(1)
	registry.SetComponent("route_source", false, false, "failure", errors.New("GET https://alice:secret@example.test failed token=abc"))
	registry.SetProbe(ProbeSnapshot{LastError: "https://bob:secret@example.test"})
	var status bytes.Buffer
	if err := registry.WriteStatus(&status); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(status.String(), "alice:secret") || strings.Contains(status.String(), "bob:secret") || strings.Contains(status.String(), "token=abc") {
		t.Fatalf("status leaked a secret: %s", status.String())
	}
}
