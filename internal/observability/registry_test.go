package observability

import (
	"fmt"
	"strings"
	"testing"

	lifecycle "github.com/alireza-attari/sakhtar-wg/internal/runtime"
)

func TestMetricCardinality(t *testing.T) {
	registry := NewRegistry()
	registry.SetActiveGeneration(lifecycle.Generation(1))
	registry.SetProxy(ProxySnapshot{Rejected: map[string]uint64{"tls|overload|non_loopback": 1}})
	baseline := registry.SeriesCount()
	rejections := make(map[string]uint64, 4000)
	dnsRequests := make(map[string]uint64, 4000)
	for i := 0; i < 2000; i++ {
		// Deliberately feed values shaped like untrusted hostnames and source IPs
		// into every enum boundary. They must collapse to one "other" series.
		rejections[fmt.Sprintf("host-%d.example|192.0.2.%d|destination-%d", i, i%255, i)] = 1
		dnsRequests[fmt.Sprintf("random-%d.example", i)] = 1
	}
	registry.SetProxy(ProxySnapshot{Rejected: rejections})
	registry.SetDNS(DNSSnapshot{Requests: dnsRequests})
	after := registry.SeriesCount()
	if after > baseline+2 {
		t.Fatalf("metric series grew with untrusted identities: baseline=%d after=%d", baseline, after)
	}
	var output strings.Builder
	registry.WritePrometheus(&output)
	if strings.Contains(output.String(), "host-") || strings.Contains(output.String(), "192.0.2.") || strings.Contains(output.String(), "destination-") {
		t.Fatalf("untrusted identity leaked into metric labels: %s", output.String())
	}
}

func TestReadinessRequiresGenerationAndRequiredComponents(t *testing.T) {
	registry := NewRegistry()
	registry.SetComponent("listeners", true, true, "ok", nil)
	if ready, _ := registry.Ready(); ready {
		t.Fatal("registry without an active generation was ready")
	}
	registry.SetActiveGeneration(1)
	registry.SetComponent("kernel", true, false, "failure", fmt.Errorf("drift"))
	if ready, reasons := registry.Ready(); ready || len(reasons) != 1 {
		t.Fatalf("ready=%t reasons=%v", ready, reasons)
	}
	registry.SetComponent("kernel", true, true, "ok", nil)
	if ready, reasons := registry.Ready(); !ready || len(reasons) != 0 {
		t.Fatalf("ready=%t reasons=%v", ready, reasons)
	}
}
