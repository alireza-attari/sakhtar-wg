package observability

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alireza-attari/sakhtar-wg/internal/health"
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
	connectAttempts := make(map[string]uint64, 2000)
	resolutions := make(map[string]DNSResolution, 2000)
	for i := 0; i < 2000; i++ {
		// The egress dimension is a configured tunnel identity. Values that name no
		// reported tunnel must fold, or one bug turns per-egress attribution into
		// unbounded series.
		connectAttempts[fmt.Sprintf("success|marked|tunnel-%d", i)] = 1
		resolutions[fmt.Sprintf("positive|tunnel-%d", i)] = DNSResolution{Count: 1}
	}
	registry.SetProxy(ProxySnapshot{Rejected: rejections, ConnectAttempts: connectAttempts})
	registry.SetDNS(DNSSnapshot{Requests: dnsRequests, Resolutions: resolutions})
	after := registry.SeriesCount()
	// baseline already has one connect-attempts and one resolutions series; the
	// 4000 junk identities may add at most the two "other" buckets.
	if after > baseline+4 {
		t.Fatalf("metric series grew with untrusted identities: baseline=%d after=%d", baseline, after)
	}
	var output strings.Builder
	registry.WritePrometheus(&output)
	if strings.Contains(output.String(), "host-") || strings.Contains(output.String(), "192.0.2.") || strings.Contains(output.String(), "destination-") || strings.Contains(output.String(), "tunnel-") {
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

// Probe results are per tunnel: an aggregate cannot say which egress is the
// broken one, and a tunnel with a fresh handshake can still be unreachable.
func TestActiveProbeIsLabelledPerTunnel(t *testing.T) {
	registry := NewRegistry()
	observed := time.Unix(1_700_000_000, 0)
	registry.SetWG([]WGSnapshot{{Tunnel: "wga"}, {Tunnel: "wgb"}})
	registry.SetProbe(ProbeSnapshot{Tunnel: "wga", ObservedAt: observed, Success: true, DurationSecond: 0.25})
	registry.SetProbe(ProbeSnapshot{Tunnel: "wgb", ObservedAt: observed, Success: false, LastError: "dial timeout"})

	var output strings.Builder
	registry.WritePrometheus(&output)
	rendered := output.String()
	for _, want := range []string{
		`sakhtar_wg_active_probe_success{tunnel="wga"} 1`,
		`sakhtar_wg_active_probe_success{tunnel="wgb"} 0`,
		`sakhtar_wg_active_probe_duration_seconds{tunnel="wga"}`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing %q in:\n%s", want, rendered)
		}
	}

	status := registry.Status()
	if len(status.ActiveProbes) != 2 || status.ActiveProbes[0].Tunnel != "wga" || status.ActiveProbes[1].Success {
		t.Fatalf("status probes = %+v", status.ActiveProbes)
	}
}

// A tunnel that drops most of its connections is only visible if attempts carry
// the egress that made them.
func TestConnectAttemptsAndResolutionsCarryEgress(t *testing.T) {
	registry := NewRegistry()
	registry.SetWG([]WGSnapshot{{Tunnel: "wga"}})
	registry.SetProxy(ProxySnapshot{ConnectAttempts: map[string]uint64{
		"failure|marked|wga":    7,
		"success|direct|direct": 3,
	}})
	registry.SetDNS(DNSSnapshot{Resolutions: map[string]DNSResolution{
		"transient|wga": {Count: 5},
	}})

	var output strings.Builder
	registry.WritePrometheus(&output)
	rendered := output.String()
	for _, want := range []string{
		`sakhtar_wg_proxy_backend_connect_attempts_total{outcome="failure",egress_class="marked",egress="wga"} 7`,
		`sakhtar_wg_proxy_backend_connect_attempts_total{outcome="success",egress_class="direct",egress="direct"} 3`,
		`sakhtar_wg_dns_resolutions_total{outcome="transient",egress_class="marked",egress="wga"} 5`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("missing %q in:\n%s", want, rendered)
		}
	}
}

func TestKernelRepairCounter(t *testing.T) {
	registry := NewRegistry()
	registry.RecordKernelRepair("success")
	registry.RecordKernelRepair("success")
	registry.RecordKernelRepair("failure")
	registry.RecordKernelRepair("rule 31002 restored")
	var out strings.Builder
	registry.WritePrometheus(&out)
	for _, line := range []string{
		`sakhtar_wg_kernel_repair_total{outcome="success"} 2`,
		`sakhtar_wg_kernel_repair_total{outcome="failure"} 1`,
		`sakhtar_wg_kernel_repair_total{outcome="other"} 1`,
	} {
		if !strings.Contains(out.String(), line) {
			t.Fatalf("metrics missing %q:\n%s", line, out.String())
		}
	}
}

// group_policy_state must name why a group chose its mark; a reason missing
// from the allow-list would collapse to "other" and hide a probe failover.
func TestGroupReasonsSurviveNormalization(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   string
	}{
		{health.ReasonRecentHandshake, health.ReasonRecentHandshake},
		{health.ReasonRecentHandshakeProbePassing, health.ReasonRecentHandshakeProbePassing},
		{health.ReasonProbeFailingFailOpen, health.ReasonProbeFailingFailOpen},
		{health.ReasonNoRecentHandshakeFailOpen, health.ReasonNoRecentHandshakeFailOpen},
		{"host-1.example", "other"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			registry := NewRegistry()
			registry.SetGroups([]GroupSnapshot{{Name: "bypass", State: "ready", Reason: tc.reason}})
			if got := registry.Status().Groups[0].Reason; got != tc.want {
				t.Fatalf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}
