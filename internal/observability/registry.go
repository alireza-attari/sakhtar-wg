// Package observability owns low-cardinality process metrics and the redacted
// operational state served by the management endpoint.
package observability

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	lifecycle "github.com/alireza-attari/sakhtar-wg/internal/runtime"
)

var allowedComponents = map[string]struct{}{
	"config": {}, "proxy": {}, "listeners": {}, "kernel": {}, "firewall": {},
	"health": {}, "dns": {}, "route_source": {}, "pfsync": {}, "list_server": {}, "management": {},
}

type ComponentState struct {
	Ready       bool       `json:"ready"`
	Required    bool       `json:"required"`
	Outcome     string     `json:"outcome"`
	LastChecked time.Time  `json:"last_checked"`
	LastSuccess *time.Time `json:"last_success,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

type ProxySnapshot struct {
	Active          int64
	Accepted        uint64
	Rejected        map[string]uint64 // protocol|reason|listener_class
	Completed       map[string]uint64 // completed|canceled|error|other
	DurationSeconds map[string]float64
	ClientBytes     map[string]uint64
	BackendBytes    map[string]uint64
	ConnectAttempts map[string]uint64 // outcome|egress_class
}

type DNSSnapshot struct {
	EntriesPositive   int64
	EntriesNegative   int64
	EvictionsPositive uint64
	EvictionsNegative uint64
	Pending           int64
	RejectedPending   uint64
	Requests          map[string]uint64
	Resolutions       map[string]DNSResolution // outcome|egress_class
}

type DNSResolution struct {
	Count           uint64
	DurationSeconds float64
}

type WGSnapshot struct {
	Tunnel        string  `json:"tunnel"`
	Signal        string  `json:"wg_session_recent"`
	HandshakeAge  float64 `json:"handshake_age_seconds"`
	ReceiveBytes  int64   `json:"receive_bytes"`
	TransmitBytes int64   `json:"transmit_bytes"`
}

type GroupSnapshot struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	Reason     string `json:"reason"`
	ActiveMark uint32 `json:"active_fwmark"`
}

type ProbeSnapshot struct {
	ObservedAt     time.Time `json:"observed_at"`
	Success        bool      `json:"success"`
	DurationSecond float64   `json:"duration_seconds"`
	LastError      string    `json:"last_error,omitempty"`
}

type RouteSourceSnapshot struct {
	Name        string    `json:"name"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastOutcome string    `json:"last_outcome"`
	PrefixCount int       `json:"prefix_count"`
	LastError   string    `json:"last_error,omitempty"`
}

type Registry struct {
	started time.Time
	mu      sync.RWMutex

	generation                 lifecycle.Generation
	reload                     map[string]uint64
	reloadTime                 map[string]float64
	components                 map[string]ComponentState
	proxy                      ProxySnapshot
	dns                        DNSSnapshot
	wg                         map[string]WGSnapshot
	groups                     map[string]GroupSnapshot
	probe                      ProbeSnapshot
	routes                     map[string]RouteSourceSnapshot
	pfSync                     map[string]uint64
	kernelDrift, firewallDrift int
}

func NewRegistry() *Registry {
	return &Registry{
		started: time.Now(), reload: map[string]uint64{}, reloadTime: map[string]float64{},
		components: map[string]ComponentState{}, wg: map[string]WGSnapshot{}, groups: map[string]GroupSnapshot{}, routes: map[string]RouteSourceSnapshot{},
		pfSync: map[string]uint64{},
	}
}

func (r *Registry) SetActiveGeneration(g lifecycle.Generation) {
	r.mu.Lock()
	r.generation = g
	r.mu.Unlock()
}

func boundedOutcome(value string) string {
	switch value {
	case "success", "failure", "completed", "canceled", "error", "ok", "degraded", "skipped", "rejected":
		return value
	default:
		return "other"
	}
}

func (r *Registry) RecordReload(outcome string, duration time.Duration) {
	outcome = boundedOutcome(outcome)
	r.mu.Lock()
	r.reload[outcome]++
	r.reloadTime[outcome] += max(duration.Seconds(), 0)
	r.mu.Unlock()
}

func (r *Registry) SetComponent(name string, required, ready bool, outcome string, err error) {
	if _, allowed := allowedComponents[name]; !allowed {
		name = "config"
	}
	now := time.Now().UTC()
	state := ComponentState{Required: required, Ready: ready, Outcome: boundedOutcome(outcome), LastChecked: now}
	if ready && err == nil {
		state.LastSuccess = &now
	}
	if err != nil {
		state.LastError = RedactText(err.Error())
	}
	r.mu.Lock()
	if previous, ok := r.components[name]; ok && state.LastSuccess == nil {
		state.LastSuccess = previous.LastSuccess
	}
	r.components[name] = state
	r.mu.Unlock()
}

func (r *Registry) SetDrift(kernel, firewall int) {
	r.mu.Lock()
	r.kernelDrift, r.firewallDrift = max(kernel, 0), max(firewall, 0)
	r.mu.Unlock()
}

func (r *Registry) SetProxy(snapshot ProxySnapshot) {
	r.mu.Lock()
	r.proxy = normalizeProxy(snapshot)
	r.mu.Unlock()
}

func normalizeProxy(value ProxySnapshot) ProxySnapshot {
	out := ProxySnapshot{Active: value.Active, Accepted: value.Accepted, Rejected: map[string]uint64{}, Completed: map[string]uint64{}, DurationSeconds: map[string]float64{}, ClientBytes: map[string]uint64{}, BackendBytes: map[string]uint64{}, ConnectAttempts: map[string]uint64{}}
	for key, count := range value.Rejected {
		parts := fixedParts(key, 3)
		bounded := strings.Join([]string{enum(parts[0], "tls", "http"), enum(parts[1], "source_denied", "parse_error", "destination_denied", "overload", "dial_error"), enum(parts[2], "loopback", "non_loopback")}, "|")
		out.Rejected[bounded] += count
	}
	for key, count := range value.Completed {
		out.Completed[enum(key, "completed", "canceled", "error")] += count
	}
	for key, count := range value.DurationSeconds {
		out.DurationSeconds[enum(key, "completed", "canceled", "error")] += count
	}
	for key, count := range value.ClientBytes {
		out.ClientBytes[enum(key, "completed", "canceled", "error")] += count
	}
	for key, count := range value.BackendBytes {
		out.BackendBytes[enum(key, "completed", "canceled", "error")] += count
	}
	for key, count := range value.ConnectAttempts {
		parts := fixedParts(key, 2)
		bounded := enum(parts[0], "success", "failure") + "|" + enum(parts[1], "direct", "marked")
		out.ConnectAttempts[bounded] += count
	}
	return out
}

func (r *Registry) SetDNS(snapshot DNSSnapshot) {
	requests := map[string]uint64{}
	for key, count := range snapshot.Requests {
		requests[enum(key, "hit", "miss", "stale", "negative", "refresh", "rejection")] += count
	}
	resolutions := map[string]DNSResolution{}
	for key, value := range snapshot.Resolutions {
		parts := fixedParts(key, 2)
		bounded := enum(parts[0], "positive", "nxdomain", "nodata", "transient") + "|" + enum(parts[1], "direct", "marked")
		current := resolutions[bounded]
		current.Count += value.Count
		current.DurationSeconds += value.DurationSeconds
		resolutions[bounded] = current
	}
	snapshot.Requests, snapshot.Resolutions = requests, resolutions
	r.mu.Lock()
	r.dns = snapshot
	r.mu.Unlock()
}

func (r *Registry) SetWG(snapshots []WGSnapshot) {
	bounded := make(map[string]WGSnapshot, len(snapshots))
	for _, snapshot := range snapshots {
		// Tunnel names are config-bounded identities. Peer keys and endpoints are
		// intentionally absent from the metric contract.
		bounded[snapshot.Tunnel] = snapshot
	}
	r.mu.Lock()
	r.wg = bounded
	r.mu.Unlock()
}

func (r *Registry) SetGroups(snapshots []GroupSnapshot) {
	bounded := make(map[string]GroupSnapshot, len(snapshots))
	for _, snapshot := range snapshots {
		snapshot.State = enum(snapshot.State, "ready", "degraded", "failed")
		snapshot.Reason = enum(snapshot.Reason, "recent_handshake", "no_recent_handshake_fail_open_primary")
		bounded[snapshot.Name] = snapshot
	}
	r.mu.Lock()
	r.groups = bounded
	r.mu.Unlock()
}

func (r *Registry) SetProbe(snapshot ProbeSnapshot) {
	snapshot.LastError = RedactText(snapshot.LastError)
	r.mu.Lock()
	r.probe = snapshot
	r.mu.Unlock()
}

func (r *Registry) SetRouteSource(snapshot RouteSourceSnapshot) {
	if snapshot.Name == "" {
		return
	}
	snapshot.LastOutcome = boundedOutcome(snapshot.LastOutcome)
	snapshot.LastError = RedactText(snapshot.LastError)
	r.mu.Lock()
	if snapshot.LastSuccess.IsZero() {
		snapshot.LastSuccess = r.routes[snapshot.Name].LastSuccess
		if snapshot.PrefixCount == 0 {
			snapshot.PrefixCount = r.routes[snapshot.Name].PrefixCount
		}
	}
	r.routes[snapshot.Name] = snapshot
	r.mu.Unlock()
	var componentErr error
	if snapshot.LastError != "" {
		componentErr = errors.New(snapshot.LastError)
	}
	r.SetComponent("route_source", false, snapshot.LastOutcome == "success", snapshot.LastOutcome, componentErr)
}

func (r *Registry) RecordPfSync(outcome string, resultErrors ...error) {
	outcome = boundedOutcome(outcome)
	r.mu.Lock()
	r.pfSync[outcome]++
	r.mu.Unlock()
	ready := outcome == "success" || outcome == "skipped"
	var resultErr error
	if len(resultErrors) > 0 {
		resultErr = resultErrors[0]
	}
	r.SetComponent("pfsync", false, ready, outcome, resultErr)
}

func (r *Registry) Ready() (bool, []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var reasons []string
	if r.generation == 0 {
		reasons = append(reasons, "no_active_generation")
	}
	for name, state := range r.components {
		if state.Required && !state.Ready {
			reasons = append(reasons, name+":"+state.Outcome)
		}
	}
	sort.Strings(reasons)
	return len(reasons) == 0, reasons
}

type Status struct {
	Live             bool                      `json:"live"`
	Ready            bool                      `json:"ready"`
	ReadinessReasons []string                  `json:"readiness_reasons,omitempty"`
	Generation       lifecycle.Generation      `json:"active_generation"`
	StartedAt        time.Time                 `json:"started_at"`
	Components       map[string]ComponentState `json:"components"`
	RouteSources     []RouteSourceSnapshot     `json:"route_sources,omitempty"`
	WireGuard        []WGSnapshot              `json:"wireguard,omitempty"`
	Groups           []GroupSnapshot           `json:"groups,omitempty"`
	ActiveProbe      *ProbeSnapshot            `json:"active_probe,omitempty"`
}

func (r *Registry) Status() Status {
	ready, reasons := r.Ready()
	r.mu.RLock()
	defer r.mu.RUnlock()
	status := Status{Live: true, Ready: ready, ReadinessReasons: reasons, Generation: r.generation, StartedAt: r.started.UTC(), Components: map[string]ComponentState{}}
	for name, state := range r.components {
		status.Components[name] = state
	}
	for _, snapshot := range r.routes {
		status.RouteSources = append(status.RouteSources, snapshot)
	}
	for _, snapshot := range r.wg {
		status.WireGuard = append(status.WireGuard, snapshot)
	}
	for _, snapshot := range r.groups {
		status.Groups = append(status.Groups, snapshot)
	}
	if !r.probe.ObservedAt.IsZero() {
		probe := r.probe
		status.ActiveProbe = &probe
	}
	sort.Slice(status.RouteSources, func(i, j int) bool { return status.RouteSources[i].Name < status.RouteSources[j].Name })
	sort.Slice(status.WireGuard, func(i, j int) bool { return status.WireGuard[i].Tunnel < status.WireGuard[j].Tunnel })
	sort.Slice(status.Groups, func(i, j int) bool { return status.Groups[i].Name < status.Groups[j].Name })
	return status
}

func (r *Registry) WriteStatus(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r.Status())
}

func labels(values ...string) string {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i+1 < len(values); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(values[i])
		b.WriteString("=\"")
		b.WriteString(strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(values[i+1]))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func metric(w io.Writer, name, metricLabels string, value any) {
	fmt.Fprintf(w, "%s%s %v\n", name, metricLabels, value)
}

// WritePrometheus emits a stable, dependency-free Prometheus text exposition.
// Every label is either a fixed enum or a configuration-bounded tunnel/source
// name. Hostnames, addresses, URLs, routes, and peer keys are never labels.
func (r *Registry) WritePrometheus(w io.Writer) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	metric(w, "sakhtar_wg_active_generation", "", uint64(r.generation))
	metric(w, "sakhtar_wg_process_uptime_seconds", "", time.Since(r.started).Seconds())
	metric(w, "sakhtar_wg_process_goroutines", "", runtime.NumGoroutine())
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	metric(w, "sakhtar_wg_process_heap_bytes", "", memory.HeapAlloc)
	if fds, ok := processFDCount(); ok {
		metric(w, "sakhtar_wg_process_open_fds", "", fds)
	}

	for _, outcome := range sortedKeys(r.reload) {
		metric(w, "sakhtar_wg_reload_attempts_total", labels("outcome", outcome), r.reload[outcome])
		metric(w, "sakhtar_wg_reload_duration_seconds_sum", labels("outcome", outcome), r.reloadTime[outcome])
	}
	for _, name := range sortedKeys(r.components) {
		state := r.components[name]
		ready := 0
		if state.Ready {
			ready = 1
		}
		metric(w, "sakhtar_wg_component_ready", labels("component", name), ready)
	}
	metric(w, "sakhtar_wg_kernel_drift", "", r.kernelDrift)
	metric(w, "sakhtar_wg_firewall_drift", "", r.firewallDrift)
	metric(w, "sakhtar_wg_proxy_sessions_active", "", r.proxy.Active)
	metric(w, "sakhtar_wg_proxy_sessions_accepted_total", "", r.proxy.Accepted)
	for _, key := range sortedKeys(r.proxy.Rejected) {
		parts := fixedParts(key, 3)
		metric(w, "sakhtar_wg_proxy_sessions_rejected_total", labels("protocol", enum(parts[0], "tls", "http"), "reason", enum(parts[1], "source_denied", "parse_error", "destination_denied", "overload", "dial_error"), "listener_class", enum(parts[2], "loopback", "non_loopback")), r.proxy.Rejected[key])
	}
	for _, outcome := range []string{"completed", "canceled", "error", "other"} {
		if total, ok := r.proxy.Completed[outcome]; ok {
			l := labels("outcome", outcome)
			metric(w, "sakhtar_wg_proxy_sessions_completed_total", l, total)
			metric(w, "sakhtar_wg_proxy_session_duration_seconds_sum", l, r.proxy.DurationSeconds[outcome])
			metric(w, "sakhtar_wg_proxy_client_bytes_total", l, r.proxy.ClientBytes[outcome])
			metric(w, "sakhtar_wg_proxy_backend_bytes_total", l, r.proxy.BackendBytes[outcome])
		}
	}
	for _, key := range sortedKeys(r.proxy.ConnectAttempts) {
		parts := fixedParts(key, 2)
		metric(w, "sakhtar_wg_proxy_backend_connect_attempts_total", labels("outcome", parts[0], "egress_class", parts[1]), r.proxy.ConnectAttempts[key])
	}
	metric(w, "sakhtar_wg_dns_cache_entries", labels("class", "positive"), r.dns.EntriesPositive)
	metric(w, "sakhtar_wg_dns_cache_entries", labels("class", "negative"), r.dns.EntriesNegative)
	metric(w, "sakhtar_wg_dns_cache_evictions_total", labels("class", "positive"), r.dns.EvictionsPositive)
	metric(w, "sakhtar_wg_dns_cache_evictions_total", labels("class", "negative"), r.dns.EvictionsNegative)
	metric(w, "sakhtar_wg_dns_pending", "", r.dns.Pending)
	metric(w, "sakhtar_wg_dns_pending_rejected_total", "", r.dns.RejectedPending)
	for _, result := range sortedKeys(r.dns.Requests) {
		metric(w, "sakhtar_wg_dns_requests_total", labels("result", enum(result, "hit", "miss", "stale", "negative", "refresh", "rejection")), r.dns.Requests[result])
	}
	for _, key := range sortedKeys(r.dns.Resolutions) {
		parts := fixedParts(key, 2)
		l := labels("outcome", enum(parts[0], "positive", "nxdomain", "nodata", "transient"), "egress_class", enum(parts[1], "direct", "marked"))
		metric(w, "sakhtar_wg_dns_resolutions_total", l, r.dns.Resolutions[key].Count)
		metric(w, "sakhtar_wg_dns_resolution_duration_seconds_sum", l, r.dns.Resolutions[key].DurationSeconds)
	}
	for _, name := range sortedKeys(r.wg) {
		snapshot := r.wg[name]
		l := labels("tunnel", name)
		metric(w, "sakhtar_wg_wg_handshake_age_seconds", l, snapshot.HandshakeAge)
		metric(w, "sakhtar_wg_wg_receive_bytes", l, snapshot.ReceiveBytes)
		metric(w, "sakhtar_wg_wg_transmit_bytes", l, snapshot.TransmitBytes)
		metric(w, "sakhtar_wg_wg_session_recent", labels("tunnel", name, "state", enum(snapshot.Signal, "recent", "idle_unknown", "failed")), 1)
	}
	for _, name := range sortedKeys(r.groups) {
		snapshot := r.groups[name]
		metric(w, "sakhtar_wg_group_policy_state", labels("group", name, "state", snapshot.State, "reason", snapshot.Reason), 1)
	}
	if !r.probe.ObservedAt.IsZero() {
		success := 0
		if r.probe.Success {
			success = 1
		}
		metric(w, "sakhtar_wg_active_probe_success", "", success)
		metric(w, "sakhtar_wg_active_probe_duration_seconds", "", r.probe.DurationSecond)
		metric(w, "sakhtar_wg_active_probe_timestamp_seconds", "", r.probe.ObservedAt.Unix())
	}
	for _, name := range sortedKeys(r.routes) {
		snapshot := r.routes[name]
		l := labels("source", name)
		metric(w, "sakhtar_wg_route_source_prefixes", l, snapshot.PrefixCount)
		if !snapshot.LastSuccess.IsZero() {
			metric(w, "sakhtar_wg_route_source_last_success_timestamp_seconds", l, snapshot.LastSuccess.Unix())
			metric(w, "sakhtar_wg_route_source_last_success_age_seconds", l, max(time.Since(snapshot.LastSuccess).Seconds(), 0))
		}
	}
	for _, outcome := range sortedKeys(r.pfSync) {
		metric(w, "sakhtar_wg_pfsync_reconcile_total", labels("outcome", outcome), r.pfSync[outcome])
	}
}

func enum(value string, allowed ...string) string {
	for _, item := range allowed {
		if value == item {
			return value
		}
	}
	return "other"
}

func fixedParts(value string, count int) []string {
	parts := strings.Split(value, "|")
	for len(parts) < count {
		parts = append(parts, "")
	}
	return parts[:count]
}

func sortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func (r *Registry) SeriesCount() int {
	var builder strings.Builder
	r.WritePrometheus(&builder)
	count := 0
	for _, line := range strings.Split(builder.String(), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			count++
		}
	}
	return count
}
