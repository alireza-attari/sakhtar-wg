package health

import (
	"errors"
	"io"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeDeviceClient struct {
	mu      sync.Mutex
	devices map[string]*wgtypes.Device
	errors  map[string]error
	calls   map[string]int
	closed  bool
}

func (f *fakeDeviceClient) Device(name string) (*wgtypes.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[name]++
	if err := f.errors[name]; err != nil {
		return nil, err
	}
	device := f.devices[name]
	if device == nil {
		return nil, errors.New("not found")
	}
	return device, nil
}

func (f *fakeDeviceClient) Close() error { f.closed = true; return nil }

func TestWGSnapshotOnce(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	client := &fakeDeviceClient{devices: map[string]*wgtypes.Device{
		"primary": {Peers: []wgtypes.Peer{{LastHandshakeTime: now.Add(-10 * time.Second), ReceiveBytes: 3, TransmitBytes: 5}}},
		"backup":  {Peers: []wgtypes.Peer{{LastHandshakeTime: now.Add(-10 * time.Minute)}}},
	}}
	monitor, err := New(client, Config{Interval: time.Second, Groups: []Group{
		{Name: "one", HealthyAfter: time.Minute, Members: []Member{{Tunnel: "primary", Mark: 51}, {Tunnel: "backup", Mark: 52}}},
		{Name: "two", HealthyAfter: time.Minute, Members: []Member{{Tunnel: "primary", Mark: 51}}},
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	monitor.now = func() time.Time { return now }
	monitor.Poll()
	if client.calls["primary"] != 1 || client.calls["backup"] != 1 {
		t.Fatalf("device calls = %#v; each unique device must be queried once", client.calls)
	}
	if got := monitor.Active("one").Load(); got != 51 {
		t.Fatalf("active mark = %d", got)
	}
	snapshot := monitor.Snapshot()
	if len(snapshot.Tunnels) != 2 || snapshot.Tunnels[1].Signal != SessionRecent || snapshot.Tunnels[1].ReceiveBytes != 3 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if err := monitor.Close(); err != nil || !client.closed {
		t.Fatalf("close err=%v closed=%t", err, client.closed)
	}
}

func TestPassiveHealthDistinguishesIdleAndFailed(t *testing.T) {
	now := time.Now()
	client := &fakeDeviceClient{devices: map[string]*wgtypes.Device{"idle": {Peers: []wgtypes.Peer{{LastHandshakeTime: now.Add(-time.Hour)}}}}, errors: map[string]error{"failed": errors.New("boom")}}
	monitor, err := New(client, Config{Interval: time.Second, Groups: []Group{{Name: "g", HealthyAfter: time.Minute, Members: []Member{{Tunnel: "idle", Mark: 1}, {Tunnel: "failed", Mark: 2}}}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	monitor.now = func() time.Time { return now }
	monitor.Poll()
	byName := map[TunnelName]SessionSignal{}
	for _, item := range monitor.Snapshot().Tunnels {
		byName[item.Tunnel] = item.Signal
	}
	if byName["idle"] != SessionIdleUnknown || byName["failed"] != SessionFailed {
		t.Fatalf("signals = %#v", byName)
	}
}

func TestGroupFailoverAndReturnToPrimary(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	primary := &wgtypes.Device{Peers: []wgtypes.Peer{{LastHandshakeTime: now.Add(-time.Second)}}}
	backup := &wgtypes.Device{Peers: []wgtypes.Peer{{LastHandshakeTime: now.Add(-time.Second)}}}
	client := &fakeDeviceClient{devices: map[string]*wgtypes.Device{"wg0": primary, "wg18": backup}}
	monitor, err := New(client, Config{Interval: 10 * time.Second, Groups: []Group{{
		Name: "bypass", HealthyAfter: 180 * time.Second,
		Members: []Member{{Tunnel: "wg0", Mark: 51}, {Tunnel: "wg18", Mark: 52018}},
	}}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	monitor.now = func() time.Time { return now }
	for _, step := range []struct {
		name string
		age  time.Duration
		mark int32
	}{
		{"primary healthy", time.Second, 51},
		{"primary stale uses backup", 181 * time.Second, 52018},
		{"primary recovered is preferred", time.Second, 51},
	} {
		t.Run(step.name, func(t *testing.T) {
			primary.Peers[0].LastHandshakeTime = now.Add(-step.age)
			monitor.Poll()
			if got := monitor.Active("bypass").Load(); got != step.mark {
				t.Fatalf("active mark = %d, want %d", got, step.mark)
			}
		})
	}
}

func newProbeAwareMonitor(t *testing.T, now *time.Time, wg0, wg18 *wgtypes.Device) *Monitor {
	t.Helper()
	client := &fakeDeviceClient{devices: map[string]*wgtypes.Device{"wg0": wg0, "wg18": wg18}}
	monitor, err := New(client, Config{
		Interval: 10 * time.Second,
		Probe:    &ProbePolicy{MaxAge: 90 * time.Second, FailAfter: 2, RecoverAfter: 3},
		Groups: []Group{{
			Name: "bypass", HealthyAfter: 180 * time.Second,
			Members: []Member{{Tunnel: "wg0", Mark: 51}, {Tunnel: "wg18", Mark: 52018}},
		}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	monitor.now = func() time.Time { return *now }
	return monitor
}

// A fresh handshake is not reachability: wg0 kept one on 2026-10-18 while it
// passed no traffic, and the group stayed on it because selection never read
// the probe. Each step below is cumulative over one monitor.
func TestGroupSelectionRequiresPassingProbe(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	wg0 := &wgtypes.Device{Peers: []wgtypes.Peer{{LastHandshakeTime: now}}}
	wg18 := &wgtypes.Device{Peers: []wgtypes.Peer{{LastHandshakeTime: now}}}
	monitor := newProbeAwareMonitor(t, &now, wg0, wg18)

	type probe struct {
		tunnel  string
		success bool
	}
	for _, step := range []struct {
		name    string
		advance time.Duration
		probes  []probe
		wg0Age  time.Duration
		mark    int32
		state   string
		reason  string
		order   []FwMark
	}{
		{name: "no probe result yet falls back to handshake", mark: 51, state: "ready", reason: ReasonRecentHandshake, order: []FwMark{51, 52018}},
		{name: "first failure is believed without history", probes: []probe{{"wg0", false}, {"wg18", true}}, mark: 52018, state: "ready", reason: ReasonRecentHandshakeProbePassing, order: []FwMark{52018}},
		{name: "one success does not fail back", advance: 30 * time.Second, probes: []probe{{"wg0", true}, {"wg18", true}}, mark: 52018, state: "ready", reason: ReasonRecentHandshakeProbePassing, order: []FwMark{52018}},
		{name: "two successes do not fail back", advance: 30 * time.Second, probes: []probe{{"wg0", true}}, mark: 52018, state: "ready", reason: ReasonRecentHandshakeProbePassing, order: []FwMark{52018}},
		{name: "third consecutive success fails back", advance: 30 * time.Second, probes: []probe{{"wg0", true}, {"wg18", true}}, mark: 51, state: "ready", reason: ReasonRecentHandshakeProbePassing, order: []FwMark{51, 52018}},
		{name: "one failure does not fail over", advance: 30 * time.Second, probes: []probe{{"wg0", false}, {"wg18", true}}, mark: 51, state: "ready", reason: ReasonRecentHandshakeProbePassing, order: []FwMark{51, 52018}},
		{name: "a success resets the failure count", advance: 30 * time.Second, probes: []probe{{"wg0", true}, {"wg0", false}}, mark: 51, state: "ready", reason: ReasonRecentHandshakeProbePassing, order: []FwMark{51, 52018}},
		{name: "second consecutive failure fails over", advance: 30 * time.Second, probes: []probe{{"wg0", false}, {"wg18", true}}, mark: 52018, state: "ready", reason: ReasonRecentHandshakeProbePassing, order: []FwMark{52018}},
		{name: "both failing keeps a member with a session", probes: []probe{{"wg18", false}, {"wg18", false}}, mark: 51, state: "degraded", reason: ReasonProbeFailingFailOpen, order: []FwMark{51, 52018}},
		{name: "no handshake anywhere fails open to primary", wg0Age: time.Hour, mark: 51, state: "degraded", reason: ReasonNoRecentHandshakeFailOpen, order: []FwMark{51, 52018}},
	} {
		t.Run(step.name, func(t *testing.T) {
			now = now.Add(step.advance)
			wg0.Peers[0].LastHandshakeTime = now.Add(-step.wg0Age)
			wg18.Peers[0].LastHandshakeTime = now
			if step.wg0Age > 0 {
				wg18.Peers[0].LastHandshakeTime = now.Add(-step.wg0Age)
			}
			for _, p := range step.probes {
				monitor.ObserveProbe(p.tunnel, ProbeResult{At: now, Success: p.success})
			}
			monitor.Poll()
			if got := monitor.Active("bypass").Load(); got != step.mark {
				t.Fatalf("active mark = %d, want %d", got, step.mark)
			}
			group := monitor.Snapshot().Groups[0]
			if group.State != step.state || group.Reason != step.reason {
				t.Fatalf("group = %s/%s, want %s/%s", group.State, group.Reason, step.state, step.reason)
			}
			if got := *monitor.Order("bypass").Load(); !slices.Equal(got, step.order) {
				t.Fatalf("failover order = %v, want %v", got, step.order)
			}
		})
	}
}

// A probe loop that stops reporting must not keep a tunnel eligible on its last
// verdict: the tunnel could have died the moment the reports stopped.
func TestStaleProbeResultMakesMemberIneligible(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		name string
		age  time.Duration
		mark int32
	}{
		{"result within max_age counts", 90 * time.Second, 51},
		{"result past max_age is stale", 91 * time.Second, 52018},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wg0 := &wgtypes.Device{Peers: []wgtypes.Peer{{LastHandshakeTime: now}}}
			wg18 := &wgtypes.Device{Peers: []wgtypes.Peer{{LastHandshakeTime: now}}}
			monitor := newProbeAwareMonitor(t, &now, wg0, wg18)
			monitor.ObserveProbe("wg0", ProbeResult{At: now.Add(-tc.age), Success: true})
			monitor.Poll()
			if got := monitor.Active("bypass").Load(); got != tc.mark {
				t.Fatalf("active mark = %d, want %d", got, tc.mark)
			}
		})
	}
}

func TestProbePolicyValidation(t *testing.T) {
	client := &fakeDeviceClient{}
	groups := []Group{{Name: "g", HealthyAfter: time.Minute, Members: []Member{{Tunnel: "wg0", Mark: 1}}}}
	for _, tc := range []struct {
		name   string
		policy ProbePolicy
		valid  bool
	}{
		{"valid", ProbePolicy{MaxAge: time.Minute, FailAfter: 1, RecoverAfter: 1}, true},
		{"zero max age", ProbePolicy{FailAfter: 1, RecoverAfter: 1}, false},
		{"zero fail_after", ProbePolicy{MaxAge: time.Minute, RecoverAfter: 1}, false},
		{"zero recover_after", ProbePolicy{MaxAge: time.Minute, FailAfter: 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := tc.policy
			_, err := New(client, Config{Interval: time.Second, Groups: groups, Probe: &policy}, nil)
			if (err == nil) != tc.valid {
				t.Fatalf("err = %v, valid = %t", err, tc.valid)
			}
		})
	}
}
