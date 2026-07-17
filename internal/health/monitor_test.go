package health

import (
	"errors"
	"io"
	"log/slog"
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
