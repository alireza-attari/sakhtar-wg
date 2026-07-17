// Package health computes passive WireGuard and group-policy health from one
// bounded device snapshot per interval. It deliberately does not equate an old
// handshake with failed end-to-end reachability: idle/unknown is a distinct
// passive signal.
package health

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type TunnelName string
type FwMark uint32

type DeviceClient interface {
	Device(string) (*wgtypes.Device, error)
	Close() error
}

type Member struct {
	Tunnel TunnelName
	Mark   FwMark
}

type Group struct {
	Name         string
	Members      []Member
	HealthyAfter time.Duration
}

type Config struct {
	Interval time.Duration
	Groups   []Group
	Observe  func(Snapshot)
}

type SessionSignal string

const (
	SessionRecent      SessionSignal = "recent"
	SessionIdleUnknown SessionSignal = "idle_unknown"
	SessionFailed      SessionSignal = "failed"
)

type TunnelSnapshot struct {
	Tunnel          TunnelName    `json:"tunnel"`
	Signal          SessionSignal `json:"wg_session_recent"`
	HandshakeAge    time.Duration `json:"-"`
	HandshakeAgeSec float64       `json:"handshake_age_seconds,omitempty"`
	ReceiveBytes    int64         `json:"receive_bytes"`
	TransmitBytes   int64         `json:"transmit_bytes"`
	Error           string        `json:"error,omitempty"`
}

type GroupSnapshot struct {
	Name       string   `json:"name"`
	ActiveMark FwMark   `json:"active_fwmark"`
	State      string   `json:"state"`
	Reason     string   `json:"reason"`
	Members    []Member `json:"-"`
}

type Snapshot struct {
	ObservedAt time.Time        `json:"observed_at"`
	Tunnels    []TunnelSnapshot `json:"tunnels"`
	Groups     []GroupSnapshot  `json:"groups"`
}

type groupState struct {
	group  Group
	active atomic.Int32
}

// Monitor queries every unique device at most once per poll, even when a
// tunnel belongs to several groups.
type Monitor struct {
	wg       DeviceClient
	groups   []*groupState
	byName   map[string]*groupState
	interval time.Duration
	now      func() time.Time
	logger   *slog.Logger
	observe  func(Snapshot)

	mu       sync.RWMutex
	snapshot Snapshot
}

func New(client DeviceClient, cfg Config, logger *slog.Logger) (*Monitor, error) {
	if client == nil {
		return nil, errors.New("health: device client is required")
	}
	if cfg.Interval <= 0 {
		return nil, errors.New("health: interval must be positive")
	}
	if logger == nil {
		logger = slog.Default()
	}
	m := &Monitor{wg: client, interval: cfg.Interval, now: time.Now, logger: logger, observe: cfg.Observe, byName: map[string]*groupState{}}
	for _, group := range cfg.Groups {
		if group.Name == "" || len(group.Members) == 0 || group.HealthyAfter <= 0 {
			return nil, errors.New("health: invalid group")
		}
		state := &groupState{group: group}
		state.active.Store(int32(group.Members[0].Mark))
		m.groups = append(m.groups, state)
		m.byName[group.Name] = state
	}
	return m, nil
}

func (m *Monitor) Active(name string) *atomic.Int32 {
	if m == nil {
		return nil
	}
	if group := m.byName[name]; group != nil {
		return &group.active
	}
	return nil
}

func (m *Monitor) Run(ctx context.Context) {
	if m == nil {
		return
	}
	m.Poll()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Poll()
		}
	}
}

func (m *Monitor) Close() error {
	if m == nil || m.wg == nil {
		return nil
	}
	return m.wg.Close()
}

func (m *Monitor) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := m.snapshot
	result.Tunnels = append([]TunnelSnapshot(nil), result.Tunnels...)
	result.Groups = append([]GroupSnapshot(nil), result.Groups...)
	return result
}

func (m *Monitor) Poll() {
	if m == nil {
		return
	}
	now := m.now()
	thresholds := map[TunnelName]time.Duration{}
	for _, state := range m.groups {
		for _, member := range state.group.Members {
			if current := thresholds[member.Tunnel]; current == 0 || state.group.HealthyAfter < current {
				thresholds[member.Tunnel] = state.group.HealthyAfter
			}
		}
	}
	names := make([]string, 0, len(thresholds))
	for name := range thresholds {
		names = append(names, string(name))
	}
	sort.Strings(names)
	byTunnel := make(map[TunnelName]TunnelSnapshot, len(names))
	for _, rawName := range names {
		name := TunnelName(rawName)
		state := TunnelSnapshot{Tunnel: name, Signal: SessionIdleUnknown}
		device, err := m.wg.Device(rawName)
		switch {
		case err != nil:
			state.Signal, state.Error = SessionFailed, "device query failed"
		case len(device.Peers) == 0:
			state.Signal, state.Error = SessionFailed, "peer missing"
		default:
			peer := device.Peers[0]
			state.ReceiveBytes, state.TransmitBytes = peer.ReceiveBytes, peer.TransmitBytes
			if !peer.LastHandshakeTime.IsZero() {
				state.HandshakeAge = max(now.Sub(peer.LastHandshakeTime), 0)
				state.HandshakeAgeSec = state.HandshakeAge.Seconds()
				if state.HandshakeAge < thresholds[name] {
					state.Signal = SessionRecent
				}
			}
		}
		byTunnel[name] = state
	}

	groups := make([]GroupSnapshot, 0, len(m.groups))
	for _, state := range m.groups {
		chosen := state.group.Members[0].Mark
		groupState, reason := "degraded", "no_recent_handshake_fail_open_primary"
		for _, member := range state.group.Members {
			if byTunnel[member.Tunnel].Signal == SessionRecent {
				chosen, groupState, reason = member.Mark, "ready", "recent_handshake"
				break
			}
		}
		previous := FwMark(uint32(state.active.Swap(int32(chosen))))
		if previous != chosen {
			m.logger.Info("health.group_selection_changed", "component", "health", "group", state.group.Name, "fwmark", uint32(chosen), "outcome", groupState)
		}
		groups = append(groups, GroupSnapshot{Name: state.group.Name, ActiveMark: chosen, State: groupState, Reason: reason})
	}
	tunnels := make([]TunnelSnapshot, 0, len(names))
	for _, name := range names {
		tunnels = append(tunnels, byTunnel[TunnelName(name)])
	}
	snapshot := Snapshot{ObservedAt: now.UTC(), Tunnels: tunnels, Groups: groups}
	m.mu.Lock()
	m.snapshot = snapshot
	m.mu.Unlock()
	if m.observe != nil {
		m.observe(snapshot)
	}
}
