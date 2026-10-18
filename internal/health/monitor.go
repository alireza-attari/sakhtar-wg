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
	// Probe, when set, makes group selection require a passing active probe on
	// top of a recent handshake. Nil keeps selection handshake-only.
	Probe *ProbePolicy
}

type SessionSignal string

const (
	SessionRecent      SessionSignal = "recent"
	SessionIdleUnknown SessionSignal = "idle_unknown"
	SessionFailed      SessionSignal = "failed"
)

// Group selection reasons. They are metric label values, so the observability
// registry allow-lists exactly this set.
const (
	ReasonRecentHandshake             = "recent_handshake"
	ReasonRecentHandshakeProbePassing = "recent_handshake_probe_passing"
	ReasonProbeFailingFailOpen        = "probe_failing_fail_open_recent_handshake"
	ReasonNoRecentHandshakeFailOpen   = "no_recent_handshake_fail_open_primary"
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
	// order is the chosen member followed by the other eligible members in
	// preference order: where a connection goes next when the chosen member
	// fails it. Replaced whole on every poll, never mutated.
	order atomic.Pointer[[]FwMark]
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
	probes   *probeTracker

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
	if cfg.Probe != nil {
		if err := cfg.Probe.validate(); err != nil {
			return nil, err
		}
		m.probes = newProbeTracker(*cfg.Probe)
	}
	for _, group := range cfg.Groups {
		if group.Name == "" || len(group.Members) == 0 || group.HealthyAfter <= 0 {
			return nil, errors.New("health: invalid group")
		}
		state := &groupState{group: group}
		state.active.Store(int32(group.Members[0].Mark))
		order := memberMarks(group.Members)
		state.order.Store(&order)
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

// ObserveProbe feeds one active-probe result for tunnel into group selection.
// It takes effect at the next poll.
func (m *Monitor) ObserveProbe(tunnel string, result ProbeResult) {
	if m == nil || m.probes == nil {
		return
	}
	m.probes.record(TunnelName(tunnel), result.Success, result.At)
}

// Order returns the group's published failover order (see groupState.order).
func (m *Monitor) Order(name string) *atomic.Pointer[[]FwMark] {
	if m == nil {
		return nil
	}
	if group := m.byName[name]; group != nil {
		return &group.order
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
		chosen, groupState, reason, order := m.selectMember(state.group.Members, byTunnel, now)
		state.order.Store(&order)
		previous := FwMark(uint32(state.active.Swap(int32(chosen))))
		if previous != chosen {
			m.logger.Info("health.group_selection_changed", "component", "health", "group", state.group.Name, "fwmark", uint32(chosen), "outcome", groupState, "reason", reason)
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

// selectMember picks the first member, in preference order, whose handshake is
// recent and whose probe does not rule it out, and returns the failover order
// behind it. When none qualifies it fails open: first to a member that at least
// has a recent handshake, so a probe endpoint that is itself down degrades to
// handshake-only selection rather than to a member with no session at all, and
// finally to the primary. A fail-open order lists every member, since nothing
// is known to work better than anything else.
func (m *Monitor) selectMember(members []Member, byTunnel map[TunnelName]TunnelSnapshot, now time.Time) (FwMark, string, string, []FwMark) {
	firstRecent := -1
	var eligible []FwMark
	var verdict ProbeVerdict
	for i, member := range members {
		if byTunnel[member.Tunnel].Signal != SessionRecent {
			continue
		}
		if firstRecent < 0 {
			firstRecent = i
		}
		if v := m.probes.verdict(member.Tunnel, now); v.Eligible() {
			if len(eligible) == 0 {
				verdict = v
			}
			eligible = append(eligible, member.Mark)
		}
	}
	switch {
	case len(eligible) > 0 && verdict == ProbePassing:
		return eligible[0], "ready", ReasonRecentHandshakeProbePassing, eligible
	case len(eligible) > 0:
		return eligible[0], "ready", ReasonRecentHandshake, eligible
	case firstRecent >= 0:
		return members[firstRecent].Mark, "degraded", ReasonProbeFailingFailOpen, chosenFirst(members, firstRecent)
	default:
		return members[0].Mark, "degraded", ReasonNoRecentHandshakeFailOpen, memberMarks(members)
	}
}

func memberMarks(members []Member) []FwMark {
	marks := make([]FwMark, len(members))
	for i, member := range members {
		marks[i] = member.Mark
	}
	return marks
}

func chosenFirst(members []Member, chosen int) []FwMark {
	marks := make([]FwMark, 0, len(members))
	marks = append(marks, members[chosen].Mark)
	for i, member := range members {
		if i != chosen {
			marks = append(marks, member.Mark)
		}
	}
	return marks
}
