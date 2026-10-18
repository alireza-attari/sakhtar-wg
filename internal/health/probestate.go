package health

import (
	"errors"
	"sync"
	"time"
)

// ProbePolicy turns per-tunnel active-probe results into a failover verdict.
//
// A tunnel can keep a fresh WireGuard handshake while passing no traffic, so a
// group member is eligible only while its probe also passes. The verdict has
// hysteresis: FailAfter consecutive failures take a passing tunnel out, and
// RecoverAfter consecutive successes bring it back, so one lost probe does not
// move a group and one lucky probe does not move it back.
type ProbePolicy struct {
	// MaxAge bounds how long the last result counts. A probe loop that stops
	// reporting must not keep a tunnel eligible on a verdict it no longer
	// renews.
	MaxAge       time.Duration
	FailAfter    int
	RecoverAfter int
}

func (p ProbePolicy) validate() error {
	if p.MaxAge <= 0 || p.FailAfter < 1 || p.RecoverAfter < 1 {
		return errors.New("health: invalid probe policy")
	}
	return nil
}

type ProbeVerdict string

const (
	// ProbeUnknown means the tunnel has no probe result: probing is disabled,
	// health_probe.via names a different tunnel, or the first result has not
	// arrived since start or reload. Eligibility then rests on the handshake
	// alone, exactly as it did before probes existed.
	ProbeUnknown ProbeVerdict = "unknown"
	ProbePassing ProbeVerdict = "passing"
	ProbeFailing ProbeVerdict = "failing"
	ProbeStale   ProbeVerdict = "stale"
)

// Eligible reports whether the verdict allows a group to select the tunnel.
func (v ProbeVerdict) Eligible() bool { return v == ProbeUnknown || v == ProbePassing }

type probeState struct {
	lastAt    time.Time
	passing   bool
	failures  int
	successes int
}

type probeTracker struct {
	policy ProbePolicy

	mu       sync.Mutex
	byTunnel map[TunnelName]*probeState
}

func newProbeTracker(policy ProbePolicy) *probeTracker {
	return &probeTracker{policy: policy, byTunnel: map[TunnelName]*probeState{}}
}

func (t *probeTracker) record(tunnel TunnelName, success bool, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	state, seen := t.byTunnel[tunnel]
	if !seen {
		// With no history the first result is the best evidence there is; making
		// a dead tunnel at startup wait out FailAfter would route traffic into it.
		t.byTunnel[tunnel] = &probeState{lastAt: at, passing: success, failures: boolCount(!success), successes: boolCount(success)}
		return
	}
	if at.After(state.lastAt) {
		state.lastAt = at
	}
	if success {
		state.successes++
		state.failures = 0
		if state.successes >= t.policy.RecoverAfter {
			state.passing = true
		}
		return
	}
	state.failures++
	state.successes = 0
	if state.failures >= t.policy.FailAfter {
		state.passing = false
	}
}

func (t *probeTracker) verdict(tunnel TunnelName, now time.Time) ProbeVerdict {
	if t == nil {
		return ProbeUnknown
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	state, seen := t.byTunnel[tunnel]
	switch {
	case !seen:
		return ProbeUnknown
	case now.Sub(state.lastAt) > t.policy.MaxAge:
		return ProbeStale
	case state.passing:
		return ProbePassing
	default:
		return ProbeFailing
	}
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}
