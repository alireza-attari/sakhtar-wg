package dns

import (
	"sync/atomic"
	"time"
)

const (
	requestHit = iota
	requestMiss
	requestStale
	requestNegative
	requestRefresh
	requestRejected
	requestKinds
)

const (
	classPositive = iota
	classNegative
	classKinds
)

const (
	egressDirect = iota
	egressMarked
	egressKinds
)

type resolutionMetric struct {
	count atomic.Uint64
	nanos atomic.Uint64
}

type metrics struct {
	entries    [classKinds]atomic.Int64
	evictions  [classKinds]atomic.Uint64
	requests   [requestKinds]atomic.Uint64
	pending    atomic.Int64
	rejected   atomic.Uint64
	resolution [4][egressKinds]resolutionMetric
}

type ResolutionStats struct {
	Count         uint64
	TotalDuration time.Duration
}

type MetricsSnapshot struct {
	EntriesPositive   int64
	EntriesNegative   int64
	EvictionsPositive uint64
	EvictionsNegative uint64
	Requests          map[string]uint64
	Pending           int64
	RejectedPending   uint64
	Resolutions       map[string]ResolutionStats
}

func (m *metrics) snapshot() MetricsSnapshot {
	s := MetricsSnapshot{
		EntriesPositive:   m.entries[classPositive].Load(),
		EntriesNegative:   m.entries[classNegative].Load(),
		EvictionsPositive: m.evictions[classPositive].Load(),
		EvictionsNegative: m.evictions[classNegative].Load(),
		Pending:           m.pending.Load(),
		RejectedPending:   m.rejected.Load(),
		Requests:          make(map[string]uint64, requestKinds),
		Resolutions:       make(map[string]ResolutionStats, 8),
	}
	requestNames := [...]string{"hit", "miss", "stale", "negative", "refresh", "rejection"}
	for i, name := range requestNames {
		s.Requests[name] = m.requests[i].Load()
	}
	for outcome := RCodeSuccess; outcome <= RCodeTransient; outcome++ {
		for class, className := range [...]string{"direct", "marked"} {
			metric := &m.resolution[outcome][class]
			s.Resolutions[outcome.String()+"|"+className] = ResolutionStats{
				Count:         metric.count.Load(),
				TotalDuration: time.Duration(metric.nanos.Load()),
			}
		}
	}
	return s
}

func (m *metrics) recordResolution(rcode RCode, marked bool, elapsed time.Duration) {
	if rcode > RCodeTransient {
		rcode = RCodeTransient
	}
	class := egressDirect
	if marked {
		class = egressMarked
	}
	metric := &m.resolution[rcode][class]
	metric.count.Add(1)
	metric.nanos.Add(uint64(max(elapsed, 0)))
}
