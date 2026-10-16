package dns

import (
	"sync"
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

// maxEgressLabels bounds the distinct egress identities the resolution metric
// will track. Egress names come from the daemon's own tunnel list, so the real
// count is a handful; anything beyond the cap folds into "other" rather than
// letting a misconfiguration grow the series set without limit.
const maxEgressLabels = 16

const egressDirect = "direct"

type resolutionMetric struct {
	count atomic.Uint64
	nanos atomic.Uint64
}

type metrics struct {
	entries   [classKinds]atomic.Int64
	evictions [classKinds]atomic.Uint64
	requests  [requestKinds]atomic.Uint64
	pending   atomic.Int64
	rejected  atomic.Uint64
	// resolution is keyed "<rcode>|<egress>". A resolution happens once per cache
	// miss, not once per connection, so a mutex here is not on any hot path.
	resolutionMu sync.Mutex
	resolution   map[string]*resolutionMetric
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
	m.resolutionMu.Lock()
	for key, metric := range m.resolution {
		s.Resolutions[key] = ResolutionStats{
			Count:         metric.count.Load(),
			TotalDuration: time.Duration(metric.nanos.Load()),
		}
	}
	m.resolutionMu.Unlock()
	return s
}

// recordResolution attributes one upstream resolution to the egress it was sent
// through. Without that attribution a single unhealthy tunnel losing most of its
// DNS is invisible: the aggregate still looks mostly fine, while every miss that
// happens to pick that tunnel fails.
func (m *metrics) recordResolution(rcode RCode, egress string, elapsed time.Duration) {
	if rcode > RCodeTransient {
		rcode = RCodeTransient
	}
	if egress == "" {
		egress = egressDirect
	}
	key := rcode.String() + "|" + egress
	m.resolutionMu.Lock()
	metric, ok := m.resolution[key]
	if !ok {
		if m.resolution == nil {
			m.resolution = map[string]*resolutionMetric{}
		}
		if len(m.resolution) >= maxEgressLabels*4 {
			key = rcode.String() + "|other"
			metric, ok = m.resolution[key]
		}
		if !ok {
			metric = &resolutionMetric{}
			m.resolution[key] = metric
		}
	}
	m.resolutionMu.Unlock()
	metric.count.Add(1)
	metric.nanos.Add(uint64(max(elapsed, 0)))
}
