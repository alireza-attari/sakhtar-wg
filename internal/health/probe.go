package health

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// ProbeConfig bounds optional active probes. Callers provide a probe function
// that dials the configured endpoint through the intended marked egress.
type ProbeConfig struct {
	Interval      time.Duration
	Timeout       time.Duration
	Jitter        float64
	MaxConcurrent int
	Observe       func(ProbeResult)
}

type ProbeResult struct {
	At       time.Time
	Duration time.Duration
	Success  bool
	Err      error
}

type Prober struct {
	config ProbeConfig
	probe  func(context.Context) error
	sem    chan struct{}
	inFly  atomic.Int64
	mu     sync.RWMutex
	last   ProbeResult
}

func NewProber(config ProbeConfig, probe func(context.Context) error) *Prober {
	if config.MaxConcurrent < 1 {
		config.MaxConcurrent = 1
	}
	if config.Jitter < 0 {
		config.Jitter = 0
	}
	if config.Jitter > 1 {
		config.Jitter = 1
	}
	return &Prober{config: config, probe: probe, sem: make(chan struct{}, config.MaxConcurrent)}
}

func (p *Prober) Try(ctx context.Context) bool {
	if p == nil || p.probe == nil || p.config.Timeout <= 0 {
		return false
	}
	select {
	case p.sem <- struct{}{}:
	default:
		return false
	}
	go func() {
		p.inFly.Add(1)
		defer func() { p.inFly.Add(-1); <-p.sem }()
		started := time.Now()
		probeCtx, cancel := context.WithTimeout(ctx, p.config.Timeout)
		err := p.probe(probeCtx)
		cancel()
		p.mu.Lock()
		p.last = ProbeResult{At: time.Now().UTC(), Duration: time.Since(started), Success: err == nil, Err: err}
		result := p.last
		p.mu.Unlock()
		if p.config.Observe != nil {
			p.config.Observe(result)
		}
	}()
	return true
}

func (p *Prober) Run(ctx context.Context) {
	if p == nil || p.config.Interval <= 0 {
		return
	}
	for {
		p.Try(ctx)
		factor := 1 + ((rand.Float64()*2)-1)*p.config.Jitter
		delay := time.Duration(float64(p.config.Interval) * factor)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (p *Prober) InFlight() int64 { return p.inFly.Load() }

func (p *Prober) Last() ProbeResult {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.last
}
