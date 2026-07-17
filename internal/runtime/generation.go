// Package runtime owns the lifecycle identity used to correlate a committed
// configuration with the listeners, health state, metrics, and logs it created.
package runtime

import (
	"strconv"
	"sync/atomic"
)

// Generation is a monotonically increasing, process-local configuration ID.
// A distinct type prevents it from being mixed with counters or kernel IDs.
type Generation uint64

func (g Generation) String() string { return strconv.FormatUint(uint64(g), 10) }

// Generations publishes the currently active generation.
type Generations struct{ active atomic.Uint64 }

func NewGenerations() *Generations {
	g := &Generations{}
	g.active.Store(1)
	return g
}

func (g *Generations) Active() Generation { return Generation(g.active.Load()) }

func (g *Generations) Advance() Generation { return Generation(g.active.Add(1)) }
