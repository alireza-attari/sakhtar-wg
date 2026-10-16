package main

import (
	"strings"

	kernelstate "github.com/alireza-attari/sakhtar-wg/internal/kernel"
)

// kernelChanges renders the mutations a plan needs as stable one-line strings.
// Drift entries are left out: they describe objects the reconciler refuses to
// touch, so they are not something a repair can act on.
func kernelChanges(plan kernelstate.Plan) []string {
	changes := make([]string, 0, len(plan.Operations))
	for _, op := range plan.Operations {
		changes = append(changes, string(op.Action)+" "+string(op.Kind)+" "+op.ID)
	}
	return changes
}

// kernelWatch remembers what the previous tick saw so a box that stays broken
// logs once per distinct state rather than every interval.
type kernelWatch struct {
	lastSeen string
}

// observe reports whether changes differ from the previous tick.
func (w *kernelWatch) observe(changes []string) bool {
	seen := strings.Join(changes, "; ")
	if seen == w.lastSeen {
		return false
	}
	w.lastSeen = seen
	return true
}
