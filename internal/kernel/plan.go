// Package kernel contains the ownership model shared by the Linux reconciler
// and its dry-run/status path. The planner is intentionally free of netlink
// calls: the same current and desired snapshots always produce the same plan.
package kernel

import (
	"fmt"
	"sort"
)

const (
	// RouteProtocol is reserved for sakhtar-wg routes. It is deliberately outside
	// the kernel's RTPROT_* range and must be reserved in the deployment runbook.
	RouteProtocol = 186

	// RulePriorityMin..RulePriorityMax is the environment-reserved policy-rule
	// range. A rule outside this range can never be treated as owned.
	RulePriorityMin = 31000
	RulePriorityMax = 31999

	FullMarkMask = ^uint32(0)
)

type Action string

const (
	Add    Action = "add"
	Update Action = "update"
	Delete Action = "delete"
)

type Kind string

const (
	Link    Kind = "link"
	Address Kind = "address"
	Route   Kind = "route"
	Rule    Kind = "rule"
)

// Object is one semantically unique kernel object. ID deliberately excludes
// ownership metadata (for example a route protocol) so a foreign object that
// collides with a desired tuple becomes blocking drift instead of being
// overwritten. Value is a canonical, redacted representation of mutable data.
type Object struct {
	Kind       Kind
	ID         string
	Value      string
	Owned      bool
	Evidence   string
	AllowAdopt bool
}

func (o Object) key() string { return string(o.Kind) + ":" + o.ID }

type Operation struct {
	Action   Action `json:"action"`
	Kind     Kind   `json:"kind"`
	ID       string `json:"id"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
	Evidence string `json:"ownership_evidence"`
}

type Drift struct {
	Kind     Kind   `json:"kind"`
	ID       string `json:"id"`
	Blocking bool   `json:"blocking"`
	Reason   string `json:"reason"`
}

type Plan struct {
	Operations []Operation `json:"operations"`
	Drift      []Drift     `json:"drift"`
}

func (p Plan) HasBlockingDrift() bool {
	for _, d := range p.Drift {
		if d.Blocking {
			return true
		}
	}
	return false
}

// PlanDiff returns a deterministic ownership-safe mutation plan. Foreign
// objects which do not collide with desired state are intentionally omitted;
// they are neither drift nor candidates for deletion.
func PlanDiff(current, desired []Object) (Plan, error) {
	have, err := indexObjects(current, false)
	if err != nil {
		return Plan{}, fmt.Errorf("current state: %w", err)
	}
	want, err := indexObjects(desired, true)
	if err != nil {
		return Plan{}, fmt.Errorf("desired state: %w", err)
	}

	keys := make([]string, 0, len(have)+len(want))
	seen := make(map[string]struct{}, len(have)+len(want))
	for k := range have {
		seen[k] = struct{}{}
		keys = append(keys, k)
	}
	for k := range want {
		if _, ok := seen[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var p Plan
	for _, k := range keys {
		cur, curOK := have[k]
		dst, dstOK := want[k]
		switch {
		case !curOK:
			p.Operations = append(p.Operations, Operation{
				Action: Add, Kind: dst.Kind, ID: dst.ID, After: dst.Value,
				Evidence: dst.Evidence,
			})
		case !dstOK:
			if cur.Owned {
				p.Operations = append(p.Operations, Operation{
					Action: Delete, Kind: cur.Kind, ID: cur.ID, Before: cur.Value,
					Evidence: cur.Evidence,
				})
			}
		case !cur.Owned:
			if dst.AllowAdopt && cur.Value == dst.Value {
				p.Operations = append(p.Operations, Operation{
					Action: Update, Kind: dst.Kind, ID: dst.ID,
					Before: cur.Value, After: dst.Value, Evidence: dst.Evidence,
				})
			} else {
				p.Drift = append(p.Drift, Drift{
					Kind: dst.Kind, ID: dst.ID, Blocking: true,
					Reason: "desired tuple collides with an object lacking ownership evidence",
				})
			}
		case cur.Value != dst.Value:
			p.Operations = append(p.Operations, Operation{
				Action: Update, Kind: dst.Kind, ID: dst.ID,
				Before: cur.Value, After: dst.Value, Evidence: cur.Evidence,
			})
		}
	}
	return p, nil
}

func indexObjects(objects []Object, desired bool) (map[string]Object, error) {
	indexed := make(map[string]Object, len(objects))
	for _, o := range objects {
		if o.Kind == "" || o.ID == "" {
			return nil, fmt.Errorf("object kind and id are required")
		}
		if desired && o.Evidence == "" {
			return nil, fmt.Errorf("%s lacks ownership evidence", o.key())
		}
		if _, exists := indexed[o.key()]; exists {
			return nil, fmt.Errorf("duplicate object %s", o.key())
		}
		indexed[o.key()] = o
	}
	return indexed, nil
}

type Allocation struct {
	Name     string
	Mark     uint32
	Mask     uint32
	Table    int
	Priority int
}

// ValidateAllocations proves that policy selectors cannot alias and that all
// mutable identifiers are inside the application's documented allocation.
func ValidateAllocations(allocations []Allocation) error {
	for i, a := range allocations {
		if a.Name == "" {
			return fmt.Errorf("allocation #%d: name is required", i)
		}
		if a.Mark == 0 {
			return fmt.Errorf("tunnel %q: fwmark must be non-zero", a.Name)
		}
		if a.Mask == 0 || a.Mark&a.Mask != a.Mark {
			return fmt.Errorf("tunnel %q: fwmark mask %#x does not select mark %#x exactly", a.Name, a.Mask, a.Mark)
		}
		if a.Table <= 0 || a.Table == 253 || a.Table == 254 || a.Table == 255 {
			return fmt.Errorf("tunnel %q: route table %d is zero or reserved", a.Name, a.Table)
		}
		if a.Priority < RulePriorityMin || a.Priority > RulePriorityMax {
			return fmt.Errorf("tunnel %q: rule priority %d is outside reserved range %d-%d", a.Name, a.Priority, RulePriorityMin, RulePriorityMax)
		}
		for _, b := range allocations[:i] {
			if a.Table == b.Table {
				return fmt.Errorf("tunnel %q: route table %d already used by %q", a.Name, a.Table, b.Name)
			}
			if a.Priority == b.Priority {
				return fmt.Errorf("tunnel %q: rule priority %d already used by %q", a.Name, a.Priority, b.Name)
			}
			common := a.Mask & b.Mask
			if a.Mark&common == b.Mark&common {
				return fmt.Errorf("tunnels %q and %q: fwmark/mask selectors overlap", b.Name, a.Name)
			}
		}
	}
	return nil
}
