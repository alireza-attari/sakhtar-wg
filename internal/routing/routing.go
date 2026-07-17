// Package routing contains allocation-free hostname suffix lookup and
// deterministic desired/current route planning primitives.
package routing

import (
	"sort"
	"strings"
)

// SuffixMatcher resolves exact hostnames and parent suffixes, preferring the
// most-specific configured suffix. Callers canonicalize hostnames at their
// trust boundary so this hot path does no case folding or allocation.
type SuffixMatcher[T any] struct {
	values map[string]T
}

func NewSuffixMatcher[T any](capacity int) *SuffixMatcher[T] {
	return &SuffixMatcher[T]{values: make(map[string]T, capacity)}
}

// AddFirst installs value only when suffix has not already been configured.
// This preserves the daemon's documented first-rule-wins behavior.
func (m *SuffixMatcher[T]) AddFirst(suffix string, value T) bool {
	if m == nil {
		return false
	}
	if _, exists := m.values[suffix]; exists {
		return false
	}
	m.values[suffix] = value
	return true
}

func (m *SuffixMatcher[T]) Lookup(host string) (T, bool) {
	var zero T
	if m == nil {
		return zero, false
	}
	for offset := 0; offset < len(host); {
		if value, ok := m.values[host[offset:]]; ok {
			return value, true
		}
		dot := strings.IndexByte(host[offset:], '.')
		if dot < 0 {
			break
		}
		offset += dot + 1
	}
	return zero, false
}

type Diff struct {
	Add    []string
	Delete []string
}

// PlanDiff computes sorted set differences. Duplicate inputs do not produce
// duplicate operations.
func PlanDiff(current, desired []string) Diff {
	have := make(map[string]struct{}, len(current))
	want := make(map[string]struct{}, len(desired))
	for _, item := range current {
		have[item] = struct{}{}
	}
	for _, item := range desired {
		want[item] = struct{}{}
	}
	var diff Diff
	for item := range want {
		if _, ok := have[item]; !ok {
			diff.Add = append(diff.Add, item)
		}
	}
	for item := range have {
		if _, ok := want[item]; !ok {
			diff.Delete = append(diff.Delete, item)
		}
	}
	sort.Strings(diff.Add)
	sort.Strings(diff.Delete)
	return diff
}
