package main

import internalrouting "github.com/alireza-attari/sakhtar-wg/internal/routing"

type routeDiff struct {
	Add    []string
	Delete []string
}

// planRouteDiff computes kernel mutations without performing them. Inputs are
// canonical CIDR strings; output is sorted to keep tests, logs, and dry-runs
// deterministic.
func planRouteDiff(current, desired []string) routeDiff {
	diff := internalrouting.PlanDiff(current, desired)
	return routeDiff{Add: diff.Add, Delete: diff.Delete}
}
