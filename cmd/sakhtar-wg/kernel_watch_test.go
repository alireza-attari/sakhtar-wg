package main

import (
	"reflect"
	"testing"

	kernelstate "github.com/alireza-attari/sakhtar-wg/internal/kernel"
)

func TestKernelChangesListsOperationsNotDrift(t *testing.T) {
	plan := kernelstate.Plan{
		Operations: []kernelstate.Operation{
			{Action: kernelstate.Add, Kind: kernelstate.Rule, ID: "priority=31002"},
			{Action: kernelstate.Delete, Kind: kernelstate.Route, ID: "wg0/table=254/10.0.0.0/8"},
		},
		Drift: []kernelstate.Drift{{Kind: kernelstate.Address, ID: "wg0/192.0.2.1/32", Reason: "unowned"}},
	}
	got := kernelChanges(plan)
	want := []string{"add rule priority=31002", "delete route wg0/table=254/10.0.0.0/8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("kernelChanges() = %q, want %q", got, want)
	}
	if got := kernelChanges(kernelstate.Plan{}); len(got) != 0 {
		t.Fatalf("kernelChanges(empty) = %q, want none", got)
	}
}

func TestKernelWatchReportsOnlyStateTransitions(t *testing.T) {
	missing := []string{"add rule priority=31002"}
	steps := []struct {
		name    string
		changes []string
		want    bool
	}{
		{"healthy start is not news", nil, false},
		{"rule disappears", missing, true},
		{"still missing stays quiet", missing, false},
		{"a different loss is news", []string{"add rule priority=31118"}, true},
		{"recovery is news", nil, true},
		{"healthy again stays quiet", nil, false},
	}
	var watch kernelWatch
	for _, step := range steps {
		if got := watch.observe(step.changes); got != step.want {
			t.Fatalf("%s: observe() = %v, want %v", step.name, got, step.want)
		}
	}
}
