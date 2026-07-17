package kernel

import (
	"reflect"
	"strings"
	"testing"
)

func TestPlanDiffDeterministicAndIdempotent(t *testing.T) {
	current := []Object{
		{Kind: Route, ID: "254/2/192.0.2.0/24", Value: "proto=186", Owned: true, Evidence: "route protocol 186 + owned link"},
		{Kind: Route, ID: "254/2/198.51.100.0/24", Value: "proto=99", Owned: false},
	}
	desired := []Object{
		{Kind: Route, ID: "254/2/203.0.113.0/24", Value: "proto=186", Owned: true, Evidence: "route protocol 186 + owned link"},
	}
	got, err := PlanDiff(current, desired)
	if err != nil {
		t.Fatal(err)
	}
	want := Plan{Operations: []Operation{
		{Action: Delete, Kind: Route, ID: "254/2/192.0.2.0/24", Before: "proto=186", Evidence: "route protocol 186 + owned link"},
		{Action: Add, Kind: Route, ID: "254/2/203.0.113.0/24", After: "proto=186", Evidence: "route protocol 186 + owned link"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("plan = %#v, want %#v", got, want)
	}
	clean, err := PlanDiff(desired, desired)
	if err != nil || len(clean.Operations) != 0 || len(clean.Drift) != 0 {
		t.Fatalf("idempotent plan = %#v, %v", clean, err)
	}
}

func TestOwnershipForeignStatePreserved(t *testing.T) {
	foreign := Object{Kind: Route, ID: "254/4/203.0.113.0/24", Value: "proto=boot", Owned: false}
	plan, err := PlanDiff([]Object{foreign}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Operations) != 0 {
		t.Fatalf("foreign object scheduled for mutation: %#v", plan)
	}

	desired := foreign
	desired.Value = "proto=186"
	desired.Owned = true
	desired.Evidence = "reserved route protocol"
	plan, err = PlanDiff([]Object{foreign}, []Object{desired})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HasBlockingDrift() || len(plan.Operations) != 0 {
		t.Fatalf("foreign collision was not blocked: %#v", plan)
	}
}

func TestAdoptionMustBeExplicitAndExact(t *testing.T) {
	foreign := Object{Kind: Link, ID: "wg0", Value: "type=wireguard,key=abc"}
	desired := Object{Kind: Link, ID: "wg0", Value: foreign.Value, Owned: true, Evidence: "sakhtar-wg alias"}
	plan, err := PlanDiff([]Object{foreign}, []Object{desired})
	if err != nil || !plan.HasBlockingDrift() {
		t.Fatalf("implicit adoption = %#v, %v", plan, err)
	}
	desired.AllowAdopt = true
	plan, err = PlanDiff([]Object{foreign}, []Object{desired})
	if err != nil || plan.HasBlockingDrift() || len(plan.Operations) != 1 || plan.Operations[0].Action != Update {
		t.Fatalf("explicit adoption = %#v, %v", plan, err)
	}
}

func TestRulePriorityAndMarkAllocation(t *testing.T) {
	valid := []Allocation{
		{Name: "wg0", Mark: 51, Mask: FullMarkMask, Table: 51, Priority: RulePriorityMin},
		{Name: "wg1", Mark: 52, Mask: FullMarkMask, Table: 52, Priority: RulePriorityMin + 1},
	}
	if err := ValidateAllocations(valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		in   []Allocation
		want string
	}{
		{"reserved table", []Allocation{{Name: "wg0", Mark: 1, Mask: FullMarkMask, Table: 254, Priority: RulePriorityMin}}, "reserved"},
		{"bad priority", []Allocation{{Name: "wg0", Mark: 1, Mask: FullMarkMask, Table: 1, Priority: 100}}, "outside reserved"},
		{"priority collision", append(valid, Allocation{Name: "wg2", Mark: 53, Mask: FullMarkMask, Table: 53, Priority: RulePriorityMin}), "priority"},
		{"masked alias", []Allocation{{Name: "wg0", Mark: 0x10, Mask: 0xf0, Table: 10, Priority: RulePriorityMin}, {Name: "wg1", Mark: 0x11, Mask: 0xf1, Table: 11, Priority: RulePriorityMin + 1}}, "overlap"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAllocations(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}
