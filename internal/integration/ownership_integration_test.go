//go:build integration && linux

package integration

import (
	"reflect"
	"strings"
	"testing"

	"github.com/alireza-attari/sakhtar-wg/internal/firewall"
	"github.com/alireza-attari/sakhtar-wg/internal/kernel"
)

func TestKernelForeignStatePreserved(t *testing.T) {
	current := []kernel.Object{
		{Kind: kernel.Route, ID: "table=254/link=wg0/dst=192.0.2.0/24", Value: "protocol=186", Owned: true, Evidence: "protocol + alias"},
		{Kind: kernel.Route, ID: "table=254/link=wg0/dst=198.51.100.0/24", Value: "protocol=99", Owned: false},
	}
	desired := []kernel.Object{{Kind: kernel.Route, ID: "table=254/link=wg0/dst=203.0.113.0/24", Value: "protocol=186", Owned: true, Evidence: "protocol + alias"}}
	plan, err := kernel.PlanDiff(current, desired)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range plan.Operations {
		if strings.Contains(operation.ID, "198.51.100.0/24") {
			t.Fatalf("foreign fixture was mutated: %#v", operation)
		}
	}
}

func TestFirewallAtomicReplacementDropsStalePolicy(t *testing.T) {
	policy := firewall.Policy{ClientCIDRs: []string{"10.0.1.0/24"}, Tunnels: []firewall.TunnelPolicy{{Interface: "wg0", Destinations: []string{"203.0.113.0/24"}}}}
	ruleset, err := firewall.Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	input := ruleset.RestoreInput()
	if !strings.Contains(input, "-F "+firewall.FilterChain) || !strings.Contains(input, "COMMIT") {
		t.Fatalf("ruleset is not a replacement transaction:\n%s", input)
	}
	if strings.Contains(input, "192.0.2.0/24") {
		t.Fatal("stale destination survived replacement")
	}
}

func TestCrashRepairPlanDeterministic(t *testing.T) {
	current := []kernel.Object{{Kind: kernel.Rule, ID: "priority=31000", Value: "old", Owned: true, Evidence: "reserved priority + protocol"}}
	desired := []kernel.Object{{Kind: kernel.Rule, ID: "priority=31000", Value: "desired", Owned: true, Evidence: "reserved priority + protocol"}}
	first, err := kernel.PlanDiff(current, desired)
	if err != nil {
		t.Fatal(err)
	}
	second, err := kernel.PlanDiff(current, desired)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) || len(first.Operations) != 1 || first.Operations[0].Action != kernel.Update {
		t.Fatalf("repair plans differ: %#v %#v", first, second)
	}
}
