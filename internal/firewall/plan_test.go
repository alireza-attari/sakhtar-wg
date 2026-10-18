package firewall

import (
	"strings"
	"testing"
)

func TestGatewayPolicyIsNarrowAndDeterministic(t *testing.T) {
	policy := Policy{
		ClientCIDRs: []string{"10.0.1.9/24"},
		Tunnels:     []TunnelPolicy{{Interface: "wg0", Destinations: []string{"203.0.113.7/24"}}},
	}
	first, err := Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Compile(policy)
	if err != nil {
		t.Fatal(err)
	}
	if first.RestoreInput() != second.RestoreInput() {
		t.Fatal("restore input is not deterministic")
	}
	input := first.RestoreInput()
	for _, required := range []string{
		"-s 10.0.1.0/24 -d 203.0.113.0/24 -o wg0",
		"-s 203.0.113.0/24 -d 10.0.1.0/24 -i wg0 -m conntrack --ctstate RELATED,ESTABLISHED",
		"--comment " + OwnerComment,
		"-F " + FilterChain,
		"-s 10.0.1.0/24 -m comment --comment " + OwnerComment + " -j DROP",
		"-d 10.0.1.0/24 -m comment --comment " + OwnerComment + " -j DROP",
		"-d 203.0.113.0/24 -o wg0 -m comment --comment " + OwnerComment + " -j DROP",
	} {
		if !strings.Contains(input, required) {
			t.Fatalf("restore input lacks %q:\n%s", required, input)
		}
	}
	for _, line := range strings.Split(input, "\n") {
		if (strings.Contains(line, "-j ACCEPT") || strings.Contains(line, "-j MASQUERADE")) &&
			(!strings.Contains(line, "-s 10.0.1.0/24") && !strings.Contains(line, "-d 10.0.1.0/24") ||
				!strings.Contains(line, "203.0.113.0/24")) {
			t.Fatalf("policy contains a broad accept/NAT rule %q:\n%s", line, input)
		}
	}
}

func TestGatewayPolicyRejectsOverlappingEgress(t *testing.T) {
	_, err := Compile(Policy{ClientCIDRs: []string{"10.0.1.0/24"}, Tunnels: []TunnelPolicy{
		{Interface: "wg0", Destinations: []string{"203.0.113.0/24"}},
		{Interface: "wg1", Destinations: []string{"203.0.113.128/25"}},
	}})
	if err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("error = %v, want overlap rejection", err)
	}
}

func TestGatewayPolicyReloadDropsStaleRules(t *testing.T) {
	old, err := Compile(Policy{ClientCIDRs: []string{"10.0.1.0/24"}, Tunnels: []TunnelPolicy{{Interface: "wg0", Destinations: []string{"192.0.2.0/24", "203.0.113.0/24"}}}})
	if err != nil {
		t.Fatal(err)
	}
	next, err := Compile(Policy{ClientCIDRs: []string{"10.0.1.0/24"}, Tunnels: []TunnelPolicy{{Interface: "wg0", Destinations: []string{"203.0.113.0/24"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(old.RestoreInput(), "192.0.2.0/24") {
		t.Fatal("old fixture lacks stale rule")
	}
	if strings.Contains(next.RestoreInput(), "192.0.2.0/24") {
		t.Fatal("replacement retained stale rule")
	}
	if !strings.Contains(next.RestoreInput(), "-F "+FilterChain) {
		t.Fatal("replacement does not flush the owned chain")
	}
}

func TestOwnershipRejectsForeignChainContent(t *testing.T) {
	if RuleIsOwned("-A SAKHTAR_WG_FORWARD -s 10.0.0.0/8 -j ACCEPT") {
		t.Fatal("foreign rule classified as owned")
	}
	if !RuleIsOwned("-A SAKHTAR_WG_FORWARD -m comment --comment sakhtar-wg:owned:v1 -j ACCEPT") {
		t.Fatal("owned rule not recognized")
	}
}

func TestEgressGuardRejectsMarkedTrafficOffItsTunnel(t *testing.T) {
	guards := []MarkGuard{
		{Interface: "wg18", Mark: 18, Mask: ^uint32(0)},
		{Interface: "wg0", Mark: 0x200, Mask: 0xff00},
	}
	first, err := CompileEgressGuard(guards)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileEgressGuard([]MarkGuard{guards[1], guards[0]})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(first.Rules, "\n") != strings.Join(second.Rules, "\n") {
		t.Fatal("guard rules depend on config order")
	}
	if first.Table != "filter" || first.Hook != "OUTPUT" || first.Name != OutputChain {
		t.Fatalf("guard chain = %s/%s hooked at %s", first.Table, first.Name, first.Hook)
	}
	owner := "-m comment --comment " + OwnerComment
	want := []string{
		"-o lo " + owner + " -j RETURN",
		"! -o wg0 -m mark --mark 0x200/0xff00 " + owner + " -j REJECT --reject-with icmp-port-unreachable",
		"! -o wg18 -m mark --mark 0x12 " + owner + " -j REJECT --reject-with icmp-port-unreachable",
	}
	if strings.Join(first.Rules, "\n") != strings.Join(want, "\n") {
		t.Fatalf("guard rules =\n%s\nwant\n%s", strings.Join(first.Rules, "\n"), strings.Join(want, "\n"))
	}
	for _, rule := range first.Rules {
		if !RuleIsOwned(rule) {
			t.Fatalf("guard rule %q lacks ownership proof", rule)
		}
	}
}

func TestEgressGuardRefusesUnsafeInput(t *testing.T) {
	for name, guards := range map[string][]MarkGuard{
		"bad interface":  {{Interface: "wg 0", Mark: 1, Mask: ^uint32(0)}},
		"duplicate":      {{Interface: "wg0", Mark: 1, Mask: ^uint32(0)}, {Interface: "wg0", Mark: 2, Mask: ^uint32(0)}},
		"zero mark":      {{Interface: "wg0", Mark: 0, Mask: ^uint32(0)}},
		"mark past mask": {{Interface: "wg0", Mark: 0x101, Mask: 0xff00}},
	} {
		if _, err := CompileEgressGuard(guards); err == nil {
			t.Errorf("%s: guard compiled", name)
		}
	}
	empty, err := CompileEgressGuard(nil)
	if err != nil || len(empty.Rules) != 0 {
		t.Fatalf("no tunnels = %v, %v; want an empty chain", empty.Rules, err)
	}
}
