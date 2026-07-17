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
