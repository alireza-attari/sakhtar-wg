//go:build integration && linux

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
)

const (
	kernelHelperEnv   = "SAKHTAR_WG_KERNEL_HELPER"
	endpointHelperEnv = "SAKHTAR_WG_ENDPOINT_HELPER"
	egressHelperEnv   = "SAKHTAR_WG_EGRESS_HELPER"
	gatewayHelperEnv  = "SAKHTAR_WG_GATEWAY_HELPER"
)

func dialMarked(network, addr string, mark int, timeout time.Duration) (net.Conn, error) {
	return dialMarkedContext(context.Background(), network, addr, mark, timeout)
}

func requirePrivilegedIntegration(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("integration tests require root; run `sudo -E go test -tags=integration -count=1 ./...`")
	}
	for _, tool := range []string{"ip", "iptables"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required: %v", tool, err)
		}
	}
}

func runCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func cleanupNamespace(name string) {
	_ = exec.Command("ip", "netns", "delete", name).Run()
}

func TestKernelNamespaceLifecycle(t *testing.T) {
	requirePrivilegedIntegration(t)
	ns := "sakhtar-wg-kernel-" + strconv.Itoa(os.Getpid())
	cleanupNamespace(ns)
	runCommand(t, "ip", "netns", "add", ns)
	t.Cleanup(func() { cleanupNamespace(ns) })

	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestKernelNamespaceHelper$")
	cmd.Env = append(os.Environ(), kernelHelperEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kernel helper: %v\n%s", err, out)
	}
}

func TestKernelNamespaceHelper(t *testing.T) {
	if os.Getenv(kernelHelperEnv) != "1" {
		return
	}
	wg, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	defer wg.Close()

	tun := Tunnel{
		Name: "wgit0", PrivateKey: testKey(1), Address: "10.66.66.3/32", MTU: 1280,
		Fwmark: 12345, FwmarkMask: ^uint32(0), Table: 12345, RulePriority: 31000,
		Routes: []string{"203.0.113.0/24"},
		Peer:   Peer{PublicKey: testKey(2), Endpoint: "192.0.2.1:51820", AllowedIPs: []string{"0.0.0.0/0"}, Keepalive: 25},
	}
	for i := range 2 {
		if err := tunnelUp(wg, tun); err != nil {
			t.Fatalf("tunnelUp #%d: %v", i+1, err)
		}
	}
	link, err := netlink.LinkByName(tun.Name)
	if err != nil || link.Type() != "wireguard" {
		t.Fatalf("link = %v, %v", link, err)
	}
	staleDefault := netlink.Route{
		LinkIndex: link.Attrs().Index, Table: 22345,
		Dst:      &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Protocol: netlink.RouteProtocol(186),
	}
	if err := netlink.RouteAdd(&staleDefault); err != nil {
		t.Fatal(err)
	}
	if err := tunnelUp(wg, tun); err != nil {
		t.Fatalf("repair stale owned default: %v", err)
	}
	staleRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: staleDefault.Table}, netlink.RT_FILTER_TABLE)
	if err != nil || len(staleRoutes) != 0 {
		t.Fatalf("stale owned default survived repair: %v, %v", staleRoutes, err)
	}
	if got, err := netlink.AddrList(link, netlink.FAMILY_V4); err != nil || len(got) != 1 || got[0].IPNet.String() != tun.Address {
		t.Fatalf("addresses = %v, %v", got, err)
	}

	mainRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{LinkIndex: link.Attrs().Index, Table: mainTable}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil || countRoute(mainRoutes, "203.0.113.0/24") != 1 {
		t.Fatalf("main routes = %v, %v", mainRoutes, err)
	}
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil || countRule(rules, tun) != 1 {
		t.Fatalf("rules = %v, %v", rules, err)
	}

	// Parsing all desired routes happens before mutation. A bad candidate must
	// leave the last-good route intact.
	bad := tun
	bad.Routes = []string{"not-a-cidr"}
	if err := reconcileRoutes(link, bad); err == nil {
		t.Fatal("invalid candidate unexpectedly reconciled")
	}
	mainRoutes, err = netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{LinkIndex: link.Attrs().Index, Table: mainTable}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil || countRoute(mainRoutes, "203.0.113.0/24") != 1 {
		t.Fatalf("last-good route not preserved: %v, %v", mainRoutes, err)
	}

	// A foreign route on an owned link is never treated as part of the owned
	// set. Withdrawing every configured destination preserves it byte-for-byte.
	_, foreignPrefix, _ := net.ParseCIDR("198.51.100.0/24")
	foreignRoute := netlink.Route{
		LinkIndex: link.Attrs().Index, Table: mainTable, Dst: foreignPrefix,
		Protocol: netlink.RouteProtocol(99), Priority: 77,
	}
	if err := netlink.RouteAdd(&foreignRoute); err != nil {
		t.Fatal(err)
	}
	withoutRoutes := tun
	withoutRoutes.Routes = nil
	if err := reconcileRoutes(link, withoutRoutes); err != nil {
		t.Fatal(err)
	}
	mainRoutes, err = netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{LinkIndex: link.Attrs().Index, Table: mainTable}, netlink.RT_FILTER_OIF|netlink.RT_FILTER_TABLE)
	if err != nil || countRoute(mainRoutes, "203.0.113.0/24") != 0 || countRoute(mainRoutes, "198.51.100.0/24") != 1 {
		t.Fatalf("foreign route preservation = %v, %v", mainRoutes, err)
	}
	if err := reconcileRoutes(link, tun); err != nil {
		t.Fatal(err)
	}
	if err := netlink.RouteDel(&foreignRoute); err != nil {
		t.Fatal(err)
	}

	// A same-name foreign link is neither adopted nor removed by normal up/down.
	foreignAttrs := netlink.NewLinkAttrs()
	foreignAttrs.Name = "wgitforeign"
	foreignLink := &netlink.Dummy{LinkAttrs: foreignAttrs}
	if err := netlink.LinkAdd(foreignLink); err != nil {
		t.Fatal(err)
	}
	foreignTunnel := tun
	foreignTunnel.Name = foreignAttrs.Name
	foreignTunnel.Fwmark, foreignTunnel.Table, foreignTunnel.RulePriority = 12346, 12346, 31001
	if err := tunnelUp(wg, foreignTunnel); err == nil {
		t.Fatal("foreign same-name link was adopted")
	}
	if err := tunnelDown(foreignTunnel); err == nil {
		t.Fatal("foreign same-name link cleanup did not report ambiguous ownership")
	}
	if _, err := netlink.LinkByName(foreignAttrs.Name); err != nil {
		t.Fatalf("foreign link was removed: %v", err)
	}
	if err := netlink.LinkDel(foreignLink); err != nil {
		t.Fatal(err)
	}

	// Explicit adoption requires an already matching, otherwise-empty WG link.
	adopt := tun
	adopt.Name = "wgitadopt"
	adopt.Address = "10.77.77.3/32"
	adopt.Fwmark, adopt.Table, adopt.RulePriority = 12347, 12347, 31002
	adopt.Routes = nil
	adopt.AdoptExisting = true
	adoptAttrs := netlink.NewLinkAttrs()
	adoptAttrs.Name = adopt.Name
	adoptLink := &netlink.GenericLink{LinkAttrs: adoptAttrs, LinkType: "wireguard"}
	if err := netlink.LinkAdd(adoptLink); err != nil {
		t.Fatal(err)
	}
	preservedAdopted, err := netlink.LinkByName(adopt.Name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetMTU(preservedAdopted, adopt.MTU); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(preservedAdopted); err != nil {
		t.Fatal(err)
	}
	adoptConfig, err := wgConfig(adopt)
	if err != nil {
		t.Fatal(err)
	}
	if err := wg.ConfigureDevice(adopt.Name, adoptConfig); err != nil {
		t.Fatal(err)
	}
	if err := tunnelUp(wg, adopt); err != nil {
		t.Fatalf("explicit adoption: %v", err)
	}
	if err := tunnelDown(adopt); err != nil {
		t.Fatalf("adopted cleanup: %v", err)
	}
	preservedAdopted, err = netlink.LinkByName(adopt.Name)
	if err != nil {
		t.Fatalf("adopted link was deleted: %v", err)
	}
	if preservedAdopted.Attrs().Alias != "" {
		t.Fatalf("adoption marker survived down: %q", preservedAdopted.Attrs().Alias)
	}
	if err := netlink.LinkDel(preservedAdopted); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Tunnels: []Tunnel{tun}, Gateway: Gateway{Enabled: true, ClientCIDRs: []string{"10.0.1.0/24"}}}
	for i := range 2 {
		if err := gatewayUp(cfg); err != nil {
			t.Fatalf("gatewayUp #%d: %v", i+1, err)
		}
	}
	assertIPTablesRuleCount(t, "nat", "POSTROUTING", "-j SAKHTAR_WG_POSTROUTING", 1)
	assertIPTablesRuleCount(t, "nat", "SAKHTAR_WG_POSTROUTING", "-s 10.0.1.0/24 -d 203.0.113.0/24 -o wgit0", 1)
	assertIPTablesRuleCount(t, "mangle", "SAKHTAR_WG_FORWARD", "-s 10.0.1.0/24 -d 203.0.113.0/24 -o wgit0", 1)
	assertIPTablesRuleCount(t, "filter", "SAKHTAR_WG_FORWARD", "-s 10.0.1.0/24 -d 203.0.113.0/24 -o wgit0", 1)
	assertIPTablesRuleCount(t, "filter", "SAKHTAR_WG_FORWARD", "-s 10.0.1.0/24 -m comment", 1)
	assertIPTablesRuleCount(t, "filter", "SAKHTAR_WG_FORWARD", "-d 10.0.1.0/24 -m comment", 1)
	kernelPlan, err := buildKernelPlan(wg, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(kernelPlan.Operations) != 0 || len(kernelPlan.Drift) != 0 {
		t.Fatalf("idempotent kernel plan = %#v", kernelPlan)
	}
	firewallPlan, err := buildFirewallPlan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(firewallPlan) != 0 {
		t.Fatalf("idempotent firewall plan = %#v", firewallPlan)
	}

	if err := gatewayDown(cfg); err != nil {
		t.Fatal(err)
	}
	assertIPTablesRuleCount(t, "nat", "POSTROUTING", "-j SAKHTAR_WG_POSTROUTING", 0)
	assertIPTablesRuleCount(t, "filter", "FORWARD", "-j SAKHTAR_WG_FORWARD", 0)
	if err := tunnelDown(tun); err != nil {
		t.Fatal(err)
	}
	if _, err := netlink.LinkByName(tun.Name); err == nil {
		t.Fatal("WireGuard link survived cleanup")
	}
	rules, err = netlink.RuleList(netlink.FAMILY_V4)
	if err != nil || countRule(rules, tun) != 0 {
		t.Fatalf("rule survived cleanup: %v, %v", rules, err)
	}
}

func countRoute(routes []netlink.Route, cidr string) int {
	n := 0
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == cidr {
			n++
		}
	}
	return n
}

func countRule(rules []netlink.Rule, tunnel Tunnel) int {
	n := 0
	for _, rule := range rules {
		if ruleEqual(rule, *markRule(tunnel)) {
			n++
		}
	}
	return n
}

func assertIPTablesRuleCount(t *testing.T, table, chain, rule string, want int) {
	t.Helper()
	out := runCommand(t, "iptables", "-t", table, "-S", chain)
	got := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-A "+chain+" ") && strings.Contains(line, rule) {
			got++
		}
	}
	if got != want {
		t.Fatalf("iptables %s/%s count for %q = %d, want %d\n%s", table, chain, rule, got, want, out)
	}
}

func TestFirewallGatewayPolicyForwarding(t *testing.T) {
	requirePrivilegedIntegration(t)
	suffix := strconv.Itoa(os.Getpid())
	clientNS, dutNS, egressNS := "sakhtar-wg-client-"+suffix, "sakhtar-wg-gateway-"+suffix, "sakhtar-wg-egress-"+suffix
	for _, namespace := range []string{clientNS, dutNS, egressNS} {
		cleanupNamespace(namespace)
		runCommand(t, "ip", "netns", "add", namespace)
		namespace := namespace
		t.Cleanup(func() { cleanupNamespace(namespace) })
	}

	runCommand(t, "ip", "link", "add", "client0", "type", "veth", "peer", "name", "dutclient0")
	runCommand(t, "ip", "link", "add", "dutegress0", "type", "veth", "peer", "name", "egress0")
	runCommand(t, "ip", "link", "set", "client0", "netns", clientNS)
	runCommand(t, "ip", "link", "set", "dutclient0", "netns", dutNS)
	runCommand(t, "ip", "link", "set", "dutegress0", "netns", dutNS)
	runCommand(t, "ip", "link", "set", "egress0", "netns", egressNS)

	for _, namespace := range []string{clientNS, dutNS, egressNS} {
		runCommand(t, "ip", "-n", namespace, "link", "set", "lo", "up")
	}
	runCommand(t, "ip", "-n", clientNS, "addr", "add", "10.0.1.2/24", "dev", "client0")
	runCommand(t, "ip", "-n", clientNS, "addr", "add", "10.0.2.2/24", "dev", "client0")
	runCommand(t, "ip", "-n", dutNS, "addr", "add", "10.0.1.1/24", "dev", "dutclient0")
	runCommand(t, "ip", "-n", dutNS, "addr", "add", "10.0.2.1/24", "dev", "dutclient0")
	runCommand(t, "ip", "-n", dutNS, "addr", "add", "198.18.0.1/24", "dev", "dutegress0")
	runCommand(t, "ip", "-n", dutNS, "addr", "add", "203.0.113.1/24", "dev", "dutegress0")
	runCommand(t, "ip", "-n", egressNS, "addr", "add", "198.18.0.2/24", "dev", "egress0")
	runCommand(t, "ip", "-n", egressNS, "addr", "add", "203.0.113.2/24", "dev", "egress0")
	for _, item := range [][2]string{{clientNS, "client0"}, {dutNS, "dutclient0"}, {dutNS, "dutegress0"}, {egressNS, "egress0"}} {
		runCommand(t, "ip", "-n", item[0], "link", "set", item[1], "up")
	}
	runCommand(t, "ip", "-n", clientNS, "route", "add", "default", "via", "10.0.1.1")
	runCommand(t, "ip", "-n", egressNS, "route", "add", "10.0.1.0/24", "via", "198.18.0.1")
	runCommand(t, "ip", "-n", egressNS, "route", "add", "10.0.2.0/24", "via", "198.18.0.1")

	helper := exec.Command("ip", "netns", "exec", dutNS, os.Args[0], "-test.run=^TestGatewayPolicyNamespaceHelper$")
	helper.Env = append(os.Environ(), gatewayHelperEnv+"=1")
	if output, err := helper.CombinedOutput(); err != nil {
		t.Fatalf("gateway policy helper: %v\n%s", err, output)
	}

	runCommand(t, "ip", "netns", "exec", clientNS, "ping", "-c", "1", "-W", "1", "198.18.0.2")
	assertCommandFails(t, "ip", "netns", "exec", clientNS, "ping", "-c", "1", "-W", "1", "203.0.113.2")
	assertCommandFails(t, "ip", "netns", "exec", clientNS, "ping", "-I", "10.0.2.2", "-c", "1", "-W", "1", "198.18.0.2")
}

func TestGatewayPolicyNamespaceHelper(t *testing.T) {
	if os.Getenv(gatewayHelperEnv) != "1" {
		return
	}
	cfg := &Config{
		Tunnels: []Tunnel{{Name: "dutegress0", Routes: []string{"198.18.0.0/24"}}},
		Gateway: Gateway{Enabled: true, ClientCIDRs: []string{"10.0.1.0/24"}},
	}
	if err := gatewayUp(cfg); err != nil {
		t.Fatal(err)
	}
}

func assertCommandFails(t *testing.T, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("%s %s unexpectedly succeeded\n%s", name, strings.Join(args, " "), output)
	}
}

func TestMarkedTCPAndDNSEgress(t *testing.T) {
	requirePrivilegedIntegration(t)
	suffix := strconv.Itoa(os.Getpid())
	dut, peer := "sakhtar-wg-dut-"+suffix, "sakhtar-wg-peer-"+suffix
	for _, ns := range []string{dut, peer} {
		cleanupNamespace(ns)
		runCommand(t, "ip", "netns", "add", ns)
		ns := ns
		t.Cleanup(func() { cleanupNamespace(ns) })
	}

	runCommand(t, "ip", "link", "add", "veth-dut", "type", "veth", "peer", "name", "veth-peer")
	runCommand(t, "ip", "link", "set", "veth-dut", "netns", dut)
	runCommand(t, "ip", "link", "set", "veth-peer", "netns", peer)
	runCommand(t, "ip", "-n", dut, "addr", "add", "198.18.0.1/30", "dev", "veth-dut")
	runCommand(t, "ip", "-n", peer, "addr", "add", "198.18.0.2/30", "dev", "veth-peer")
	for _, item := range [][2]string{{dut, "veth-dut"}, {peer, "veth-peer"}} {
		runCommand(t, "ip", "-n", item[0], "link", "set", "lo", "up")
		runCommand(t, "ip", "-n", item[0], "link", "set", item[1], "up")
	}
	// GitHub-hosted runners enable reverse-path filtering by default. This test
	// deliberately removes the main-table route and keeps it only in a marked
	// policy table, so rp_filter would otherwise drop the valid reply before
	// the socket can receive it.
	runCommand(t, "ip", "netns", "exec", dut, "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0")
	runCommand(t, "ip", "netns", "exec", dut, "sysctl", "-q", "-w", "net.ipv4.conf.veth-dut.rp_filter=0")
	// Remove the main-table connected route. Only a socket carrying mark 24680
	// can reach the peer through the dedicated policy table.
	runCommand(t, "ip", "-n", dut, "route", "del", "198.18.0.0/30", "dev", "veth-dut")
	runCommand(t, "ip", "-n", dut, "route", "add", "198.18.0.0/30", "dev", "veth-dut", "src", "198.18.0.1", "table", "24680")
	runCommand(t, "ip", "-n", dut, "rule", "add", "fwmark", "24680", "lookup", "24680")

	server := exec.Command("ip", "netns", "exec", peer, os.Args[0], "-test.run=^TestNamespaceEndpointHelper$")
	server.Env = append(os.Environ(), endpointHelperEnv+"=1")
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	server.Stderr = server.Stdout
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_, _ = server.Process.Wait()
	})
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			ready <- scanner.Text()
			return
		}
		ready <- ""
	}()
	select {
	case line := <-ready:
		if line != "READY" {
			t.Fatalf("endpoint helper readiness = %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("endpoint helper did not become ready")
	}

	client := exec.Command("ip", "netns", "exec", dut, os.Args[0], "-test.run=^TestNamespaceEgressHelper$")
	client.Env = append(os.Environ(), egressHelperEnv+"=1")
	if out, err := client.CombinedOutput(); err != nil {
		t.Fatalf("marked egress helper: %v\n%s", err, out)
	}
}

func TestNamespaceEndpointHelper(t *testing.T) {
	if os.Getenv(endpointHelperEnv) != "1" {
		return
	}
	tcpLn, err := net.Listen("tcp", "198.18.0.2:18080")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	udpConn, err := net.ListenPacket("udp", "198.18.0.2:15353")
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	go func() {
		for {
			conn, err := tcpLn.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("tcp-ok"))
			_ = conn.Close()
		}
	}()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			if string(buf[:n]) == "dns-query" {
				_, _ = udpConn.WriteTo([]byte("dns-ok"), addr)
			}
		}
	}()
	fmt.Println("READY")
	select {}
}

func TestNamespaceEgressHelper(t *testing.T) {
	if os.Getenv(egressHelperEnv) != "1" {
		return
	}
	if conn, err := dialMarked("tcp", "198.18.0.2:18080", 0, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("unmarked TCP unexpectedly reached policy-only endpoint")
	}
	conn, err := dialMarked("tcp", "198.18.0.2:18080", 24680, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil || string(data) != "tcp-ok" {
		t.Fatalf("TCP response = %q, %v", data, err)
	}

	udp, err := dialMarked("udp", "198.18.0.2:15353", 24680, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := udp.Write([]byte("dns-query")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := udp.Read(buf)
	if err != nil || string(buf[:n]) != "dns-ok" {
		t.Fatalf("DNS response = %q, %v", buf[:n], err)
	}
}
