//go:build integration && linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/alireza-attari/sakhtar-wg/internal/firewall"
)

const (
	guardServerHelperEnv = "SAKHTAR_WG_GUARD_SERVER_HELPER"
	guardDUTHelperEnv    = "SAKHTAR_WG_GUARD_DUT_HELPER"

	guardServer  = "192.0.2.10"
	guardWANSrc  = "198.18.1.1"
	guardTunSrc  = "198.18.2.1"
	guardMark    = 24681
	guardTunnel  = "fctun-dut"
	guardRulePri = 31050
)

// TestMarkedEgressFailsClosed reproduces the 2026-10-15 failure: the DUT can
// reach the server both through the WAN (main table) and through a "tunnel"
// interface (the marked table). The server echoes the source address it sees,
// which tells the client which path a connection took.
func TestMarkedEgressFailsClosed(t *testing.T) {
	requirePrivilegedIntegration(t)
	suffix := strconv.Itoa(os.Getpid())
	dut, far := "sakhtar-wg-guard-dut-"+suffix, "sakhtar-wg-guard-far-"+suffix
	for _, ns := range []string{dut, far} {
		cleanupNamespace(ns)
		runCommand(t, "ip", "netns", "add", ns)
		ns := ns
		t.Cleanup(func() { cleanupNamespace(ns) })
	}
	t.Cleanup(func() {
		for _, name := range []string{"fcwan-dut", "fctun-dut"} {
			_ = exec.Command("ip", "link", "del", name).Run()
		}
	})
	for _, pair := range [][2]string{{"fcwan-dut", "fcwan-far"}, {"fctun-dut", "fctun-far"}} {
		runCommand(t, "ip", "link", "add", pair[0], "type", "veth", "peer", "name", pair[1])
		runCommand(t, "ip", "link", "set", pair[0], "netns", dut)
		runCommand(t, "ip", "link", "set", pair[1], "netns", far)
	}
	runCommand(t, "ip", "-n", dut, "addr", "add", guardWANSrc+"/30", "dev", "fcwan-dut")
	runCommand(t, "ip", "-n", dut, "addr", "add", guardTunSrc+"/30", "dev", "fctun-dut")
	runCommand(t, "ip", "-n", far, "addr", "add", "198.18.1.2/30", "dev", "fcwan-far")
	runCommand(t, "ip", "-n", far, "addr", "add", "198.18.2.2/30", "dev", "fctun-far")
	runCommand(t, "ip", "-n", far, "addr", "add", guardServer+"/32", "dev", "lo")
	for _, item := range [][2]string{{dut, "fcwan-dut"}, {dut, "fctun-dut"}, {far, "fcwan-far"}, {far, "fctun-far"}} {
		runCommand(t, "ip", "-n", item[0], "link", "set", "lo", "up")
		runCommand(t, "ip", "-n", item[0], "link", "set", item[1], "up")
	}
	// Replies through the tunnel arrive on an interface the main table would
	// not use for the server, which strict reverse-path filtering drops.
	for _, key := range []string{"all", "default", "fcwan-dut", "fctun-dut"} {
		runCommand(t, "ip", "netns", "exec", dut, "sysctl", "-q", "-w", "net.ipv4.conf."+key+".rp_filter=0")
	}
	runCommand(t, "ip", "-n", dut, "route", "add", guardServer+"/32", "via", "198.18.1.2", "dev", "fcwan-dut")
	runCommand(t, "ip", "-n", dut, "route", "add", "default", "via", "198.18.2.2", "dev", "fctun-dut", "table", strconv.Itoa(guardMark))

	server := exec.Command("ip", "netns", "exec", far, os.Args[0], "-test.run=^TestGuardServerHelper$")
	server.Env = append(os.Environ(), guardServerHelperEnv+"=1")
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
			t.Fatalf("guard server readiness = %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("guard server did not become ready")
	}

	client := exec.Command("ip", "netns", "exec", dut, os.Args[0], "-test.run=^TestGuardDUTHelper$", "-test.v")
	client.Env = append(os.Environ(), guardDUTHelperEnv+"=1")
	out, err := client.CombinedOutput()
	t.Logf("DUT helper:\n%s", out)
	if err != nil {
		t.Fatalf("guard DUT helper: %v", err)
	}
}

func TestGuardServerHelper(t *testing.T) {
	if os.Getenv(guardServerHelperEnv) != "1" {
		return
	}
	tcpLn, err := net.Listen("tcp", guardServer+":18080")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	udpConn, err := net.ListenPacket("udp", guardServer+":15353")
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
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			_, _ = conn.Write([]byte(host))
			_ = conn.Close()
		}
	}()
	go func() {
		buf := make([]byte, 512)
		for {
			_, addr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(addr.String())
			_, _ = udpConn.WriteTo([]byte(host), addr)
		}
	}()
	fmt.Println("READY")
	select {}
}

func TestGuardDUTHelper(t *testing.T) {
	if os.Getenv(guardDUTHelperEnv) != "1" {
		return
	}
	t.Logf("%s", runCommand(t, "iptables", "-V"))
	tun := Tunnel{Name: guardTunnel, Fwmark: guardMark, FwmarkMask: ^uint32(0), Table: guardMark, RulePriority: guardRulePri}
	cfg := &Config{Tunnels: []Tunnel{tun}}
	if err := reconcileRule(tun); err != nil {
		t.Fatal(err)
	}
	requireTCPSource(t, 0, guardWANSrc)
	requireTCPSource(t, guardMark, guardTunSrc)
	requireUDPSource(t, guardMark, guardTunSrc)

	// Without the guard, losing the rule is the leak: the marked connection
	// still succeeds, out the WAN.
	if err := deleteOwnedRule(tun); err != nil {
		t.Fatal(err)
	}
	requireTCPSource(t, guardMark, guardWANSrc)

	if err := reconcileRule(tun); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := egressGuardUp(cfg); err != nil {
			t.Fatalf("egressGuardUp #%d: %v", i+1, err)
		}
	}
	t.Logf("%s", runCommand(t, "iptables", "-S", firewall.OutputChain))
	assertIPTablesRuleCount(t, "filter", "OUTPUT", "-j "+firewall.OutputChain, 1)
	requireFirewallPlan(t, cfg, 0)
	requireTCPSource(t, guardMark, guardTunSrc)
	requireUDPSource(t, guardMark, guardTunSrc)
	requireTCPSource(t, 0, guardWANSrc)

	// The rule disappears (networkd flush): marked traffic is refused at once,
	// direct traffic is untouched.
	if err := deleteOwnedRule(tun); err != nil {
		t.Fatal(err)
	}
	requireTCPRefused(t, guardMark)
	requireUDPRefused(t, guardMark)
	requireTCPSource(t, 0, guardWANSrc)

	// The rule is back but the tunnel table lost its route: the lookup falls
	// through to main, and the guard still refuses it.
	if err := reconcileRule(tun); err != nil {
		t.Fatal(err)
	}
	runCommand(t, "ip", "route", "del", "default", "table", strconv.Itoa(guardMark))
	requireTCPRefused(t, guardMark)
	runCommand(t, "ip", "route", "add", "default", "via", "198.18.2.2", "dev", guardTunnel, "table", strconv.Itoa(guardMark))
	requireTCPSource(t, guardMark, guardTunSrc)

	// Loopback is exempt: the local table answers before any policy rule.
	local, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	go func() {
		for {
			conn, err := local.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	conn, err := dialMarked("tcp", local.Addr().String(), guardMark, time.Second)
	if err != nil {
		t.Fatalf("marked loopback dial: %v", err)
	}
	_ = conn.Close()

	// Drift detection: a removed guard rule or jump is planned and repaired.
	reject := fmt.Sprintf("! -o %s -m mark --mark %#x -m comment --comment %s -j REJECT --reject-with icmp-port-unreachable",
		guardTunnel, guardMark, firewall.OwnerComment)
	runCommand(t, "sh", "-c", "iptables -D "+firewall.OutputChain+" "+reject)
	requireFirewallPlan(t, cfg, 1)
	runCommand(t, "iptables", "-D", "OUTPUT", "-m", "comment", "--comment", firewall.OwnerComment+":filter-output", "-j", firewall.OutputChain)
	requireFirewallPlan(t, cfg, 2)
	if err := egressGuardUp(cfg); err != nil {
		t.Fatal(err)
	}
	requireFirewallPlan(t, cfg, 0)

	if err := egressGuardDown(cfg); err != nil {
		t.Fatal(err)
	}
	assertIPTablesRuleCount(t, "filter", "OUTPUT", "-j "+firewall.OutputChain, 0)
	if _, exists, err := listChain("filter", firewall.OutputChain); err != nil || exists {
		t.Fatalf("guard chain survived down: exists=%v, %v", exists, err)
	}
	if err := deleteOwnedRule(tun); err != nil {
		t.Fatal(err)
	}
}

func requireFirewallPlan(t *testing.T, cfg *Config, want int) {
	t.Helper()
	plan, err := buildFirewallPlan(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != want {
		t.Fatalf("firewall plan = %#v, want %d operations\n%s", plan, want, runCommand(t, "iptables", "-S"))
	}
}

func requireTCPSource(t *testing.T, mark int, want string) {
	t.Helper()
	conn, err := dialMarked("tcp", guardServer+":18080", mark, 2*time.Second)
	if err != nil {
		t.Fatalf("mark %d: dial: %v", mark, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != want {
		t.Fatalf("mark %d: server saw source %q (%v), want %q", mark, got, err, want)
	}
}

func requireUDPSource(t *testing.T, mark int, want string) {
	t.Helper()
	got, err := udpExchange(mark)
	if err != nil || got != want {
		t.Fatalf("mark %d: UDP server saw source %q (%v), want %q", mark, got, err, want)
	}
}

func udpExchange(mark int) (string, error) {
	conn, err := dialMarked("udp", guardServer+":15353", mark, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("query")); err != nil {
		return "", err
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	return string(buf[:n]), err
}

// A refusal, not a timeout, is what fails the probe and moves a connection to
// the next group member within its dial budget.
func requireTCPRefused(t *testing.T, mark int) {
	t.Helper()
	started := time.Now()
	conn, err := dialMarked("tcp", guardServer+":18080", mark, 3*time.Second)
	if err == nil {
		got, _ := io.ReadAll(conn)
		_ = conn.Close()
		t.Fatalf("mark %d: marked dial leaked; server saw source %q", mark, got)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) || time.Since(started) > time.Second {
		t.Fatalf("mark %d: dial error %v after %s, want a prompt ECONNREFUSED", mark, err, time.Since(started))
	}
}

// A UDP send that netfilter rejects in OUTPUT fails the write itself with
// EPERM, before any ICMP could arrive; either error is immediate.
func requireUDPRefused(t *testing.T, mark int) {
	t.Helper()
	started := time.Now()
	got, err := udpExchange(mark)
	if err == nil {
		t.Fatalf("mark %d: marked UDP leaked; server saw source %q", mark, got)
	}
	if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.ECONNREFUSED) || time.Since(started) > time.Second {
		t.Fatalf("mark %d: UDP error %v after %s, want a prompt EPERM or ECONNREFUSED", mark, err, time.Since(started))
	}
}
