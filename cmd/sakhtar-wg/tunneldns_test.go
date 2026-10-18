package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsBehavior int

const (
	dnsAnswer dnsBehavior = iota
	dnsSilent
	dnsNXDomain
	dnsPoisoned
)

var (
	testDNSAnswer     = [4]byte{93, 184, 216, 34}
	testPoisonedReply = [4]byte{10, 10, 34, 36}
)

func dnsReply(t *testing.T, query []byte, behavior dnsBehavior) []byte {
	t.Helper()
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		t.Errorf("parse query: %v", err)
		return nil
	}
	question, err := parser.Question()
	if err != nil {
		t.Errorf("parse question: %v", err)
		return nil
	}
	rcode := dnsmessage.RCodeSuccess
	if behavior == dnsNXDomain {
		rcode = dnsmessage.RCodeNameError
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true, RCode: rcode})
	_ = builder.StartQuestions()
	_ = builder.Question(question)
	if rcode == dnsmessage.RCodeSuccess && question.Type == dnsmessage.TypeA {
		_ = builder.StartAnswers()
		answer := testDNSAnswer
		if behavior == dnsPoisoned {
			answer = testPoisonedReply
		}
		_ = builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: answer})
	}
	reply, err := builder.Finish()
	if err != nil {
		t.Errorf("build reply: %v", err)
	}
	return reply
}

// testDNSServer listens on loopback over UDP and TCP, each with its own
// behavior, and counts the queries that reach each transport.
type testDNSServer struct {
	udp     net.PacketConn
	tcp     net.Listener
	mu      sync.Mutex
	queries map[string]int
}

func startTestDNSServer(t *testing.T, udpBehavior, tcpBehavior dnsBehavior) *testDNSServer {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &testDNSServer{udp: udp, tcp: tcp, queries: map[string]int{}}
	t.Cleanup(func() { _ = udp.Close(); _ = tcp.Close() })
	go func() {
		buffer := make([]byte, 512)
		for {
			n, from, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			server.count("udp")
			if udpBehavior != dnsSilent {
				_, _ = udp.WriteTo(dnsReply(t, buffer[:n], udpBehavior), from)
			}
		}
	}()
	go func() {
		for {
			conn, err := tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				for {
					var length uint16
					if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
						return
					}
					query := make([]byte, length)
					if _, err := io.ReadFull(conn, query); err != nil {
						return
					}
					server.count("tcp")
					if tcpBehavior == dnsSilent {
						continue
					}
					reply := dnsReply(t, query, tcpBehavior)
					_ = binary.Write(conn, binary.BigEndian, uint16(len(reply)))
					_, _ = conn.Write(reply)
				}
			}()
		}
	}()
	return server
}

func (s *testDNSServer) count(network string) {
	s.mu.Lock()
	s.queries[network]++
	s.mu.Unlock()
}

func (s *testDNSServer) counts() (udp, tcp int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queries["udp"], s.queries["tcp"]
}

// wg0's relay hijacks UDP/53 (10.10.34.x for blocked names) while TCP/53 is
// clean, and OpenDNS loses most UDP from wg18's exit while TCP answers. Both
// must still resolve through the tunnel.
func TestTunnelResolverFallsBackToTCPOnUDPTimeout(t *testing.T) {
	const mark = 52018
	clean := []netip.Addr{netip.AddrFrom4(testDNSAnswer)}
	poisoned := []netip.Addr{netip.AddrFrom4(testPoisonedReply)}
	for _, tc := range []struct {
		name     string
		servers  [][2]dnsBehavior
		want     []netip.Addr
		notFound bool
		usedTCP  []bool
	}{
		{name: "UDP answer needs no TCP", servers: [][2]dnsBehavior{{dnsAnswer, dnsAnswer}}, want: clean, usedTCP: []bool{false}},
		{name: "UDP timeout retries over TCP", servers: [][2]dnsBehavior{{dnsSilent, dnsAnswer}}, want: clean, usedTCP: []bool{true}},
		{name: "NXDOMAIN over UDP is final", servers: [][2]dnsBehavior{{dnsNXDomain, dnsAnswer}}, notFound: true, usedTCP: []bool{false}},
		{name: "both transports silent fails within budget", servers: [][2]dnsBehavior{{dnsSilent, dnsSilent}}, usedTCP: []bool{true}},
		{name: "a dead server falls through to the next", servers: [][2]dnsBehavior{{dnsSilent, dnsSilent}, {dnsAnswer, dnsAnswer}}, want: clean, usedTCP: []bool{true, false}},
		{name: "poisoned UDP answer retries over TCP", servers: [][2]dnsBehavior{{dnsPoisoned, dnsAnswer}}, want: clean, usedTCP: []bool{true}},
		{name: "poisoned server falls through to the next", servers: [][2]dnsBehavior{{dnsPoisoned, dnsPoisoned}, {dnsAnswer, dnsAnswer}}, want: clean, usedTCP: []bool{true, false}},
		{name: "poisoned everywhere hands the answer on", servers: [][2]dnsBehavior{{dnsPoisoned, dnsPoisoned}, {dnsPoisoned, dnsSilent}}, want: poisoned, usedTCP: []bool{true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			servers := make([]*testDNSServer, 0, len(tc.servers))
			names := make([]string, 0, len(tc.servers))
			byName := map[string]*testDNSServer{}
			for i, behavior := range tc.servers {
				server := startTestDNSServer(t, behavior[0], behavior[1])
				name := netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), uint16(53+i)).String()
				servers, names, byName[name] = append(servers, server), append(names, name), server
			}
			var dialMu sync.Mutex
			var dialedMarks []int
			dial := func(ctx context.Context, network, address string, dialMark int, _ time.Duration) (net.Conn, error) {
				dialMu.Lock()
				dialedMarks = append(dialedMarks, dialMark)
				dialMu.Unlock()
				server := byName[address]
				target := server.udp.LocalAddr().String()
				if network == "tcp" {
					target = server.tcp.Addr().String()
				}
				return (&net.Dialer{}).DialContext(ctx, network, target)
			}
			policy := newDestinationPolicy(&Config{Tunnels: []Tunnel{{Name: "wg18", Fwmark: mark}}})
			resolver := newTunnelResolver(dial, names, mark, 600*time.Millisecond, policy.answerAllowed(mark))
			resolver.slice = func(remaining time.Duration, attemptsLeft int) time.Duration {
				return remaining / time.Duration(attemptsLeft)
			}

			started := time.Now()
			addrs, err := resolver.LookupNetIP(context.Background(), "ip", "www.gstatic.com.")
			// Twice the budget: generous enough for a loaded -race runner, still
			// far below an unbounded retry.
			if elapsed := time.Since(started); elapsed > 1200*time.Millisecond {
				t.Fatalf("lookup took %s, over twice its 600ms budget", elapsed)
			}
			switch {
			case tc.want != nil && (err != nil || !slices.Equal(addrs, tc.want)):
				t.Fatalf("addrs = %v, err = %v; want %v", addrs, err, tc.want)
			case tc.notFound && !isDNSNotFound(err):
				t.Fatalf("err = %v, want not found", err)
			case tc.want == nil && !tc.notFound && err == nil:
				t.Fatalf("addrs = %v, want an error", addrs)
			}
			for i, server := range servers {
				if _, tcp := server.counts(); (tcp > 0) != tc.usedTCP[i] {
					t.Errorf("server %d TCP queries = %d, want TCP used = %t", i, tcp, tc.usedTCP[i])
				}
			}
			dialMu.Lock()
			defer dialMu.Unlock()
			for _, dialed := range dialedMarks {
				if dialed != mark {
					t.Fatalf("resolver dialed mark %d, want every query on %d", dialed, mark)
				}
			}
		})
	}
}
