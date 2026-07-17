package proxy

import (
	"fmt"
	"net/netip"
	"testing"
)

func BenchmarkAddressSelection(b *testing.B) {
	for _, count := range []int{1, 16, 256} {
		input := make([]netip.Addr, 0, count+2)
		for i := 0; i < count; i++ {
			input = append(input, netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}))
		}
		input = append(input, input[0], netip.Addr{})
		selector := &RotatingSelector{Strategy: Interleave, MaxAttempts: min(count, 64)}
		b.Run(fmt.Sprintf("answers_%d", count), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if got := selector.Select(input, func(addr netip.Addr) bool { return addr.IsValid() }); len(got) == 0 {
					b.Fatal("empty selection")
				}
			}
		})
	}
}
