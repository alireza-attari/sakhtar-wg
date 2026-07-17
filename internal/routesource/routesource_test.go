package routesource

import (
	"fmt"
	"reflect"
	"testing"
)

func TestMergeDedup(t *testing.T) {
	got := MergeDedup([]string{"b", "a"}, []string{"b", "c"})
	if want := []string{"a", "b", "c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("merge = %v, want %v", got, want)
	}
}

func TestAggregateIPv4(t *testing.T) {
	got := AggregateIPv4([]string{"10.0.0.0/25", "10.0.0.128/25", "bad", "2001:db8::/32"})
	if want := []string{"10.0.0.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("aggregate = %v, want %v", got, want)
	}
}

func BenchmarkRouteMergeDedup(b *testing.B) {
	for _, size := range []int{10, 1_000, 10_000} {
		left, right := make([]string, size), make([]string, size)
		for i := 0; i < size; i++ {
			left[i] = fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256)
			right[i] = left[i]
		}
		b.Run(fmt.Sprintf("routes_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if got := MergeDedup(left, right); len(got) == 0 {
					b.Fatal("empty merge")
				}
			}
		})
	}
}

func BenchmarkCIDRAggregation(b *testing.B) {
	for _, size := range []int{10, 1_000, 10_000} {
		input := make([]string, size)
		for i := range input {
			input[i] = fmt.Sprintf("10.%d.%d.%d/32", (i>>16)%256, (i>>8)%256, i%256)
		}
		b.Run(fmt.Sprintf("prefixes_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if got := AggregateIPv4(input); len(got) == 0 {
					b.Fatal("empty aggregation")
				}
			}
		})
	}
}
