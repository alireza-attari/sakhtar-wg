package routing

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSuffixMatcherMostSpecificAndFirstWins(t *testing.T) {
	m := NewSuffixMatcher[int](3)
	m.AddFirst("example.com", 1)
	m.AddFirst("api.example.com", 2)
	m.AddFirst("example.com", 3)
	for host, want := range map[string]int{
		"example.com": 1, "www.example.com": 1, "api.example.com": 2,
		"v1.api.example.com": 2,
	} {
		if got, ok := m.Lookup(host); !ok || got != want {
			t.Fatalf("Lookup(%q) = %d, %v; want %d, true", host, got, ok, want)
		}
	}
	if _, ok := m.Lookup("notexample.com"); ok {
		t.Fatal("label-boundary mismatch")
	}
}

func TestPlanDiff(t *testing.T) {
	got := PlanDiff([]string{"a", "b", "b"}, []string{"b", "c"})
	want := Diff{Add: []string{"c"}, Delete: []string{"a"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("diff = %#v, want %#v", got, want)
	}
}

func BenchmarkSuffixLookup(b *testing.B) {
	for _, rules := range []int{1, 100, 10_000} {
		b.Run(fmt.Sprintf("rules_%d", rules), func(b *testing.B) {
			matcher := NewSuffixMatcher[int](rules + 1)
			for i := 0; i < rules; i++ {
				matcher.AddFirst(fmt.Sprintf("service-%d.example", i), i)
			}
			matcher.AddFirst("api.deep.example.com", 42)
			b.ReportAllocs()
			for b.Loop() {
				value, ok := matcher.Lookup("v1.api.deep.example.com")
				if !ok || value != 42 {
					b.Fatal("lookup failed")
				}
			}
		})
	}
}

func BenchmarkDesiredCurrentDiff(b *testing.B) {
	for _, size := range []int{10, 1_000, 10_000} {
		current := make([]string, size)
		desired := make([]string, size)
		for i := 0; i < size; i++ {
			current[i] = fmt.Sprintf("10.%d.%d.0/24", (i/256)%256, i%256)
			desired[i] = current[i]
		}
		desired[size-1] = "203.0.113.0/24"
		b.Run(fmt.Sprintf("routes_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				result := PlanDiff(current, desired)
				if len(result.Add) != 1 || len(result.Delete) != 1 {
					b.Fatal("unexpected diff")
				}
			}
		})
	}
}
