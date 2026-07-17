// Package routesource contains pure set and IPv4 aggregation operations used
// by the route-source and pfSense control paths.
package routesource

import (
	"fmt"
	"math/bits"
	"net"
	"sort"
	"strings"
)

// MergeDedup returns a sorted union without retaining any input backing array.
func MergeDedup(groups ...[]string) []string {
	capacity := 0
	for _, group := range groups {
		capacity += len(group)
	}
	set := make(map[string]struct{}, capacity)
	for _, group := range groups {
		for _, item := range group {
			set[item] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for item := range set {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}

// AggregateIPv4 returns the minimal sorted covering prefix set. Invalid and
// IPv6 entries are ignored because the gateway path is explicitly IPv4-only.
func AggregateIPv4(cidrs []string) []string {
	type interval struct{ low, high uint32 }
	intervals := make([]interval, 0, len(cidrs))
	for _, cidr := range cidrs {
		low, high, ok := cidrRange(cidr)
		if ok {
			intervals = append(intervals, interval{low: low, high: high})
		}
	}
	if len(intervals) == 0 {
		return nil
	}
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].low < intervals[j].low })
	merged := intervals[:1]
	for _, candidate := range intervals[1:] {
		last := &merged[len(merged)-1]
		if candidate.low <= last.high || (last.high != ^uint32(0) && candidate.low == last.high+1) {
			if candidate.high > last.high {
				last.high = candidate.high
			}
			continue
		}
		merged = append(merged, candidate)
	}
	var result []string
	for _, item := range merged {
		result = append(result, rangeCIDRs(item.low, item.high)...)
	}
	sort.Strings(result)
	return result
}

func cidrRange(raw string) (low, high uint32, ok bool) {
	_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil || network.IP.To4() == nil {
		return 0, 0, false
	}
	low = ipUint32(network.IP)
	ones, _ := network.Mask.Size()
	if ones == 0 {
		return low, ^uint32(0), true
	}
	return low, low | (^uint32(0) >> uint(ones)), true
}

func rangeCIDRs(low, high uint32) []string {
	var result []string
	for {
		var size uint
		if low == 0 {
			size = 32
		} else {
			size = uint(bits.TrailingZeros32(low))
		}
		for size > 0 && uint64(1)<<size > uint64(high)-uint64(low)+1 {
			size--
		}
		result = append(result, fmt.Sprintf("%s/%d", uint32IP(low), 32-size))
		next := uint64(low) + (uint64(1) << size)
		if next > uint64(high) {
			return result
		}
		low = uint32(next)
	}
}

func ipUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32IP(value uint32) string {
	return net.IPv4(byte(value>>24), byte(value>>16), byte(value>>8), byte(value)).String()
}
