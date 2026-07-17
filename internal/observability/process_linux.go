//go:build linux

package observability

import "os"

func processFDCount() (int, bool) {
	entries, err := os.ReadDir("/proc/self/fd")
	return len(entries), err == nil
}
