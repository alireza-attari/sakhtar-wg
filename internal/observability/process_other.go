//go:build !linux

package observability

func processFDCount() (int, bool) { return 0, false }
