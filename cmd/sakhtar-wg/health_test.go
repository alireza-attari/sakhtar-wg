package main

import "testing"

func TestNewHealthMonitorWithoutGroups(t *testing.T) {
	monitor, err := NewHealthMonitor(&Config{})
	if err != nil || monitor != nil {
		t.Fatalf("monitor = %v, err = %v", monitor, err)
	}
}
