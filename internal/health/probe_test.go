package health

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeBounds(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int64
	prober := NewProber(ProbeConfig{Timeout: time.Second, MaxConcurrent: 2}, func(context.Context) error {
		calls.Add(1)
		<-release
		return nil
	})
	for i := 0; i < 100; i++ {
		prober.Try(context.Background())
	}
	deadline := time.Now().Add(time.Second)
	for prober.InFlight() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if prober.InFlight() != 2 || calls.Load() != 2 {
		t.Fatalf("in-flight=%d calls=%d", prober.InFlight(), calls.Load())
	}
	close(release)
}
