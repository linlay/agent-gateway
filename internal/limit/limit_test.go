package limit

import (
	"testing"
	"time"
)

func TestRateAndConcurrencyDimensions(t *testing.T) {
	limiter := New(2, 1)
	now := time.Now()
	keys := []string{"tenant:t1", "agent:a1"}
	if !limiter.Allow(keys, now) || !limiter.Allow(keys, now) || limiter.Allow(keys, now) {
		t.Fatal("expected exactly two requests in the fixed minute window")
	}
	if !limiter.Allow(keys, now.Add(time.Minute)) {
		t.Fatal("window should reset after one minute")
	}
	release, ok := limiter.Acquire(keys)
	if !ok {
		t.Fatal("first concurrent request should be accepted")
	}
	if _, ok := limiter.Acquire(keys); ok {
		t.Fatal("second concurrent request should be rejected")
	}
	release()
	if _, ok := limiter.Acquire(keys); !ok {
		t.Fatal("release should return capacity")
	}
}
