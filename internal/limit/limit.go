package limit

import (
	"sync"
	"time"
)

type window struct {
	start time.Time
	count int
}

// Limiter is intentionally local: the SQLite release is single-active-instance.
// Its API is dimension-based so a distributed adapter can replace it later.
type Limiter struct {
	mu             sync.Mutex
	perMinute      int
	maxConcurrency int
	windows        map[string]window
	active         map[string]int
}

func New(perMinute, maxConcurrency int) *Limiter {
	if perMinute <= 0 {
		perMinute = 240
	}
	if maxConcurrency <= 0 {
		maxConcurrency = 8
	}
	return &Limiter{perMinute: perMinute, maxConcurrency: maxConcurrency, windows: map[string]window{}, active: map[string]int{}}
}

func (l *Limiter) Allow(keys []string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		item := l.windows[key]
		if item.start.IsZero() || now.Sub(item.start) >= time.Minute {
			continue
		}
		if item.count >= l.perMinute {
			return false
		}
	}
	for _, key := range keys {
		item := l.windows[key]
		if item.start.IsZero() || now.Sub(item.start) >= time.Minute {
			item = window{start: now}
		}
		item.count++
		l.windows[key] = item
	}
	return true
}

func (l *Limiter) Acquire(keys []string) (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		if l.active[key] >= l.maxConcurrency {
			return func() {}, false
		}
	}
	for _, key := range keys {
		l.active[key]++
	}
	once := sync.Once{}
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			for _, key := range keys {
				if l.active[key] <= 1 {
					delete(l.active, key)
				} else {
					l.active[key]--
				}
			}
		})
	}, true
}
