package auth

import (
	"context"
	"sync"
	"time"
)

type MemoryRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]rateBucket
}

type rateBucket struct {
	count int
	reset time.Time
}

func NewMemoryRateLimiter() *MemoryRateLimiter {
	return &MemoryRateLimiter{buckets: map[string]rateBucket{}}
}

func (l *MemoryRateLimiter) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	bucket := l.buckets[key]
	if bucket.reset.IsZero() || !bucket.reset.After(now) {
		bucket = rateBucket{reset: now.Add(window)}
	}
	bucket.count++
	l.buckets[key] = bucket
	return bucket.count <= limit, nil
}
