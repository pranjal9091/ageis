package security

import (
	"sync"
	"time"
)

type TokenBucket struct {
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

func NewTokenBucket(ratePerSec int) *TokenBucket {
	cap := float64(ratePerSec * 2) // allow 2x burst
	if cap < 5 {
		cap = 5
	}
	return &TokenBucket{
		capacity:   cap,
		tokens:     cap,
		refillRate: float64(ratePerSec),
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.lastRefill = now

	// Refill tokens based on elapsed time
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}

	if tb.tokens >= 1.0 {
		tb.tokens -= 1.0
		return true
	}
	return false
}

type RateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*TokenBucket // key: "ip:policyId"
}

var GlobalRateLimiter *RateLimiter

func InitRateLimiter() {
	GlobalRateLimiter = &RateLimiter{
		buckets: make(map[string]*TokenBucket),
	}
	// Periodically purge old buckets every 5 minutes to prevent memory leak
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			GlobalRateLimiter.mu.Lock()
			// Simple reset for memory hygiene
			if len(GlobalRateLimiter.buckets) > 10000 {
				GlobalRateLimiter.buckets = make(map[string]*TokenBucket)
			}
			GlobalRateLimiter.mu.Unlock()
		}
	}()
}

// CheckLimit returns true if the request is permitted, false if rate limited
func (rl *RateLimiter) CheckLimit(key string, ratePerSec int) bool {
	if ratePerSec <= 0 {
		return true
	}

	rl.mu.RLock()
	bucket, exists := rl.buckets[key]
	rl.mu.RUnlock()

	if !exists {
		rl.mu.Lock()
		bucket, exists = rl.buckets[key]
		if !exists {
			bucket = NewTokenBucket(ratePerSec)
			rl.buckets[key] = bucket
		}
		rl.mu.Unlock()
	}

	return bucket.Allow()
}
