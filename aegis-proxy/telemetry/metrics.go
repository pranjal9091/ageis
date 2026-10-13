package telemetry

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type LatencySample struct {
	Timestamp time.Time
	LatencyMs float64
}

type MetricsCollector struct {
	TotalRequests   uint64 `json:"totalRequests"`
	AllowedRequests uint64 `json:"allowedRequests"`
	BlockedRequests uint64 `json:"blockedRequests"`

	Status2xx uint64 `json:"status2xx"`
	Status3xx uint64 `json:"status3xx"`
	Status4xx uint64 `json:"status4xx"`
	Status5xx uint64 `json:"status5xx"`

	ThreatsBlocked uint64 `json:"threatsBlocked"`
	RateLimitsHit  uint64 `json:"rateLimitsHit"`
	ZeroTrustDeny  uint64 `json:"zeroTrustDeny"`

	// Sliding window for rate & latency
	latencyMu   sync.RWMutex
	latencies   []float64
	clientMap   map[string]time.Time
	clientMapMu sync.RWMutex

	lastTickCount uint64
	lastTickTime  time.Time
	CurrentRps    float64 `json:"currentRps"`
	P50LatencyMs  float64 `json:"p50LatencyMs"`
	P95LatencyMs  float64 `json:"p95LatencyMs"`
	P99LatencyMs  float64 `json:"p99LatencyMs"`
	AvgLatencyMs  float64 `json:"avgLatencyMs"`
	ActiveClients int     `json:"activeClients"`
}

var GlobalMetrics *MetricsCollector

func InitMetrics() {
	GlobalMetrics = &MetricsCollector{
		latencies:    make([]float64, 0, 1000),
		clientMap:    make(map[string]time.Time),
		lastTickTime: time.Now(),
	}
	go GlobalMetrics.startMetricsTicker()
}

func (m *MetricsCollector) Reset() {
	atomic.StoreUint64(&m.TotalRequests, 0)
	atomic.StoreUint64(&m.AllowedRequests, 0)
	atomic.StoreUint64(&m.BlockedRequests, 0)
	atomic.StoreUint64(&m.Status2xx, 0)
	atomic.StoreUint64(&m.Status3xx, 0)
	atomic.StoreUint64(&m.Status4xx, 0)
	atomic.StoreUint64(&m.Status5xx, 0)
	atomic.StoreUint64(&m.ThreatsBlocked, 0)
	atomic.StoreUint64(&m.RateLimitsHit, 0)
	atomic.StoreUint64(&m.ZeroTrustDeny, 0)

	m.latencyMu.Lock()
	m.latencies = make([]float64, 0, 1000)
	m.AvgLatencyMs = 0
	m.P50LatencyMs = 0
	m.P95LatencyMs = 0
	m.P99LatencyMs = 0
	m.latencyMu.Unlock()

	m.CurrentRps = 0
}

func (m *MetricsCollector) RecordRequest(verdict string, status int, latencyMs float64, clientIP string, threatType string) {
	atomic.AddUint64(&m.TotalRequests, 1)

	if verdict == "ALLOWED" {
		atomic.AddUint64(&m.AllowedRequests, 1)
	} else {
		atomic.AddUint64(&m.BlockedRequests, 1)
		switch verdict {
		case "BLOCKED_WAF":
			atomic.AddUint64(&m.ThreatsBlocked, 1)
		case "BLOCKED_RATE_LIMIT":
			atomic.AddUint64(&m.RateLimitsHit, 1)
		case "BLOCKED_ZERO_TRUST":
			atomic.AddUint64(&m.ZeroTrustDeny, 1)
		}
	}

	// Status codes
	switch {
	case status >= 200 && status < 300:
		atomic.AddUint64(&m.Status2xx, 1)
	case status >= 300 && status < 400:
		atomic.AddUint64(&m.Status3xx, 1)
	case status >= 400 && status < 500:
		atomic.AddUint64(&m.Status4xx, 1)
	case status >= 500:
		atomic.AddUint64(&m.Status5xx, 1)
	}

	// Record latency
	m.latencyMu.Lock()
	if len(m.latencies) >= 1000 {
		m.latencies = m.latencies[1:]
	}
	m.latencies = append(m.latencies, latencyMs)
	m.latencyMu.Unlock()

	// Track active client
	if clientIP != "" {
		m.clientMapMu.Lock()
		m.clientMap[clientIP] = time.Now()
		m.clientMapMu.Unlock()
	}
}

func (m *MetricsCollector) startMetricsTicker() {
	ticker := time.NewTicker(500 * time.Millisecond)
	for range ticker.C {
		m.computeRollingStats()
		if GlobalHub != nil {
			GlobalHub.BroadcastMetrics(m.GetSnapshot())
		}
	}
}

func (m *MetricsCollector) computeRollingStats() {
	now := time.Now()
	dur := now.Sub(m.lastTickTime).Seconds()
	if dur <= 0 {
		dur = 0.5
	}

	curTotal := atomic.LoadUint64(&m.TotalRequests)
	diff := curTotal - m.lastTickCount
	m.lastTickCount = curTotal
	m.lastTickTime = now

	// Calculate RPS with smoothing
	instantRps := float64(diff) / dur
	m.CurrentRps = math.Round(instantRps*10) / 10

	// Latency percentiles
	m.latencyMu.RLock()
	n := len(m.latencies)
	if n > 0 {
		sorted := make([]float64, n)
		copy(sorted, m.latencies)
		sort.Float64s(sorted)

		sum := 0.0
		for _, v := range sorted {
			sum += v
		}
		m.AvgLatencyMs = math.Round((sum/float64(n))*100) / 100
		m.P50LatencyMs = math.Round(sorted[int(float64(n)*0.50)]*100) / 100
		m.P95LatencyMs = math.Round(sorted[int(float64(n)*0.95)]*100) / 100
		p99Idx := int(float64(n) * 0.99)
		if p99Idx >= n {
			p99Idx = n - 1
		}
		m.P99LatencyMs = math.Round(sorted[p99Idx]*100) / 100
	}
	m.latencyMu.RUnlock()

	// Clean inactive clients (idle > 2 mins)
	m.clientMapMu.Lock()
	cutoff := now.Add(-2 * time.Minute)
	for ip, t := range m.clientMap {
		if t.Before(cutoff) {
			delete(m.clientMap, ip)
		}
	}
	m.ActiveClients = len(m.clientMap)
	m.clientMapMu.Unlock()
}

func (m *MetricsCollector) GetSnapshot() map[string]interface{} {
	return map[string]interface{}{
		"totalRequests":   atomic.LoadUint64(&m.TotalRequests),
		"allowedRequests": atomic.LoadUint64(&m.AllowedRequests),
		"blockedRequests": atomic.LoadUint64(&m.BlockedRequests),
		"status2xx":       atomic.LoadUint64(&m.Status2xx),
		"status3xx":       atomic.LoadUint64(&m.Status3xx),
		"status4xx":       atomic.LoadUint64(&m.Status4xx),
		"status5xx":       atomic.LoadUint64(&m.Status5xx),
		"threatsBlocked":  atomic.LoadUint64(&m.ThreatsBlocked),
		"rateLimitsHit":   atomic.LoadUint64(&m.RateLimitsHit),
		"zeroTrustDeny":   atomic.LoadUint64(&m.ZeroTrustDeny),
		"currentRps":      m.CurrentRps,
		"p50LatencyMs":    m.P50LatencyMs,
		"p95LatencyMs":    m.P95LatencyMs,
		"p99LatencyMs":    m.P99LatencyMs,
		"avgLatencyMs":    m.AvgLatencyMs,
		"activeClients":   m.ActiveClients,
		"timestamp":       time.Now().UnixMilli(),
	}
}
