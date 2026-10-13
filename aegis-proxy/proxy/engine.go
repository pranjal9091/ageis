package proxy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"aegis-proxy/security"
	"aegis-proxy/telemetry"
)

type ProxyEngine struct {
	mu          sync.RWMutex
	upstreamURL *url.URL
	revProxy    *httputil.ReverseProxy
	transport   *http.Transport
}

func NewProxyEngine(defaultUpstreamTarget string) (*ProxyEngine, error) {
	u, err := url.Parse(defaultUpstreamTarget)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}

	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = transport
	rp.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Access-Control-Allow-Origin")
		resp.Header.Del("Access-Control-Allow-Credentials")
		resp.Header.Del("Access-Control-Allow-Methods")
		resp.Header.Del("Access-Control-Allow-Headers")
		resp.Header.Del("Access-Control-Expose-Headers")
		return nil
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":    "Upstream Service Unavailable",
			"target":   u.String(),
			"details":  err.Error(),
		})
	}

	return &ProxyEngine{
		upstreamURL: u,
		revProxy:    rp,
		transport:   transport,
	}, nil
}

func (pe *ProxyEngine) GetUpstream() string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.upstreamURL.String()
}

func (pe *ProxyEngine) SetUpstream(target string) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.upstreamURL = u
	rp := httputil.NewSingleHostReverseProxy(u)
	rp.Transport = pe.transport
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":    "Upstream Service Unavailable",
			"target":   u.String(),
			"details":  err.Error(),
		})
	}
	pe.revProxy = rp
	return nil
}

// ServeHTTP is the primary inspection and proxy pipeline
func (pe *ProxyEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	eventID := fmt.Sprintf("evt-%d-%04d", time.Now().UnixMilli(), time.Now().Nanosecond()%10000)

	// Determine effective target upstream (allows per-request live link override)
	targetURL := pe.getTargetURL(r)

	// 1. Peek body snippet for WAF inspection without discarding request stream
	var bodySnippet string
	if r.Body != nil && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch) {
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err == nil {
			bodySnippet = string(bodyBytes)
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}
	}

	// 2. Extract Zero-Trust Context
	ztCtx := security.ExtractZeroTrustContext(r)

	// 3. WAF Threat Inspection
	threat := security.GlobalWAF.InspectRequest(r, bodySnippet)
	if threat.Detected {
		latency := roundLatency(time.Since(start))
		emitEvent(eventID, r, ztCtx, http.StatusForbidden, "BLOCKED_WAF", threat.MatchedRule, threat.ThreatType, threat.Severity, latency, threat.Snippet, "", targetURL.Host)
		
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Aegis-Verdict", "BLOCKED_WAF")
		w.Header().Set("X-Aegis-Threat", threat.ThreatType)
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"gateway":        "Aegis Zero-Trust Edge",
			"verdict":        "BLOCKED",
			"reason":         threat.MatchedRule,
			"threatType":     threat.ThreatType,
			"severity":       threat.Severity,
			"payloadSnippet": threat.Snippet,
			"eventId":        eventID,
		})
		return
	}

	// 4. Policy Matching
	matchedPolicy := security.GlobalPolicies.MatchPolicy(r.URL.Path, r.Method)
	policyID := "default-allow"
	rateLimitRps := 100 // default fallback

	if matchedPolicy != nil {
		policyID = matchedPolicy.ID
		rateLimitRps = matchedPolicy.RateLimitRps

		// 4a. Zero-Trust Role & Identity Verification
		roleAuthorized := false
		for _, reqRole := range matchedPolicy.RequiredRoles {
			if reqRole == "*" || reqRole == ztCtx.UserRole {
				roleAuthorized = true
				break
			}
		}

		if !roleAuthorized {
			latency := roundLatency(time.Since(start))
			reason := fmt.Sprintf("Role '%s' unauthorized for '%s'. Required: %v", ztCtx.UserRole, matchedPolicy.Name, matchedPolicy.RequiredRoles)
			emitEvent(eventID, r, ztCtx, http.StatusForbidden, "BLOCKED_ZERO_TRUST", reason, "", "", latency, "", policyID, targetURL.Host)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Aegis-Verdict", "BLOCKED_ZERO_TRUST")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"gateway":   "Aegis Zero-Trust Edge",
				"verdict":   "BLOCKED",
				"violation": "ROLE_UNAUTHORIZED",
				"reason":    reason,
				"eventId":   eventID,
			})
			return
		}

		// 4b. Zero-Trust Device Posture & Trust Score Verification
		if ztCtx.DeviceTrust < matchedPolicy.MinDeviceTrust {
			latency := roundLatency(time.Since(start))
			reason := fmt.Sprintf("Device trust (%d/100) below threshold (%d/100)", ztCtx.DeviceTrust, matchedPolicy.MinDeviceTrust)
			emitEvent(eventID, r, ztCtx, http.StatusForbidden, "BLOCKED_ZERO_TRUST", reason, "", "", latency, "", policyID, targetURL.Host)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Aegis-Verdict", "BLOCKED_ZERO_TRUST")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"gateway":       "Aegis Zero-Trust Edge",
				"verdict":       "BLOCKED",
				"violation":     "DEVICE_TRUST_FAILED",
				"deviceTrust":   ztCtx.DeviceTrust,
				"minTrustScore": matchedPolicy.MinDeviceTrust,
				"reason":        reason,
				"eventId":       eventID,
			})
			return
		}
	}

	// 5. Distributed Token-Bucket Rate Limiter
	rateLimitKey := fmt.Sprintf("%s:%s", ztCtx.ClientIP, policyID)
	if !security.GlobalRateLimiter.CheckLimit(rateLimitKey, rateLimitRps) {
		latency := roundLatency(time.Since(start))
		reason := fmt.Sprintf("Rate limit of %d req/s exceeded for %s", rateLimitRps, ztCtx.ClientIP)
		emitEvent(eventID, r, ztCtx, http.StatusTooManyRequests, "BLOCKED_RATE_LIMIT", reason, "", "", latency, "", policyID, targetURL.Host)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.Header().Set("X-Aegis-Verdict", "BLOCKED_RATE_LIMIT")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"gateway": "Aegis Zero-Trust Edge",
			"verdict": "BLOCKED",
			"reason":  reason,
			"eventId": eventID,
		})
		return
	}

	// 6. Upstream Proxying & Response Interception
	r.Header.Set("X-Aegis-Verified-User", ztCtx.UserID)
	r.Header.Set("X-Aegis-Verified-Role", ztCtx.UserRole)
	r.Header.Set("X-Aegis-Device-Trust", fmt.Sprintf("%d", ztCtx.DeviceTrust))

	// Dynamically proxy to chosen target
	proxy := pe.getProxyFor(targetURL)

	// Set host header for upstream virtual hosting (e.g. https://httpbin.org)
	r.Host = targetURL.Host
	r.URL.Host = targetURL.Host
	r.URL.Scheme = targetURL.Scheme

	// Clean internal headers before sending to remote
	r.Header.Del("X-Aegis-Upstream")

	// Capture response status code via wrapper
	rw := &responseCaptureWriter{ResponseWriter: w, statusCode: http.StatusOK}
	proxy.ServeHTTP(rw, r)

	latency := roundLatency(time.Since(start))
	emitEvent(eventID, r, ztCtx, rw.statusCode, "ALLOWED", "Zero-Trust Verified & Forwarded", "", "", latency, "", policyID, targetURL.Host)
}

func (pe *ProxyEngine) getTargetURL(r *http.Request) *url.URL {
	// 1. Check header override
	if customUpstream := r.Header.Get("X-Aegis-Upstream"); customUpstream != "" {
		if u, err := url.Parse(customUpstream); err == nil && u.Host != "" {
			return u
		}
	}
	// 2. Check query parameter override (?__upstream=https://httpbin.org)
	if qUpstream := r.URL.Query().Get("__upstream"); qUpstream != "" {
		if u, err := url.Parse(qUpstream); err == nil && u.Host != "" {
			q := r.URL.Query()
			q.Del("__upstream")
			r.URL.RawQuery = q.Encode()
			return u
		}
	}
	// 3. Fallback to default
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.upstreamURL
}

func (pe *ProxyEngine) getProxyFor(targetURL *url.URL) *httputil.ReverseProxy {
	pe.mu.RLock()
	defaultURL := pe.upstreamURL
	pe.mu.RUnlock()

	if targetURL.String() == defaultURL.String() {
		pe.mu.RLock()
		defer pe.mu.RUnlock()
		return pe.revProxy
	}

	// Create dynamic proxy for external live URL
	rp := httputil.NewSingleHostReverseProxy(targetURL)
	rp.Transport = pe.transport
	rp.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Access-Control-Allow-Origin")
		resp.Header.Del("Access-Control-Allow-Credentials")
		resp.Header.Del("Access-Control-Allow-Methods")
		resp.Header.Del("Access-Control-Allow-Headers")
		resp.Header.Del("Access-Control-Expose-Headers")
		return nil
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":    "Live Remote Upstream Error",
			"target":   targetURL.String(),
			"details":  err.Error(),
		})
	}
	return rp
}

type responseCaptureWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseCaptureWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func roundLatency(d time.Duration) float64 {
	ms := float64(d.Microseconds()) / 1000.0
	return math.Round(ms*100) / 100
}

func emitEvent(id string, r *http.Request, ztCtx security.ZeroTrustContext, status int, verdict, reason, threatType, severity string, latencyMs float64, snippet, policyID, targetHost string) {
	event := telemetry.SecurityEvent{
		ID:             id,
		Timestamp:      time.Now(),
		ClientIP:       ztCtx.ClientIP,
		Method:         r.Method,
		Path:           r.URL.Path,
		UserAgent:      r.UserAgent(),
		UserID:         ztCtx.UserID,
		UserRole:       ztCtx.UserRole,
		DeviceTrust:    ztCtx.DeviceTrust,
		Status:         status,
		Verdict:        verdict,
		Reason:         reason,
		ThreatType:     threatType,
		ThreatSeverity: severity,
		LatencyMs:      latencyMs,
		UpstreamTarget: targetHost,
		MatchedPolicy:  policyID,
		PayloadSnippet: snippet,
	}

	if telemetry.GlobalHub != nil {
		telemetry.GlobalHub.BroadcastEvent(event)
	}
	if telemetry.GlobalMetrics != nil {
		telemetry.GlobalMetrics.RecordRequest(verdict, status, latencyMs, ztCtx.ClientIP, threatType)
	}
}
