package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"aegis-proxy/proxy"
	"aegis-proxy/security"
	"aegis-proxy/telemetry"
	"aegis-proxy/upstreams"
)

func main() {
	log.Println("=====================================================")
	log.Println("  AEGIS: Zero-Trust Edge Proxy & Telemetry Engine   ")
	log.Println("=====================================================")

	// 1. Start embedded upstream microservices on 127.0.0.1:8081
	upstreams.StartMockUpstreamServer(8081)

	// 2. Initialize Telemetry Hub & Real-Time Metrics
	telemetry.InitHub()
	telemetry.InitMetrics()

	// 3. Initialize Security Subsystems
	_ = os.MkdirAll("config", 0755)
	policyEngine := security.InitPolicyEngine("config/policies.json")
	security.InitRateLimiter()
	security.InitWAF()

	// 4. Initialize Proxy Engine targeting live upstream (defaults to public echo https://httpbin.org)
	proxyEngine, err := proxy.NewProxyEngine("https://httpbin.org")
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize proxy engine: %v", err)
	}

	// 5. Build Unified Router
	mux := http.NewServeMux()

	// WebSocket Telemetry Stream
	mux.HandleFunc("/ws/telemetry", telemetry.HandleWebSocket)

	// Control Plane REST API
	mux.HandleFunc("/api/control/policies", handlePolicies(policyEngine))
	mux.HandleFunc("/api/control/metrics", handleMetrics)
	mux.HandleFunc("/api/control/recent", handleRecentEvents)
	mux.HandleFunc("/api/control/reset", handleResetTelemetry)
	mux.HandleFunc("/api/control/upstream", handleUpstream(proxyEngine))

	// Catch-all Proxy route
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Forward to Proxy Engine
		proxyEngine.ServeHTTP(w, r)
	})

	// Wrap with CORS & Logging
	rootHandler := corsMiddleware(mux)

	server := &http.Server{
		Addr:         ":8080",
		Handler:      rootHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Println("[AEGIS] Proxy & Control Plane listening on http://0.0.0.0:8080")
		log.Println("[AEGIS] WebSocket Telemetry available at ws://0.0.0.0:8080/ws/telemetry")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] Gateway server terminated: %v", err)
		}
	}()

	// Graceful shutdown listener
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("[AEGIS] Initiating graceful shutdown...")
	time.Sleep(500 * time.Millisecond)
	log.Println("[AEGIS] System stopped safely.")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Device-Id, X-Device-Trust, X-Aegis-Token, X-Aegis-Upstream")
		w.Header().Set("Access-Control-Expose-Headers", "X-Aegis-Verdict, X-Aegis-Threat, X-Aegis-Latency-Ms, Retry-After")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handlePolicies(pe *security.PolicyEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			policies := pe.GetAllPolicies()
			_ = json.NewEncoder(w).Encode(policies)

		case http.MethodPost, http.MethodPut:
			var rule security.PolicyRule
			if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid policy JSON"})
				return
			}
			if rule.ID == "" {
				rule.ID = fmt.Sprintf("pol-custom-%d", time.Now().Unix()%100000)
			}
			if err := pe.UpsertPolicy(rule); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(rule)

		case http.MethodDelete:
			id := r.URL.Query().Get("id")
			if id == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Missing policy id parameter"})
				return
			}
			pe.DeletePolicy(id)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "DELETED", "id": id})

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if telemetry.GlobalMetrics != nil {
		_ = json.NewEncoder(w).Encode(telemetry.GlobalMetrics.GetSnapshot())
	} else {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "INITIALIZING"})
	}
}

func handleRecentEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if telemetry.GlobalHub != nil {
		_ = json.NewEncoder(w).Encode(telemetry.GlobalHub.GetRecentEvents())
	} else {
		_ = json.NewEncoder(w).Encode([]interface{}{})
	}
}

// handleResetTelemetry clears all accumulated metrics and packet logs
func handleResetTelemetry(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if telemetry.GlobalMetrics != nil {
		telemetry.GlobalMetrics.Reset()
	}
	if telemetry.GlobalHub != nil {
		telemetry.GlobalHub.ClearEvents()
	}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "TELEMETRY_RESET",
		"message": "All counters and in-memory event backlogs cleared to zero.",
	})
}

func handleUpstream(pe *proxy.ProxyEngine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"currentUpstream": pe.GetUpstream(),
			})
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			var body struct {
				Target string `json:"target"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Target == "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "Missing target URL"})
				return
			}
			if err := pe.SetUpstream(body.Target); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status":  "UPSTREAM_UPDATED",
				"target":  body.Target,
			})
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
