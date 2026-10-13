package upstreams

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// StartMockUpstreamServer starts the internal corporate microservices on localhost:8081
func StartMockUpstreamServer(port int) {
	mux := http.NewServeMux()

	// 1. Billing & Treasury Service
	mux.HandleFunc("/api/v1/billing/ledger", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"service":   "Treasury & Ledger v2.4",
			"status":    "SYNCHRONIZED",
			"totalPool": "$42,850,290.00 USD",
			"activeAccounts": 14,
			"settlements": []map[string]interface{}{
				{"id": "TX-9901", "entity": "Z-Cloud Infrastructure", "amount": "$142,500.00", "status": "CLEARED", "timestamp": time.Now().Add(-10 * time.Minute)},
				{"id": "TX-9902", "entity": "Edge Transit Provider", "amount": "$89,200.00", "status": "PENDING", "timestamp": time.Now().Add(-2 * time.Minute)},
				{"id": "TX-9903", "entity": "Global TLS Certificate CA", "amount": "$12,400.00", "status": "CLEARED", "timestamp": time.Now().Add(-45 * time.Minute)},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/v1/billing/transfer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"transactionId": fmt.Sprintf("TX-CONF-%d", time.Now().UnixNano()%100000),
			"verdict":       "TRANSACTION_EXECUTED",
			"timestamp":     time.Now(),
		})
	})

	// 2. Identity & Access Directory
	mux.HandleFunc("/api/v1/identity/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"directory": "Active Directory / Okta Sync",
			"totalUsers": 1284,
			"users": []map[string]interface{}{
				{"name": "Pranjal Singh", "email": "pranjal.singh@corp.aegis", "role": "super_admin", "status": "ACTIVE", "mfa": true},
				{"name": "Vikram K", "email": "vikram.k@corp.aegis", "role": "devops", "status": "ACTIVE", "mfa": true},
				{"name": "Neha Sharma", "email": "neha.sharma@corp.aegis", "role": "finance_lead", "status": "ACTIVE", "mfa": true},
				{"name": "Guest Intern", "email": "guest.intern@corp.aegis", "role": "intern", "status": "QUARANTINED", "mfa": false},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 3. Cloud Workloads & Kubernetes
	mux.HandleFunc("/api/v1/workloads/clusters", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"orchestrator": "Kubernetes v1.30.2",
			"clusters": []map[string]interface{}{
				{"name": "ap-south-mumbai-01", "region": "ap-south-1", "nodes": 32, "pods": 412, "health": "HEALTHY", "cpu": "48%", "memory": "64%"},
				{"name": "us-east-virginia-02", "region": "us-east-1", "nodes": 64, "pods": 890, "health": "HEALTHY", "cpu": "62%", "memory": "78%"},
				{"name": "eu-central-frankfurt-01", "region": "eu-central-1", "nodes": 24, "pods": 298, "health": "HEALTHY", "cpu": "39%", "memory": "51%"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	// 4. Public Gateway
	mux.HandleFunc("/api/v1/public/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"system":    "Aegis Edge Gateway",
			"status":    "OPERATIONAL",
			"version":   "1.0.4-prod",
			"uptime":    "99.999%",
			"timestamp": time.Now().UTC(),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("[UPSTREAM] Internal Microservices listening on http://%s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[UPSTREAM] Failed to start mock upstream: %v", err)
		}
	}()
}
