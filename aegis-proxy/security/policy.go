package security

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

type PolicyRule struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	PathPrefix     string   `json:"pathPrefix"`
	Methods        []string `json:"methods"` // ["GET", "POST"] or ["*"]
	RequiredRoles  []string `json:"requiredRoles"`
	MinDeviceTrust int      `json:"minDeviceTrust"` // 0 - 100
	RateLimitRps   int      `json:"rateLimitRps"`   // requests per second
	EnforceMFA     bool     `json:"enforceMfa"`
	Enabled        bool     `json:"enabled"`
	Description    string   `json:"description"`
}

type PolicyEngine struct {
	mu       sync.RWMutex
	policies map[string]PolicyRule
	filePath string
}

var GlobalPolicies *PolicyEngine

func InitPolicyEngine(configPath string) *PolicyEngine {
	pe := &PolicyEngine{
		policies: make(map[string]PolicyRule),
		filePath: configPath,
	}

	// Try reading initial config file or load defaults
	if err := pe.loadFromFile(); err != nil {
		pe.loadDefaults()
		_ = pe.saveToFile()
	}

	GlobalPolicies = pe
	return pe
}

func (pe *PolicyEngine) loadDefaults() {
	defaults := []PolicyRule{
		{
			ID:             "pol-fin-001",
			Name:           "Treasury & Ledger Protection",
			PathPrefix:     "/api/v1/billing",
			Methods:        []string{"*"},
			RequiredRoles:  []string{"finance_lead", "super_admin"},
			MinDeviceTrust: 80,
			RateLimitRps:   15,
			EnforceMFA:     true,
			Enabled:        true,
			Description:    "Zero-Trust isolation for banking ledgers and financial transfers.",
		},
		{
			ID:             "pol-id-002",
			Name:           "Core Identity Directory",
			PathPrefix:     "/api/v1/identity",
			Methods:        []string{"*"},
			RequiredRoles:  []string{"it_admin", "super_admin", "devops"},
			MinDeviceTrust: 65,
			RateLimitRps:   25,
			EnforceMFA:     false,
			Enabled:        true,
			Description:    "Identity directory and employee credential vault.",
		},
		{
			ID:             "pol-ops-003",
			Name:           "Cloud Compute Workloads",
			PathPrefix:     "/api/v1/workloads",
			Methods:        []string{"*"},
			RequiredRoles:  []string{"devops", "cloud_engineer", "super_admin"},
			MinDeviceTrust: 70,
			RateLimitRps:   30,
			EnforceMFA:     false,
			Enabled:        true,
			Description:    "Kubernetes workload orchestrator and edge node telemetry.",
		},
		{
			ID:             "pol-pub-004",
			Name:           "Public Ingress Gateway",
			PathPrefix:     "/api/v1/public",
			Methods:        []string{"GET"},
			RequiredRoles:  []string{"*"}, // Publicly accessible with rate limit
			MinDeviceTrust: 0,
			RateLimitRps:   50,
			EnforceMFA:     false,
			Enabled:        true,
			Description:    "External unauthenticated catalog and system health probes.",
		},
	}

	pe.mu.Lock()
	defer pe.mu.Unlock()
	for _, p := range defaults {
		pe.policies[p.ID] = p
	}
}

func (pe *PolicyEngine) loadFromFile() error {
	data, err := os.ReadFile(pe.filePath)
	if err != nil {
		return err
	}
	var list []PolicyRule
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.policies = make(map[string]PolicyRule)
	for _, p := range list {
		pe.policies[p.ID] = p
	}
	return nil
}

func (pe *PolicyEngine) saveToFile() error {
	pe.mu.RLock()
	list := make([]PolicyRule, 0, len(pe.policies))
	for _, p := range pe.policies {
		list = append(list, p)
	}
	pe.mu.RUnlock()

	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pe.filePath, data, 0644)
}

func (pe *PolicyEngine) GetAllPolicies() []PolicyRule {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	list := make([]PolicyRule, 0, len(pe.policies))
	for _, p := range pe.policies {
		list = append(list, p)
	}
	return list
}

func (pe *PolicyEngine) UpsertPolicy(rule PolicyRule) error {
	pe.mu.Lock()
	pe.policies[rule.ID] = rule
	pe.mu.Unlock()
	return pe.saveToFile()
}

func (pe *PolicyEngine) DeletePolicy(id string) {
	pe.mu.Lock()
	delete(pe.policies, id)
	pe.mu.Unlock()
	_ = pe.saveToFile()
}

// MatchPolicy finds the most specific matching policy rule for path and method
func (pe *PolicyEngine) MatchPolicy(path string, method string) *PolicyRule {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	var bestMatch *PolicyRule
	longestPrefix := -1

	for _, p := range pe.policies {
		if !p.Enabled {
			continue
		}
		if strings.HasPrefix(path, p.PathPrefix) {
			// Check method
			methodAllowed := false
			for _, m := range p.Methods {
				if m == "*" || strings.EqualFold(m, method) {
					methodAllowed = true
					break
				}
			}
			if !methodAllowed {
				continue
			}

			if len(p.PathPrefix) > longestPrefix {
				longestPrefix = len(p.PathPrefix)
				ruleCopy := p
				bestMatch = &ruleCopy
			}
		}
	}
	return bestMatch
}
