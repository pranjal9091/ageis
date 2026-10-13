package security

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type ThreatResult struct {
	Detected    bool   `json:"detected"`
	ThreatType  string `json:"threatType"`
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM
	MatchedRule string `json:"matchedRule"`
	Snippet     string `json:"snippet"`
}

type WAFEngine struct {
	sqliRegex   *regexp.Regexp
	xssRegex    *regexp.Regexp
	lfiRegex    *regexp.Regexp
	rceRegex    *regexp.Regexp
	scannerUser *regexp.Regexp
}

var GlobalWAF *WAFEngine

func InitWAF() {
	GlobalWAF = &WAFEngine{
		// Regex patterns for SQL Injection
		sqliRegex: regexp.MustCompile(`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|drop\s+database|truncate\s+table|alter\s+table|exec(\s|\+)+(s|x)p|benchmark\s*\(|sleep\s*\(\s*\d+\s*\)|--\s*$|'\s*or\s*['\d]+=['\d]+|or\s+1=1|\bor\s+true\b|admin'\s*--)`),
		
		// Regex patterns for Cross-Site Scripting
		xssRegex: regexp.MustCompile(`(?i)(<script[^>]*>|javascript\s*:|vbscript\s*:|onload\s*=|onerror\s*=|onclick\s*=|onmouseover\s*=|document\.cookie|document\.domain|window\.location|<svg[^>]*onload=|<img[^>]*onerror=)`),
		
		// Regex patterns for Path Traversal / LFI
		lfiRegex: regexp.MustCompile(`(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\/etc\/passwd|\/etc\/shadow|\/proc\/self|\/boot\.ini|c:\\windows|c:\\boot)`),
		
		// Regex patterns for Command Injection / RCE
		rceRegex: regexp.MustCompile(`(?i)(\|\||&&|\$\(.*\)|` + "`" + `.*` + "`" + `|;\s*(rm|cat|ls|curl|wget|nc|sh|bash|powershell|chmod)\b)`),

		// Scanner detection
		scannerUser: regexp.MustCompile(`(?i)(sqlmap|nikto|havij|acunetix|nessus|masscan|zgrab|nmap)`),
	}
}

// InspectRequest analyzes query params, URL path, headers, and payload snippet
func (w *WAFEngine) InspectRequest(r *http.Request, bodySnippet string) ThreatResult {
	// 1. Inspect User-Agent for known scanners
	ua := r.UserAgent()
	if w.scannerUser.MatchString(ua) {
		return ThreatResult{
			Detected:    true,
			ThreatType:  "MALICIOUS_SCANNER",
			Severity:    "CRITICAL",
			MatchedRule: "Identified automated vulnerability scanner signature",
			Snippet:     truncateString(ua, 80),
		}
	}

	// 2. Aggregate searchable inputs: Raw Path, Unescaped Path, Query string, Body snippet
	searchPool := []string{
		r.URL.Path,
		r.URL.RawQuery,
	}

	if decodedQuery, err := url.QueryUnescape(r.URL.RawQuery); err == nil && decodedQuery != r.URL.RawQuery {
		searchPool = append(searchPool, decodedQuery)
	}

	if bodySnippet != "" {
		searchPool = append(searchPool, bodySnippet)
	}

	// Check headers for injection
	for k, v := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-") || k == "Referer" {
			searchPool = append(searchPool, strings.Join(v, " "))
		}
	}

	for _, input := range searchPool {
		if input == "" {
			continue
		}

		// Check SQLi
		if match := w.sqliRegex.FindString(input); match != "" {
			return ThreatResult{
				Detected:    true,
				ThreatType:  "SQL_INJECTION",
				Severity:    "CRITICAL",
				MatchedRule: "Heuristic pattern match for SQL dialect injection",
				Snippet:     truncateString(match, 100),
			}
		}

		// Check RCE
		if match := w.rceRegex.FindString(input); match != "" {
			return ThreatResult{
				Detected:    true,
				ThreatType:  "REMOTE_COMMAND_EXECUTION",
				Severity:    "CRITICAL",
				MatchedRule: "System shell or command pipeline injection vector",
				Snippet:     truncateString(match, 100),
			}
		}

		// Check Path Traversal
		if match := w.lfiRegex.FindString(input); match != "" {
			return ThreatResult{
				Detected:    true,
				ThreatType:  "PATH_TRAVERSAL",
				Severity:    "HIGH",
				MatchedRule: "Directory traversal or restricted system file access",
				Snippet:     truncateString(match, 100),
			}
		}

		// Check XSS
		if match := w.xssRegex.FindString(input); match != "" {
			return ThreatResult{
				Detected:    true,
				ThreatType:  "CROSS_SITE_SCRIPTING",
				Severity:    "HIGH",
				MatchedRule: "DOM manipulation / inline script tag payload",
				Snippet:     truncateString(match, 100),
			}
		}
	}

	return ThreatResult{Detected: false}
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
