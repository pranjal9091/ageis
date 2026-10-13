package security

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type ZeroTrustContext struct {
	UserID         string
	UserRole       string
	DeviceID       string
	DeviceTrust    int    // 0 to 100
	ClientIP       string
	IsAuthenticated bool
}

// ExtractZeroTrustContext resolves client identity, device security posture, and network attributes dynamically from incoming HTTP headers and tokens.
func ExtractZeroTrustContext(r *http.Request) ZeroTrustContext {
	ctx := ZeroTrustContext{
		UserID:          "anonymous.guest",
		UserRole:        "public",
		DeviceID:        "DEV-" + strings.ToUpper(extractClientIP(r)),
		DeviceTrust:     30,
		ClientIP:        extractClientIP(r),
		IsAuthenticated: false,
	}

	// 1. Direct Context Headers (commonly injected by Zscaler Client Connector / Enterprise Identity Proxies)
	if uid := r.Header.Get("X-User-Id"); uid != "" {
		ctx.UserID = uid
		ctx.IsAuthenticated = true
	}
	if role := r.Header.Get("X-User-Role"); role != "" {
		ctx.UserRole = role
		ctx.IsAuthenticated = true
	}
	if dev := r.Header.Get("X-Device-Id"); dev != "" {
		ctx.DeviceID = dev
	}
	if trustStr := r.Header.Get("X-Device-Trust"); trustStr != "" {
		if val, err := strconv.Atoi(trustStr); err == nil && val >= 0 && val <= 100 {
			ctx.DeviceTrust = val
		}
	}

	// 2. Token Resolution (Bearer JWT, Base64 Claims, or colon-delimited identity tuple)
	authHeader := r.Header.Get("Authorization")
	customToken := r.Header.Get("X-Aegis-Token")

	token := ""
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if customToken != "" {
		token = customToken
	}

	if token != "" {
		ctx.IsAuthenticated = true

		// Check for identity tuple format: "userId:role:trust" (e.g. "pranjal:super_admin:95")
		parts := strings.Split(token, ":")
		if len(parts) == 3 {
			trust, _ := strconv.Atoi(parts[2])
			ctx.UserID = parts[0]
			ctx.UserRole = parts[1]
			ctx.DeviceTrust = trust
			return ctx
		}

		// Check for Base64 encoded JSON Claims
		if decoded, err := base64.StdEncoding.DecodeString(token); err == nil {
			var customClaims struct {
				User        string `json:"user"`
				Role        string `json:"role"`
				DeviceTrust int    `json:"deviceTrust"`
				DeviceID    string `json:"deviceId"`
			}
			if err := json.Unmarshal(decoded, &customClaims); err == nil && customClaims.User != "" {
				ctx.UserID = customClaims.User
				if customClaims.Role != "" {
					ctx.UserRole = customClaims.Role
				}
				if customClaims.DeviceTrust > 0 {
					ctx.DeviceTrust = customClaims.DeviceTrust
				}
				if customClaims.DeviceID != "" {
					ctx.DeviceID = customClaims.DeviceID
				}
				return ctx
			}
		}

		// If direct user role or id wasn't set, derive from token string
		if ctx.UserRole == "public" {
			lowered := strings.ToLower(token)
			switch {
			case strings.Contains(lowered, "admin"):
				ctx.UserRole = "super_admin"
				if ctx.DeviceTrust == 30 {
					ctx.DeviceTrust = 95
				}
			case strings.Contains(lowered, "devops") || strings.Contains(lowered, "ops"):
				ctx.UserRole = "devops"
				if ctx.DeviceTrust == 30 {
					ctx.DeviceTrust = 85
				}
			case strings.Contains(lowered, "finance"):
				ctx.UserRole = "finance_lead"
				if ctx.DeviceTrust == 30 {
					ctx.DeviceTrust = 90
				}
			case strings.Contains(lowered, "intern") || strings.Contains(lowered, "guest"):
				ctx.UserRole = "intern"
				if ctx.DeviceTrust == 30 {
					ctx.DeviceTrust = 45
				}
			default:
				ctx.UserRole = "employee"
				if ctx.DeviceTrust == 30 {
					ctx.DeviceTrust = 75
				}
			}
		}

		if ctx.UserID == "anonymous.guest" {
			ctx.UserID = token
		}
	}

	return ctx
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
