package telemetry

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for dev/dashboard access
	},
}

// SecurityEvent represents a full forensic trace of an inspected request
type SecurityEvent struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	ClientIP       string    `json:"clientIp"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	UserAgent      string    `json:"userAgent"`
	UserID         string    `json:"userId"`
	UserRole       string    `json:"userRole"`
	DeviceTrust    int       `json:"deviceTrust"`
	Status         int       `json:"status"`
	Verdict        string    `json:"verdict"` // ALLOWED, BLOCKED_WAF, BLOCKED_RATE_LIMIT, BLOCKED_ZERO_TRUST
	Reason         string    `json:"reason"`
	ThreatType     string    `json:"threatType,omitempty"`
	ThreatSeverity string    `json:"threatSeverity,omitempty"`
	LatencyMs      float64   `json:"latencyMs"`
	UpstreamTarget string    `json:"upstreamTarget"`
	MatchedPolicy  string    `json:"matchedPolicy,omitempty"`
	PayloadSnippet string    `json:"payloadSnippet,omitempty"`
}

// Hub maintains the set of active clients and broadcasts telemetry events
type Hub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan []byte
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mutex      sync.RWMutex

	// In-memory ring buffer for last 150 events to seed newly connected dashboards
	recentEvents []SecurityEvent
	ringMutex    sync.RWMutex
}

var GlobalHub *Hub

func NewHub() *Hub {
	return &Hub{
		clients:      make(map[*websocket.Conn]bool),
		broadcast:    make(chan []byte, 1024),
		register:     make(chan *websocket.Conn),
		unregister:   make(chan *websocket.Conn),
		recentEvents: make([]SecurityEvent, 0, 150),
	}
}

func InitHub() {
	GlobalHub = NewHub()
	go GlobalHub.Run()
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mutex.Lock()
			h.clients[client] = true
			h.mutex.Unlock()

			// Send recent backlog on connect
			h.ringMutex.RLock()
			recent := make([]SecurityEvent, len(h.recentEvents))
			copy(recent, h.recentEvents)
			h.ringMutex.RUnlock()

			initMsg, _ := json.Marshal(map[string]interface{}{
				"type":   "INIT_BACKLOG",
				"events": recent,
			})
			_ = client.WriteMessage(websocket.TextMessage, initMsg)

		case client := <-h.unregister:
			h.mutex.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				_ = client.Close()
			}
			h.mutex.Unlock()

		case message := <-h.broadcast:
			h.mutex.RLock()
			for client := range h.clients {
				err := client.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					_ = client.Close()
					delete(h.clients, client)
				}
			}
			h.mutex.RUnlock()
		}
	}
}

// BroadcastEvent adds the event to history and pushes it to all dashboard websockets
func (h *Hub) BroadcastEvent(event SecurityEvent) {
	// Append to ring buffer
	h.ringMutex.Lock()
	if len(h.recentEvents) >= 150 {
		h.recentEvents = h.recentEvents[1:]
	}
	h.recentEvents = append(h.recentEvents, event)
	h.ringMutex.Unlock()

	msg, err := json.Marshal(map[string]interface{}{
		"type":  "SECURITY_EVENT",
		"event": event,
	})
	if err != nil {
		return
	}

	select {
	case h.broadcast <- msg:
	default:
		// Drop message if channel is full to prevent proxy pipeline stalling
	}
}

// BroadcastMetrics pushes live aggregate stats to the dashboard
func (h *Hub) BroadcastMetrics(stats interface{}) {
	msg, err := json.Marshal(map[string]interface{}{
		"type":  "METRICS_UPDATE",
		"stats": stats,
	})
	if err != nil {
		return
	}

	select {
	case h.broadcast <- msg:
	default:
	}
}

// ClearEvents empties the recent events ring buffer
func (h *Hub) ClearEvents() {
	h.ringMutex.Lock()
	defer h.ringMutex.Unlock()
	h.recentEvents = make([]SecurityEvent, 0, 150)
}

// GetRecentEvents returns a copy of recent events
func (h *Hub) GetRecentEvents() []SecurityEvent {
	h.ringMutex.RLock()
	defer h.ringMutex.RUnlock()
	res := make([]SecurityEvent, len(h.recentEvents))
	copy(res, h.recentEvents)
	return res
}

// HandleWebSocket upgrades incoming HTTP connections to WebSocket
func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] Upgrade failed: %v", err)
		return
	}

	if GlobalHub != nil {
		GlobalHub.register <- conn
	}

	// Keep alive & handle disconnect
	go func() {
		defer func() {
			if GlobalHub != nil {
				GlobalHub.unregister <- conn
			}
		}()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()
}
