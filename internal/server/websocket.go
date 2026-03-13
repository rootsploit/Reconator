package server

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// WebSocket upgrader with secure defaults
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// In production, validate origin against allowed origins
		origin := r.Header.Get("Origin")
		// Allow localhost for development
		if origin == "" || origin == "http://localhost:8888" || origin == "http://127.0.0.1:8888" {
			return true
		}
		return false
	},
	HandshakeTimeout: 10 * time.Second,
}

// WebSocketMessage represents a message to broadcast
type WebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// WebSocketClient represents a connected WebSocket client
type WebSocketClient struct {
	hub      *WebSocketHub
	conn     *websocket.Conn
	send     chan []byte
	scanID   string // Optional: subscribe to specific scan
	clientID string
}

// WebSocketHub manages WebSocket connections
type WebSocketHub struct {
	clients    map[*WebSocketClient]bool
	broadcast  chan []byte
	register   chan *WebSocketClient
	unregister chan *WebSocketClient
	mu         sync.RWMutex
}

// NewWebSocketHub creates a new WebSocket hub
func NewWebSocketHub() *WebSocketHub {
	return &WebSocketHub{
		clients:    make(map[*WebSocketClient]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *WebSocketClient),
		unregister: make(chan *WebSocketClient),
	}
}

// Run starts the WebSocket hub
func (h *WebSocketHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			// Silently track WebSocket connections

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			// Silently track WebSocket disconnections

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					// Client buffer full, close connection
					h.mu.RUnlock()
					h.mu.Lock()
					close(client.send)
					delete(h.clients, client)
					h.mu.Unlock()
					h.mu.RLock()
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast sends a message to all connected clients
func (h *WebSocketHub) Broadcast(msg WebSocketMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[WebSocket] Failed to marshal message: %v", err)
		return
	}
	h.broadcast <- data
}

// BroadcastToScan sends a message to clients subscribed to a specific scan
func (h *WebSocketHub) BroadcastToScan(scanID string, msg WebSocketMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[WebSocket] Failed to marshal message: %v", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		if client.scanID == "" || client.scanID == scanID {
			select {
			case client.send <- data:
			default:
				// Skip if buffer full
			}
		}
	}
}

// ClientCount returns the number of connected clients
func (h *WebSocketHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// handleWebSocket handles WebSocket upgrade requests
func (s *Server) handleWebSocket(c *gin.Context) {
	// Upgrade HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("[WebSocket] Upgrade failed: %v", err)
		return
	}

	// Get optional scan ID to subscribe to
	scanID := c.Query("scan_id")

	// Generate client ID
	clientID := c.ClientIP() + "-" + time.Now().Format("150405")

	client := &WebSocketClient{
		hub:      s.wsHub,
		conn:     conn,
		send:     make(chan []byte, 256),
		scanID:   scanID,
		clientID: clientID,
	}

	s.wsHub.register <- client

	// Start read and write pumps
	go client.writePump()
	go client.readPump()

	// Send welcome message
	welcome := WebSocketMessage{
		Type: "connected",
		Data: map[string]interface{}{
			"client_id": clientID,
			"scan_id":   scanID,
			"message":   "Connected to Reconator WebSocket",
		},
	}
	if data, err := json.Marshal(welcome); err == nil {
		client.send <- data
	}
}

// readPump reads messages from the WebSocket connection
func (c *WebSocketClient) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	// Configure connection
	c.conn.SetReadLimit(4096) // 4KB max message size
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[WebSocket] Read error: %v", err)
			}
			break
		}

		// Handle incoming messages (e.g., subscribe to scan)
		var msg struct {
			Type   string `json:"type"`
			ScanID string `json:"scan_id,omitempty"`
		}
		if json.Unmarshal(message, &msg) == nil {
			switch msg.Type {
			case "subscribe":
				c.scanID = msg.ScanID
				log.Printf("[WebSocket] Client %s subscribed to scan %s", c.clientID, msg.ScanID)
			case "ping":
				// Respond with pong
				if data, err := json.Marshal(WebSocketMessage{Type: "pong"}); err == nil {
					c.send <- data
				}
			}
		}
	}
}

// writePump writes messages to the WebSocket connection
func (c *WebSocketClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				// Hub closed the channel
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			// Add queued messages to current WebSocket message
			n := len(c.send)
			for i := 0; i < n; i++ {
				w.Write([]byte{'\n'})
				w.Write(<-c.send)
			}

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
