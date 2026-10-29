// Package controlchannel implements a minimal Engine.IO v4 / Socket.IO v4 client over a raw
// WebSocket connection — the Linux port of RemoteAssistSocket.cs. Deliberately hand-rolled rather
// than a third-party Socket.IO client library: the wire protocol is small and well-documented
// (a handful of single-digit packet-type prefixes), and hand-rolling it means no dependency on an
// unmaintained/unverified Go Socket.IO client package for a security-relevant control channel.
//
// WebSocket-only (no HTTP long-polling fallback) — unlike the docs/ARCHITECTURE.md invariant "keep Socket.IO
// transport order ['polling', 'websocket']" (which matters for a BROWSER hitting
// app.example.com through real Cloudflare proxying), this client's connection is carried
// through the local xray/REALITY tunnel, not through Cloudflare's HTTP edge — the polling-first
// requirement doesn't apply to this path. Engine.IO's protocol explicitly supports starting a
// connection directly over WebSocket (no prior polling handshake required).
package controlchannel

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Engine.IO packet types (single-digit prefix on every frame).
const (
	eioOpen    = '0'
	eioClose   = '1'
	eioPing    = '2'
	eioPong    = '3'
	eioMessage = '4'
	eioUpgrade = '5'
	eioNoop    = '6'
)

// Socket.IO packet types (follow the eioMessage prefix).
const (
	sioConnect      = '0'
	sioDisconnect   = '1'
	sioEvent        = '2'
	sioAck          = '3'
	sioConnectError = '4'
)

type openPacket struct {
	SID          string   `json:"sid"`
	Upgrades     []string `json:"upgrades"`
	PingInterval int      `json:"pingInterval"`
	PingTimeout  int      `json:"pingTimeout"`
}

// Client is a connected Socket.IO session. Not safe for concurrent Emit calls with itself beyond
// what gorilla/websocket already serializes internally — callers should serialize writes (the
// daemon has exactly one control-channel client, so this hasn't needed a write-mutex in practice,
// but Emit takes one anyway since a health-check goroutine and an event handler could plausibly
// both want to emit around the same time).
type Client struct {
	conn *websocket.Conn

	writeMu sync.Mutex

	handlersMu sync.RWMutex
	handlers   map[string][]func(json.RawMessage)

	closeOnce sync.Once
	closed    chan struct{}

	pingInterval time.Duration
	pingTimeout  time.Duration
}

// Connect performs the full Engine.IO + Socket.IO v4 handshake against baseURL (e.g.
// "http://127.0.0.1:<controlPort>" when dialing through the local xray dokodemo-door, matching
// RemoteAssistSocket.cs's controlUrl construction) at path "/socket.io", authenticates with
// authPayload as the Socket.IO CONNECT packet's auth data, and returns a live Client. Blocks until
// either the full handshake completes or an error/timeout occurs.
func Connect(baseURL string, authPayload any, extraHeaders map[string]string) (*Client, error) {
	wsURL, err := toWebSocketURL(baseURL)
	if err != nil {
		return nil, err
	}

	header := make(map[string][]string, len(extraHeaders))
	for k, v := range extraHeaders {
		header[k] = []string{v}
	}

	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	c := &Client{
		conn:     conn,
		handlers: make(map[string][]func(json.RawMessage)),
		closed:   make(chan struct{}),
	}

	if err := c.completeHandshake(authPayload); err != nil {
		conn.Close()
		return nil, err
	}

	go c.readLoop()
	go c.pingWatchdog()

	return c, nil
}

func toWebSocketURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL: %w", err)
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		// already correct
	default:
		return "", fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	u.Path = "/socket.io/"
	u.RawQuery = "EIO=4&transport=websocket"
	return u.String(), nil
}

func (c *Client) completeHandshake(authPayload any) error {
	c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	// 1) Engine.IO open packet: "0{...}".
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read engine.io open packet: %w", err)
	}
	if len(msg) == 0 || msg[0] != eioOpen {
		return fmt.Errorf("expected engine.io open packet, got: %q", msg)
	}
	var open openPacket
	if err := json.Unmarshal(msg[1:], &open); err != nil {
		return fmt.Errorf("parse engine.io open payload: %w", err)
	}
	c.pingInterval = time.Duration(open.PingInterval) * time.Millisecond
	c.pingTimeout = time.Duration(open.PingTimeout) * time.Millisecond

	// 2) Socket.IO CONNECT packet, default namespace: "40{...auth...}".
	authJSON, err := json.Marshal(authPayload)
	if err != nil {
		return fmt.Errorf("marshal auth payload: %w", err)
	}
	connectFrame := append([]byte{eioMessage, sioConnect}, authJSON...)
	if err := c.conn.WriteMessage(websocket.TextMessage, connectFrame); err != nil {
		return fmt.Errorf("write socket.io connect packet: %w", err)
	}

	// 3) Server's CONNECT ack ("40{...}") or CONNECT_ERROR ("44{...}").
	_, msg, err = c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read socket.io connect ack: %w", err)
	}
	if len(msg) < 2 || msg[0] != eioMessage {
		return fmt.Errorf("expected engine.io message frame for connect ack, got: %q", msg)
	}
	switch msg[1] {
	case sioConnect:
		return nil
	case sioConnectError:
		return fmt.Errorf("socket.io connect rejected: %s", msg[2:])
	default:
		return fmt.Errorf("unexpected socket.io packet type %q during handshake", msg[1])
	}
}

// On registers a handler for a named event (e.g. "registered", "command", "hop2_session_open").
// Multiple handlers may be registered for the same event; all are called, in registration order.
func (c *Client) On(event string, handler func(json.RawMessage)) {
	c.handlersMu.Lock()
	defer c.handlersMu.Unlock()
	c.handlers[event] = append(c.handlers[event], handler)
}

// Emit sends a Socket.IO EVENT packet: 42["event", payload].
func (c *Client) Emit(event string, payload any) error {
	arr := []any{event, payload}
	body, err := json.Marshal(arr)
	if err != nil {
		return fmt.Errorf("marshal emit payload: %w", err)
	}
	frame := append([]byte{eioMessage, sioEvent}, body...)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteMessage(websocket.TextMessage, frame)
}

// Done returns a channel closed when the connection has terminated (read loop exited).
func (c *Client) Done() <-chan struct{} { return c.closed }

func (c *Client) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.conn.Close()
}

func (c *Client) readLoop() {
	defer c.closeOnce.Do(func() { close(c.closed) })
	defer c.conn.Close()

	for {
		c.conn.SetReadDeadline(time.Now().Add(c.pingTimeout + c.pingInterval))
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		if len(msg) == 0 {
			continue
		}

		switch msg[0] {
		case eioPing:
			// Engine.IO v4: SERVER sends ping, client responds pong (flipped from v3).
			c.writeMu.Lock()
			_ = c.conn.WriteMessage(websocket.TextMessage, []byte{eioPong})
			c.writeMu.Unlock()
		case eioNoop, eioClose:
			// eioClose: server-initiated close — let the next read fail naturally, nothing to do.
		case eioMessage:
			if len(msg) < 2 {
				continue
			}
			c.dispatchSocketIO(msg[1:])
		}
	}
}

func (c *Client) dispatchSocketIO(msg []byte) {
	if len(msg) == 0 {
		return
	}
	switch msg[0] {
	case sioEvent:
		c.dispatchEvent(msg[1:])
	case sioDisconnect:
		// Server-initiated disconnect at the Socket.IO layer — the underlying Engine.IO
		// connection may still be open, but there's nothing meaningful left to do here beyond
		// what the eventual read error / Close() already handles.
	}
}

func (c *Client) dispatchEvent(body []byte) {
	var raw []json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || len(raw) == 0 {
		return
	}
	var eventName string
	if err := json.Unmarshal(raw[0], &eventName); err != nil {
		return
	}

	var payload json.RawMessage
	if len(raw) > 1 {
		payload = raw[1]
	} else {
		payload = json.RawMessage("null")
	}

	c.handlersMu.RLock()
	handlers := append([]func(json.RawMessage){}, c.handlers[eventName]...)
	c.handlersMu.RUnlock()

	for _, h := range handlers {
		h(payload)
	}
}

// pingWatchdog is a safety net, not the primary keepalive mechanism (the server drives ping
// cadence per the Engine.IO v4 spec, handled inline in readLoop) — it exists only so a
// completely silent connection (no ping ever arrives, e.g. a NAT/middlebox black-holing the
// connection without an RST) still gets noticed and torn down within one ping interval + timeout,
// rather than hanging forever on a read that will never unblock on its own.
func (c *Client) pingWatchdog() {
	if c.pingInterval <= 0 {
		return
	}
	ticker := time.NewTicker(c.pingInterval + c.pingTimeout)
	defer ticker.Stop()
	select {
	case <-c.closed:
	case <-ticker.C:
		// SetReadDeadline in readLoop already handles the actual timeout/close; this goroutine's
		// only job is to exist so a future health-check hook has somewhere to attach without
		// restructuring readLoop.
	}
}
