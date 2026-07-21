package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"agent-gateway/internal/auth"
	"agent-gateway/internal/channel"
	"agent-gateway/internal/domain"
	"agent-gateway/internal/policy"
	"agent-gateway/internal/store"

	"github.com/gorilla/websocket"
)

type browserConnection struct {
	server    *Server
	socket    *websocket.Conn
	tenant    domain.Tenant
	principal domain.Principal
	base      *http.Request
	send      chan []byte
	done      chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
}

func (c *browserConnection) close(code int, reason string) {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		_ = c.socket.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
		_ = c.socket.Close()
		close(c.done)
	})
}

func (c *browserConnection) sendValue(value any) bool {
	raw, err := json.Marshal(value)
	if err != nil {
		return false
	}
	return c.sendRaw(raw)
}

func (c *browserConnection) sendRaw(raw []byte) bool {
	if c.closed.Load() {
		return false
	}
	select {
	case c.send <- append([]byte(nil), raw...):
		return true
	case <-c.done:
		return false
	default:
		c.close(1013, "browser write queue overflow")
		return false
	}
}

func (c *browserConnection) writeLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case raw := <-c.send:
			_ = c.socket.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if err := c.socket.WriteMessage(websocket.TextMessage, raw); err != nil {
				c.close(1001, "write failed")
				return
			}
		case <-ticker.C:
			_ = c.socket.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if err := c.socket.WriteMessage(websocket.PingMessage, nil); err != nil {
				c.close(1001, "heartbeat failed")
				return
			}
		case <-c.done:
			return
		}
	}
}

func (s *Server) handleBrowserWS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.browserOriginAllowed(r) {
		writeAPIError(w, http.StatusForbidden, "origin_forbidden", "WebSocket Origin is not allowed")
		return
	}
	upgrader := websocket.Upgrader{HandshakeTimeout: 10 * time.Second, CheckOrigin: s.browserOriginAllowed}
	socket, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	socket.SetReadLimit(s.cfg.MaxWSMessageBytes)
	conn := &browserConnection{server: s, socket: socket, tenant: tenantFromContext(r.Context()), principal: principalFromContext(r.Context()), base: r.Clone(r.Context()), send: make(chan []byte, s.cfg.WriteQueueSize), done: make(chan struct{})}
	s.browserMu.Lock()
	s.browsers[conn] = struct{}{}
	s.browserMu.Unlock()
	defer func() {
		conn.close(1000, "connection closed")
		s.browserMu.Lock()
		delete(s.browsers, conn)
		s.browserMu.Unlock()
	}()
	go conn.writeLoop()
	conn.sendValue(map[string]any{"frame": channel.FramePush, "type": "connected", "data": map[string]any{"gateway": true, "authenticated": conn.principal.Authenticated, "timestamp": time.Now().UnixMilli()}})
	_ = socket.SetReadDeadline(time.Now().Add(90 * time.Second))
	socket.SetPongHandler(func(string) error { return socket.SetReadDeadline(time.Now().Add(90 * time.Second)) })
	for {
		messageType, raw, err := socket.ReadMessage()
		if err != nil {
			return
		}
		if messageType != websocket.TextMessage {
			continue
		}
		var request channel.RequestFrame
		if err := json.Unmarshal(raw, &request); err != nil || request.Frame != channel.FrameRequest || strings.TrimSpace(request.ID) == "" || strings.TrimSpace(request.Type) == "" {
			conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "invalid_request", ID: request.ID, Code: http.StatusBadRequest, Msg: "a request frame with type and id is required"})
			continue
		}
		go s.dispatchBrowserRequest(conn, request)
	}
}

func (s *Server) dispatchBrowserRequest(conn *browserConnection, request channel.RequestFrame) {
	if !s.limiter.Allow([]string{"tenant:" + conn.tenant.ID, "principal:" + conn.tenant.ID + ":" + conn.principal.OwnerKind() + ":" + conn.principal.OwnerID()}, time.Now()) {
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "rate_limited", ID: request.ID, Code: http.StatusTooManyRequests, Msg: "Request rate limit exceeded"})
		return
	}
	switch request.Type {
	case "/api/query":
		s.proxyBrowserQuery(conn, request)
	case "/api/attach":
		s.proxyBrowserAttach(conn, request)
	case "/api/agents", "/api/agent", "/api/chats", "/api/chat", "/api/gateway/session",
		"/api/chats/search", "/api/archives", "/api/archive", "/api/archives/search", "/api/archive/delete", "/api/archive/restore", "/api/chat/archive",
		"/api/viewport",
		"/api/submit", "/api/steer", "/api/interrupt", "/api/detach", "/api/read", "/api/feedback",
		"/api/chat/rename", "/api/chat/derive", "/api/chat/delete":
		s.proxyBrowserRPC(conn, request)
	default:
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "route_not_found", ID: request.ID, Code: http.StatusNotFound, Msg: "Gateway does not expose this platform route"})
	}
}

func decodeRequestMap(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	body := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		return nil, err
	}
	return body, nil
}

func (s *Server) proxyBrowserQuery(conn *browserConnection, request channel.RequestFrame) {
	body, err := decodeRequestMap(request.Payload)
	if err != nil {
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "invalid_request", ID: request.ID, Code: 400, Msg: err.Error()})
		return
	}
	requestContext := conn.base.Clone(conn.base.Context())
	requestContext.Header = conn.base.Header.Clone()
	requestContext.Header.Del("Idempotency-Key")
	agent, chat, run, requestID, replay, err := s.prepareQuery(requestContext, body)
	if err != nil {
		s.sendBrowserRelayError(conn, request.ID, err)
		return
	}
	ownerRef := auth.OwnerReference(s.cfg.TenantHMACSecret, chat.TenantID, conn.principal.OwnerKind(), conn.principal.OwnerID())
	release, acquired := s.limiter.Acquire(streamLimitKeys(agent, conn.principal))
	if !acquired {
		_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "rate_limited", run.LastSeq, time.Now().UnixMilli())
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "concurrency_limited", ID: request.ID, Code: 429, Msg: "Concurrent stream limit exceeded"})
		return
	}
	defer release()
	requestType := "/api/query"
	payload := upstreamQueryPayload(body, agent, chat, run, requestID, ownerRef)
	if replay {
		requestType = "/api/attach"
		payload = map[string]any{"runId": run.RunID, "externalAgentKey": agent.Route.ExternalAgentKey, "lastSeq": run.LastSeq}
	}
	s.proxyBrowserStream(conn, request.ID, requestType, payload, agent, run)
}

func (s *Server) proxyBrowserAttach(conn *browserConnection, request channel.RequestFrame) {
	body, err := decodeRequestMap(request.Payload)
	if err != nil {
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "invalid_request", ID: request.ID, Code: 400, Msg: err.Error()})
		return
	}
	runID := textValue(body["runId"])
	run, err := s.store.RunBinding(conn.base.Context(), conn.tenant.ID, runID)
	if err != nil {
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "run_not_found", ID: request.ID, Code: 404, Msg: "Run was not found"})
		return
	}
	chat, err := s.store.ChatBinding(conn.base.Context(), conn.tenant.ID, run.ChatID)
	if err != nil {
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "chat_not_found", ID: request.ID, Code: 404, Msg: "Chat was not found"})
		return
	}
	agent, err := s.bindingAgent(conn.base, chat, domain.PermissionRunControl)
	if err != nil || !routeOperationAllowed(agent, "attach") {
		s.sendBrowserRelayError(conn, request.ID, store.ErrNotFound)
		return
	}
	lastSeq := numberValue(body["lastSeq"])
	payload := map[string]any{"runId": run.RunID, "externalAgentKey": agent.Route.ExternalAgentKey, "lastSeq": lastSeq}
	s.proxyBrowserStream(conn, request.ID, "/api/attach", payload, agent, run)
}

func (s *Server) proxyBrowserStream(conn *browserConnection, frontendID, requestType string, payload any, agent domain.GatewayAgent, run domain.RunBinding) {
	frames, cleanup, err := s.channels.Call(conn.base.Context(), agent.Route, requestType, payload)
	if err != nil {
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "platform_offline", ID: frontendID, Code: 503, Msg: "Platform channel is offline"})
		return
	}
	defer cleanup()
	terminal := false
	for raw := range frames {
		var object map[string]any
		if json.Unmarshal(raw, &object) != nil {
			conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "invalid_upstream_frame", ID: frontendID, Code: 502, Msg: "Platform returned an invalid frame"})
			return
		}
		object["id"] = frontendID
		if data, ok := object["data"].(map[string]any); ok {
			rewriteKnownOwnerFields(data, agent.PublicKey)
		}
		if event, ok := object["event"].(map[string]any); ok {
			s.recordViewportData(run, event)
			rewriteKnownOwnerFields(event, agent.PublicKey)
		}
		if number := numberValue(object["lastSeq"]); number > run.LastSeq {
			run.LastSeq = number
			_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "running", run.LastSeq, time.Now().UnixMilli())
		}
		if !conn.sendValue(object) {
			return
		}
		if object["frame"] == channel.FrameError {
			_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "error", run.LastSeq, time.Now().UnixMilli())
			return
		}
		if object["frame"] == channel.FrameResponse || object["frame"] == channel.FrameStream && object["event"] == nil {
			terminal = true
		}
	}
	if terminal {
		_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "completed", run.LastSeq, time.Now().UnixMilli())
		return
	}
	_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "upstream_unavailable", run.LastSeq, time.Now().UnixMilli())
	conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "platform_disconnected", ID: frontendID, Code: http.StatusServiceUnavailable, Msg: "Platform channel disconnected before the run completed"})
}

func (s *Server) sendBrowserRelayError(conn *browserConnection, requestID string, err error) {
	code := http.StatusBadRequest
	typeName := "invalid_request"
	message := err.Error()
	if errors.Is(err, store.ErrNotFound) {
		code = http.StatusForbidden
		typeName = "forbidden"
		message = "Agent or resource is not available to this user"
		if !conn.principal.Authenticated {
			code = http.StatusUnauthorized
			typeName = "auth.required"
			message = "Authentication is required"
		}
	} else if errors.Is(err, store.ErrConflict) {
		code = http.StatusConflict
		typeName = "conflict"
	} else if errors.Is(err, errRateLimited) {
		code = http.StatusTooManyRequests
		typeName = "rate_limited"
	}
	conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: typeName, ID: requestID, Code: code, Msg: message})
}

type captureWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *captureWriter) Header() http.Header { return w.header }
func (w *captureWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *captureWriter) Write(raw []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(raw)
}

func (s *Server) proxyBrowserRPC(conn *browserConnection, request channel.RequestFrame) {
	method := http.MethodPost
	u := &url.URL{Path: request.Type}
	if request.Type == "/api/agents" || request.Type == "/api/agent" || request.Type == "/api/chats" || request.Type == "/api/chat" || request.Type == "/api/archives" || request.Type == "/api/archive" || request.Type == "/api/viewport" || request.Type == "/api/gateway/session" {
		method = http.MethodGet
	}
	params, err := decodeRequestMap(request.Payload)
	if err != nil {
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "invalid_request", ID: request.ID, Code: 400, Msg: err.Error()})
		return
	}
	if method == http.MethodGet {
		query := url.Values{}
		for key, value := range params {
			switch typed := value.(type) {
			case string:
				query.Set(key, typed)
			case bool:
				query.Set(key, strconv.FormatBool(typed))
			case json.Number:
				query.Set(key, typed.String())
			}
		}
		u.RawQuery = query.Encode()
	}
	body := io.NopCloser(bytes.NewReader(request.Payload))
	httpRequest := &http.Request{Method: method, URL: u, Header: conn.base.Header.Clone(), Body: body, Host: conn.base.Host}
	httpRequest = httpRequest.WithContext(conn.base.Context())
	w := &captureWriter{header: make(http.Header)}
	switch request.Type {
	case "/api/agents":
		s.handleAgents(w, httpRequest)
	case "/api/agent":
		s.handleAgent(w, httpRequest)
	case "/api/chats":
		s.handleChats(w, httpRequest)
	case "/api/chat":
		s.handleChat(w, httpRequest)
	case "/api/gateway/session":
		s.handleSession(w, httpRequest)
	case "/api/viewport":
		s.handleViewport(w, httpRequest)
	case "/api/chats/search", "/api/archives", "/api/archive", "/api/archives/search", "/api/archive/delete", "/api/archive/restore", "/api/chat/archive":
		s.handleHistory(w, httpRequest)
	case "/api/submit", "/api/steer", "/api/interrupt", "/api/detach":
		s.handleRunControl(w, httpRequest)
	default:
		s.handleChatMutation(w, httpRequest)
	}
	var envelope struct {
		Code int             `json:"code"`
		Msg  string          `json:"msg"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(w.body.Bytes(), &envelope) != nil {
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: "internal_error", ID: request.ID, Code: 500, Msg: "Gateway returned an invalid internal response"})
		return
	}
	if w.status >= 400 {
		var errorData struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(envelope.Data, &errorData)
		if errorData.Error.Code == "" {
			errorData.Error.Code = "request_failed"
		}
		if errorData.Error.Message == "" {
			errorData.Error.Message = http.StatusText(w.status)
		}
		conn.sendValue(channel.ErrorFrame{Frame: channel.FrameError, Type: errorData.Error.Code, ID: request.ID, Code: w.status, Msg: errorData.Error.Message})
		return
	}
	conn.sendValue(channel.ResponseFrame{Frame: channel.FrameResponse, Type: request.Type, ID: request.ID, Code: 0, Msg: "success", Data: dataOrEmpty(envelope.Data)})
}

func (s *Server) handlePlatformPush(identity auth.PlatformIdentity, raw []byte) {
	var frame map[string]any
	if json.Unmarshal(raw, &frame) != nil {
		return
	}
	data, _ := frame["data"].(map[string]any)
	chatID := textValue(data["chatId"])
	runID := textValue(data["runId"])
	var pushedRun domain.RunBinding
	if payload, ok := data["payload"].(map[string]any); ok {
		if chatID == "" {
			chatID = textValue(payload["chatId"])
		}
		if runID == "" {
			runID = textValue(payload["runId"])
		}
	}
	if chatID == "" && runID != "" {
		if run, err := s.store.RunBinding(context.Background(), identity.TenantID, runID); err == nil {
			pushedRun = run
			chatID = run.ChatID
		}
	}
	if chatID == "" {
		return
	}
	chat, err := s.store.ChatBinding(context.Background(), identity.TenantID, chatID)
	if err != nil {
		return
	}
	agent, err := s.store.AgentByID(context.Background(), identity.TenantID, chat.AgentID)
	if err != nil || agent.Route.PlatformID != identity.PlatformID || agent.Route.ChannelID != identity.ChannelID || agent.RouteID != chat.RouteID {
		return
	}
	if pushedRun.RunID == "" && runID != "" {
		pushedRun, _ = s.store.RunBinding(context.Background(), identity.TenantID, runID)
	}
	if pushedRun.RouteID == agent.RouteID && data != nil {
		s.recordViewportData(pushedRun, data)
	}
	if data != nil {
		rewriteKnownOwnerFields(data, agent.PublicKey)
	}
	rewritten, _ := json.Marshal(frame)
	s.browserMu.RLock()
	connections := make([]*browserConnection, 0, len(s.browsers))
	for conn := range s.browsers {
		connections = append(connections, conn)
	}
	s.browserMu.RUnlock()
	for _, conn := range connections {
		if conn.tenant.ID == chat.TenantID && conn.principal.OwnerKind() == chat.OwnerKind && conn.principal.OwnerID() == chat.OwnerID && policy.Can(agent, conn.principal, domain.PermissionHistoryRead) {
			conn.sendRaw(rewritten)
		}
	}
}
