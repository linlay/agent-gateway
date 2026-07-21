package channel

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"agent-gateway/internal/auth"
	"agent-gateway/internal/domain"
	"agent-gateway/internal/id"
	"agent-gateway/internal/store"

	"github.com/gorilla/websocket"
)

type sessionKey struct{ tenantID, platformID, channelID string }

var ErrOffline = errors.New("platform channel is offline")

type stagedSnapshot struct {
	begin CatalogBegin
	cards map[string]CardUpdate
}

type PushHandler func(identity auth.PlatformIdentity, raw []byte)

type Manager struct {
	store           store.Store
	tokens          *auth.PlatformTokens
	logger          *slog.Logger
	maxMessageBytes int64
	writeQueueSize  int
	requestTimeout  time.Duration

	mu          sync.RWMutex
	sessions    map[sessionKey]*Session
	pushHandler PushHandler
	upgrader    websocket.Upgrader
}

func NewManager(st store.Store, tokens *auth.PlatformTokens, logger *slog.Logger, maxMessageBytes int64, writeQueueSize int, requestTimeout time.Duration) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	if maxMessageBytes <= 0 {
		maxMessageBytes = 1 << 20
	}
	if writeQueueSize <= 0 {
		writeQueueSize = 256
	}
	if requestTimeout <= 0 {
		requestTimeout = 30 * time.Second
	}
	return &Manager{store: st, tokens: tokens, logger: logger, maxMessageBytes: maxMessageBytes, writeQueueSize: writeQueueSize, requestTimeout: requestTimeout, sessions: map[sessionKey]*Session{}, upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, HandshakeTimeout: 10 * time.Second}}
}

func (m *Manager) SetPushHandler(handler PushHandler) {
	m.mu.Lock()
	m.pushHandler = handler
	m.mu.Unlock()
}

func (m *Manager) ServePlatformHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authorization, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	identity, err := m.tokens.Verify(r.Context(), strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer ")))
	if err != nil {
		m.logger.Warn("platform websocket authentication failed", "error", err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	channelID := strings.TrimSpace(r.URL.Query().Get("channelId"))
	if channelID == "" {
		channelID = strings.TrimSpace(r.URL.Query().Get("channel"))
	}
	if channelID == "" || channelID != identity.ChannelID {
		http.Error(w, "channelId does not match credential", http.StatusForbidden)
		return
	}
	platform, err := m.store.Platform(r.Context(), identity.TenantID, identity.PlatformID)
	if err != nil || !platform.Enabled {
		http.Error(w, "platform is disabled", http.StatusForbidden)
		return
	}
	socket, err := m.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	socket.SetReadLimit(m.maxMessageBytes)
	session := newSession(identity, socket, m.writeQueueSize, m.logger)
	key := sessionKey{identity.TenantID, identity.PlatformID, identity.ChannelID}
	m.mu.Lock()
	previous := m.sessions[key]
	m.sessions[key] = session
	m.mu.Unlock()
	if previous != nil {
		previous.Close(4009, "superseded by a newer channel connection")
	}
	_ = m.store.MarkChannelStatus(context.Background(), identity.TenantID, identity.PlatformID, identity.ChannelID, "online", time.Now().UnixMilli())
	m.logger.Info("platform channel connected", "tenant", identity.TenantID, "platform", identity.PlatformID, "channel", identity.ChannelID, "session", session.id)
	session.Run(func(raw []byte) { m.handleInbound(session, raw) })
	m.mu.Lock()
	isCurrent := false
	if m.sessions[key] == session {
		delete(m.sessions, key)
		isCurrent = true
	}
	m.mu.Unlock()
	if isCurrent {
		_ = m.store.MarkChannelStatus(context.Background(), identity.TenantID, identity.PlatformID, identity.ChannelID, "offline", time.Now().UnixMilli())
	}
	m.logger.Info("platform channel disconnected", "tenant", identity.TenantID, "platform", identity.PlatformID, "channel", identity.ChannelID, "session", session.id)
}

func (m *Manager) Connected(route domain.Route) bool {
	m.mu.RLock()
	session := m.sessions[sessionKey{route.TenantID, route.PlatformID, route.ChannelID}]
	m.mu.RUnlock()
	return session != nil && !session.Closed()
}

func (m *Manager) Call(ctx context.Context, route domain.Route, requestType string, payload any) (<-chan []byte, func(), error) {
	m.mu.RLock()
	session := m.sessions[sessionKey{route.TenantID, route.PlatformID, route.ChannelID}]
	m.mu.RUnlock()
	if session == nil || session.Closed() {
		return nil, nil, ErrOffline
	}
	requestID := id.New("up")
	frame := RequestFrame{Frame: FrameRequest, Type: requestType, ID: requestID, Payload: Payload(payload)}
	frames, cleanup, err := session.OpenRequest(frame)
	if err != nil {
		return nil, nil, ErrOffline
	}
	if requestType == "/api/query" || requestType == "/api/attach" {
		forwarded := make(chan []byte, 64)
		forwardCtx, cancel := context.WithCancel(ctx)
		var once sync.Once
		stop := func() { once.Do(func() { cancel(); cleanup() }) }
		go func() {
			defer close(forwarded)
			defer stop()
			timer := time.NewTimer(m.requestTimeout)
			defer timer.Stop()
			first := true
			for {
				select {
				case raw, ok := <-frames:
					if !ok {
						return
					}
					if first {
						first = false
						if !timer.Stop() {
							select {
							case <-timer.C:
							default:
							}
						}
					}
					select {
					case forwarded <- raw:
					case <-forwardCtx.Done():
						return
					}
				case <-timer.C:
					if first {
						return
					}
				case <-forwardCtx.Done():
					return
				case <-session.done:
					return
				}
			}
		}()
		return forwarded, stop, nil
	}
	if requestType != "/api/query" && requestType != "/api/attach" {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > m.requestTimeout {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, m.requestTimeout)
			previous := cleanup
			cleanup = func() { cancel(); previous() }
		}
	}
	go func() {
		select {
		case <-ctx.Done():
			cleanup()
		case <-session.done:
		}
	}()
	return frames, cleanup, nil
}

func (m *Manager) handleInbound(session *Session, raw []byte) {
	var header struct {
		Frame string `json:"frame"`
		Type  string `json:"type"`
		ID    string `json:"id"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		session.Send(ErrorFrame{Frame: FrameError, Type: "invalid_request", Code: 400, Msg: "invalid json frame"})
		return
	}
	switch header.Frame {
	case FrameRequest:
		var request RequestFrame
		if err := json.Unmarshal(raw, &request); err != nil {
			session.Send(ErrorFrame{Frame: FrameError, Type: "invalid_request", ID: header.ID, Code: 400, Msg: "invalid request frame"})
			return
		}
		m.handlePlatformRequest(session, request)
	case FrameResponse, FrameError, FrameStream:
		session.Deliver(header.ID, raw, header.Frame)
	case FramePush:
		m.mu.RLock()
		handler := m.pushHandler
		m.mu.RUnlock()
		if handler != nil {
			handler(session.identity, raw)
		}
	default:
		session.Send(ErrorFrame{Frame: FrameError, Type: "invalid_request", ID: header.ID, Code: 400, Msg: "unsupported frame"})
	}
}

func (m *Manager) handlePlatformRequest(session *Session, request RequestFrame) {
	switch request.Type {
	case "agent.catalog.begin":
		m.catalogBegin(session, request)
	case "agent.card.update":
		m.cardUpdate(session, request)
	case "agent.catalog.commit":
		m.catalogCommit(session, request)
	default:
		session.Send(ErrorFrame{Frame: FrameError, Type: "not_found", ID: request.ID, Code: 404, Msg: "unsupported platform-originated request type"})
	}
}

func (m *Manager) catalogBegin(session *Session, request RequestFrame) {
	var begin CatalogBegin
	if err := json.Unmarshal(request.Payload, &begin); err != nil || strings.TrimSpace(begin.SnapshotID) == "" || begin.Revision < 0 || begin.CardCount < 0 {
		session.Send(ErrorFrame{Frame: FrameError, Type: "invalid_request", ID: request.ID, Code: 400, Msg: "invalid catalog snapshot"})
		return
	}
	if begin.CardCount > 10000 {
		session.Send(ErrorFrame{Frame: FrameError, Type: "invalid_request", ID: request.ID, Code: 413, Msg: "catalog snapshot is too large"})
		return
	}
	if err := m.store.BeginCatalogSnapshot(context.Background(), session.identity.TenantID, session.identity.PlatformID, session.identity.ChannelID, begin); err != nil {
		session.Send(ErrorFrame{Frame: FrameError, Type: "internal_error", ID: request.ID, Code: 500, Msg: "could not begin catalog snapshot"})
		return
	}
	session.stageMu.Lock()
	session.stage = &stagedSnapshot{begin: begin, cards: map[string]CardUpdate{}}
	session.stageMu.Unlock()
	session.Send(ResponseFrame{Frame: FrameResponse, Type: request.Type, ID: request.ID, Code: 0, Msg: "success", Data: map[string]any{"snapshotId": begin.SnapshotID, "accepted": true}})
}

func validateCard(update CardUpdate) error {
	if strings.TrimSpace(update.AgentKey) == "" || len(update.AgentKey) > 128 {
		return errors.New("invalid agentKey")
	}
	if strings.TrimSpace(update.AgentCard.Name) == "" || len([]rune(update.AgentCard.Name)) > 256 {
		return errors.New("invalid agentCard.name")
	}
	if len([]rune(update.AgentCard.Description)) > 4096 {
		return errors.New("agentCard.description is too long")
	}
	if len(update.AgentCard.Skills) > 256 || len(update.AgentCard.Tools) > 256 {
		return errors.New("agentCard has too many features")
	}
	return nil
}

func (m *Manager) cardUpdate(session *Session, request RequestFrame) {
	var update CardUpdate
	if err := json.Unmarshal(request.Payload, &update); err != nil || validateCard(update) != nil {
		session.Send(ErrorFrame{Frame: FrameError, Type: "invalid_request", ID: request.ID, Code: 400, Msg: "invalid agent card"})
		return
	}
	update.AgentKey = strings.TrimSpace(update.AgentKey)
	if update.SnapshotID != "" {
		session.stageMu.Lock()
		stage := session.stage
		if stage == nil || stage.begin.SnapshotID != update.SnapshotID || stage.begin.Revision != update.Revision {
			session.stageMu.Unlock()
			session.Send(ErrorFrame{Frame: FrameError, Type: "conflict", ID: request.ID, Code: 409, Msg: "catalog snapshot is not active"})
			return
		}
		if _, exists := stage.cards[update.AgentKey]; exists {
			session.stageMu.Unlock()
			session.Send(ErrorFrame{Frame: FrameError, Type: "conflict", ID: request.ID, Code: 409, Msg: "duplicate agentKey in snapshot"})
			return
		}
		if len(stage.cards) >= stage.begin.CardCount {
			session.stageMu.Unlock()
			session.Send(ErrorFrame{Frame: FrameError, Type: "conflict", ID: request.ID, Code: 409, Msg: "catalog snapshot exceeds declared cardCount"})
			return
		}
		stage.cards[update.AgentKey] = update
		session.stageMu.Unlock()
	} else {
		if _, err := m.store.UpsertLegacyCard(context.Background(), session.identity.TenantID, session.identity.PlatformID, session.identity.ChannelID, update, time.Now().UnixMilli()); err != nil {
			session.Send(ErrorFrame{Frame: FrameError, Type: "internal_error", ID: request.ID, Code: 500, Msg: "could not store agent card"})
			return
		}
	}
	accepted := true
	session.Send(ResponseFrame{Frame: FrameResponse, Type: request.Type, ID: request.ID, Code: 0, Msg: "success", Data: map[string]any{"agentKey": update.AgentKey, "accepted": accepted}})
}

func (m *Manager) catalogCommit(session *Session, request RequestFrame) {
	var commit CatalogCommit
	if err := json.Unmarshal(request.Payload, &commit); err != nil || commit.SnapshotID == "" {
		session.Send(ErrorFrame{Frame: FrameError, Type: "invalid_request", ID: request.ID, Code: 400, Msg: "invalid catalog commit"})
		return
	}
	session.stageMu.Lock()
	stage := session.stage
	if stage == nil || stage.begin.SnapshotID != commit.SnapshotID {
		session.stageMu.Unlock()
		session.Send(ErrorFrame{Frame: FrameError, Type: "conflict", ID: request.ID, Code: 409, Msg: "catalog snapshot is not active"})
		return
	}
	cards := make([]CardUpdate, 0, len(stage.cards))
	for _, card := range stage.cards {
		cards = append(cards, card)
	}
	if stage.begin.CardCount != len(cards) || commit.CardCount != len(cards) || commit.Revision != stage.begin.Revision {
		session.stageMu.Unlock()
		session.Send(ErrorFrame{Frame: FrameError, Type: "conflict", ID: request.ID, Code: 409, Msg: "catalog snapshot count or revision mismatch"})
		return
	}
	session.stage = nil
	session.stageMu.Unlock()
	if err := m.store.ApplyCatalogSnapshot(context.Background(), session.identity.TenantID, session.identity.PlatformID, session.identity.ChannelID, stage.begin, cards, time.Now().UnixMilli()); err != nil {
		session.Send(ErrorFrame{Frame: FrameError, Type: "internal_error", ID: request.ID, Code: 500, Msg: "could not commit catalog snapshot"})
		return
	}
	session.Send(ResponseFrame{Frame: FrameResponse, Type: request.Type, ID: request.ID, Code: 0, Msg: "success", Data: map[string]any{"snapshotId": commit.SnapshotID, "accepted": true, "cardCount": len(cards)}})
}

func (m *Manager) Close() {
	m.mu.Lock()
	sessions := m.sessions
	m.sessions = map[sessionKey]*Session{}
	m.mu.Unlock()
	for _, session := range sessions {
		session.Close(1001, "gateway shutdown")
	}
}

func (m *Manager) ConnectionCount() int { m.mu.RLock(); defer m.mu.RUnlock(); return len(m.sessions) }

func (m *Manager) InflightCount() int {
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	m.mu.RUnlock()
	total := 0
	for _, session := range sessions {
		total += session.PendingCount()
	}
	return total
}
