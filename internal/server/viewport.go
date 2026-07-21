package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"agent-gateway/internal/domain"
)

func viewportKeyFromData(value map[string]any) string {
	if key := textValue(value["viewportKey"]); key != "" {
		return key
	}
	for _, field := range []string{"payload", "awaiting", "data"} {
		if nested, ok := value[field].(map[string]any); ok {
			if key := textValue(nested["viewportKey"]); key != "" {
				return key
			}
		}
	}
	return ""
}

func (s *Server) recordViewportEvent(run domain.RunBinding, raw json.RawMessage) {
	var value map[string]any
	if json.Unmarshal(raw, &value) == nil {
		s.recordViewportData(run, value)
	}
}

func (s *Server) recordViewportData(run domain.RunBinding, value map[string]any) {
	viewportKey := viewportKeyFromData(value)
	if viewportKey == "" || len(viewportKey) > 256 || run.RunID == "" {
		return
	}
	now := time.Now().UnixMilli()
	_ = s.store.PutViewportBinding(context.Background(), domain.ViewportBinding{TenantID: run.TenantID, RunID: run.RunID, ChatID: run.ChatID, RouteID: run.RouteID, ViewportKey: viewportKey, CreatedAt: now, UpdatedAt: now})
}

func (s *Server) handleViewport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantFromContext(r.Context())
	runID := strings.TrimSpace(r.URL.Query().Get("runId"))
	viewportKey := strings.TrimSpace(r.URL.Query().Get("viewportKey"))
	if runID == "" || viewportKey == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "runId and viewportKey are required")
		return
	}
	viewport, err := s.store.ViewportBinding(r.Context(), tenant.ID, runID, viewportKey)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "viewport_not_found", "Viewport was not found for this run")
		return
	}
	run, err := s.store.RunBinding(r.Context(), tenant.ID, runID)
	if err != nil || run.ChatID != viewport.ChatID || run.RouteID != viewport.RouteID {
		writeAPIError(w, http.StatusNotFound, "viewport_not_found", "Viewport was not found for this run")
		return
	}
	chat, err := s.store.ChatBinding(r.Context(), tenant.ID, run.ChatID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "chat_not_found", "Chat was not found")
		return
	}
	agent, err := s.bindingAgent(r, chat, domain.PermissionHistoryRead)
	if err != nil {
		writeAPIError(w, http.StatusForbidden, "viewport_forbidden", "Viewport is not available to this user")
		return
	}
	if !s.limiter.Allow(agentRateKeys(agent), time.Now()) {
		writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "Request rate limit exceeded")
		return
	}
	frame, err := s.upstreamRPC(r.Context(), agent.Route, "/api/viewport", map[string]any{"viewportKey": viewportKey})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dataOrEmpty(rewriteRawData(frame.Data, agent.PublicKey)))
}
