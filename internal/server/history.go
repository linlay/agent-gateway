package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"agent-gateway/internal/domain"
)

type historyRouteGroup struct {
	agent domain.GatewayAgent
	ids   []string
}

func (s *Server) historyGroups(r *http.Request, status, requestedPublicKey, permission string) (map[string]*historyRouteGroup, map[string]bool, error) {
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	bindings, err := s.store.ListChatBindings(r.Context(), tenant.ID, principal.OwnerKind(), principal.OwnerID(), "")
	if err != nil {
		return nil, nil, err
	}
	groups := map[string]*historyRouteGroup{}
	allowed := map[string]bool{}
	for _, binding := range bindings {
		if status == "archived" && binding.Status != "archived" {
			continue
		}
		if status == "active" && binding.Status == "archived" {
			continue
		}
		agent, err := s.bindingAgent(r, binding, permission)
		if err != nil || requestedPublicKey != "" && agent.PublicKey != requestedPublicKey {
			continue
		}
		entry := groups[binding.RouteID]
		if entry == nil {
			entry = &historyRouteGroup{agent: agent}
			groups[binding.RouteID] = entry
		}
		entry.ids = append(entry.ids, binding.ChatID)
		allowed[binding.ChatID] = true
	}
	return groups, allowed, nil
}

func responseCollection(raw json.RawMessage, key string) []any {
	var object map[string]any
	if json.Unmarshal(raw, &object) != nil {
		return nil
	}
	items, _ := object[key].([]any)
	return items
}

func filterHistoryItems(items []any, allowed map[string]bool, agent domain.GatewayAgent) []any {
	filtered := make([]any, 0, len(items))
	for _, value := range items {
		object, ok := value.(map[string]any)
		if !ok || !allowed[textValue(object["chatId"])] {
			continue
		}
		rewriteKnownOwnerFields(object, agent.PublicKey)
		filtered = append(filtered, object)
	}
	return filtered
}

func copyMap(value map[string]any) map[string]any {
	copy := make(map[string]any, len(value)+1)
	for key, item := range value {
		copy[key] = item
	}
	return copy
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/archives":
		s.handleArchives(w, r)
	case "/api/archive":
		s.handleHistoryDetail(w, r, true)
	case "/api/chats/search":
		s.handleHistorySearch(w, r, false)
	case "/api/archives/search":
		s.handleHistorySearch(w, r, true)
	case "/api/chat/archive":
		s.handleArchiveChange(w, r, true)
	case "/api/archive/restore":
		s.handleArchiveChange(w, r, false)
	case "/api/archive/delete":
		s.handleArchiveDelete(w, r)
	default:
		writeAPIError(w, http.StatusNotFound, "route_not_found", "History route is not exposed")
	}
}

func (s *Server) handleArchives(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	requestedAgent := strings.TrimSpace(r.URL.Query().Get("agentKey"))
	groups, allowed, err := s.historyGroups(r, "archived", requestedAgent, domain.PermissionHistoryRead)
	if err != nil {
		writeAPIError(w, 500, "archive_list_failed", err.Error())
		return
	}
	items := []any{}
	for _, group := range groups {
		frame, err := s.upstreamRPC(r.Context(), group.agent.Route, "/api/archives", map[string]any{"chatIds": group.ids, "limit": len(group.ids), "offset": 0})
		if err != nil {
			writeAPIError(w, 503, "platform_offline", "A platform holding archive history is unavailable")
			return
		}
		items = append(items, filterHistoryItems(responseCollection(frame.Data, "items"), allowed, group.agent)...)
	}
	sort.Slice(items, func(i, j int) bool {
		return numberValue(items[i].(map[string]any)["archivedAt"]) > numberValue(items[j].(map[string]any)["archivedAt"])
	})
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	total := len(items)
	if offset > len(items) {
		offset = len(items)
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	writeJSON(w, 200, map[string]any{"total": total, "items": items[offset:end]})
}

func (s *Server) handleHistoryDetail(w http.ResponseWriter, r *http.Request, archived bool) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantFromContext(r.Context())
	chatID := strings.TrimSpace(r.URL.Query().Get("chatId"))
	binding, err := s.store.ChatBinding(r.Context(), tenant.ID, chatID)
	if err != nil || archived && binding.Status != "archived" {
		writeAPIError(w, 404, "archive_not_found", "Archive was not found")
		return
	}
	agent, err := s.bindingAgent(r, binding, domain.PermissionHistoryRead)
	if err != nil {
		writeAPIError(w, 403, "forbidden", "Archive is not available to this user")
		return
	}
	frame, err := s.upstreamRPC(r.Context(), agent.Route, "/api/archive", map[string]any{"chatId": chatID, "includeRawMessages": r.URL.Query().Get("includeRawMessages") == "true"})
	if err != nil {
		writeAPIError(w, 503, "platform_offline", err.Error())
		return
	}
	writeJSON(w, 200, dataOrEmpty(rewriteRawData(frame.Data, agent.PublicKey)))
}

func (s *Server) handleHistorySearch(w http.ResponseWriter, r *http.Request, archived bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := readJSONMap(r, 1<<20)
	if err != nil || textValue(body["query"]) == "" || textValue(body["teamId"]) != "" {
		writeAPIError(w, 400, "invalid_request", "query is required and teamId is not supported")
		return
	}
	status := "active"
	requestType := "/api/chats/search"
	if archived {
		status = "archived"
		requestType = "/api/archives/search"
	}
	requestedAgent := textValue(body["agentKey"])
	groups, allowed, err := s.historyGroups(r, status, requestedAgent, domain.PermissionHistoryRead)
	if err != nil {
		writeAPIError(w, 500, "search_failed", err.Error())
		return
	}
	results := []any{}
	for _, group := range groups {
		payload := copyMap(body)
		delete(payload, "agentKey")
		delete(payload, "teamId")
		payload["chatIds"] = group.ids
		payload["limit"] = len(group.ids)
		frame, err := s.upstreamRPC(r.Context(), group.agent.Route, requestType, payload)
		if err != nil {
			writeAPIError(w, 503, "platform_offline", "A platform holding searchable history is unavailable")
			return
		}
		results = append(results, filterHistoryItems(responseCollection(frame.Data, "results"), allowed, group.agent)...)
	}
	sort.Slice(results, func(i, j int) bool {
		left := results[i].(map[string]any)
		right := results[j].(map[string]any)
		if numberValue(left["score"]) != numberValue(right["score"]) {
			return numberValue(left["score"]) > numberValue(right["score"])
		}
		return numberValue(left["timestamp"]) > numberValue(right["timestamp"])
	})
	limit := int(numberValue(body["limit"]))
	if limit <= 0 || limit > 200 {
		limit = 20
	}
	if len(results) > limit {
		results = results[:limit]
	}
	writeJSON(w, 200, map[string]any{"query": textValue(body["query"]), "count": len(results), "results": results})
}

func chatIDsFromBody(body map[string]any) []string {
	ids := []string{}
	if value := textValue(body["chatId"]); value != "" {
		ids = append(ids, value)
	}
	if values, ok := body["chatIds"].([]any); ok {
		for _, value := range values {
			if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
				ids = append(ids, strings.TrimSpace(text))
			}
		}
	}
	return ids
}

func (s *Server) handleArchiveChange(w http.ResponseWriter, r *http.Request, archive bool) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := readJSONMap(r, 1<<20)
	if err != nil {
		writeAPIError(w, 400, "invalid_request", err.Error())
		return
	}
	ids := chatIDsFromBody(body)
	if len(ids) == 0 {
		writeAPIError(w, 400, "invalid_request", "chatIds is required")
		return
	}
	tenant := tenantFromContext(r.Context())
	groups := map[string]*historyRouteGroup{}
	for _, chatID := range ids {
		binding, err := s.store.ChatBinding(r.Context(), tenant.ID, chatID)
		if err != nil {
			writeAPIError(w, 404, "chat_not_found", "Chat was not found")
			return
		}
		if archive && binding.Status == "archived" || !archive && binding.Status != "archived" {
			writeAPIError(w, 409, "invalid_chat_status", "Chat has an incompatible archive status")
			return
		}
		agent, err := s.bindingAgent(r, binding, domain.PermissionRunControl)
		if err != nil {
			writeAPIError(w, 403, "forbidden", "Chat is not available to this user")
			return
		}
		entry := groups[binding.RouteID]
		if entry == nil {
			entry = &historyRouteGroup{agent: agent}
			groups[binding.RouteID] = entry
		}
		entry.ids = append(entry.ids, chatID)
	}
	requestType := "/api/chat/archive"
	nextStatus := "archived"
	if !archive {
		requestType = "/api/archive/restore"
		nextStatus = "active"
	}
	results := []any{}
	for _, group := range groups {
		frame, err := s.upstreamRPC(r.Context(), group.agent.Route, requestType, map[string]any{"chatIds": group.ids})
		if err != nil {
			writeUpstreamError(w, err)
			return
		}
		items := responseCollection(frame.Data, "results")
		for _, item := range items {
			object, ok := item.(map[string]any)
			if !ok {
				continue
			}
			chatID := textValue(object["chatId"])
			if success, _ := object["success"].(bool); success {
				_ = s.store.UpdateChatBindingStatus(context.Background(), tenant.ID, chatID, nextStatus, time.Now().UnixMilli())
			}
			rewriteKnownOwnerFields(object, group.agent.PublicKey)
			results = append(results, object)
		}
	}
	writeJSON(w, 200, map[string]any{"results": results})
}

func (s *Server) handleArchiveDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := readJSONMap(r, 1<<20)
	if err != nil {
		writeAPIError(w, 400, "invalid_request", err.Error())
		return
	}
	chatID := textValue(body["chatId"])
	tenant := tenantFromContext(r.Context())
	binding, err := s.store.ChatBinding(r.Context(), tenant.ID, chatID)
	if err != nil || binding.Status != "archived" {
		writeAPIError(w, 404, "archive_not_found", "Archive was not found")
		return
	}
	agent, err := s.bindingAgent(r, binding, domain.PermissionRunControl)
	if err != nil {
		writeAPIError(w, 403, "forbidden", "Archive is not available to this user")
		return
	}
	frame, err := s.upstreamRPC(r.Context(), agent.Route, "/api/archive/delete", map[string]any{"chatId": chatID})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	_ = s.store.DeleteChatBinding(context.Background(), tenant.ID, chatID)
	writeJSON(w, 200, dataOrEmpty(rewriteRawData(frame.Data, agent.PublicKey)))
}
