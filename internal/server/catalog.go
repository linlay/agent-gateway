package server

import (
	"net/http"
	"strings"

	"agent-gateway/internal/domain"
	"agent-gateway/internal/policy"
	"agent-gateway/internal/store"
)

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	agents, err := s.store.ListAgents(r.Context(), tenant.ID, false)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "catalog_failed", "Could not load agent catalog")
		return
	}
	items := make([]any, 0, len(agents))
	for _, agent := range agents {
		if !policy.Can(agent, principal, domain.PermissionDiscover) {
			continue
		}
		items = append(items, agentSummary(agent))
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	key := strings.TrimSpace(r.URL.Query().Get("agentKey"))
	if key == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "agentKey is required")
		return
	}
	agent, err := s.store.AgentByPublicKey(r.Context(), tenant.ID, key)
	if err != nil {
		status := statusForError(err)
		writeAPIError(w, status, "agent_not_found", "Agent was not found")
		return
	}
	if !policy.Can(agent, principal, domain.PermissionDiscover) {
		if !principal.Authenticated && agent.Enabled {
			writeUnauthorized(w, r)
			return
		}
		writeAPIError(w, http.StatusForbidden, "forbidden", "Agent is not available to this user")
		return
	}
	writeJSON(w, http.StatusOK, agentDetail(agent))
}

func agentSummary(agent domain.GatewayAgent) map[string]any {
	card := agent.Route.Card
	mode := strings.TrimSpace(card.Mode)
	if mode == "" {
		mode = "CHANNEL"
	}
	return map[string]any{"kind": "agent", "key": agent.PublicKey, "name": agent.EffectiveName(), "description": agent.EffectiveDescription(), "role": card.Role, "icon": card.Icon, "mode": mode, "stats": map[string]int{"totalCount": 0, "unreadCount": 0}, "chats": []any{}, "meta": map[string]any{"gateway": true, "online": agent.Route.Status == "online"}}
}
func agentDetail(agent domain.GatewayAgent) map[string]any {
	card := agent.Route.Card
	mode := strings.TrimSpace(card.Mode)
	if mode == "" {
		mode = "CHANNEL"
	}
	skills := make([]string, 0, len(card.Skills))
	for _, item := range card.Skills {
		skills = append(skills, item.ID)
	}
	tools := make([]string, 0, len(card.Tools))
	for _, item := range card.Tools {
		tools = append(tools, item.ID)
	}
	return map[string]any{"key": agent.PublicKey, "name": agent.EffectiveName(), "description": agent.EffectiveDescription(), "role": card.Role, "icon": card.Icon, "greetings": nonNilStrings(card.Greetings), "wonders": nonNilStrings(card.Wonders), "mode": mode, "model": "", "tools": tools, "skills": skills, "controls": []any{}, "meta": map[string]any{"gateway": true, "online": agent.Route.Status == "online"}}
}
func nonNilStrings(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

func resolveAgentForPermission(st store.Store, r *http.Request, key, permission string) (domain.GatewayAgent, int, error) {
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	agent, err := st.AgentByPublicKey(r.Context(), tenant.ID, strings.TrimSpace(key))
	if err != nil {
		return agent, statusForError(err), err
	}
	if !policy.Can(agent, principal, permission) {
		if !principal.Authenticated && agent.Enabled {
			return agent, http.StatusUnauthorized, store.ErrNotFound
		}
		return agent, http.StatusForbidden, store.ErrNotFound
	}
	return agent, 0, nil
}
