package server

import (
	"net/http"
	"strings"

	"agent-gateway/internal/policy"
)

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/gateway/session":
		s.handleSession(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/gateway/admin/"):
		s.handleAdmin(w, r)
	case r.URL.Path == "/api/agents":
		s.handleAgents(w, r)
	case r.URL.Path == "/api/agent":
		s.handleAgent(w, r)
	case r.URL.Path == "/api/chats":
		s.handleChats(w, r)
	case r.URL.Path == "/api/chat":
		s.handleChat(w, r)
	case r.URL.Path == "/api/chats/search" || r.URL.Path == "/api/archives" || r.URL.Path == "/api/archive" || r.URL.Path == "/api/archives/search" || r.URL.Path == "/api/archive/delete" || r.URL.Path == "/api/archive/restore" || r.URL.Path == "/api/chat/archive":
		s.handleHistory(w, r)
	case r.URL.Path == "/api/query":
		s.handleQuery(w, r)
	case r.URL.Path == "/api/attach":
		s.handleAttach(w, r)
	case r.URL.Path == "/api/submit" || r.URL.Path == "/api/steer" || r.URL.Path == "/api/interrupt" || r.URL.Path == "/api/detach":
		s.handleRunControl(w, r)
	case r.URL.Path == "/api/read" || r.URL.Path == "/api/feedback" || r.URL.Path == "/api/chat/rename" || r.URL.Path == "/api/chat/derive" || r.URL.Path == "/api/chat/delete":
		s.handleChatMutation(w, r)
	case r.URL.Path == "/api/upload":
		s.handleUpload(w, r)
	case r.URL.Path == "/api/resource":
		s.handleResource(w, r)
	case r.URL.Path == "/api/viewport":
		s.handleViewport(w, r)
	default:
		writeAPIError(w, http.StatusNotFound, "route_not_found", "Gateway does not expose this platform route")
	}
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"tenant": map[string]any{"tenantId": tenant.ID, "name": tenant.Name}, "authenticated": principal.Authenticated, "user": func() any {
		if !principal.Authenticated {
			return nil
		}
		return map[string]any{"subject": principal.Subject, "name": principal.DisplayName, "roles": principal.Roles, "groups": principal.Groups}
	}(), "csrfToken": principal.CSRFToken, "loginUrl": "/auth/login", "logoutUrl": "/auth/logout", "features": map[string]bool{"chat": true, "hitl": true, "files": true, "admin": policy.IsTenantAdmin(principal), "memory": false, "automation": false, "terminal": false, "agentManagement": false, "modelOverride": false}})
}
