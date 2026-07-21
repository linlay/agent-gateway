package server

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"agent-gateway/internal/domain"
	"agent-gateway/internal/policy"
	"agent-gateway/internal/store"
)

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	principal := principalFromContext(r.Context())
	if !policy.IsTenantAdmin(principal) {
		if !principal.Authenticated {
			writeUnauthorized(w, r)
			return
		}
		writeAPIError(w, http.StatusForbidden, "admin_required", "Tenant administrator role is required")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/gateway/admin/")
	switch {
	case path == "tenants":
		s.adminTenants(w, r)
	case path == "platforms":
		s.adminPlatforms(w, r)
	case strings.HasPrefix(path, "platforms/") && strings.HasSuffix(path, "/credentials"):
		s.adminPlatformCredential(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "platforms/"), "/credentials"))
	case path == "routes":
		s.adminRoutes(w, r)
	case path == "agents":
		s.adminAgents(w, r)
	case strings.HasPrefix(path, "agents/") && strings.HasSuffix(path, "/policy"):
		s.adminAgentPolicy(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "agents/"), "/policy"))
	case strings.HasPrefix(path, "agents/"):
		s.adminAgent(w, r, strings.TrimPrefix(path, "agents/"))
	case path == "audit":
		s.adminAudit(w, r)
	default:
		writeAPIError(w, http.StatusNotFound, "admin_route_not_found", "Unknown Gateway admin route")
	}
}

func (s *Server) adminTenants(w http.ResponseWriter, r *http.Request) {
	principal := principalFromContext(r.Context())
	if !policy.IsGatewayAdmin(principal) {
		writeAPIError(w, http.StatusForbidden, "gateway_admin_required", "Gateway administrator role is required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListTenants(r.Context())
		if err != nil {
			writeAPIError(w, 500, "list_failed", err.Error())
			return
		}
		writeJSON(w, 200, items)
	case http.MethodPost:
		var request struct {
			TenantID            string   `json:"tenantId"`
			Name                string   `json:"name"`
			Status              string   `json:"status"`
			Hosts               []string `json:"hosts"`
			OIDCIssuer          string   `json:"oidcIssuer"`
			OIDCClientID        string   `json:"oidcClientId"`
			OIDCClientSecretEnv string   `json:"oidcClientSecretEnv"`
			RolesClaim          string   `json:"rolesClaim"`
			GroupsClaim         string   `json:"groupsClaim"`
		}
		if err := decodeJSON(r, &request); err != nil {
			writeAPIError(w, 400, "invalid_request", err.Error())
			return
		}
		item, err := s.store.UpsertTenant(r.Context(), domain.Tenant{ID: request.TenantID, Name: request.Name, Status: request.Status, OIDCIssuer: request.OIDCIssuer, OIDCClientID: request.OIDCClientID, OIDCClientSecretEnv: request.OIDCClientSecretEnv, RolesClaim: request.RolesClaim, GroupsClaim: request.GroupsClaim}, request.Hosts)
		if err != nil {
			writeAPIError(w, statusForError(err), "tenant_update_failed", err.Error())
			return
		}
		s.audit(r.Context(), principal.Subject, "tenant.upsert", item.ID, "success", nil)
		writeJSON(w, 200, item)
	default:
		w.WriteHeader(405)
	}
}

func (s *Server) adminPlatforms(w http.ResponseWriter, r *http.Request) {
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	switch r.Method {
	case http.MethodGet:
		items, err := s.store.ListPlatforms(r.Context(), tenant.ID)
		if err != nil {
			writeAPIError(w, 500, "list_failed", err.Error())
			return
		}
		writeJSON(w, 200, items)
	case http.MethodPost:
		var request struct {
			PlatformID string `json:"platformId"`
			Name       string `json:"name"`
			Enabled    *bool  `json:"enabled"`
		}
		if err := decodeJSON(r, &request); err != nil {
			writeAPIError(w, 400, "invalid_request", err.Error())
			return
		}
		enabled := true
		if request.Enabled != nil {
			enabled = *request.Enabled
		}
		item, err := s.store.UpsertPlatform(r.Context(), domain.Platform{TenantID: tenant.ID, ID: request.PlatformID, Name: request.Name, Enabled: enabled})
		if err != nil {
			writeAPIError(w, statusForError(err), "platform_update_failed", err.Error())
			return
		}
		s.audit(r.Context(), principal.Subject, "platform.upsert", item.ID, "success", nil)
		writeJSON(w, 200, item)
	default:
		w.WriteHeader(405)
	}
}

func (s *Server) adminPlatformCredential(w http.ResponseWriter, r *http.Request, platformID string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	var request struct {
		ChannelID string `json:"channelId"`
	}
	if err := decodeJSON(r, &request); err != nil || strings.TrimSpace(request.ChannelID) == "" {
		writeAPIError(w, 400, "invalid_request", "channelId is required")
		return
	}
	if _, err := s.store.Platform(r.Context(), tenant.ID, platformID); err != nil {
		writeAPIError(w, 404, "platform_not_found", "Platform was not found")
		return
	}
	token, expiresAt, err := s.platformTokens.Issue(r.Context(), tenant.ID, platformID, strings.TrimSpace(request.ChannelID))
	if err != nil {
		writeAPIError(w, http.StatusNotImplemented, "credential_issue_failed", err.Error())
		return
	}
	s.audit(r.Context(), principal.Subject, "platform.credential.issue", platformID+"/"+request.ChannelID, "success", map[string]any{"expiresAt": expiresAt})
	writeJSON(w, 200, map[string]any{"token": token, "expiresAt": expiresAt, "endpoint": "/ws/agent?channelId=" + request.ChannelID})
}

func (s *Server) adminRoutes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	tenant := tenantFromContext(r.Context())
	items, err := s.store.ListRoutes(r.Context(), tenant.ID)
	if err != nil {
		writeAPIError(w, 500, "list_failed", err.Error())
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) adminAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	tenant := tenantFromContext(r.Context())
	items, err := s.store.ListAgents(r.Context(), tenant.ID, true)
	if err != nil {
		writeAPIError(w, 500, "list_failed", err.Error())
		return
	}
	writeJSON(w, 200, items)
}

func expectedVersion(r *http.Request, body int64) int64 {
	if body > 0 {
		return body
	}
	value := strings.TrimSpace(r.Header.Get("If-Match"))
	value = strings.Trim(value, "\"")
	parsed, _ := strconv.ParseInt(value, 10, 64)
	return parsed
}
func (s *Server) adminAgent(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodPatch && r.Method != http.MethodPut {
		w.WriteHeader(405)
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	var request struct {
		Enabled            *bool   `json:"enabled"`
		Visibility         *string `json:"visibility"`
		DisplayName        *string `json:"displayName"`
		DisplayDescription *string `json:"displayDescription"`
		SortOrder          *int    `json:"sortOrder"`
		PolicyVersion      int64   `json:"policyVersion"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeAPIError(w, 400, "invalid_request", err.Error())
		return
	}
	version := expectedVersion(r, request.PolicyVersion)
	if version <= 0 {
		writeAPIError(w, http.StatusPreconditionRequired, "policy_version_required", "policyVersion or If-Match is required")
		return
	}
	current, err := s.store.AgentByID(r.Context(), tenant.ID, agentID)
	if err != nil {
		writeAPIError(w, statusForError(err), "agent_not_found", "Agent was not found")
		return
	}
	enabled, visibility, name, description, sortOrder := current.Enabled, current.Visibility, current.DisplayName, current.DisplayDescription, current.SortOrder
	if request.Enabled != nil {
		enabled = *request.Enabled
	}
	if request.Visibility != nil {
		visibility = *request.Visibility
	}
	if request.DisplayName != nil {
		name = *request.DisplayName
	}
	if request.DisplayDescription != nil {
		description = *request.DisplayDescription
	}
	if request.SortOrder != nil {
		sortOrder = *request.SortOrder
	}
	item, err := s.store.UpdateAgent(r.Context(), tenant.ID, agentID, enabled, visibility, name, description, sortOrder, version)
	if err != nil {
		code := "agent_update_failed"
		if errors.Is(err, store.ErrConflict) {
			code = "version_conflict"
		}
		writeAPIError(w, statusForError(err), code, err.Error())
		return
	}
	s.audit(r.Context(), principal.Subject, "agent.update", agentID, "success", map[string]any{"policyVersion": item.PolicyVersion})
	writeJSON(w, 200, item)
}

func (s *Server) adminAgentPolicy(w http.ResponseWriter, r *http.Request, agentID string) {
	if r.Method != http.MethodPut {
		w.WriteHeader(405)
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	var request struct {
		Visibility    string           `json:"visibility"`
		Permissions   map[string]bool  `json:"permissions"`
		ACL           []domain.ACLRule `json:"acl"`
		PolicyVersion int64            `json:"policyVersion"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeAPIError(w, 400, "invalid_request", err.Error())
		return
	}
	version := expectedVersion(r, request.PolicyVersion)
	if version <= 0 {
		writeAPIError(w, http.StatusPreconditionRequired, "policy_version_required", "policyVersion or If-Match is required")
		return
	}
	item, err := s.store.ReplaceAgentPolicy(r.Context(), tenant.ID, agentID, request.Visibility, request.Permissions, request.ACL, version)
	if err != nil {
		code := "policy_update_failed"
		if errors.Is(err, store.ErrConflict) {
			code = "version_conflict"
		}
		writeAPIError(w, statusForError(err), code, err.Error())
		return
	}
	s.audit(r.Context(), principal.Subject, "agent.policy.update", agentID, "success", map[string]any{"policyVersion": item.PolicyVersion})
	writeJSON(w, 200, item)
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	tenant := tenantFromContext(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.ListAudit(r.Context(), tenant.ID, limit)
	if err != nil {
		writeAPIError(w, 500, "list_failed", err.Error())
		return
	}
	writeJSON(w, 200, items)
}
