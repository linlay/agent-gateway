package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"agent-gateway/internal/auth"
	"agent-gateway/internal/channel"
	"agent-gateway/internal/domain"
	"agent-gateway/internal/id"
	"agent-gateway/internal/policy"
	"agent-gateway/internal/store"
)

type upstreamFrame struct {
	Frame    string          `json:"frame"`
	Type     string          `json:"type"`
	ID       string          `json:"id"`
	Code     int             `json:"code"`
	Msg      string          `json:"msg"`
	Data     json.RawMessage `json:"data"`
	StreamID string          `json:"streamId"`
	Event    json.RawMessage `json:"event"`
	Reason   string          `json:"reason"`
	LastSeq  int64           `json:"lastSeq"`
}

var errRateLimited = errors.New("rate limit exceeded")

func normalizeUpstreamAuthError(status int, code string, message string) (int, string, string) {
	if status == http.StatusUnauthorized {
		return http.StatusBadGateway, "upstream_auth_failed", "Platform upstream authentication failed"
	}
	return status, code, message
}

func agentRateKeys(agent domain.GatewayAgent) []string {
	return []string{"agent:" + agent.TenantID + ":" + agent.ID, "channel:" + agent.TenantID + ":" + agent.Route.PlatformID + ":" + agent.Route.ChannelID}
}

func streamLimitKeys(agent domain.GatewayAgent, principal domain.Principal) []string {
	return []string{"tenant:" + agent.TenantID, "principal:" + agent.TenantID + ":" + principal.OwnerKind() + ":" + principal.OwnerID(), "agent:" + agent.TenantID + ":" + agent.ID, "channel:" + agent.TenantID + ":" + agent.Route.PlatformID + ":" + agent.Route.ChannelID}
}

func readJSONMap(r *http.Request, max int64) (map[string]any, error) {
	if max <= 0 {
		max = 2 << 20
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("request body is too large")
	}
	body := map[string]any{}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		return nil, err
	}
	return body, nil
}
func textValue(value any) string { text, _ := value.(string); return strings.TrimSpace(text) }
func boolValue(value any, fallback bool) bool {
	if parsed, ok := value.(bool); ok {
		return parsed
	}
	return fallback
}

func owns(principal domain.Principal, binding domain.ChatBinding) bool {
	return binding.OwnerKind == principal.OwnerKind() && binding.OwnerID == principal.OwnerID()
}

func (s *Server) bindingAgent(r *http.Request, binding domain.ChatBinding, permission string) (domain.GatewayAgent, error) {
	principal := principalFromContext(r.Context())
	if !owns(principal, binding) {
		return domain.GatewayAgent{}, store.ErrNotFound
	}
	agent, err := s.store.AgentByID(r.Context(), binding.TenantID, binding.AgentID)
	if err != nil {
		return agent, err
	}
	if !policy.CanIgnoringPresence(agent, principal, permission) {
		return agent, store.ErrNotFound
	}
	if agent.RouteID != binding.RouteID {
		return agent, errors.New("binding route does not match agent route")
	}
	return agent, nil
}

func routeOperationAllowed(agent domain.GatewayAgent, operation string) bool {
	switch operation {
	case "query", "attach", "detach":
		return agent.Route.Operations.Query
	case "submit":
		return agent.Route.Operations.Submit
	case "steer":
		return agent.Route.Operations.Steer
	case "interrupt":
		return agent.Route.Operations.Interrupt
	case "fileTransfer":
		return agent.Route.Operations.FileTransfer
	default:
		return false
	}
}

func (s *Server) prepareQuery(r *http.Request, body map[string]any) (domain.GatewayAgent, domain.ChatBinding, domain.RunBinding, string, bool, error) {
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	if textValue(body["teamId"]) != "" {
		return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, fmt.Errorf("teams are not exposed by gateway")
	}
	if _, exists := body["model"]; exists {
		return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, fmt.Errorf("model override is not allowed")
	}
	if level := textValue(body["accessLevel"]); level != "" && level != "default" {
		return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, fmt.Errorf("only default accessLevel is allowed")
	}
	if textValue(body["message"]) == "" {
		return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, fmt.Errorf("message is required")
	}
	requestID := textValue(body["requestId"])
	var idempotency *domain.IdempotencyBinding
	if rawKey := strings.TrimSpace(r.Header.Get("Idempotency-Key")); rawKey != "" {
		if len(rawKey) > 256 {
			return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, fmt.Errorf("idempotency key is too long")
		}
		canonical := copyMap(body)
		delete(canonical, "requestId")
		rawRequest, _ := json.Marshal(canonical)
		keyHash := auth.HashToken(tenant.ID + "\x00" + principal.OwnerKind() + "\x00" + principal.OwnerID() + "\x00" + rawKey)
		requestHash := hashBytes(rawRequest)
		if existingKey, keyErr := s.store.IdempotencyBinding(r.Context(), tenant.ID, keyHash); keyErr == nil {
			if existingKey.OwnerKind != principal.OwnerKind() || existingKey.OwnerID != principal.OwnerID() || existingKey.RequestHash != requestHash {
				return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, store.ErrConflict
			}
			existing, runErr := s.store.RunBinding(r.Context(), tenant.ID, existingKey.RunID)
			if runErr != nil {
				return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, runErr
			}
			chat, chatErr := s.store.ChatBinding(r.Context(), tenant.ID, existing.ChatID)
			if chatErr != nil || !owns(principal, chat) {
				return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, store.ErrConflict
			}
			agent, agentErr := s.bindingAgent(r, chat, domain.PermissionInvoke)
			return agent, chat, existing, existing.RequestID, true, agentErr
		} else if !errors.Is(keyErr, store.ErrNotFound) {
			return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, keyErr
		}
		requestID = "idem_" + strings.ToLower(keyHash[:24])
		idempotency = &domain.IdempotencyBinding{TenantID: tenant.ID, KeyHash: keyHash, OwnerKind: principal.OwnerKind(), OwnerID: principal.OwnerID(), RequestHash: requestHash, ExpiresAt: time.Now().Add(24 * time.Hour).UnixMilli()}
	}
	if requestID == "" {
		requestID = id.New("req")
	}
	if existing, err := s.store.RunBindingByRequest(r.Context(), tenant.ID, requestID); err == nil {
		chat, err := s.store.ChatBinding(r.Context(), tenant.ID, existing.ChatID)
		if err != nil || !owns(principal, chat) {
			return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, store.ErrConflict
		}
		agent, err := s.bindingAgent(r, chat, domain.PermissionInvoke)
		return agent, chat, existing, requestID, true, err
	} else if !errors.Is(err, store.ErrNotFound) {
		return domain.GatewayAgent{}, domain.ChatBinding{}, domain.RunBinding{}, "", false, err
	}
	chatID := textValue(body["chatId"])
	var chat domain.ChatBinding
	var agent domain.GatewayAgent
	newChat := false
	if chatID != "" {
		var err error
		chat, err = s.store.ChatBinding(r.Context(), tenant.ID, chatID)
		if err != nil || !owns(principal, chat) {
			return agent, chat, domain.RunBinding{}, "", false, store.ErrNotFound
		}
		agent, err = s.bindingAgent(r, chat, domain.PermissionInvoke)
		if err != nil {
			return agent, chat, domain.RunBinding{}, "", false, err
		}
		if requested := textValue(body["agentKey"]); requested != "" && requested != agent.PublicKey {
			return agent, chat, domain.RunBinding{}, "", false, store.ErrConflict
		}
	}
	if chatID == "" {
		key := textValue(body["agentKey"])
		if key == "" {
			return agent, chat, domain.RunBinding{}, "", false, fmt.Errorf("agentKey is required for a new chat")
		}
		var err error
		agent, _, err = resolveAgentForPermission(s.store, r, key, domain.PermissionInvoke)
		if err != nil {
			return agent, chat, domain.RunBinding{}, "", false, err
		}
		if strings.Contains(agent.Route.ChannelID, "#") {
			return agent, chat, domain.RunBinding{}, "", false, errors.New("channelId cannot contain #")
		}
		ownerRef := auth.OwnerReference(s.cfg.TenantHMACSecret, tenant.ID, principal.OwnerKind(), principal.OwnerID())
		chatID = agent.Route.ChannelID + "#web#" + ownerRef + "#" + id.New("chat")
		now := time.Now().UnixMilli()
		chat = domain.ChatBinding{TenantID: tenant.ID, ChatID: chatID, OwnerKind: principal.OwnerKind(), OwnerID: principal.OwnerID(), AgentID: agent.ID, RouteID: agent.RouteID, Status: "active", CreatedAt: now, UpdatedAt: now}
		newChat = true
	}
	if !routeOperationAllowed(agent, "query") {
		return agent, chat, domain.RunBinding{}, "", false, store.ErrNotFound
	}
	if !s.limiter.Allow(agentRateKeys(agent), time.Now()) {
		return agent, chat, domain.RunBinding{}, "", false, errRateLimited
	}
	runID := id.New("run")
	now := time.Now().UnixMilli()
	run := domain.RunBinding{TenantID: tenant.ID, RunID: runID, ChatID: chatID, RouteID: agent.RouteID, RequestID: requestID, Status: "starting", CreatedAt: now, UpdatedAt: now}
	if idempotency != nil {
		idempotency.ChatID = chatID
		idempotency.RunID = runID
		idempotency.CreatedAt = now
	}
	var err error
	if newChat {
		err = s.store.CreateChatRunBindings(r.Context(), chat, run, idempotency)
	} else {
		err = s.store.CreateRunBinding(r.Context(), run, idempotency)
	}
	if err != nil {
		if errors.Is(err, store.ErrConflict) && idempotency != nil {
			if existingKey, keyErr := s.store.IdempotencyBinding(r.Context(), tenant.ID, idempotency.KeyHash); keyErr == nil && existingKey.RequestHash == idempotency.RequestHash && existingKey.OwnerKind == principal.OwnerKind() && existingKey.OwnerID == principal.OwnerID() {
				if existing, runErr := s.store.RunBinding(r.Context(), tenant.ID, existingKey.RunID); runErr == nil {
					if existingChat, chatErr := s.store.ChatBinding(r.Context(), tenant.ID, existing.ChatID); chatErr == nil && owns(principal, existingChat) {
						existingAgent, agentErr := s.bindingAgent(r, existingChat, domain.PermissionInvoke)
						return existingAgent, existingChat, existing, existing.RequestID, true, agentErr
					}
				}
			}
		}
		return agent, chat, run, "", false, err
	}
	return agent, chat, run, requestID, false, nil
}

func upstreamQueryPayload(body map[string]any, agent domain.GatewayAgent, chat domain.ChatBinding, run domain.RunBinding, requestID, sourceUser string) map[string]any {
	payload := map[string]any{}
	for key, value := range body {
		payload[key] = value
	}
	delete(payload, "agentKey")
	delete(payload, "teamId")
	delete(payload, "model")
	payload["externalAgentKey"] = agent.Route.ExternalAgentKey
	payload["chatId"] = chat.ChatID
	payload["runId"] = run.RunID
	payload["requestId"] = requestID
	payload["sourceUser"] = sourceUser
	payload["accessLevel"] = "default"
	return payload
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := readJSONMap(r, 2<<20)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	agent, chat, run, requestID, replay, err := s.prepareQuery(r, body)
	if err != nil {
		s.writeRelayError(w, r, err, "query_not_allowed")
		return
	}
	principal := principalFromContext(r.Context())
	release, acquired := s.limiter.Acquire(streamLimitKeys(agent, principal))
	if !acquired {
		_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "rate_limited", run.LastSeq, time.Now().UnixMilli())
		writeAPIError(w, http.StatusTooManyRequests, "concurrency_limited", "Concurrent stream limit exceeded")
		return
	}
	defer release()
	ownerRef := auth.OwnerReference(s.cfg.TenantHMACSecret, chat.TenantID, principal.OwnerKind(), principal.OwnerID())
	requestType := "/api/query"
	payload := upstreamQueryPayload(body, agent, chat, run, requestID, ownerRef)
	if replay {
		requestType = "/api/attach"
		payload = map[string]any{"runId": run.RunID, "externalAgentKey": agent.Route.ExternalAgentKey, "lastSeq": run.LastSeq}
	}
	frames, cleanup, err := s.channels.Call(r.Context(), agent.Route, requestType, payload)
	if err != nil {
		_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "upstream_unavailable", run.LastSeq, time.Now().UnixMilli())
		writeAPIError(w, http.StatusServiceUnavailable, "platform_offline", "Platform channel is offline")
		return
	}
	defer cleanup()
	s.audit(r.Context(), principal.OwnerID(), "agent.invoke", agent.PublicKey, "accepted", map[string]any{"chatId": chat.ChatID, "runId": run.RunID, "replay": replay})
	s.relayHTTPFrames(w, r, frames, agent, run, boolValue(body["stream"], true))
}

func (s *Server) writeRelayError(w http.ResponseWriter, r *http.Request, err error, code string) {
	status := http.StatusBadRequest
	if errors.Is(err, store.ErrNotFound) {
		status = http.StatusForbidden
		if !principalFromContext(r.Context()).Authenticated {
			s.writeUnauthorized(w, r)
			return
		}
	} else if errors.Is(err, store.ErrConflict) {
		status = http.StatusConflict
	} else if errors.Is(err, errRateLimited) {
		status = http.StatusTooManyRequests
	} else if !strings.Contains(err.Error(), "required") && !strings.Contains(err.Error(), "allowed") && !strings.Contains(err.Error(), "exposed") {
		status = http.StatusInternalServerError
	}
	writeAPIError(w, status, code, err.Error())
}

func (s *Server) relayHTTPFrames(w http.ResponseWriter, r *http.Request, frames <-chan []byte, agent domain.GatewayAgent, run domain.RunBinding, streamExpected bool) {
	first, ok := <-frames
	if !ok {
		writeAPIError(w, http.StatusBadGateway, "upstream_closed", "Platform closed the request without a response")
		return
	}
	var parsed upstreamFrame
	if err := json.Unmarshal(first, &parsed); err != nil {
		writeAPIError(w, http.StatusBadGateway, "invalid_upstream_frame", "Platform returned an invalid frame")
		return
	}
	if parsed.Frame == channel.FrameError {
		status := parsed.Code
		if status < 400 || status > 599 {
			status = http.StatusBadGateway
		}
		status, code, message := normalizeUpstreamAuthError(status, parsed.Type, parsed.Msg)
		writeAPIError(w, status, code, message)
		_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "error", run.LastSeq, time.Now().UnixMilli())
		return
	}
	if parsed.Frame == channel.FrameResponse {
		data := rewriteRawData(parsed.Data, agent.PublicKey)
		writeJSON(w, http.StatusOK, dataOrEmpty(data))
		_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "completed", run.LastSeq, time.Now().UnixMilli())
		return
	}
	if parsed.Frame != channel.FrameStream {
		writeAPIError(w, http.StatusBadGateway, "unexpected_upstream_frame", "Unexpected platform response")
		return
	}
	if !streamExpected {
		writeAPIError(w, http.StatusBadGateway, "stream_contract_mismatch", "Platform returned a stream for a non-stream request")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	completed := false
	ended := false
	writeStream := func(frame upstreamFrame) bool {
		if len(frame.Event) > 0 {
			s.recordViewportEvent(run, frame.Event)
			event := rewriteEvent(frame.Event, agent.PublicKey)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", event)
			if frame.LastSeq > run.LastSeq {
				run.LastSeq = frame.LastSeq
			}
			_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "running", run.LastSeq, time.Now().UnixMilli())
			if flusher != nil {
				flusher.Flush()
			}
			return true
		}
		completed = true
		ended = true
		return false
	}
	writeStream(parsed)
	for raw := range frames {
		if r.Context().Err() != nil {
			return
		}
		var frame upstreamFrame
		if json.Unmarshal(raw, &frame) != nil {
			continue
		}
		if frame.Frame == channel.FrameStream {
			writeStream(frame)
			if len(frame.Event) == 0 {
				completed = true
				ended = true
				break
			}
		} else if frame.Frame == channel.FrameError {
			errorEvent, _ := json.Marshal(map[string]any{"type": "run.error", "timestamp": time.Now().UnixMilli(), "payload": map[string]any{"code": frame.Type, "message": frame.Msg}})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", errorEvent)
			_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "error", run.LastSeq, time.Now().UnixMilli())
			ended = true
			break
		}
	}
	if !ended {
		errorEvent, _ := json.Marshal(map[string]any{"type": "run.error", "timestamp": time.Now().UnixMilli(), "payload": map[string]any{"code": "platform_disconnected", "message": "Platform channel disconnected before the run completed"}})
		_, _ = fmt.Fprintf(w, "data: %s\n\n", errorEvent)
		_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "upstream_unavailable", run.LastSeq, time.Now().UnixMilli())
	}
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
	if completed {
		_ = s.store.UpdateRunProgress(context.Background(), run.TenantID, run.RunID, "completed", run.LastSeq, time.Now().UnixMilli())
	}
}

func dataOrEmpty(raw json.RawMessage) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return map[string]any{}
	}
	return value
}
func rewriteRawData(raw json.RawMessage, publicKey string) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return raw
	}
	rewriteKnownOwnerFields(value, publicKey)
	updated, _ := json.Marshal(value)
	return updated
}
func rewriteEvent(raw json.RawMessage, publicKey string) json.RawMessage {
	return rewriteRawData(raw, publicKey)
}
func rewriteKnownOwnerFields(value any, publicKey string) {
	object, ok := value.(map[string]any)
	if !ok {
		return
	}
	if _, exists := object["agentKey"]; exists {
		object["agentKey"] = publicKey
	}
	for _, key := range []string{"owner", "activeRun", "awaiting"} {
		if nested, ok := object[key].(map[string]any); ok {
			if _, exists := nested["agentKey"]; exists {
				nested["agentKey"] = publicKey
			}
		}
	}
	if payload, ok := object["payload"].(map[string]any); ok {
		if _, exists := payload["agentKey"]; exists {
			payload["agentKey"] = publicKey
		}
	}
}

func (s *Server) upstreamRPC(ctx context.Context, route domain.Route, requestType string, payload any) (upstreamFrame, error) {
	frames, cleanup, err := s.channels.Call(ctx, route, requestType, payload)
	if err != nil {
		return upstreamFrame{}, err
	}
	defer cleanup()
	for raw := range frames {
		var frame upstreamFrame
		if err := json.Unmarshal(raw, &frame); err != nil {
			return upstreamFrame{}, err
		}
		if frame.Frame == channel.FrameResponse {
			return frame, nil
		}
		if frame.Frame == channel.FrameError {
			return frame, fmt.Errorf("upstream %d: %s", frame.Code, frame.Msg)
		}
	}
	return upstreamFrame{}, errors.New("platform closed request")
}

func writeUpstreamError(w http.ResponseWriter, err error) {
	if errors.Is(err, channel.ErrOffline) {
		writeAPIError(w, http.StatusServiceUnavailable, "platform_offline", "Platform channel is offline")
		return
	}
	writeAPIError(w, http.StatusBadGateway, "upstream_error", err.Error())
}

func (s *Server) handleChats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	bindings, err := s.store.ListChatBindings(r.Context(), tenant.ID, principal.OwnerKind(), principal.OwnerID(), "")
	if err != nil {
		writeAPIError(w, 500, "chat_list_failed", err.Error())
		return
	}
	type group struct {
		agent domain.GatewayAgent
		ids   []string
	}
	groups := map[string]*group{}
	allowed := map[string]bool{}
	for _, binding := range bindings {
		if binding.Status == "archived" {
			continue
		}
		agent, err := s.bindingAgent(r, binding, domain.PermissionHistoryRead)
		if err != nil {
			continue
		}
		entry := groups[binding.RouteID]
		if entry == nil {
			entry = &group{agent: agent}
			groups[binding.RouteID] = entry
		}
		entry.ids = append(entry.ids, binding.ChatID)
		allowed[binding.ChatID] = true
	}
	items := []any{}
	for _, entry := range groups {
		frame, err := s.upstreamRPC(r.Context(), entry.agent.Route, "/api/chats", map[string]any{"chatIds": entry.ids})
		if err != nil {
			writeAPIError(w, http.StatusServiceUnavailable, "platform_offline", "A platform holding chat history is unavailable")
			return
		}
		var values []any
		if json.Unmarshal(frame.Data, &values) != nil {
			continue
		}
		for _, value := range values {
			object, ok := value.(map[string]any)
			if !ok || !allowed[textValue(object["chatId"])] {
				continue
			}
			rewriteKnownOwnerFields(object, entry.agent.PublicKey)
			items = append(items, object)
		}
	}
	sort.Slice(items, func(i, j int) bool {
		left, _ := items[i].(map[string]any)
		right, _ := items[j].(map[string]any)
		return numberValue(left["updatedAt"]) > numberValue(right["updatedAt"])
	})
	writeJSON(w, 200, items)
}

func numberValue(value any) int64 {
	switch typed := value.(type) {
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	case string:
		parsed, _ := strconv.ParseInt(typed, 10, 64)
		return parsed
	}
	return 0
}

func (s *Server) handleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	tenant := tenantFromContext(r.Context())
	chatID := strings.TrimSpace(r.URL.Query().Get("chatId"))
	binding, err := s.store.ChatBinding(r.Context(), tenant.ID, chatID)
	if err != nil {
		writeAPIError(w, 404, "chat_not_found", "Chat was not found")
		return
	}
	agent, err := s.bindingAgent(r, binding, domain.PermissionHistoryRead)
	if err != nil {
		writeAPIError(w, 403, "forbidden", "Chat is not available to this user")
		return
	}
	frame, err := s.upstreamRPC(r.Context(), agent.Route, "/api/chat", map[string]any{"chatId": chatID, "includeRawMessages": r.URL.Query().Get("includeRawMessages") == "true"})
	if err != nil {
		writeAPIError(w, 503, "platform_offline", err.Error())
		return
	}
	writeJSON(w, 200, dataOrEmpty(rewriteRawData(frame.Data, agent.PublicKey)))
}

func (s *Server) handleAttach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	runID := strings.TrimSpace(r.URL.Query().Get("runId"))
	lastSeq, _ := strconv.ParseInt(r.URL.Query().Get("lastSeq"), 10, 64)
	s.handleAttachLike(w, r, runID, lastSeq)
}

func (s *Server) handleAttachLike(w http.ResponseWriter, r *http.Request, runID string, lastSeq int64) {
	tenant := tenantFromContext(r.Context())
	run, err := s.store.RunBinding(r.Context(), tenant.ID, runID)
	if err != nil {
		writeAPIError(w, 404, "run_not_found", "Run was not found")
		return
	}
	chat, err := s.store.ChatBinding(r.Context(), tenant.ID, run.ChatID)
	if err != nil {
		writeAPIError(w, 404, "chat_not_found", "Chat was not found")
		return
	}
	agent, err := s.bindingAgent(r, chat, domain.PermissionRunControl)
	if err != nil {
		writeAPIError(w, 403, "forbidden", "Run is not available to this user")
		return
	}
	if !routeOperationAllowed(agent, "attach") {
		writeAPIError(w, 403, "operation_not_allowed", "Attach is not enabled for this agent")
		return
	}
	frames, cleanup, err := s.channels.Call(r.Context(), agent.Route, "/api/attach", map[string]any{"runId": run.RunID, "externalAgentKey": agent.Route.ExternalAgentKey, "lastSeq": lastSeq})
	if err != nil {
		writeAPIError(w, 503, "platform_offline", err.Error())
		return
	}
	defer cleanup()
	s.relayHTTPFrames(w, r, frames, agent, run, true)
}

func (s *Server) handleRunControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	body, err := readJSONMap(r, 2<<20)
	if err != nil {
		writeAPIError(w, 400, "invalid_request", err.Error())
		return
	}
	tenant := tenantFromContext(r.Context())
	runID := textValue(body["runId"])
	run, err := s.store.RunBinding(r.Context(), tenant.ID, runID)
	if err != nil {
		writeAPIError(w, 404, "run_not_found", "Run was not found")
		return
	}
	chat, err := s.store.ChatBinding(r.Context(), tenant.ID, run.ChatID)
	if err != nil {
		writeAPIError(w, 404, "chat_not_found", "Chat was not found")
		return
	}
	agent, err := s.bindingAgent(r, chat, domain.PermissionRunControl)
	if err != nil {
		writeAPIError(w, 403, "forbidden", "Run is not available to this user")
		return
	}
	operation := strings.TrimPrefix(r.URL.Path, "/api/")
	if !routeOperationAllowed(agent, operation) {
		writeAPIError(w, 403, "operation_not_allowed", "Operation is not exported by platform")
		return
	}
	if requestedChatID := textValue(body["chatId"]); requestedChatID != "" && requestedChatID != chat.ChatID {
		writeAPIError(w, http.StatusConflict, "binding_conflict", "chatId does not belong to runId")
		return
	}
	if !s.limiter.Allow(agentRateKeys(agent), time.Now()) {
		writeAPIError(w, http.StatusTooManyRequests, "rate_limited", "Request rate limit exceeded")
		return
	}
	delete(body, "agentKey")
	delete(body, "teamId")
	body["externalAgentKey"] = agent.Route.ExternalAgentKey
	body["runId"] = run.RunID
	body["chatId"] = chat.ChatID
	frame, err := s.upstreamRPC(r.Context(), agent.Route, r.URL.Path, body)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	writeJSON(w, 200, dataOrEmpty(rewriteRawData(frame.Data, agent.PublicKey)))
}

func (s *Server) handleChatMutation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	body, err := readJSONMap(r, 2<<20)
	if err != nil {
		writeAPIError(w, 400, "invalid_request", err.Error())
		return
	}
	tenant := tenantFromContext(r.Context())
	chatID := textValue(body["chatId"])
	if chatID == "" {
		chatID = textValue(body["sourceChatId"])
	}
	binding, err := s.store.ChatBinding(r.Context(), tenant.ID, chatID)
	if err != nil {
		writeAPIError(w, 404, "chat_not_found", "Chat was not found")
		return
	}
	agent, err := s.bindingAgent(r, binding, domain.PermissionRunControl)
	if err != nil {
		writeAPIError(w, 403, "forbidden", "Chat is not available to this user")
		return
	}
	var derived *domain.ChatBinding
	if r.URL.Path == "/api/chat/derive" {
		principal := principalFromContext(r.Context())
		ownerRef := auth.OwnerReference(s.cfg.TenantHMACSecret, tenant.ID, principal.OwnerKind(), principal.OwnerID())
		newID := agent.Route.ChannelID + "#web#" + ownerRef + "#" + id.New("chat")
		now := time.Now().UnixMilli()
		item := domain.ChatBinding{TenantID: tenant.ID, ChatID: newID, OwnerKind: principal.OwnerKind(), OwnerID: principal.OwnerID(), AgentID: agent.ID, RouteID: agent.RouteID, Status: "provisioning", CreatedAt: now, UpdatedAt: now}
		if err := s.store.CreateChatBinding(r.Context(), item); err != nil {
			writeAPIError(w, 500, "binding_failed", err.Error())
			return
		}
		body["chatId"] = newID
		derived = &item
	}
	frame, err := s.upstreamRPC(r.Context(), agent.Route, r.URL.Path, body)
	if err != nil {
		if derived != nil {
			_ = s.store.DeleteChatBinding(context.Background(), tenant.ID, derived.ChatID)
		}
		writeUpstreamError(w, err)
		return
	}
	if r.URL.Path == "/api/chat/delete" {
		_ = s.store.DeleteChatBinding(context.Background(), tenant.ID, chatID)
	}
	writeJSON(w, 200, dataOrEmpty(rewriteRawData(frame.Data, agent.PublicKey)))
}
