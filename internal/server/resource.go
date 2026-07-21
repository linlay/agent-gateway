package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"agent-gateway/internal/auth"
	"agent-gateway/internal/domain"
	"agent-gateway/internal/id"
	"agent-gateway/internal/store"
)

func safeFileName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "." || value == ".." || strings.ContainsAny(value, "\x00/\\") || filepath.Base(value) != value {
		return "", errors.New("invalid file name")
	}
	if len([]byte(value)) > 255 {
		return "", errors.New("file name is too long")
	}
	return value, nil
}

func validResourceFile(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\x00\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value || strings.HasPrefix(value, "../") {
		return "", "", errors.New("invalid resource path")
	}
	parts := strings.SplitN(value, "/", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" {
		return "", "", errors.New("resource path must include chatId")
	}
	name, err := safeFileName(path.Base(value))
	return parts[0], name, err
}

func (s *Server) createSpoolFile() (*os.File, error) {
	if err := os.MkdirAll(s.cfg.SpoolDir, 0o700); err != nil {
		return nil, err
	}
	return os.CreateTemp(s.cfg.SpoolDir, "agw-resource-*")
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadBytes+(2<<20))
	reader, err := r.MultipartReader()
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "multipart_required", "Upload must use multipart/form-data")
		return
	}
	var chatID, requestID, fileName, mimeType string
	var spoolPath, digest string
	var size int64
	defer func() {
		if spoolPath != "" {
			_ = os.Remove(spoolPath)
		}
	}()
	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid_multipart", nextErr.Error())
			return
		}
		field := part.FormName()
		if part.FileName() == "" {
			raw, readErr := io.ReadAll(io.LimitReader(part, 64<<10))
			_ = part.Close()
			if readErr != nil {
				writeAPIError(w, http.StatusBadRequest, "invalid_multipart", readErr.Error())
				return
			}
			switch field {
			case "chatId":
				chatID = strings.TrimSpace(string(raw))
			case "requestId":
				requestID = strings.TrimSpace(string(raw))
			}
			continue
		}
		if field != "file" && field != "upload" {
			_ = part.Close()
			continue
		}
		if spoolPath != "" {
			_ = part.Close()
			writeAPIError(w, http.StatusBadRequest, "too_many_files", "Only one file is accepted per request")
			return
		}
		fileName, err = safeFileName(part.FileName())
		if err != nil {
			_ = part.Close()
			writeAPIError(w, http.StatusBadRequest, "invalid_file_name", err.Error())
			return
		}
		mimeType = strings.TrimSpace(part.Header.Get("Content-Type"))
		mimeType = safeMIMEType(mimeType)
		file, createErr := s.createSpoolFile()
		if createErr != nil {
			_ = part.Close()
			writeAPIError(w, http.StatusInternalServerError, "spool_unavailable", "Temporary upload storage is unavailable")
			return
		}
		spoolPath = file.Name()
		hasher := sha256.New()
		size, err = io.Copy(io.MultiWriter(file, hasher), io.LimitReader(part, s.cfg.MaxUploadBytes+1))
		closeErr := file.Close()
		_ = part.Close()
		if err != nil || closeErr != nil {
			writeAPIError(w, http.StatusInternalServerError, "spool_write_failed", "Could not spool upload")
			return
		}
		if size > s.cfg.MaxUploadBytes {
			writeAPIError(w, http.StatusRequestEntityTooLarge, "upload_too_large", "Upload exceeds the configured size limit")
			return
		}
		digest = hex.EncodeToString(hasher.Sum(nil))
	}
	if chatID == "" || spoolPath == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid_upload", "chatId and one file are required")
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	chat, err := s.store.ChatBinding(r.Context(), tenant.ID, chatID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "chat_not_found", "Chat was not found")
		return
	}
	agent, err := s.bindingAgent(r, chat, domain.PermissionFileTransfer)
	if err != nil || !routeOperationAllowed(agent, "fileTransfer") {
		if !principal.Authenticated {
			writeUnauthorized(w, r)
			return
		}
		writeAPIError(w, http.StatusForbidden, "file_transfer_forbidden", "File transfer is not allowed")
		return
	}
	if requestID == "" {
		requestID = id.New("upload_req")
	}
	token := id.RandomToken(32)
	now := time.Now().UnixMilli()
	binding := domain.ResourceBinding{TenantID: tenant.ID, ResourceKey: id.New("resource"), ChatID: chatID, OwnerKind: principal.OwnerKind(), OwnerID: principal.OwnerID(), RouteID: chat.RouteID, Direction: "pull", TokenHash: auth.HashToken(token), SpoolPath: spoolPath, FileName: fileName, MimeType: mimeType, SizeBytes: size, SHA256: digest, Status: "ready", ExpiresAt: time.Now().Add(s.cfg.ResourceTicketTTL).UnixMilli(), CreatedAt: now, UpdatedAt: now}
	if err := s.store.PutResourceBinding(r.Context(), binding); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "upload_binding_failed", "Could not create upload ticket")
		return
	}
	pullURL := s.baseURL(r) + "/internal/resource/pull/" + token
	payload := map[string]any{"chatId": chatID, "requestId": requestID, "upload": map[string]any{"id": binding.ResourceKey, "type": "file", "name": fileName, "mimeType": mimeType, "sizeBytes": size, "sha256": digest, "url": pullURL}}
	frame, err := s.upstreamRPC(r.Context(), agent.Route, "/api/upload", payload)
	_ = s.store.DeleteResourceBinding(context.Background(), tenant.ID, binding.ResourceKey)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dataOrEmpty(rewriteRawData(frame.Data, agent.PublicKey)))
}

func (s *Server) handleResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	fileParam := strings.TrimSpace(r.URL.Query().Get("file"))
	chatID, fileName, err := validResourceFile(fileParam)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_resource", err.Error())
		return
	}
	tenant := tenantFromContext(r.Context())
	principal := principalFromContext(r.Context())
	chat, err := s.store.ChatBinding(r.Context(), tenant.ID, chatID)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "resource_not_found", "Resource was not found")
		return
	}
	agent, err := s.bindingAgent(r, chat, domain.PermissionFileTransfer)
	if err != nil || !routeOperationAllowed(agent, "fileTransfer") {
		if !principal.Authenticated {
			writeUnauthorized(w, r)
			return
		}
		writeAPIError(w, http.StatusForbidden, "resource_forbidden", "Resource is not available to this user")
		return
	}
	spool, err := s.createSpoolFile()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "spool_unavailable", "Temporary download storage is unavailable")
		return
	}
	spoolPath := spool.Name()
	_ = spool.Close()
	defer os.Remove(spoolPath)
	token := id.RandomToken(32)
	now := time.Now().UnixMilli()
	binding := domain.ResourceBinding{TenantID: tenant.ID, ResourceKey: id.New("resource"), ChatID: chatID, OwnerKind: principal.OwnerKind(), OwnerID: principal.OwnerID(), RouteID: chat.RouteID, Direction: "push", TokenHash: auth.HashToken(token), SpoolPath: spoolPath, FileName: fileName, Status: "awaiting", ExpiresAt: time.Now().Add(s.cfg.ResourceTicketTTL).UnixMilli(), CreatedAt: now, UpdatedAt: now}
	if err := s.store.PutResourceBinding(r.Context(), binding); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "resource_binding_failed", "Could not create resource ticket")
		return
	}
	defer s.store.DeleteResourceBinding(context.Background(), tenant.ID, binding.ResourceKey)
	pushURL := s.baseURL(r) + "/internal/resource/push/" + token
	if _, err := s.upstreamRPC(r.Context(), agent.Route, "/api/resource", map[string]any{"file": fileParam, "pushURL": pushURL}); err != nil {
		writeUpstreamError(w, err)
		return
	}
	ready, err := s.store.ResourceBindingByToken(r.Context(), tenant.ID, auth.HashToken(token), time.Now().UnixMilli())
	if err != nil || ready.Status != "ready" {
		writeAPIError(w, http.StatusBadGateway, "resource_push_incomplete", "Platform did not complete the resource transfer")
		return
	}
	file, err := os.Open(ready.SpoolPath)
	if err != nil {
		writeAPIError(w, http.StatusBadGateway, "resource_push_incomplete", "Transferred resource is unavailable")
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", safeMIMEType(ready.MimeType))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if value := mime.FormatMediaType("attachment", map[string]string{"filename": ready.FileName}); value != "" {
		w.Header().Set("Content-Disposition", value)
	}
	if ready.SizeBytes >= 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", ready.SizeBytes))
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, file)
}

func safeMIMEType(value string) string {
	mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(value))
	if err != nil || mediaType == "" {
		return "application/octet-stream"
	}
	return mime.FormatMediaType(mediaType, params)
}

func (s *Server) platformResourceBinding(r *http.Request, expectedDirection string) (domain.ResourceBinding, domain.Route, error) {
	rawToken := strings.TrimPrefix(r.URL.Path, "/internal/resource/"+expectedDirection+"/")
	if rawToken == "" || strings.Contains(rawToken, "/") {
		return domain.ResourceBinding{}, domain.Route{}, store.ErrNotFound
	}
	identity, err := s.platformTokens.Verify(r.Context(), bearerToken(r))
	if err != nil {
		return domain.ResourceBinding{}, domain.Route{}, err
	}
	binding, err := s.store.ResourceBindingByToken(r.Context(), identity.TenantID, auth.HashToken(rawToken), time.Now().UnixMilli())
	if err != nil || binding.Direction != expectedDirection {
		return domain.ResourceBinding{}, domain.Route{}, store.ErrNotFound
	}
	route, err := s.store.Route(r.Context(), identity.TenantID, binding.RouteID)
	if err != nil || route.PlatformID != identity.PlatformID || route.ChannelID != identity.ChannelID {
		return domain.ResourceBinding{}, domain.Route{}, store.ErrNotFound
	}
	return binding, route, nil
}

func (s *Server) handleResourcePull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	binding, _, err := s.platformResourceBinding(r, "pull")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now().UnixMilli()
	if err := s.store.ClaimResourceBinding(r.Context(), binding.TenantID, binding.ResourceKey, "ready", "consuming", now); err != nil {
		http.Error(w, "ticket already used", http.StatusGone)
		return
	}
	file, err := os.Open(binding.SpoolPath)
	if err != nil {
		http.Error(w, "resource unavailable", http.StatusGone)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", safeMIMEType(binding.MimeType))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", binding.SizeBytes))
	w.WriteHeader(http.StatusOK)
	_, copyErr := io.Copy(w, file)
	status := "consumed"
	if copyErr != nil {
		status = "failed"
	}
	_ = s.store.UpdateResourceBinding(context.Background(), binding.TenantID, binding.ResourceKey, status, "", "", -1, time.Now().UnixMilli())
}

func (s *Server) handleResourcePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	binding, _, err := s.platformResourceBinding(r, "push")
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	now := time.Now().UnixMilli()
	if err := s.store.ClaimResourceBinding(r.Context(), binding.TenantID, binding.ResourceKey, "awaiting", "receiving", now); err != nil {
		http.Error(w, "ticket already used", http.StatusGone)
		return
	}
	file, err := os.OpenFile(binding.SpoolPath, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		http.Error(w, "spool unavailable", http.StatusInternalServerError)
		return
	}
	size, copyErr := io.Copy(file, io.LimitReader(r.Body, s.cfg.MaxUploadBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || size > s.cfg.MaxUploadBytes {
		_ = os.Remove(binding.SpoolPath)
		_ = s.store.UpdateResourceBinding(context.Background(), binding.TenantID, binding.ResourceKey, "failed", "", "", -1, time.Now().UnixMilli())
		http.Error(w, "resource too large or incomplete", http.StatusRequestEntityTooLarge)
		return
	}
	mimeType := safeMIMEType(r.Header.Get("Content-Type"))
	if err := s.store.UpdateResourceBinding(r.Context(), binding.TenantID, binding.ResourceKey, "ready", binding.SpoolPath, mimeType, size, time.Now().UnixMilli()); err != nil {
		http.Error(w, "could not complete transfer", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
