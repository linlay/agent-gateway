package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"agent-gateway/internal/channel"
)

func newRootTestServer() *Server {
	s := &Server{
		channels: &channel.Manager{},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:  &gatewayMetrics{},
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s
}

func TestRootAvailableWithoutPlatformConnections(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	newRootTestServer().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("root status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response struct {
		Code int `json:"code"`
		Data struct {
			Service             string `json:"service"`
			Status              string `json:"status"`
			PlatformConnections int    `json:"platformConnections"`
		} `json:"data"`
	}
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Code != 0 || response.Data.Service != "agent-gateway" || response.Data.Status != "ok" || response.Data.PlatformConnections != 0 {
		t.Fatalf("unexpected root response: %#v", response)
	}
}

func TestRootHandlerKeepsUnknownPathsNotFound(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	newRootTestServer().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want %d", recorder.Code, http.StatusNotFound)
	}
}

func TestRootRejectsUnsupportedMethods(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	newRootTestServer().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("root POST status = %d, want %d", recorder.Code, http.StatusMethodNotAllowed)
	}
	if allow := recorder.Header().Get("Allow"); allow != http.MethodGet {
		t.Fatalf("Allow header = %q, want %q", allow, http.MethodGet)
	}
}
