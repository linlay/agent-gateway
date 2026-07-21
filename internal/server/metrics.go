package server

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

type gatewayMetrics struct {
	total atomic.Int64
	s401  atomic.Int64
	s403  atomic.Int64
	s429  atomic.Int64
	s503  atomic.Int64
}

func (m *gatewayMetrics) observe(status int) {
	m.total.Add(1)
	switch status {
	case 401:
		m.s401.Add(1)
	case 403:
		m.s403.Add(1)
	case 429:
		m.s429.Add(1)
	case 503:
		m.s503.Add(1)
	}
}

type observedResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *observedResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *observedResponseWriter) Write(raw []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(raw)
}
func (w *observedResponseWriter) statusCode() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
func (w *observedResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
func (w *observedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijacking")
	}
	return hijacker.Hijack()
}
func (w *observedResponseWriter) Push(target string, options *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, options)
	}
	return http.ErrNotSupported
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.browserMu.RLock()
	browserConnections := len(s.browsers)
	s.browserMu.RUnlock()
	var spoolBytes int64
	if entries, err := os.ReadDir(s.cfg.SpoolDir); err == nil {
		for _, entry := range entries {
			if info, err := entry.Info(); err == nil && !info.IsDir() {
				spoolBytes += info.Size()
			}
		}
	}
	lines := []string{
		"# TYPE agent_gateway_http_requests_total counter",
		fmt.Sprintf("agent_gateway_http_requests_total %d", s.metrics.total.Load()),
		"# TYPE agent_gateway_http_responses_total counter",
		fmt.Sprintf("agent_gateway_http_responses_total{status=\"401\"} %d", s.metrics.s401.Load()),
		fmt.Sprintf("agent_gateway_http_responses_total{status=\"403\"} %d", s.metrics.s403.Load()),
		fmt.Sprintf("agent_gateway_http_responses_total{status=\"429\"} %d", s.metrics.s429.Load()),
		fmt.Sprintf("agent_gateway_http_responses_total{status=\"503\"} %d", s.metrics.s503.Load()),
		"# TYPE agent_gateway_platform_channels gauge",
		fmt.Sprintf("agent_gateway_platform_channels %d", s.channels.ConnectionCount()),
		"# TYPE agent_gateway_platform_inflight_requests gauge",
		fmt.Sprintf("agent_gateway_platform_inflight_requests %d", s.channels.InflightCount()),
		"# TYPE agent_gateway_browser_websockets gauge",
		fmt.Sprintf("agent_gateway_browser_websockets %d", browserConnections),
		"# TYPE agent_gateway_spool_bytes gauge",
		fmt.Sprintf("agent_gateway_spool_bytes %d", spoolBytes),
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(strings.Join(lines, "\n") + "\n"))
}
