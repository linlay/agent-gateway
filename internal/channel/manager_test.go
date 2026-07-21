package channel

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agent-gateway/internal/auth"
	"agent-gateway/internal/domain"
	sqlitestore "agent-gateway/internal/store/sqlite"

	"github.com/gorilla/websocket"
)

func writeTestKeys(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(privatePath, privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return publicPath, privatePath
}

func newLoopbackTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener is unavailable in this test environment: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server
}

func TestPlatformJWTConnectionAndAtomicCatalog(t *testing.T) {
	ctx := context.Background()
	st, err := sqlitestore.Open(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.BootstrapTenant(ctx, domain.Tenant{ID: "t1", Name: "Tenant", Status: "active"}, []string{"gateway.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPlatform(ctx, domain.Platform{TenantID: "t1", ID: "p1", Name: "Platform", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := writeTestKeys(t)
	tokens, err := auth.NewPlatformTokens("test-gateway", publicKey, privateKey, st, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := tokens.Issue(ctx, "t1", "p1", "channel-a")
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(st, tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), 1<<20, 16, 2*time.Second)
	server := newLoopbackTestServer(t, http.HandlerFunc(manager.ServePlatformHTTP))
	defer server.Close()
	header := http.Header{"Authorization": []string{"Bearer " + token}}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?channelId=channel-a"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatal(err)
	}

	send := func(frame RequestFrame) {
		t.Helper()
		if err := conn.WriteJSON(frame); err != nil {
			t.Fatal(err)
		}
		var response ResponseFrame
		if err := conn.ReadJSON(&response); err != nil {
			t.Fatal(err)
		}
		if response.Frame != FrameResponse || response.ID != frame.ID || response.Code != 0 {
			t.Fatalf("unexpected response: %#v", response)
		}
	}
	send(RequestFrame{Frame: FrameRequest, Type: "agent.catalog.begin", ID: "begin", Payload: Payload(CatalogBegin{SnapshotID: "snap-1", Revision: 1, CardCount: 1})})
	if routes, err := st.ListRoutes(ctx, "t1"); err != nil || len(routes) != 0 {
		t.Fatalf("begin made catalog visible: routes=%d err=%v", len(routes), err)
	}
	send(RequestFrame{Frame: FrameRequest, Type: "agent.card.update", ID: "card", Payload: Payload(CardUpdate{SnapshotID: "snap-1", Revision: 1, AgentKey: "assistant", Operations: domain.Operations{Query: true}, AgentCard: domain.AgentCard{Name: "Assistant", Skills: []domain.AgentCardFeature{}, Tools: []domain.AgentCardFeature{}}})})
	send(RequestFrame{Frame: FrameRequest, Type: "agent.catalog.commit", ID: "commit", Payload: Payload(CatalogCommit{SnapshotID: "snap-1", Revision: 1, CardCount: 1})})
	agents, err := st.ListAgents(ctx, "t1", true)
	if err != nil || len(agents) != 1 || agents[0].Enabled || agents[0].Route.ChannelID != "channel-a" {
		t.Fatalf("unexpected projected agent: %#v err=%v", agents, err)
	}
	_ = conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		route, err := st.Route(ctx, "t1", agents[0].RouteID)
		if err == nil && route.Status == "offline" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("route was not marked offline after disconnect")
}

func TestPlatformChannelClaimMustMatchURL(t *testing.T) {
	ctx := context.Background()
	st, err := sqlitestore.Open(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_ = st.BootstrapTenant(ctx, domain.Tenant{ID: "t1", Name: "Tenant", Status: "active"}, []string{"gateway.example"})
	_, _ = st.UpsertPlatform(ctx, domain.Platform{TenantID: "t1", ID: "p1", Name: "Platform", Enabled: true})
	publicKey, privateKey := writeTestKeys(t)
	tokens, _ := auth.NewPlatformTokens("test-gateway", publicKey, privateKey, st, time.Hour)
	token, _, _ := tokens.Issue(ctx, "t1", "p1", "channel-a")
	manager := NewManager(st, tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), 1<<20, 16, time.Second)
	server := newLoopbackTestServer(t, http.HandlerFunc(manager.ServePlatformHTTP))
	defer server.Close()
	header := http.Header{"Authorization": []string{"Bearer " + token}}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "?channelId=channel-b"
	conn, response, err := websocket.DefaultDialer.Dial(wsURL, header)
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched channel claim was accepted: status=%v err=%v", func() int {
			if response == nil {
				return 0
			}
			return response.StatusCode
		}(), err)
	}
}
