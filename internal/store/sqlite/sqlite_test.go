package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"agent-gateway/internal/domain"
	storepkg "agent-gateway/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "gateway.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func seedTenantPlatform(t *testing.T, st *Store, tenantID, host, platformID string) {
	t.Helper()
	ctx := context.Background()
	if err := st.BootstrapTenant(ctx, domain.Tenant{ID: tenantID, Name: tenantID, Status: "active"}, []string{host}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertPlatform(ctx, domain.Platform{TenantID: tenantID, ID: platformID, Name: platformID, Enabled: true}); err != nil {
		t.Fatal(err)
	}
}

func testCard(key, name string) domain.CardUpdate {
	return domain.CardUpdate{AgentKey: key, Operations: domain.Operations{Query: true, FileTransfer: true}, AgentCard: domain.AgentCard{Name: name, Skills: []domain.AgentCardFeature{}, Tools: []domain.AgentCardFeature{}}}
}

func TestCatalogSnapshotIsAtomicAndTenantScoped(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedTenantPlatform(t, st, "t1", "one.example", "p1")
	seedTenantPlatform(t, st, "t2", "two.example", "p2")

	begin := domain.CatalogBegin{SnapshotID: "snap-1", Revision: 1, CardCount: 2}
	if err := st.BeginCatalogSnapshot(ctx, "t1", "p1", "channel-a", begin); err != nil {
		t.Fatal(err)
	}
	if routes, err := st.ListRoutes(ctx, "t1"); err != nil || len(routes) != 0 {
		t.Fatalf("uncommitted snapshot changed routes: routes=%d err=%v", len(routes), err)
	}
	if err := st.ApplyCatalogSnapshot(ctx, "t1", "p1", "channel-a", begin, []domain.CardUpdate{testCard("assistant", "A"), testCard("helper", "H")}, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	agents, err := st.ListAgents(ctx, "t1", true)
	if err != nil || len(agents) != 2 {
		t.Fatalf("expected two projected agents, got %d err=%v", len(agents), err)
	}
	for _, agent := range agents {
		if agent.Enabled || agent.Visibility != domain.VisibilityRestricted {
			t.Fatal("new routes must default to disabled and restricted")
		}
	}
	if other, err := st.ListAgents(ctx, "t2", true); err != nil || len(other) != 0 {
		t.Fatalf("tenant t2 saw t1 catalog: %d err=%v", len(other), err)
	}

	stableKey := agents[0].PublicKey
	stableID := agents[0].ID
	updated, err := st.UpdateAgent(ctx, "t1", stableID, true, domain.VisibilityPublic, "Published", "", 0, agents[0].PolicyVersion)
	if err != nil || updated.PublicKey != stableKey {
		t.Fatalf("publish changed stable public key: %#v err=%v", updated, err)
	}

	begin2 := domain.CatalogBegin{SnapshotID: "snap-2", Revision: 2, CardCount: 1}
	if err := st.BeginCatalogSnapshot(ctx, "t1", "p1", "channel-a", begin2); err != nil {
		t.Fatal(err)
	}
	if err := st.ApplyCatalogSnapshot(ctx, "t1", "p1", "channel-a", begin2, []domain.CardUpdate{testCard(agents[0].Route.ExternalAgentKey, "Updated")}, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	routes, err := st.ListRoutes(ctx, "t1")
	if err != nil || len(routes) != 2 {
		t.Fatalf("expected preserved routes, got %d err=%v", len(routes), err)
	}
	removed := 0
	for _, route := range routes {
		if route.Status == "removed" {
			removed++
		}
	}
	if removed != 1 {
		t.Fatalf("expected one removed route, got %d", removed)
	}
	if err := st.BeginCatalogSnapshot(ctx, "t1", "p1", "channel-a", domain.CatalogBegin{SnapshotID: "stale", Revision: 1}); !errors.Is(err, storepkg.ErrConflict) {
		t.Fatalf("stale revision was accepted: %v", err)
	}
}

func TestSameExternalKeyOnTwoChannelsCreatesIndependentAgents(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	seedTenantPlatform(t, st, "t1", "one.example", "p1")
	for index, channelID := range []string{"channel-a", "channel-b"} {
		begin := domain.CatalogBegin{SnapshotID: channelID, Revision: 1, CardCount: 1}
		if err := st.BeginCatalogSnapshot(ctx, "t1", "p1", channelID, begin); err != nil {
			t.Fatal(err)
		}
		if err := st.ApplyCatalogSnapshot(ctx, "t1", "p1", channelID, begin, []domain.CardUpdate{testCard("assistant", "Agent")}, time.Now().Add(time.Duration(index)*time.Millisecond).UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	agents, err := st.ListAgents(ctx, "t1", true)
	if err != nil || len(agents) != 2 {
		t.Fatalf("expected two agents, got %d err=%v", len(agents), err)
	}
	if agents[0].ID == agents[1].ID || agents[0].PublicKey == agents[1].PublicKey || agents[0].RouteID == agents[1].RouteID {
		t.Fatal("channels with the same externalAgentKey were incorrectly merged")
	}
}

func TestIntegrityAndConsistentBackup(t *testing.T) {
	st := newTestStore(t)
	seedTenantPlatform(t, st, "t1", "one.example", "p1")
	if err := st.IntegrityCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := st.Backup(context.Background(), backup); err != nil {
		t.Fatal(err)
	}
	restored, err := Open(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if tenant, err := restored.TenantByHost(context.Background(), "one.example"); err != nil || tenant.ID != "t1" {
		t.Fatalf("backup did not preserve tenant: %#v err=%v", tenant, err)
	}
}
