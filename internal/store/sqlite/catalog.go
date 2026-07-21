package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"agent-gateway/internal/domain"
	"agent-gateway/internal/id"
	storepkg "agent-gateway/internal/store"
)

func normalizeOperations(value domain.Operations) domain.Operations {
	if !value.Query && !value.Submit && !value.Steer && !value.Interrupt && !value.FileTransfer {
		value.Query = true
	}
	return value
}

func (s *Store) BeginCatalogSnapshot(ctx context.Context, tenantID, platformID, channelID string, begin domain.CatalogBegin) error {
	now := time.Now().UnixMilli()
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		var current int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision),-1) FROM catalog_snapshots WHERE tenant_id=? AND platform_id=? AND channel_id=? AND status='committed'`, tenantID, platformID, channelID).Scan(&current); err != nil {
			return err
		}
		if begin.Revision <= current {
			return fmt.Errorf("%w: catalog revision must increase", storepkg.ErrConflict)
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO catalog_snapshots(tenant_id,platform_id,channel_id,snapshot_id,revision,card_count,status,created_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,platform_id,channel_id,snapshot_id) DO NOTHING`, tenantID, platformID, channelID, begin.SnapshotID, begin.Revision, begin.CardCount, "staging", now)
		if err != nil {
			return mapSQLError(err)
		}
		if count, _ := result.RowsAffected(); count != 1 {
			return fmt.Errorf("%w: snapshot id already exists", storepkg.ErrConflict)
		}
		return nil
	})
}

func (s *Store) ApplyCatalogSnapshot(ctx context.Context, tenantID, platformID, channelID string, begin domain.CatalogBegin, cards []domain.CardUpdate, now int64) error {
	return s.writeTx(ctx, func(tx *sql.Tx) error {
		var status string
		err := tx.QueryRowContext(ctx, `SELECT status FROM catalog_snapshots WHERE tenant_id=? AND platform_id=? AND channel_id=? AND snapshot_id=?`, tenantID, platformID, channelID, begin.SnapshotID).Scan(&status)
		if err != nil {
			return mapSQLError(err)
		}
		if status != "staging" {
			return fmt.Errorf("%w: snapshot is not staging", storepkg.ErrConflict)
		}
		seen := map[string]struct{}{}
		for _, card := range cards {
			routeID, err := upsertRouteTx(ctx, tx, tenantID, platformID, channelID, "snapshot-v2", begin.SnapshotID, begin.Revision, card, now)
			if err != nil {
				return err
			}
			seen[routeID] = struct{}{}
		}
		rows, err := tx.QueryContext(ctx, `SELECT route_id FROM channel_routes WHERE tenant_id=? AND platform_id=? AND channel_id=?`, tenantID, platformID, channelID)
		if err != nil {
			return err
		}
		var existing []string
		for rows.Next() {
			var routeID string
			if err := rows.Scan(&routeID); err != nil {
				rows.Close()
				return err
			}
			existing = append(existing, routeID)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, routeID := range existing {
			if _, ok := seen[routeID]; ok {
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE channel_routes SET status='removed',updated_at=? WHERE tenant_id=? AND route_id=?`, now, tenantID, routeID); err != nil {
				return err
			}
		}
		result, err := tx.ExecContext(ctx, `UPDATE catalog_snapshots SET status='committed',committed_at=? WHERE tenant_id=? AND platform_id=? AND channel_id=? AND snapshot_id=? AND status='staging'`, now, tenantID, platformID, channelID, begin.SnapshotID)
		if err != nil {
			return err
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return fmt.Errorf("%w: snapshot commit lost", storepkg.ErrConflict)
		}
		return nil
	})
}

func upsertRouteTx(ctx context.Context, tx *sql.Tx, tenantID, platformID, channelID, protocolMode, snapshotID string, revision int64, card domain.CardUpdate, now int64) (string, error) {
	card.AgentKey = strings.TrimSpace(card.AgentKey)
	if card.AgentKey == "" {
		return "", fmt.Errorf("agentKey is required")
	}
	var routeID string
	err := tx.QueryRowContext(ctx, `SELECT route_id FROM channel_routes WHERE tenant_id=? AND platform_id=? AND channel_id=? AND external_agent_key=?`, tenantID, platformID, channelID, card.AgentKey).Scan(&routeID)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	if routeID == "" {
		routeID = id.New("route")
	}
	operations := card.Operations
	if protocolMode == "legacy" {
		operations = normalizeOperations(operations)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO channel_routes(route_id,tenant_id,platform_id,channel_id,external_agent_key,card_json,operations_json,protocol_mode,status,revision,snapshot_id,last_seen_at,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,platform_id,channel_id,external_agent_key) DO UPDATE SET
		card_json=excluded.card_json,operations_json=excluded.operations_json,protocol_mode=excluded.protocol_mode,status='online',revision=excluded.revision,
		snapshot_id=excluded.snapshot_id,last_seen_at=excluded.last_seen_at,updated_at=excluded.updated_at`,
		routeID, tenantID, platformID, channelID, card.AgentKey, jsonText(card.AgentCard), jsonText(operations), protocolMode, "online", revision, snapshotID, now, now, now)
	if err != nil {
		return "", mapSQLError(err)
	}
	permissions := map[string]bool{}
	for _, permission := range domain.AllPermissions {
		permissions[permission] = true
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO gateway_agents(agent_id,tenant_id,route_id,public_key,enabled,visibility,permissions_json,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(route_id) DO NOTHING`, id.New("agent"), tenantID, routeID, id.New("agt"), 0, domain.VisibilityRestricted, jsonText(permissions), now, now)
	return routeID, mapSQLError(err)
}

func (s *Store) UpsertLegacyCard(ctx context.Context, tenantID, platformID, channelID string, card domain.CardUpdate, now int64) (domain.Route, error) {
	var routeID string
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		var err error
		routeID, err = upsertRouteTx(ctx, tx, tenantID, platformID, channelID, "legacy", "", card.Revision, card, now)
		return err
	})
	if err != nil {
		return domain.Route{}, err
	}
	return s.Route(ctx, tenantID, routeID)
}

func (s *Store) MarkChannelStatus(ctx context.Context, tenantID, platformID, channelID, status string, now int64) error {
	if status != "online" && status != "offline" {
		return fmt.Errorf("invalid channel status")
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.ExecContext(ctx, `UPDATE channel_routes SET status=CASE WHEN status='removed' THEN status ELSE ? END,last_seen_at=?,updated_at=?
		WHERE tenant_id=? AND platform_id=? AND channel_id=?`, status, now, now, tenantID, platformID, channelID)
	return err
}

func scanRoute(scanner interface{ Scan(...any) error }) (domain.Route, error) {
	var item domain.Route
	var cardJSON, operationsJSON string
	err := scanner.Scan(&item.ID, &item.TenantID, &item.PlatformID, &item.ChannelID, &item.ExternalAgentKey,
		&cardJSON, &operationsJSON, &item.ProtocolMode, &item.Status, &item.Revision, &item.SnapshotID,
		&item.LastSeenAt, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		return domain.Route{}, mapSQLError(err)
	}
	if err := json.Unmarshal([]byte(cardJSON), &item.Card); err != nil {
		return domain.Route{}, err
	}
	if err := json.Unmarshal([]byte(operationsJSON), &item.Operations); err != nil {
		return domain.Route{}, err
	}
	return item, nil
}

const routeColumns = `route_id,tenant_id,platform_id,channel_id,external_agent_key,card_json,operations_json,protocol_mode,status,revision,snapshot_id,last_seen_at,created_at,updated_at`

func (s *Store) Route(ctx context.Context, tenantID, routeID string) (domain.Route, error) {
	return scanRoute(s.db.QueryRowContext(ctx, `SELECT `+routeColumns+` FROM channel_routes WHERE tenant_id=? AND route_id=?`, tenantID, routeID))
}

func (s *Store) ListRoutes(ctx context.Context, tenantID string) ([]domain.Route, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+routeColumns+` FROM channel_routes WHERE tenant_id=? ORDER BY platform_id,channel_id,external_agent_key`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.Route{}
	for rows.Next() {
		item, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanAgent(scanner interface{ Scan(...any) error }) (domain.GatewayAgent, error) {
	var item domain.GatewayAgent
	var enabled int
	var permissionsJSON string
	var cardJSON, operationsJSON string
	err := scanner.Scan(&item.ID, &item.TenantID, &item.RouteID, &item.PublicKey, &enabled, &item.Visibility,
		&permissionsJSON, &item.DisplayName, &item.DisplayDescription, &item.SortOrder, &item.PolicyVersion, &item.CreatedAt, &item.UpdatedAt,
		&item.Route.ID, &item.Route.PlatformID, &item.Route.ChannelID, &item.Route.ExternalAgentKey, &cardJSON, &operationsJSON,
		&item.Route.ProtocolMode, &item.Route.Status, &item.Route.Revision, &item.Route.SnapshotID, &item.Route.LastSeenAt, &item.Route.CreatedAt, &item.Route.UpdatedAt)
	if err != nil {
		return domain.GatewayAgent{}, mapSQLError(err)
	}
	item.Enabled = enabled != 0
	item.Route.TenantID = item.TenantID
	if err := json.Unmarshal([]byte(permissionsJSON), &item.Permissions); err != nil {
		return item, err
	}
	if err := json.Unmarshal([]byte(cardJSON), &item.Route.Card); err != nil {
		return item, err
	}
	if err := json.Unmarshal([]byte(operationsJSON), &item.Route.Operations); err != nil {
		return item, err
	}
	if item.Permissions == nil {
		item.Permissions = map[string]bool{}
	}
	return item, nil
}

const agentJoinColumns = `a.agent_id,a.tenant_id,a.route_id,a.public_key,a.enabled,a.visibility,a.permissions_json,a.display_name,a.display_description,
	a.sort_order,a.policy_version,a.created_at,a.updated_at,r.route_id,r.platform_id,r.channel_id,r.external_agent_key,r.card_json,r.operations_json,
	r.protocol_mode,r.status,r.revision,r.snapshot_id,r.last_seen_at,r.created_at,r.updated_at`

func (s *Store) agentQuery(ctx context.Context, where string, args ...any) (domain.GatewayAgent, error) {
	item, err := scanAgent(s.db.QueryRowContext(ctx, `SELECT `+agentJoinColumns+` FROM gateway_agents a JOIN channel_routes r ON r.route_id=a.route_id WHERE `+where, args...))
	if err != nil {
		return item, err
	}
	item.ACL, err = s.agentACL(ctx, item.TenantID, item.ID)
	return item, err
}

func (s *Store) AgentByPublicKey(ctx context.Context, tenantID, publicKey string) (domain.GatewayAgent, error) {
	return s.agentQuery(ctx, `a.tenant_id=? AND a.public_key=?`, tenantID, publicKey)
}

func (s *Store) AgentByID(ctx context.Context, tenantID, agentID string) (domain.GatewayAgent, error) {
	return s.agentQuery(ctx, `a.tenant_id=? AND a.agent_id=?`, tenantID, agentID)
}

func (s *Store) ListAgents(ctx context.Context, tenantID string, includeDisabled bool) ([]domain.GatewayAgent, error) {
	query := `SELECT ` + agentJoinColumns + ` FROM gateway_agents a JOIN channel_routes r ON r.route_id=a.route_id WHERE a.tenant_id=?`
	if !includeDisabled {
		query += ` AND a.enabled=1 AND r.status='online'`
	}
	query += ` ORDER BY a.sort_order,a.public_key`
	rows, err := s.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.GatewayAgent{}
	for rows.Next() {
		item, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range items {
		items[i].ACL, err = s.agentACL(ctx, tenantID, items[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return items, nil
}

func (s *Store) agentACL(ctx context.Context, tenantID, agentID string) ([]domain.ACLRule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT subject_type,subject_value,permission FROM agent_acl WHERE tenant_id=? AND agent_id=? ORDER BY subject_type,subject_value,permission`, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []domain.ACLRule{}
	for rows.Next() {
		var item domain.ACLRule
		if err := rows.Scan(&item.SubjectType, &item.SubjectValue, &item.Permission); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdateAgent(ctx context.Context, tenantID, agentID string, enabled bool, visibility, name, description string, sortOrder int, expectedVersion int64) (domain.GatewayAgent, error) {
	if !validVisibility(visibility) {
		return domain.GatewayAgent{}, fmt.Errorf("invalid visibility")
	}
	now := time.Now().UnixMilli()
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		query := `UPDATE gateway_agents SET enabled=?,visibility=?,display_name=?,display_description=?,sort_order=?,policy_version=policy_version+1,updated_at=? WHERE tenant_id=? AND agent_id=?`
		args := []any{boolInt(enabled), visibility, strings.TrimSpace(name), strings.TrimSpace(description), sortOrder, now, tenantID, agentID}
		if expectedVersion > 0 {
			query += ` AND policy_version=?`
			args = append(args, expectedVersion)
		}
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return mapSQLError(err)
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return storepkg.ErrConflict
		}
		return nil
	})
	if err != nil {
		return domain.GatewayAgent{}, err
	}
	return s.AgentByID(ctx, tenantID, agentID)
}

func validVisibility(value string) bool {
	return value == domain.VisibilityPublic || value == domain.VisibilityAuthenticated || value == domain.VisibilityRestricted
}

func (s *Store) ReplaceAgentPolicy(ctx context.Context, tenantID, agentID, visibility string, permissions map[string]bool, acl []domain.ACLRule, expectedVersion int64) (domain.GatewayAgent, error) {
	if !validVisibility(visibility) {
		return domain.GatewayAgent{}, fmt.Errorf("invalid visibility")
	}
	allowed := map[string]bool{}
	for _, permission := range domain.AllPermissions {
		allowed[permission] = true
	}
	for permission := range permissions {
		if !allowed[permission] {
			return domain.GatewayAgent{}, fmt.Errorf("invalid permission %q", permission)
		}
	}
	sort.Slice(acl, func(i, j int) bool {
		if acl[i].SubjectType != acl[j].SubjectType {
			return acl[i].SubjectType < acl[j].SubjectType
		}
		if acl[i].SubjectValue != acl[j].SubjectValue {
			return acl[i].SubjectValue < acl[j].SubjectValue
		}
		return acl[i].Permission < acl[j].Permission
	})
	now := time.Now().UnixMilli()
	err := s.writeTx(ctx, func(tx *sql.Tx) error {
		query := `UPDATE gateway_agents SET visibility=?,permissions_json=?,policy_version=policy_version+1,updated_at=? WHERE tenant_id=? AND agent_id=?`
		args := []any{visibility, jsonText(permissions), now, tenantID, agentID}
		if expectedVersion > 0 {
			query += ` AND policy_version=?`
			args = append(args, expectedVersion)
		}
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		count, _ := result.RowsAffected()
		if count != 1 {
			return storepkg.ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM agent_acl WHERE tenant_id=? AND agent_id=?`, tenantID, agentID); err != nil {
			return err
		}
		for _, rule := range acl {
			if rule.SubjectType != "user" && rule.SubjectType != "role" && rule.SubjectType != "group" {
				return fmt.Errorf("invalid acl subject type")
			}
			if strings.TrimSpace(rule.SubjectValue) == "" || !allowed[rule.Permission] {
				return fmt.Errorf("invalid acl rule")
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO agent_acl(acl_id,tenant_id,agent_id,subject_type,subject_value,permission,created_at) VALUES(?,?,?,?,?,?,?)`, id.New("acl"), tenantID, agentID, rule.SubjectType, strings.TrimSpace(rule.SubjectValue), rule.Permission, now); err != nil {
				return mapSQLError(err)
			}
		}
		return nil
	})
	if err != nil {
		return domain.GatewayAgent{}, err
	}
	return s.AgentByID(ctx, tenantID, agentID)
}
