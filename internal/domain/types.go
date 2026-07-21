package domain

import (
	"encoding/json"
	"strings"
)

const (
	VisibilityPublic        = "public"
	VisibilityAuthenticated = "authenticated"
	VisibilityRestricted    = "restricted"

	PermissionDiscover     = "discover"
	PermissionInvoke       = "invoke"
	PermissionHistoryRead  = "history.read"
	PermissionRunControl   = "run.control"
	PermissionFileTransfer = "file.transfer"
)

var AllPermissions = []string{
	PermissionDiscover,
	PermissionInvoke,
	PermissionHistoryRead,
	PermissionRunControl,
	PermissionFileTransfer,
}

type Tenant struct {
	ID                  string `json:"tenantId"`
	Name                string `json:"name"`
	Status              string `json:"status"`
	OIDCIssuer          string `json:"oidcIssuer,omitempty"`
	OIDCClientID        string `json:"oidcClientId,omitempty"`
	OIDCClientSecretEnv string `json:"oidcClientSecretEnv,omitempty"`
	RolesClaim          string `json:"rolesClaim,omitempty"`
	GroupsClaim         string `json:"groupsClaim,omitempty"`
	CreatedAt           int64  `json:"createdAt"`
	UpdatedAt           int64  `json:"updatedAt"`
}

type Platform struct {
	TenantID  string `json:"tenantId"`
	ID        string `json:"platformId"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
}

type Operations struct {
	Query        bool `json:"query"`
	Submit       bool `json:"submit"`
	Steer        bool `json:"steer"`
	Interrupt    bool `json:"interrupt"`
	FileTransfer bool `json:"fileTransfer"`
}

type AgentCardFeature struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags"`
}

type AgentCard struct {
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Role        string             `json:"role,omitempty"`
	Icon        any                `json:"icon,omitempty"`
	Greetings   []string           `json:"greetings,omitempty"`
	Wonders     []string           `json:"wonders,omitempty"`
	Mode        string             `json:"mode,omitempty"`
	Skills      []AgentCardFeature `json:"skills"`
	Tools       []AgentCardFeature `json:"tools"`
}

// CatalogBegin and CardUpdate are domain-level catalog messages. The channel
// package aliases these types so persistence remains independent of the
// transport implementation (and a PostgreSQL adapter can reuse the contract).
type CatalogBegin struct {
	SnapshotID string `json:"snapshotId"`
	Revision   int64  `json:"revision"`
	CardCount  int    `json:"cardCount"`
}

type CardUpdate struct {
	SnapshotID string     `json:"snapshotId,omitempty"`
	Revision   int64      `json:"revision,omitempty"`
	AgentKey   string     `json:"agentKey"`
	Operations Operations `json:"operations,omitempty"`
	AgentCard  AgentCard  `json:"agentCard"`
}

type Route struct {
	ID               string     `json:"routeId"`
	TenantID         string     `json:"tenantId"`
	PlatformID       string     `json:"platformId"`
	ChannelID        string     `json:"channelId"`
	ExternalAgentKey string     `json:"externalAgentKey"`
	Card             AgentCard  `json:"agentCard"`
	Operations       Operations `json:"operations"`
	ProtocolMode     string     `json:"protocolMode"`
	Status           string     `json:"status"`
	Revision         int64      `json:"revision"`
	SnapshotID       string     `json:"snapshotId,omitempty"`
	LastSeenAt       int64      `json:"lastSeenAt,omitempty"`
	CreatedAt        int64      `json:"createdAt"`
	UpdatedAt        int64      `json:"updatedAt"`
}

type GatewayAgent struct {
	ID                 string          `json:"agentId"`
	TenantID           string          `json:"tenantId"`
	RouteID            string          `json:"routeId"`
	PublicKey          string          `json:"publicKey"`
	Enabled            bool            `json:"enabled"`
	Visibility         string          `json:"visibility"`
	Permissions        map[string]bool `json:"permissions"`
	DisplayName        string          `json:"displayName,omitempty"`
	DisplayDescription string          `json:"displayDescription,omitempty"`
	SortOrder          int             `json:"sortOrder"`
	PolicyVersion      int64           `json:"policyVersion"`
	Route              Route           `json:"route"`
	ACL                []ACLRule       `json:"acl,omitempty"`
	CreatedAt          int64           `json:"createdAt"`
	UpdatedAt          int64           `json:"updatedAt"`
}

func (a GatewayAgent) EffectiveName() string {
	if value := strings.TrimSpace(a.DisplayName); value != "" {
		return value
	}
	if value := strings.TrimSpace(a.Route.Card.Name); value != "" {
		return value
	}
	return a.PublicKey
}

func (a GatewayAgent) EffectiveDescription() string {
	if value := strings.TrimSpace(a.DisplayDescription); value != "" {
		return value
	}
	return strings.TrimSpace(a.Route.Card.Description)
}

type ACLRule struct {
	SubjectType  string `json:"subjectType"`
	SubjectValue string `json:"subjectValue"`
	Permission   string `json:"permission"`
}

type Principal struct {
	TenantID      string
	Subject       string
	AnonymousID   string
	DisplayName   string
	Roles         []string
	Groups        []string
	Authenticated bool
	AuthMethod    string
	CSRFToken     string
}

func (p Principal) OwnerKind() string {
	if p.Authenticated {
		return "user"
	}
	return "anonymous"
}

func (p Principal) OwnerID() string {
	if p.Authenticated {
		return p.Subject
	}
	return p.AnonymousID
}

type WebSession struct {
	TenantID    string
	SessionHash string
	Subject     string
	DisplayName string
	Roles       []string
	Groups      []string
	CSRFToken   string
	ExpiresAt   int64
	CreatedAt   int64
	UpdatedAt   int64
}

type AnonymousSession struct {
	TenantID    string
	SessionHash string
	AnonymousID string
	CSRFToken   string
	ExpiresAt   int64
	CreatedAt   int64
	UpdatedAt   int64
}

type OIDCFlow struct {
	TenantID    string
	StateHash   string
	Verifier    string
	Nonce       string
	RedirectURI string
	ReturnTo    string
	AnonymousID string
	ExpiresAt   int64
	CreatedAt   int64
}

type ChatBinding struct {
	TenantID  string `json:"tenantId"`
	ChatID    string `json:"chatId"`
	OwnerKind string `json:"ownerKind"`
	OwnerID   string `json:"ownerId"`
	AgentID   string `json:"agentId"`
	RouteID   string `json:"routeId"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
}

type RunBinding struct {
	TenantID  string `json:"tenantId"`
	RunID     string `json:"runId"`
	ChatID    string `json:"chatId"`
	RouteID   string `json:"routeId"`
	RequestID string `json:"requestId"`
	Status    string `json:"status"`
	LastSeq   int64  `json:"lastSeq"`
	CreatedAt int64  `json:"createdAt"`
	UpdatedAt int64  `json:"updatedAt"`
}

type ResourceBinding struct {
	TenantID    string `json:"tenantId"`
	ResourceKey string `json:"resourceKey"`
	ChatID      string `json:"chatId"`
	OwnerKind   string `json:"ownerKind"`
	OwnerID     string `json:"ownerId"`
	RouteID     string `json:"routeId"`
	Direction   string `json:"direction"`
	TokenHash   string `json:"-"`
	SpoolPath   string `json:"-"`
	FileName    string `json:"fileName"`
	MimeType    string `json:"mimeType"`
	SizeBytes   int64  `json:"sizeBytes"`
	SHA256      string `json:"sha256"`
	Status      string `json:"status"`
	ExpiresAt   int64  `json:"expiresAt"`
	CreatedAt   int64  `json:"createdAt"`
	UpdatedAt   int64  `json:"updatedAt"`
}

type IdempotencyBinding struct {
	TenantID    string
	KeyHash     string
	OwnerKind   string
	OwnerID     string
	RequestHash string
	ChatID      string
	RunID       string
	ExpiresAt   int64
	CreatedAt   int64
}

type ViewportBinding struct {
	TenantID    string
	RunID       string
	ChatID      string
	RouteID     string
	ViewportKey string
	CreatedAt   int64
	UpdatedAt   int64
}

type AuditRecord struct {
	TenantID  string          `json:"tenantId"`
	ID        string          `json:"auditId"`
	Subject   string          `json:"subject"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	Result    string          `json:"result"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt int64           `json:"createdAt"`
}
