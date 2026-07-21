package store

import (
	"context"
	"errors"

	"agent-gateway/internal/domain"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

type Store interface {
	Close() error
	Ping(context.Context) error

	BootstrapTenant(context.Context, domain.Tenant, []string) error
	TenantByHost(context.Context, string) (domain.Tenant, error)
	TenantByID(context.Context, string) (domain.Tenant, error)
	ListTenants(context.Context) ([]domain.Tenant, error)
	UpsertTenant(context.Context, domain.Tenant, []string) (domain.Tenant, error)

	ListPlatforms(context.Context, string) ([]domain.Platform, error)
	UpsertPlatform(context.Context, domain.Platform) (domain.Platform, error)
	Platform(context.Context, string, string) (domain.Platform, error)
	AddPlatformCredential(context.Context, string, string, string, int64) error
	ValidatePlatformCredential(context.Context, string, string, string, int64) error

	WebSession(context.Context, string, string) (domain.WebSession, error)
	PutWebSession(context.Context, domain.WebSession) error
	DeleteWebSession(context.Context, string, string) error
	AnonymousSession(context.Context, string, string) (domain.AnonymousSession, error)
	PutAnonymousSession(context.Context, domain.AnonymousSession) error
	PutOIDCFlow(context.Context, domain.OIDCFlow) error
	ConsumeOIDCFlow(context.Context, string, string, int64) (domain.OIDCFlow, error)
	ClaimAnonymous(context.Context, string, string, string) error

	BeginCatalogSnapshot(context.Context, string, string, string, domain.CatalogBegin) error
	ApplyCatalogSnapshot(context.Context, string, string, string, domain.CatalogBegin, []domain.CardUpdate, int64) error
	UpsertLegacyCard(context.Context, string, string, string, domain.CardUpdate, int64) (domain.Route, error)
	MarkChannelStatus(context.Context, string, string, string, string, int64) error
	Route(context.Context, string, string) (domain.Route, error)
	ListRoutes(context.Context, string) ([]domain.Route, error)

	AgentByPublicKey(context.Context, string, string) (domain.GatewayAgent, error)
	AgentByID(context.Context, string, string) (domain.GatewayAgent, error)
	ListAgents(context.Context, string, bool) ([]domain.GatewayAgent, error)
	UpdateAgent(context.Context, string, string, bool, string, string, string, int, int64) (domain.GatewayAgent, error)
	ReplaceAgentPolicy(context.Context, string, string, string, map[string]bool, []domain.ACLRule, int64) (domain.GatewayAgent, error)

	CreateChatRunBindings(context.Context, domain.ChatBinding, domain.RunBinding, *domain.IdempotencyBinding) error
	CreateChatBinding(context.Context, domain.ChatBinding) error
	CreateRunBinding(context.Context, domain.RunBinding, *domain.IdempotencyBinding) error
	ChatBinding(context.Context, string, string) (domain.ChatBinding, error)
	RunBinding(context.Context, string, string) (domain.RunBinding, error)
	RunBindingByRequest(context.Context, string, string) (domain.RunBinding, error)
	ListChatBindings(context.Context, string, string, string, string) ([]domain.ChatBinding, error)
	UpdateRunProgress(context.Context, string, string, string, int64, int64) error
	UpdateChatBindingStatus(context.Context, string, string, string, int64) error
	DeleteChatBinding(context.Context, string, string) error
	PutResourceBinding(context.Context, domain.ResourceBinding) error
	ResourceBindingByToken(context.Context, string, string, int64) (domain.ResourceBinding, error)
	ClaimResourceBinding(context.Context, string, string, string, string, int64) error
	UpdateResourceBinding(context.Context, string, string, string, string, string, int64, int64) error
	DeleteResourceBinding(context.Context, string, string) error
	IdempotencyBinding(context.Context, string, string) (domain.IdempotencyBinding, error)
	PutViewportBinding(context.Context, domain.ViewportBinding) error
	ViewportBinding(context.Context, string, string, string) (domain.ViewportBinding, error)

	AppendAudit(context.Context, domain.AuditRecord) error
	ListAudit(context.Context, string, int) ([]domain.AuditRecord, error)
	Cleanup(context.Context, int64) error
}
