package server

import (
	"context"

	"agent-gateway/internal/domain"
)

type tenantContextKey struct{}
type principalContextKey struct{}

func withIdentityContext(ctx context.Context, tenant domain.Tenant, principal domain.Principal) context.Context {
	ctx = context.WithValue(ctx, tenantContextKey{}, tenant)
	return context.WithValue(ctx, principalContextKey{}, principal)
}
func tenantFromContext(ctx context.Context) domain.Tenant {
	tenant, _ := ctx.Value(tenantContextKey{}).(domain.Tenant)
	return tenant
}
func principalFromContext(ctx context.Context) domain.Principal {
	principal, _ := ctx.Value(principalContextKey{}).(domain.Principal)
	return principal
}
