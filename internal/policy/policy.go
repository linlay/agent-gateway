package policy

import (
	"strings"

	"agent-gateway/internal/domain"
)

func Can(agent domain.GatewayAgent, principal domain.Principal, permission string) bool {
	return agent.Route.Status == "online" && CanIgnoringPresence(agent, principal, permission)
}

func CanIgnoringPresence(agent domain.GatewayAgent, principal domain.Principal, permission string) bool {
	if !agent.Enabled || agent.Route.Status == "removed" || !agent.Permissions[permission] || !routeAllows(agent.Route.Operations, permission) {
		return false
	}
	switch agent.Visibility {
	case domain.VisibilityPublic:
		return true
	case domain.VisibilityAuthenticated:
		return principal.Authenticated
	case domain.VisibilityRestricted:
		if !principal.Authenticated {
			return false
		}
		return aclAllows(agent.ACL, principal, permission)
	default:
		return false
	}
}

func routeAllows(operations domain.Operations, permission string) bool {
	switch permission {
	case domain.PermissionDiscover, domain.PermissionInvoke, domain.PermissionHistoryRead:
		return operations.Query
	case domain.PermissionRunControl:
		return operations.Query || operations.Submit || operations.Steer || operations.Interrupt
	case domain.PermissionFileTransfer:
		return operations.FileTransfer
	default:
		return false
	}
}

func aclAllows(rules []domain.ACLRule, principal domain.Principal, permission string) bool {
	roles := toSet(principal.Roles)
	groups := toSet(principal.Groups)
	for _, rule := range rules {
		if rule.Permission != permission {
			continue
		}
		switch rule.SubjectType {
		case "user":
			if rule.SubjectValue == principal.Subject {
				return true
			}
		case "role":
			if roles[rule.SubjectValue] {
				return true
			}
		case "group":
			if groups[rule.SubjectValue] {
				return true
			}
		}
	}
	return false
}

func IsTenantAdmin(principal domain.Principal) bool {
	if !principal.Authenticated {
		return false
	}
	for _, role := range principal.Roles {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "gateway_admin", "tenant_admin":
			return true
		}
	}
	return false
}
func IsGatewayAdmin(principal domain.Principal) bool {
	if !principal.Authenticated {
		return false
	}
	for _, role := range principal.Roles {
		if strings.EqualFold(strings.TrimSpace(role), "gateway_admin") {
			return true
		}
	}
	return false
}

func toSet(items []string) map[string]bool {
	set := map[string]bool{}
	for _, item := range items {
		if value := strings.TrimSpace(item); value != "" {
			set[value] = true
		}
	}
	return set
}
