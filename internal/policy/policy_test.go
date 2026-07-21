package policy

import (
	"testing"

	"agent-gateway/internal/domain"
)

func TestVisibilityAndOperationIntersection(t *testing.T) {
	agent := domain.GatewayAgent{Enabled: true, Visibility: domain.VisibilityPublic, Permissions: map[string]bool{domain.PermissionDiscover: true, domain.PermissionInvoke: true, domain.PermissionFileTransfer: true}, Route: domain.Route{Status: "online", Operations: domain.Operations{Query: true}}}
	anonymous := domain.Principal{AnonymousID: "anon-1"}
	if !Can(agent, anonymous, domain.PermissionDiscover) || !Can(agent, anonymous, domain.PermissionInvoke) {
		t.Fatal("public query agent should be discoverable and invokable anonymously")
	}
	if Can(agent, anonymous, domain.PermissionFileTransfer) {
		t.Fatal("gateway policy must not grant file transfer absent platform export operation")
	}
	agent.Route.Status = "offline"
	if Can(agent, anonymous, domain.PermissionInvoke) {
		t.Fatal("offline agent must be hidden from ordinary policy checks")
	}
	if !CanIgnoringPresence(agent, anonymous, domain.PermissionInvoke) {
		t.Fatal("bound-resource authorization must be checkable independently from presence")
	}
}

func TestRestrictedACLIsPermissionSpecific(t *testing.T) {
	agent := domain.GatewayAgent{Enabled: true, Visibility: domain.VisibilityRestricted, Permissions: map[string]bool{domain.PermissionDiscover: true, domain.PermissionInvoke: true}, ACL: []domain.ACLRule{{SubjectType: "role", SubjectValue: "member", Permission: domain.PermissionDiscover}}, Route: domain.Route{Status: "online", Operations: domain.Operations{Query: true}}}
	principal := domain.Principal{Authenticated: true, Subject: "u1", Roles: []string{"member"}}
	if !Can(agent, principal, domain.PermissionDiscover) {
		t.Fatal("matching role should grant discover")
	}
	if Can(agent, principal, domain.PermissionInvoke) {
		t.Fatal("discover ACL must not grant invoke")
	}
}
