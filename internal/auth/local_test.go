package auth

import "testing"

func TestLocalAuthenticate(t *testing.T) {
	service, err := NewLocal("admin", "$2y$10$zyl54qe9Gnag/R1Z3zyPKOl1ky4JeO0xx.FfkmDsTudw/ld/T6io2", "Administrator", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	identity, ok := service.Authenticate("admin", "password")
	if !ok || identity.Subject != "local:admin" || identity.DisplayName != "Administrator" {
		t.Fatalf("unexpected identity: %#v, ok=%v", identity, ok)
	}
	if _, ok := service.Authenticate("admin", "wrong"); ok {
		t.Fatal("wrong password must be rejected")
	}
	if _, ok := service.Authenticate("other", "password"); ok {
		t.Fatal("wrong username must be rejected")
	}
}
