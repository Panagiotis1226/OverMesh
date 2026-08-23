package store

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func usersTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestUserLifecycle(t *testing.T) {
	s := usersTestStore(t)

	u, err := s.CreateUser("Peter", "hunter2hunter2", RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "peter" {
		t.Fatalf("username not normalized: %q", u.Username)
	}
	if _, err := s.CreateUser("peter", "anotherpass123", RoleMember); err == nil {
		t.Fatal("duplicate username must fail")
	}
	if _, err := s.CreateUser("x", "short", RoleMember); err == nil {
		t.Fatal("short password must fail")
	}
	if _, err := s.CreateUser("bad name!", "longenough1", RoleMember); err == nil {
		t.Fatal("invalid username must fail")
	}

	if _, err := s.CheckPassword("peter", "hunter2hunter2"); err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
	if _, err := s.CheckPassword("peter", "wrong-password"); err == nil {
		t.Fatal("wrong password accepted")
	}

	if err := s.SetUserDisabled(u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckPassword("peter", "hunter2hunter2"); err == nil {
		t.Fatal("disabled account must not log in")
	}
	if err := s.SetUserDisabled(u.ID, false); err != nil {
		t.Fatal(err)
	}

	if err := s.SetUserPassword(u.ID, "newpassword99"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckPassword("peter", "newpassword99"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}

	if err := s.SetUserRole(u.ID, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	got, _ := s.UserByID(u.ID)
	if got.Role != RoleAdmin {
		t.Fatalf("role = %q", got.Role)
	}

	if err := s.DeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByName("peter"); err != ErrNotFound {
		t.Fatalf("deleted user still found: %v", err)
	}
}

func TestEnsureAdminUserMigration(t *testing.T) {
	s := usersTestStore(t)

	// Legacy hash present -> migrated into user 'admin'.
	legacy := "$2a$10$0123456789012345678901uZVNDIWZuOZAyLLLGXKjSLRqTY2Nqhi" // shape only
	need, err := s.EnsureAdminUser("", legacy)
	if err != nil || need {
		t.Fatalf("EnsureAdminUser legacy: need=%v err=%v", need, err)
	}
	if _, err := s.UserByName("admin"); err != nil {
		t.Fatal("legacy admin not migrated")
	}

	// Explicit password resets it.
	if _, err := s.EnsureAdminUser("brand-new-password", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckPassword("admin", "brand-new-password"); err != nil {
		t.Fatalf("explicit reset didn't take: %v", err)
	}
}

func TestOwnershipFlow(t *testing.T) {
	s := usersTestStore(t)
	nw, err := s.EnsureNetwork("default",
		netip.MustParsePrefix("100.96.0.0/11"), netip.MustParsePrefix("fdab:3f19::/48"))
	if err != nil {
		t.Fatal(err)
	}
	member, err := s.CreateUser("member1", "memberpass123", RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	k, err := s.NewSetupKey(nw.ID, true, time.Time{}, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	nw2, ownerID, err := s.UseSetupKey(k.Key)
	if err != nil || nw2.ID != nw.ID || ownerID != member.ID {
		t.Fatalf("UseSetupKey: owner=%d err=%v", ownerID, err)
	}

	n, err := s.CreateNode(Node{
		NetworkID: nw.ID, Hostname: "members-laptop", MachineKey: "mkey:01", NodeKey: "nodekey:02",
		IPv4: netip.MustParseAddr("100.96.0.9"), IPv6: netip.MustParseAddr("fdab:3f19::9"),
		OwnerUserID: ownerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.NodeByID(n.ID)
	if err != nil || got.OwnerUserID != member.ID {
		t.Fatalf("node owner = %d, want %d (err=%v)", got.OwnerUserID, member.ID, err)
	}
}

func TestAuditLog(t *testing.T) {
	s := usersTestStore(t)
	for _, a := range []string{"login", "acl.save", "route.approve"} {
		if err := s.Audit("peter", a, "target-x", "details-y"); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := s.AuditLog(10)
	if err != nil || len(entries) != 3 {
		t.Fatalf("audit entries = %d, err=%v", len(entries), err)
	}
	if entries[0].Action != "route.approve" {
		t.Fatalf("newest-first violated: %+v", entries[0])
	}
}
