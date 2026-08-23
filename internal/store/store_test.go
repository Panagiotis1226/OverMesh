package store

import (
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testNetwork(t *testing.T, s *Store) Network {
	t.Helper()
	nw, err := s.EnsureNetwork("default",
		netip.MustParsePrefix("100.96.0.0/11"), netip.MustParsePrefix("fdab:3f19::/48"))
	if err != nil {
		t.Fatal(err)
	}
	return nw
}

func TestEnsureNetworkIdempotent(t *testing.T) {
	s := open(t)
	a := testNetwork(t, s)
	b := testNetwork(t, s)
	if a.ID != b.ID {
		t.Fatalf("EnsureNetwork not idempotent: %d != %d", a.ID, b.ID)
	}
	if a.V4Prefix.String() != "100.96.0.0/11" {
		t.Fatalf("v4 prefix round trip: %v", a.V4Prefix)
	}
}

func TestNodeLifecycle(t *testing.T) {
	s := open(t)
	nw := testNetwork(t, s)

	n, err := s.CreateNode(Node{
		NetworkID:  nw.ID,
		Hostname:   "laptop",
		MachineKey: "mkey:aa",
		NodeKey:    "nodekey:bb",
		IPv4:       netip.MustParseAddr("100.96.0.1"),
		IPv6:       netip.MustParseAddr("fdab:3f19::1"),
		OS:         "linux",
	})
	if err != nil {
		t.Fatal(err)
	}
	if n.ID == 0 {
		t.Fatal("no ID assigned")
	}

	got, err := s.NodeByMachineKey("mkey:aa")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hostname != "laptop" || got.IPv4 != n.IPv4 || got.IPv6 != n.IPv6 {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if !got.LastSeen.IsZero() {
		t.Fatal("fresh node should have zero LastSeen")
	}

	if err := s.UpdateNodeEndpoints(n.ID, []string{"10.0.0.5:41642"}); err != nil {
		t.Fatal(err)
	}
	if err := s.TouchNode(n.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.NodeByID(n.ID)
	if len(got.Endpoints) != 1 || got.Endpoints[0] != "10.0.0.5:41642" {
		t.Fatalf("endpoints round trip: %v", got.Endpoints)
	}
	if got.LastSeen.IsZero() {
		t.Fatal("LastSeen not touched")
	}

	taken, _ := s.HostnameTaken(nw.ID, "laptop")
	if !taken {
		t.Fatal("hostname should be taken")
	}

	nodes, _ := s.NodesInNetwork(nw.ID)
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}

	if err := s.DeleteNode(n.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NodeByID(n.ID); err != ErrNotFound {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
	if err := s.DeleteNode(n.ID); err != ErrNotFound {
		t.Fatalf("double delete: want ErrNotFound, got %v", err)
	}
}

func TestSetupKeyFlow(t *testing.T) {
	s := open(t)
	nw := testNetwork(t, s)

	reusable, err := s.NewSetupKey(nw.ID, true, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(reusable.Key) != 3+48 || reusable.Key[:3] != "sk-" {
		t.Fatalf("unexpected key format %q", reusable.Key)
	}

	// Reusable key works twice.
	if _, err := s.UseSetupKey(reusable.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseSetupKey(reusable.Key); err != nil {
		t.Fatal(err)
	}

	// Single-use key works once.
	oneshot, _ := s.NewSetupKey(nw.ID, false, time.Time{})
	if _, err := s.UseSetupKey(oneshot.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseSetupKey(oneshot.Key); err == nil {
		t.Fatal("single-use key accepted twice")
	}

	// Expired key rejected.
	expired, _ := s.NewSetupKey(nw.ID, true, time.Now().Add(-time.Hour))
	if _, err := s.UseSetupKey(expired.Key); err == nil {
		t.Fatal("expired key accepted")
	}

	// Revoked key rejected.
	revoked, _ := s.NewSetupKey(nw.ID, true, time.Time{})
	if err := s.RevokeSetupKey(revoked.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseSetupKey(revoked.Key); err == nil {
		t.Fatal("revoked key accepted")
	}

	// Unknown key rejected.
	if _, err := s.UseSetupKey("sk-doesnotexist"); err == nil {
		t.Fatal("unknown key accepted")
	}

	keys, _ := s.SetupKeys(nw.ID)
	if len(keys) != 4 {
		t.Fatalf("want 4 keys, got %d", len(keys))
	}
}

func TestSettings(t *testing.T) {
	s := open(t)
	if _, err := s.Setting("admin_hash"); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.SetSetting("admin_hash", "x"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting("admin_hash", "y"); err != nil {
		t.Fatal(err)
	}
	v, err := s.Setting("admin_hash")
	if err != nil || v != "y" {
		t.Fatalf("got %q, %v", v, err)
	}
}
