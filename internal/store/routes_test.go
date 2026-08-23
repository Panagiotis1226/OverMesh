package store

import (
	"net/netip"
	"path/filepath"
	"testing"
)

func routesTestStore(t *testing.T) (*Store, int64) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "routes.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	nw, err := s.EnsureNetwork("default",
		netip.MustParsePrefix("100.96.0.0/11"), netip.MustParsePrefix("fdab:3f19::/48"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.CreateNode(Node{
		NetworkID: nw.ID, Hostname: "router", MachineKey: "mkey:aa", NodeKey: "nodekey:bb",
		IPv4: netip.MustParseAddr("100.96.0.1"), IPv6: netip.MustParseAddr("fdab:3f19::1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, n.ID
}

func TestRoutesLifecycle(t *testing.T) {
	s, id := routesTestStore(t)

	if err := s.SetAdvertisedRoutes(id, []string{"10.0.0.0/24", "0.0.0.0/0"}); err != nil {
		t.Fatal(err)
	}
	rs, err := s.NodeRoutes(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || rs[0].Approved || rs[1].Approved {
		t.Fatalf("fresh offers must be unapproved: %+v", rs)
	}

	if err := s.SetRouteApproved(id, "10.0.0.0/24", true); err != nil {
		t.Fatal(err)
	}
	appr, err := s.ApprovedNodeRoutes(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(appr) != 1 || appr[0] != "10.0.0.0/24" {
		t.Fatalf("approved = %v, want [10.0.0.0/24]", appr)
	}

	// Re-advertising keeps approval for retained routes, drops removed ones.
	if err := s.SetAdvertisedRoutes(id, []string{"10.0.0.0/24", "192.168.7.0/24"}); err != nil {
		t.Fatal(err)
	}
	rs, _ = s.NodeRoutes(id)
	if len(rs) != 2 {
		t.Fatalf("routes after re-advertise = %+v", rs)
	}
	for _, r := range rs {
		switch r.Route {
		case "10.0.0.0/24":
			if !r.Approved {
				t.Fatal("retained route lost its approval")
			}
		case "192.168.7.0/24":
			if r.Approved {
				t.Fatal("new route must start unapproved")
			}
		default:
			t.Fatalf("unexpected route %q (0.0.0.0/0 should be gone)", r.Route)
		}
	}

	if err := s.SetRouteApproved(id, "8.8.8.0/24", true); err != ErrNotFound {
		t.Fatalf("approving an unknown route: err = %v, want ErrNotFound", err)
	}
}

func TestNormalizeRoute(t *testing.T) {
	got, err := NormalizeRoute(" 10.0.0.7/24 ")
	if err != nil || got != "10.0.0.0/24" {
		t.Fatalf("NormalizeRoute = %q, %v", got, err)
	}
	if _, err := NormalizeRoute("not-a-cidr"); err == nil {
		t.Fatal("garbage must not normalize")
	}
	if !IsExitRoute("0.0.0.0/0") || !IsExitRoute("::/0") || IsExitRoute("10.0.0.0/8") {
		t.Fatal("IsExitRoute misclassifies")
	}
}
