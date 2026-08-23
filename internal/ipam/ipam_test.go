package ipam

import (
	"net/netip"
	"sync"
	"testing"
)

func TestDefaultsAreNotTailscales(t *testing.T) {
	// Guard against regressing to Tailscale's exact ranges.
	if DefaultIPv4Prefix == netip.MustParsePrefix("100.64.0.0/10") {
		t.Fatal("IPv4 default must differ from Tailscale's 100.64.0.0/10")
	}
	if DefaultIPv6Prefix.Addr() == netip.MustParseAddr("fd7a:115c:a1e0::") {
		t.Fatal("IPv6 default must differ from Tailscale's ULA prefix")
	}
	// Still inside CGNAT space so it can't collide with LANs.
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	if !cgnat.Contains(DefaultIPv4Prefix.Addr()) {
		t.Fatal("IPv4 default must stay inside CGNAT 100.64.0.0/10")
	}
}

func TestAllocateV4SkipsNetworkAndIsSequential(t *testing.T) {
	a, err := New(netip.MustParsePrefix("100.96.0.0/24"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := a.AllocateV4()
	if err != nil {
		t.Fatal(err)
	}
	if first != netip.MustParseAddr("100.96.0.1") {
		t.Fatalf("first allocation = %v, want 100.96.0.1", first)
	}
	second, _ := a.AllocateV4()
	if second != netip.MustParseAddr("100.96.0.2") {
		t.Fatalf("second allocation = %v, want 100.96.0.2", second)
	}
}

func TestAllocateV4ExhaustionAndReservedAddrs(t *testing.T) {
	a, err := New(netip.MustParsePrefix("100.96.0.0/30"), netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	// /30 = 4 addresses, minus network (.0) and broadcast (.3) = 2 usable.
	got := map[netip.Addr]bool{}
	for i := 0; i < 2; i++ {
		ad, err := a.AllocateV4()
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		got[ad] = true
	}
	if got[netip.MustParseAddr("100.96.0.0")] || got[netip.MustParseAddr("100.96.0.3")] {
		t.Fatal("allocated a reserved network/broadcast address")
	}
	if _, err := a.AllocateV4(); err == nil {
		t.Fatal("expected exhaustion error on 3rd allocation from a /30")
	}
	// Releasing makes the address available again.
	for ad := range got {
		a.Release(ad)
		break
	}
	if _, err := a.AllocateV4(); err != nil {
		t.Fatalf("allocation after release: %v", err)
	}
}

func TestMarkUsedIsRespected(t *testing.T) {
	a, _ := New(netip.MustParsePrefix("100.96.0.0/29"), netip.Prefix{})
	a.MarkUsed(netip.MustParseAddr("100.96.0.1"), netip.MustParseAddr("100.96.0.2"))
	ad, err := a.AllocateV4()
	if err != nil {
		t.Fatal(err)
	}
	if ad != netip.MustParseAddr("100.96.0.3") {
		t.Fatalf("got %v, want 100.96.0.3 (first two marked used)", ad)
	}
}

func TestAllocateV6IsDeterministic(t *testing.T) {
	a, _ := New(netip.Prefix{}, netip.Prefix{})
	ad7, err := a.AllocateV6For(7)
	if err != nil {
		t.Fatal(err)
	}
	if ad7 != netip.MustParseAddr("fdab:3f19::7") {
		t.Fatalf("node 7 = %v, want fdab:3f19::7", ad7)
	}
	ad7again, _ := a.AllocateV6For(7)
	if ad7 != ad7again {
		t.Fatal("v6 allocation not deterministic")
	}
	if _, err := a.AllocateV6For(0); err == nil {
		t.Fatal("node ID 0 must be rejected")
	}
}

func TestConcurrentAllocationsAreUnique(t *testing.T) {
	a, _ := New(netip.MustParsePrefix("100.96.0.0/24"), netip.Prefix{})
	const n = 100
	var wg sync.WaitGroup
	results := make([]netip.Addr, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ad, err := a.AllocateV4()
			if err != nil {
				t.Error(err)
				return
			}
			results[i] = ad
		}(i)
	}
	wg.Wait()
	seen := map[netip.Addr]bool{}
	for _, ad := range results {
		if seen[ad] {
			t.Fatalf("duplicate allocation %v", ad)
		}
		seen[ad] = true
	}
}

func TestRejectsBadPrefixes(t *testing.T) {
	if _, err := New(netip.MustParsePrefix("fdab::/64"), netip.Prefix{}); err == nil {
		t.Fatal("v6 prefix accepted as v4")
	}
	if _, err := New(netip.Prefix{}, netip.MustParsePrefix("10.0.0.0/8")); err == nil {
		t.Fatal("v4 prefix accepted as v6")
	}
	if _, err := New(netip.MustParsePrefix("100.96.0.0/31"), netip.Prefix{}); err == nil {
		t.Fatal("/31 accepted (too small)")
	}
}
