package meshdns

import (
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := NewServer(t.Logf)
	s.SetRecords("default.mesh", map[string][]netip.Addr{
		"ps-iphone": {netip.MustParseAddr("100.96.0.7"), netip.MustParseAddr("fdab:3f19::7")},
		"server-1":  {netip.MustParseAddr("100.96.0.1")},
	})
	// Bind on loopback with an ephemeral port via the raw dns.Server so
	// tests need no privileges.
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	pc := &dns.Server{Addr: "127.0.0.1:0", Net: "udp", Handler: mux}
	ready := make(chan struct{})
	pc.NotifyStartedFunc = func() { close(ready) }
	go pc.ListenAndServe()
	t.Cleanup(func() { pc.Shutdown() })
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("dns server never started")
	}
	return s, pc.PacketConn.LocalAddr().String()
}

func query(t *testing.T, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return resp
}

func TestResolveInZone(t *testing.T) {
	_, addr := startTestServer(t)

	// Exactly the user's scenario: ps-iphone via the search domain.
	resp := query(t, addr, "ps-iphone.default.mesh", dns.TypeA)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("A: rcode=%v answers=%d", resp.Rcode, len(resp.Answer))
	}
	if a := resp.Answer[0].(*dns.A); a.A.String() != "100.96.0.7" {
		t.Fatalf("A = %s", a.A)
	}

	resp = query(t, addr, "PS-IPHONE.Default.Mesh", dns.TypeAAAA) // case-insensitive
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("AAAA: rcode=%v answers=%d", resp.Rcode, len(resp.Answer))
	}
	if aaaa := resp.Answer[0].(*dns.AAAA); aaaa.AAAA.String() != "fdab:3f19::7" {
		t.Fatalf("AAAA = %s", aaaa.AAAA)
	}
}

func TestNXDomainInZoneAndRefusedOutside(t *testing.T) {
	_, addr := startTestServer(t)

	resp := query(t, addr, "nope.default.mesh", dns.TypeA)
	if resp.Rcode != dns.RcodeNameError {
		t.Fatalf("unknown host in zone: rcode=%v, want NXDOMAIN", resp.Rcode)
	}
	resp = query(t, addr, "example.com", dns.TypeA)
	if resp.Rcode != dns.RcodeRefused {
		t.Fatalf("out-of-zone: rcode=%v, want REFUSED (so stub resolvers fall through)", resp.Rcode)
	}
}

func TestRecordsCanBeReplaced(t *testing.T) {
	s, addr := startTestServer(t)
	s.SetRecords("default.mesh", map[string][]netip.Addr{
		"newbie": {netip.MustParseAddr("100.96.0.42")},
	})
	if r := query(t, addr, "newbie.default.mesh", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Fatalf("new record: rcode=%v", r.Rcode)
	}
	if r := query(t, addr, "ps-iphone.default.mesh", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Fatalf("stale record survived: rcode=%v", r.Rcode)
	}
}

