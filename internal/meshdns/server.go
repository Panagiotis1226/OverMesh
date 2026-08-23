// Package meshdns is the overlay DNS: every daemon runs a small
// authoritative resolver for the network's zone (e.g. "default.mesh"),
// answering <hostname>.<zone> for every node in the netmap. The zone is
// also installed as an OS *search domain*, so bare hostnames work the
// way they do on Tailscale: `ping ps-iphone` expands to
// ps-iphone.default.mesh and lands here.
//
// The resolver is strictly scoped: queries outside the zone get REFUSED
// (stub resolvers then move on to the next nameserver), so OverMesh
// never becomes the system's general-purpose DNS.
package meshdns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Server answers A/AAAA for one zone.
type Server struct {
	logf func(string, ...any)

	mu      sync.RWMutex
	zone    string // fqdn form with trailing dot, lower-case
	records map[string][]netip.Addr

	udp *dns.Server
	tcp *dns.Server
}

// NewServer creates an empty resolver; SetRecords fills it.
func NewServer(logf func(string, ...any)) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Server{logf: logf, records: map[string][]netip.Addr{}}
}

// SetRecords replaces the zone and its records. Hostnames are bare
// labels ("ps-iphone"); addrs may mix v4 and v6.
func (s *Server) SetRecords(domain string, records map[string][]netip.Addr) {
	norm := make(map[string][]netip.Addr, len(records))
	for h, addrs := range records {
		norm[strings.ToLower(h)] = addrs
	}
	s.mu.Lock()
	s.zone = dns.Fqdn(strings.ToLower(domain))
	s.records = norm
	s.mu.Unlock()
}

// Start listens on addr:53 (UDP and TCP).
func (s *Server) Start(addr netip.Addr) error {
	hp := net.JoinHostPort(addr.String(), "53")
	mux := dns.NewServeMux()
	mux.HandleFunc(".", s.handle)
	s.udp = &dns.Server{Addr: hp, Net: "udp", Handler: mux}
	s.tcp = &dns.Server{Addr: hp, Net: "tcp", Handler: mux}
	errc := make(chan error, 2)
	go func() { errc <- s.udp.ListenAndServe() }()
	go func() { errc <- s.tcp.ListenAndServe() }()
	// Surface immediate bind errors; later errors just log.
	go func() {
		for err := range errc {
			if err != nil {
				s.logf("meshdns: %v", err)
			}
		}
	}()
	s.logf("meshdns: serving on %s", hp)
	return nil
}

// Close stops the listeners.
func (s *Server) Close() {
	if s.udp != nil {
		_ = s.udp.Shutdown()
	}
	if s.tcp != nil {
		_ = s.tcp.Shutdown()
	}
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	if len(req.Question) != 1 {
		m.SetRcode(req, dns.RcodeFormatError)
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)

	s.mu.RLock()
	zone := s.zone
	var addrs []netip.Addr
	inZone := zone != "" && strings.HasSuffix(name, "."+zone) || name == zone
	if inZone && name != zone {
		host := strings.TrimSuffix(name, "."+zone)
		if !strings.Contains(host, ".") { // only single labels exist
			addrs = s.records[host]
		}
	}
	s.mu.RUnlock()

	if !inZone {
		// Not ours: refuse so the stub resolver tries its other servers.
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	if addrs == nil {
		m.SetRcode(req, dns.RcodeNameError) // NXDOMAIN inside our zone
		m.Authoritative = true
		_ = w.WriteMsg(m)
		return
	}

	m.SetReply(req)
	m.Authoritative = true
	for _, a := range addrs {
		switch {
		case a.Is4() && (q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY):
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   a.AsSlice(),
			})
		case a.Is6() && (q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY):
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: a.AsSlice(),
			})
		}
	}
	_ = w.WriteMsg(m)
}

// String describes the server (diagnostics).
func (s *Server) String() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("meshdns[%s, %d names]", s.zone, len(s.records))
}
