package router

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// MarkControl is a no-op on macOS (no SO_MARK); the exit-node client is
// Linux-only in this phase, so nothing needs the mark here.
func MarkControl(network, address string, c syscall.RawConn) error { return nil }

// Advertiser: macOS as a subnet router / exit node arrives in a later
// phase (pf NAT rules + sysctl net.inet.ip.forwarding).
type Advertiser struct{ logf Logf }

func NewAdvertiser(logf Logf) *Advertiser {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Advertiser{logf: logf}
}

func (a *Advertiser) Apply(iface string, routes []netip.Prefix) error {
	if len(routes) > 0 {
		a.logf("router: acting as a router/exit node is not supported on macOS yet; approved routes are ignored on this device")
	}
	return nil
}
func (a *Advertiser) Close() {}

// ExitClient: not yet supported on macOS (needs route scoping so the
// daemon's own traffic bypasses the tunnel).
type ExitClient struct{ logf Logf }

func NewExitClient(logf Logf) *ExitClient {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &ExitClient{logf: logf}
}

func (e *ExitClient) Apply(iface string, v6 bool) error {
	return fmt.Errorf("using an exit node is not supported on macOS yet")
}
func (e *ExitClient) Remove() {}

// RouteSync works on macOS: subnet routes point at the utun interface.
type RouteSync struct {
	mu      sync.Mutex
	logf    Logf
	iface   string
	current map[netip.Prefix]bool
}

func NewRouteSync(logf Logf) *RouteSync {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &RouteSync{logf: logf, current: make(map[netip.Prefix]bool)}
}

func (r *RouteSync) Sync(iface string, want []netip.Prefix) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.iface = iface
	wanted := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		wanted[p] = true
	}
	for p := range r.current {
		if !wanted[p] {
			_ = routeCmd("delete", p, iface)
			delete(r.current, p)
		}
	}
	for p := range wanted {
		if !r.current[p] {
			if err := routeCmd("add", p, iface); err != nil {
				r.logf("router: subnet route %s: %v", p, err)
				continue
			}
			r.current[p] = true
			r.logf("router: subnet route %s via %s", p, iface)
		}
	}
}

func (r *RouteSync) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for p := range r.current {
		_ = routeCmd("delete", p, r.iface)
		delete(r.current, p)
	}
}

func routeCmd(op string, p netip.Prefix, iface string) error {
	fam := "-inet"
	if p.Addr().Is6() {
		fam = "-inet6"
	}
	out, err := exec.Command("route", "-n", op, fam, p.String(), "-interface", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %s %s: %v: %s", op, p, err, strings.TrimSpace(string(out)))
	}
	return nil
}
