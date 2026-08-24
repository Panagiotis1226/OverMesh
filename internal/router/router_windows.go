package router

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// MarkControl is a no-op on Windows (no SO_MARK); the exit-node client
// is Linux-only for now, so nothing needs the mark here.
func MarkControl(network, address string, c syscall.RawConn) error { return nil }

// Advertiser: Windows as a subnet router / exit node is future work
// (needs RRAS/ICS-style forwarding + NAT configuration).
type Advertiser struct{ logf Logf }

func NewAdvertiser(logf Logf) *Advertiser {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Advertiser{logf: logf}
}

func (a *Advertiser) Apply(iface string, routes []netip.Prefix) error {
	if len(routes) > 0 {
		a.logf("router: acting as a router/exit node is not supported on Windows yet; approved routes are ignored on this device")
	}
	return nil
}
func (a *Advertiser) Close() {}

// ExitClient: not yet supported on Windows (needs loop-free policy
// routing for the daemon's own traffic).
type ExitClient struct{ logf Logf }

func NewExitClient(logf Logf) *ExitClient {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &ExitClient{logf: logf}
}

func (e *ExitClient) Apply(iface string, v6 bool) error {
	return fmt.Errorf("using an exit node is not supported on Windows yet")
}
func (e *ExitClient) Remove()                       {}
func (e *ExitClient) SetBypassHosts([]netip.Addr)   {}

// RouteSync works on Windows: peers' approved subnet routes are added
// as on-link routes on the mesh adapter via the IP Helper API.
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
	luid, err := routeLUID(iface)
	if err != nil {
		if len(want) > 0 {
			r.logf("router: subnet routes: %v", err)
		}
		return
	}
	wanted := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		wanted[p] = true
	}
	for p := range r.current {
		if !wanted[p] {
			_ = luid.DeleteRoute(p, onLink(p))
			delete(r.current, p)
			r.logf("router: subnet route %s removed", p)
		}
	}
	for p := range wanted {
		if !r.current[p] {
			if err := luid.AddRoute(p, onLink(p), 0); err != nil && err != windows.ERROR_OBJECT_ALREADY_EXISTS {
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
	luid, err := routeLUID(r.iface)
	if err != nil {
		return
	}
	for p := range r.current {
		_ = luid.DeleteRoute(p, onLink(p))
		delete(r.current, p)
	}
}

func onLink(p netip.Prefix) netip.Addr {
	if p.Addr().Is6() {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

func routeLUID(iface string) (winipcfg.LUID, error) {
	var lastErr error
	for i := 0; i < 4; i++ {
		ifc, err := net.InterfaceByName(iface)
		if err == nil {
			luid, err := winipcfg.LUIDFromIndex(uint32(ifc.Index))
			if err == nil {
				return luid, nil
			}
			lastErr = err
		} else {
			lastErr = err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return 0, fmt.Errorf("adapter %q: %w", iface, lastErr)
}
