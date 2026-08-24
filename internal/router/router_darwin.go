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

// ExitClient sends all traffic through the selected exit node using
// the classic macOS VPN technique: two half-default routes (0.0.0.0/1
// + 128.0.0.0/1, and their v6 twins) into the utun interface beat the
// real default route by prefix length without touching it. Loop
// protection — the daemon's own control/relay/WireGuard flows must NOT
// enter the tunnel — is per-host routes via the original default
// gateway for every bypass host the daemon reports (server, relays,
// peer endpoints), since macOS has no fwmark equivalent.
type ExitClient struct {
	logf Logf

	mu       sync.Mutex
	iface    string
	active   bool
	v6       bool
	gw4, gw6 netip.Addr
	want     map[netip.Addr]bool // bypass hosts the daemon asked for
	up       map[netip.Addr]bool // bypass host routes installed
}

var exitHalves4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
}
var exitHalves6 = []netip.Prefix{
	netip.MustParsePrefix("::/1"),
	netip.MustParsePrefix("8000::/1"),
}

func NewExitClient(logf Logf) *ExitClient {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &ExitClient{
		logf: logf,
		want: make(map[netip.Addr]bool),
		up:   make(map[netip.Addr]bool),
	}
}

func (e *ExitClient) Apply(iface string, v6 bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active && e.iface == iface && e.v6 == v6 {
		return nil
	}

	gw4, err := defaultGateway(false)
	if err != nil {
		return fmt.Errorf("exit node needs a default IPv4 route to protect against loops: %w", err)
	}
	e.gw4 = gw4
	e.gw6, _ = defaultGateway(true) // best effort; v6 endpoints are rare

	// Bypass routes FIRST, then flip the halves — never a window where
	// the daemon's own flows would loop through the tunnel.
	e.syncBypassLocked()
	halves := exitHalves4
	if v6 {
		halves = append(append([]netip.Prefix{}, exitHalves4...), exitHalves6...)
	}
	for _, p := range halves {
		if err := routeCmd("add", p, iface); err != nil && !strings.Contains(err.Error(), "exists") {
			e.logf("router: exit route %s: %v", p, err)
		}
	}
	e.iface, e.v6, e.active = iface, v6, true
	e.logf("router: exit-node routing active on %s (gateway %s bypasses %d hosts)", iface, gw4, len(e.up))
	return nil
}

// SetBypassHosts replaces the set of underlay hosts whose traffic must
// keep using the physical default gateway while an exit node is
// active: the control server, relays, and peer WireGuard endpoints.
func (e *ExitClient) SetBypassHosts(ips []netip.Addr) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.want = make(map[netip.Addr]bool, len(ips))
	for _, ip := range ips {
		if ip.IsValid() && !ip.IsLoopback() {
			e.want[ip.Unmap()] = true
		}
	}
	if e.active {
		e.syncBypassLocked()
	}
}

func (e *ExitClient) syncBypassLocked() {
	for ip := range e.up {
		if !e.want[ip] {
			_ = hostRouteCmd("delete", ip, e.gwFor(ip))
			delete(e.up, ip)
		}
	}
	for ip := range e.want {
		if e.up[ip] {
			continue
		}
		gw := e.gwFor(ip)
		if !gw.IsValid() {
			continue // no underlying route of this family; nothing to protect
		}
		if err := hostRouteCmd("add", ip, gw); err != nil && !strings.Contains(err.Error(), "exists") {
			e.logf("router: exit bypass %s: %v", ip, err)
			continue
		}
		e.up[ip] = true
	}
}

func (e *ExitClient) gwFor(ip netip.Addr) netip.Addr {
	if ip.Is6() {
		return e.gw6
	}
	return e.gw4
}

func (e *ExitClient) Remove() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.active {
		return
	}
	halves := exitHalves4
	if e.v6 {
		halves = append(append([]netip.Prefix{}, exitHalves4...), exitHalves6...)
	}
	for _, p := range halves {
		_ = routeCmd("delete", p, e.iface)
	}
	for ip := range e.up {
		_ = hostRouteCmd("delete", ip, e.gwFor(ip))
		delete(e.up, ip)
	}
	e.active = false
	e.logf("router: exit-node routing removed")
}

// defaultGateway parses `route -n get default` for the underlay's
// current gateway address.
func defaultGateway(v6 bool) (netip.Addr, error) {
	args := []string{"-n", "get"}
	if v6 {
		args = append(args, "-inet6")
	}
	args = append(args, "default")
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("route get default: %v: %s", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "gateway:"); ok {
			if ip, err := netip.ParseAddr(strings.TrimSpace(rest)); err == nil {
				return ip, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no gateway in `route get default` output")
}

func hostRouteCmd(op string, ip netip.Addr, gw netip.Addr) error {
	fam := "-inet"
	if ip.Is6() {
		fam = "-inet6"
	}
	out, err := exec.Command("route", "-n", op, fam, "-host", ip.String(), gw.String()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %s -host %s: %v: %s", op, ip, err, strings.TrimSpace(string(out)))
	}
	return nil
}

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
