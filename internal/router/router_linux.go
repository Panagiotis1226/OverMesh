package router

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// MarkControl is a net.Dialer/ListenConfig Control function that stamps
// SocketMark on the socket, so the exit-node policy rules let the
// daemon's own traffic bypass the tunnel. Needs CAP_NET_ADMIN (the
// daemon already runs as root for TUN).
func MarkControl(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, SocketMark)
	})
	if err != nil {
		return err
	}
	return serr
}

// run executes a command, returning combined output in the error.
func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runOK reports whether the command succeeded (for "-C" rule checks).
func runOK(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}

// --- Advertiser: router/exit-node side -------------------------------

// Advertiser enables forwarding + NAT for a router or exit node.
// Packets that arrive via the mesh interface get FwdMark in mangle
// PREROUTING; the nat POSTROUTING rule masquerades exactly those, so
// mesh clients can use this machine's connectivity without the LAN or
// the internet needing routes back to the overlay.
type Advertiser struct {
	mu      sync.Mutex
	logf    Logf
	iface   string
	v4, v6  bool   // which stacks are currently programmed
	oldFwd4 string // previous ip_forward value, restored on Close
	oldFwd6 string
}

func NewAdvertiser(logf Logf) *Advertiser {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Advertiser{logf: logf}
}

// Apply makes the machine route the given approved prefixes for the
// mesh (idempotent; routes==nil tears everything down).
func (a *Advertiser) Apply(iface string, routes []netip.Prefix) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	wantV4, wantV6 := hasV4(routes), hasV6(routes)
	if a.iface != "" && a.iface != iface {
		// Interface changed (new session): drop old rules first.
		a.teardownLocked()
	}
	a.iface = iface

	if wantV4 && !a.v4 {
		a.oldFwd4 = readSysctl("/proc/sys/net/ipv4/ip_forward")
		if err := writeSysctl("/proc/sys/net/ipv4/ip_forward", "1"); err != nil {
			return err
		}
		if err := a.rules("iptables", iface, true); err != nil {
			return err
		}
		a.v4 = true
		a.logf("router: IPv4 forwarding + NAT enabled on %s", iface)
	}
	if !wantV4 && a.v4 {
		a.rules("iptables", iface, false)
		restoreSysctl("/proc/sys/net/ipv4/ip_forward", a.oldFwd4)
		a.v4 = false
	}
	if wantV6 && !a.v6 {
		a.oldFwd6 = readSysctl("/proc/sys/net/ipv6/conf/all/forwarding")
		if err := writeSysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1"); err != nil {
			a.logf("router: IPv6 forwarding unavailable: %v", err)
		} else if err := a.rules("ip6tables", iface, true); err != nil {
			a.logf("router: ip6tables: %v", err)
		} else {
			a.v6 = true
			a.logf("router: IPv6 forwarding + NAT enabled on %s", iface)
		}
	}
	if !wantV6 && a.v6 {
		a.rules("ip6tables", iface, false)
		restoreSysctl("/proc/sys/net/ipv6/conf/all/forwarding", a.oldFwd6)
		a.v6 = false
	}
	return nil
}

// Close removes all rules and restores forwarding sysctls.
func (a *Advertiser) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.teardownLocked()
}

func (a *Advertiser) teardownLocked() {
	if a.v4 {
		a.rules("iptables", a.iface, false)
		restoreSysctl("/proc/sys/net/ipv4/ip_forward", a.oldFwd4)
		a.v4 = false
	}
	if a.v6 {
		a.rules("ip6tables", a.iface, false)
		restoreSysctl("/proc/sys/net/ipv6/conf/all/forwarding", a.oldFwd6)
		a.v6 = false
	}
}

// rules adds (add=true) or deletes the three rules for one stack.
func (a *Advertiser) rules(ipt, iface string, add bool) error {
	mark := fmt.Sprintf("0x%x", FwdMark)
	specs := [][]string{
		{"-t", "mangle", "PREROUTING", "-i", iface, "-j", "MARK", "--set-xmark", mark},
		{"-t", "nat", "POSTROUTING", "-m", "mark", "--mark", mark, "-j", "MASQUERADE"},
		{"-t", "filter", "FORWARD", "-i", iface, "-j", "ACCEPT"},
		{"-t", "filter", "FORWARD", "-o", iface, "-j", "ACCEPT"},
	}
	for _, s := range specs {
		table, chain, rest := s[1], s[2], s[3:]
		check := append([]string{"-t", table, "-C", chain}, rest...)
		if add {
			if runOK(ipt, check...) {
				continue // already present
			}
			if err := run(ipt, append([]string{"-t", table, "-A", chain}, rest...)...); err != nil {
				return err
			}
		} else {
			if runOK(ipt, check...) {
				_ = run(ipt, append([]string{"-t", table, "-D", chain}, rest...)...)
			}
		}
	}
	return nil
}

func readSysctl(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func writeSysctl(path, val string) error {
	return os.WriteFile(path, []byte(val), 0o644)
}

func restoreSysctl(path, old string) {
	if old != "" {
		_ = writeSysctl(path, old)
	}
}

// SetBypassHosts is a no-op on Linux: the daemon's own flows carry
// SocketMark and the policy rules already exempt them — no per-host
// routes needed.
func (e *ExitClient) SetBypassHosts([]netip.Addr) {}

// --- ExitClient: send everything through a selected exit node --------

// exitTable is the dedicated routing table holding "default via the
// mesh interface". Rule scheme (Tailscale-style):
//
//	pref 5250: not fwmark SocketMark lookup main suppress_prefixlength 0
//	           (LAN/specific routes keep working for everyone)
//	pref 5270: not fwmark SocketMark lookup 52
//	           (everything else goes into the tunnel)
//
// The daemon's own sockets carry SocketMark and skip both rules, so
// control, relay, and WireGuard packets use the untouched main table.
const exitTable = "52"

// ExitClient installs/removes the exit-node policy routing.
type ExitClient struct {
	mu     sync.Mutex
	logf   Logf
	active bool
	iface  string
	oldRP  string // previous rp_filter value for the mesh interface
}

func NewExitClient(logf Logf) *ExitClient {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &ExitClient{logf: logf}
}

// Apply routes all traffic via iface (idempotent). v6 also programs the
// IPv6 tables when true.
func (e *ExitClient) Apply(iface string, v6 bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.active && e.iface == iface {
		return nil
	}
	if e.active {
		e.teardownLocked()
	}

	mark := fmt.Sprintf("0x%x", SocketMark)
	if err := run("ip", "route", "replace", "default", "dev", iface, "table", exitTable); err != nil {
		return err
	}
	if err := run("ip", "rule", "add", "pref", "5250", "not", "fwmark", mark,
		"lookup", "main", "suppress_prefixlength", "0"); err != nil {
		return err
	}
	if err := run("ip", "rule", "add", "pref", "5270", "not", "fwmark", mark,
		"lookup", exitTable); err != nil {
		return err
	}
	if v6 {
		// Best-effort: v6-less hosts still get a v4 exit.
		if err := run("ip", "-6", "route", "replace", "default", "dev", iface, "table", exitTable); err == nil {
			_ = run("ip", "-6", "rule", "add", "pref", "5250", "not", "fwmark", mark,
				"lookup", "main", "suppress_prefixlength", "0")
			_ = run("ip", "-6", "rule", "add", "pref", "5270", "not", "fwmark", mark,
				"lookup", exitTable)
		}
	}
	// Loose reverse-path filtering on the mesh interface: exit traffic
	// returns from arbitrary sources.
	rpPath := "/proc/sys/net/ipv4/conf/" + iface + "/rp_filter"
	e.oldRP = readSysctl(rpPath)
	_ = writeSysctl(rpPath, "2")

	e.active, e.iface = true, iface
	e.logf("router: exit-node routing active via %s", iface)
	return nil
}

// Remove restores normal routing (idempotent).
func (e *ExitClient) Remove() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.teardownLocked()
}

func (e *ExitClient) teardownLocked() {
	if !e.active {
		return
	}
	mark := fmt.Sprintf("0x%x", SocketMark)
	for _, fam := range []string{"", "-6"} {
		args := func(a ...string) []string {
			if fam == "" {
				return a
			}
			return append([]string{fam}, a...)
		}
		_ = run("ip", args("rule", "del", "pref", "5270", "not", "fwmark", mark, "lookup", exitTable)...)
		_ = run("ip", args("rule", "del", "pref", "5250", "not", "fwmark", mark,
			"lookup", "main", "suppress_prefixlength", "0")...)
		_ = run("ip", args("route", "flush", "table", exitTable)...)
	}
	restoreSysctl("/proc/sys/net/ipv4/conf/"+e.iface+"/rp_filter", e.oldRP)
	e.logf("router: exit-node routing removed")
	e.active, e.iface = false, ""
}

// --- RouteSync: consume peers' subnet routes --------------------------

// RouteSync keeps the OS routing table in sync with the mesh's approved
// subnet routes (peer LANs reachable through their routers).
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

// Sync makes the installed route set equal to want.
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
			_ = run("ip", famArgs(p, "route", "del", p.String(), "dev", iface)...)
			delete(r.current, p)
			r.logf("router: subnet route %s removed", p)
		}
	}
	for p := range wanted {
		if !r.current[p] {
			if err := run("ip", famArgs(p, "route", "replace", p.String(), "dev", iface)...); err != nil {
				r.logf("router: subnet route %s: %v", p, err)
				continue
			}
			r.current[p] = true
			r.logf("router: subnet route %s via %s", p, iface)
		}
	}
}

// Close removes all installed routes.
func (r *RouteSync) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for p := range r.current {
		_ = run("ip", famArgs(p, "route", "del", p.String(), "dev", r.iface)...)
		delete(r.current, p)
	}
}

func famArgs(p netip.Prefix, a ...string) []string {
	if p.Addr().Is6() {
		return append([]string{"-6"}, a...)
	}
	return a
}
