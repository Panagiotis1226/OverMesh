package wgengine

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// tunName on macOS must be "utun" (or utunN); the kernel assigns the
// actual number. A requested name like "overmesh0" is ignored.
func tunName(requested string) string {
	if strings.HasPrefix(requested, "utun") {
		return requested
	}
	return "utun"
}

// newAuto on macOS is always userspace: there is no kernel WireGuard.
func newAuto(opts Options) (Engine, error) { return newUserspace(opts) }

func newKernel(opts Options) (Engine, error) {
	return nil, fmt.Errorf("wgengine: no kernel WireGuard on macOS; use userspace")
}

// configureInterface assigns addresses and routes with ifconfig/route —
// the same approach wireguard-tools' wg-quick uses on macOS.
func configureInterface(name string, addrs, routes []netip.Prefix, logf func(string, ...any)) error {
	for _, a := range addrs {
		var args []string
		if a.Addr().Is4() {
			// Point-to-point: self as both local and destination.
			args = []string{name, "inet", a.String(), a.Addr().String(), "alias"}
		} else {
			args = []string{name, "inet6", a.Addr().String(), "prefixlen", strconv.Itoa(a.Bits()), "alias"}
		}
		if out, err := exec.Command("ifconfig", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ifconfig %v: %v: %s", args, err, out)
		}
	}
	if out, err := exec.Command("ifconfig", name, "mtu", strconv.Itoa(MTU), "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig up: %v: %s", err, out)
	}
	for _, r := range routes {
		family := "-inet"
		if r.Addr().Is6() {
			family = "-inet6"
		}
		if out, err := exec.Command("route", "-q", "-n", "add", family, r.String(), "-interface", name).CombinedOutput(); err != nil {
			return fmt.Errorf("route add %s: %v: %s", r, err, out)
		}
	}
	return nil
}
