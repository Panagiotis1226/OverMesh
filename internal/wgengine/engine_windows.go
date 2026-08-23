package wgengine

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Windows runs the userspace engine over a Wintun adapter (wintun.dll
// must sit next to overmeshd.exe — install.ps1 takes care of that).
// Direct WireGuardNT kernel-driver support is future work; Wintun is
// the same data plane Tailscale ships on Windows.
func newKernel(Options) (Engine, error) {
	return nil, fmt.Errorf("wgengine: kernel mode is not supported on Windows; use the default userspace engine")
}

// tunName: Windows adapter names are free-form; keep the requested one.
func tunName(requested string) string { return requested }

// configureInterface assigns overlay addresses, routes, and MTU via
// the IP Helper API (winipcfg). The adapter can take a moment to be
// visible after Wintun creates it, so the LUID lookup retries briefly.
func configureInterface(name string, mtu int, addrs, routes []netip.Prefix, logf func(string, ...any)) error {
	luid, err := luidByName(name)
	if err != nil {
		return err
	}

	if err := luid.SetIPAddresses(addrs); err != nil {
		return fmt.Errorf("set addresses: %w", err)
	}
	for _, r := range routes {
		nextHop := netip.IPv4Unspecified()
		if r.Addr().Is6() {
			nextHop = netip.IPv6Unspecified()
		}
		if err := luid.AddRoute(r, nextHop, 0); err != nil {
			// IPv6 may be disabled system-wide; degrade like Linux does.
			if r.Addr().Is6() {
				logf("wgengine: IPv6 route %s skipped: %v", r, err)
				continue
			}
			return fmt.Errorf("add route %s: %w", r, err)
		}
	}
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		ipif, err := luid.IPInterface(family)
		if err != nil {
			continue // family not present (e.g. IPv6 disabled)
		}
		ipif.NLMTU = uint32(mtu)
		if err := ipif.Set(); err != nil {
			logf("wgengine: set MTU (family %d): %v", family, err)
		}
	}
	return nil
}

// luidByName resolves an adapter name to its LUID, retrying while the
// freshly created Wintun adapter registers with the stack.
func luidByName(name string) (winipcfg.LUID, error) {
	var lastErr error
	for i := 0; i < 20; i++ {
		ifc, err := net.InterfaceByName(name)
		if err == nil {
			luid, err := winipcfg.LUIDFromIndex(uint32(ifc.Index))
			if err == nil {
				return luid, nil
			}
			lastErr = err
		} else {
			lastErr = err
		}
		time.Sleep(250 * time.Millisecond)
	}
	return 0, fmt.Errorf("adapter %q not found: %w", name, lastErr)
}
