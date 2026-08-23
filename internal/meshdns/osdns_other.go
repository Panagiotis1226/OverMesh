//go:build !linux && !darwin && !windows

package meshdns

import "net/netip"

// ConfigureOS is a no-op on platforms without daemon support yet.
func ConfigureOS(iface, domain string, resolver netip.Addr, logf func(string, ...any)) error {
	logf("meshdns: OS DNS configuration not supported on this platform yet")
	return nil
}

// DeconfigureOS is a no-op on platforms without daemon support yet.
func DeconfigureOS(iface string, logf func(string, ...any)) {}
