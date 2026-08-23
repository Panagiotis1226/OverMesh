package meshdns

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Windows: the mesh adapter gets the overlay resolver plus the mesh
// zone as its connection-specific DNS suffix (winipcfg SetDNS). With
// Windows' default "append connection-specific suffixes" resolution,
// FQDNs work immediately and bare hostnames resolve for lookups that
// go out this adapter. To make bare names work regardless of adapter
// binding, the zone is also PREPENDED to the global suffix SearchList
// (saved and restored on down).
const searchListKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

// ConfigureOS points the mesh adapter at the overlay resolver and
// installs domain as its DNS suffix + a global search-list entry.
func ConfigureOS(iface, domain string, resolver netip.Addr, logf func(string, ...any)) error {
	luid, err := dnsLUID(iface)
	if err != nil {
		return err
	}
	if err := luid.SetDNS(windows.AF_INET, []netip.Addr{resolver}, []string{domain}); err != nil {
		return fmt.Errorf("set adapter dns: %w", err)
	}

	// Global suffix search list (bare hostnames from any adapter).
	if err := prependSearchList(domain); err != nil {
		logf("meshdns: global search list: %v (bare names may need the FQDN on this host)", err)
	}
	logf("meshdns: configured adapter %s (suffix %s)", iface, domain)
	return nil
}

// DeconfigureOS removes the search-list entry; the adapter's DNS
// settings vanish with the Wintun adapter itself.
func DeconfigureOS(iface string, logf func(string, ...any)) {
	if err := stripSearchList(); err != nil {
		logf("meshdns: restore search list: %v", err)
	}
}

const searchMarker = "overmesh-managed:"

// prependSearchList puts domain first in the global SearchList value,
// remembering the original in a sibling value for restore.
func prependSearchList(domain string) error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, searchListKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	orig, _, err := k.GetStringValue("SearchList")
	if err != nil && err != registry.ErrNotExist {
		return err
	}
	// Idempotence across restarts: never save an overmesh-modified list
	// as the "original".
	if saved, _, err := k.GetStringValue("OverMeshSavedSearchList"); err != nil || saved == "" {
		if err := k.SetStringValue("OverMeshSavedSearchList", searchMarker+orig); err != nil {
			return err
		}
	}
	newList := domain
	if orig != "" {
		newList = domain + "," + orig
	}
	return k.SetStringValue("SearchList", newList)
}

// stripSearchList restores the saved original list.
func stripSearchList() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, searchListKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	saved, _, err := k.GetStringValue("OverMeshSavedSearchList")
	if err != nil {
		return nil // nothing to restore
	}
	orig := saved[len(searchMarker):]
	if orig == "" {
		_ = k.DeleteValue("SearchList")
	} else if err := k.SetStringValue("SearchList", orig); err != nil {
		return err
	}
	return k.DeleteValue("OverMeshSavedSearchList")
}

func dnsLUID(iface string) (winipcfg.LUID, error) {
	var lastErr error
	for i := 0; i < 8; i++ {
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
		time.Sleep(250 * time.Millisecond)
	}
	return 0, fmt.Errorf("adapter %q: %w", iface, lastErr)
}
