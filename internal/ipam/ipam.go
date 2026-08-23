// Package ipam allocates overlay addresses for nodes.
//
// Defaults are deliberately distinct from Tailscale's so both meshes can
// coexist on one machine: IPv4 comes from 100.96.0.0/11 (the upper half of
// the CGNAT block; Tailscale uses the full 100.64.0.0/10 starting at the
// bottom) and IPv6 from the fdab:3f19::/48 ULA prefix. Both are
// per-network configurable.
//
// The allocator is in-memory; Phase 1 wraps it with database persistence
// (allocations are loaded at startup and recorded on assignment).
package ipam

import (
	"fmt"
	"math/big"
	"net/netip"
	"sync"
)

// Default overlay prefixes.
var (
	DefaultIPv4Prefix = netip.MustParsePrefix("100.96.0.0/11")
	DefaultIPv6Prefix = netip.MustParsePrefix("fdab:3f19::/48")
)

// Allocator hands out one IPv4 and one IPv6 address per node from its
// configured prefixes. It is safe for concurrent use.
type Allocator struct {
	mu   sync.Mutex
	v4   netip.Prefix
	v6   netip.Prefix
	used map[netip.Addr]bool
	next netip.Addr // next candidate v4, advances monotonically with wrap
}

// New returns an allocator over the given prefixes. Zero-value prefixes
// select the OverMesh defaults.
func New(v4, v6 netip.Prefix) (*Allocator, error) {
	if !v4.IsValid() {
		v4 = DefaultIPv4Prefix
	}
	if !v6.IsValid() {
		v6 = DefaultIPv6Prefix
	}
	if !v4.Addr().Is4() {
		return nil, fmt.Errorf("ipam: %v is not an IPv4 prefix", v4)
	}
	if !v6.Addr().Is6() || v6.Addr().Is4In6() {
		return nil, fmt.Errorf("ipam: %v is not an IPv6 prefix", v6)
	}
	if v4.Bits() > 30 {
		return nil, fmt.Errorf("ipam: IPv4 prefix %v too small (need /30 or larger)", v4)
	}
	a := &Allocator{
		v4:   v4.Masked(),
		v6:   v6.Masked(),
		used: make(map[netip.Addr]bool),
	}
	a.next = a.v4.Addr().Next() // skip the network address
	return a, nil
}

// MarkUsed records addresses already assigned (loaded from the database)
// so they are never handed out again.
func (a *Allocator) MarkUsed(addrs ...netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ad := range addrs {
		a.used[ad.Unmap()] = true
	}
}

// AllocateV4 returns the next free IPv4 address in the prefix.
func (a *Allocator) AllocateV4() (netip.Addr, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	start := a.next
	for {
		c := a.next
		a.next = a.advance(c)
		if !a.used[c] && !a.isReservedV4(c) {
			a.used[c] = true
			return c, nil
		}
		if a.next == start {
			return netip.Addr{}, fmt.Errorf("ipam: IPv4 prefix %v exhausted", a.v4)
		}
	}
}

// advance steps to the next candidate address, wrapping to the start of
// the prefix past the end.
func (a *Allocator) advance(c netip.Addr) netip.Addr {
	n := c.Next()
	if !a.v4.Contains(n) {
		return a.v4.Addr().Next()
	}
	return n
}

// isReservedV4 reports whether c is the network or broadcast address.
func (a *Allocator) isReservedV4(c netip.Addr) bool {
	if c == a.v4.Addr() {
		return true
	}
	// Broadcast: last address of the prefix.
	last := lastAddr(a.v4)
	return c == last
}

// AllocateV6For derives the node's IPv6 address from its node ID: the
// prefix plus the 64-bit ID in the low bits. Deterministic, no scanning,
// and collision-free as long as node IDs are unique.
func (a *Allocator) AllocateV6For(nodeID uint64) (netip.Addr, error) {
	if nodeID == 0 {
		return netip.Addr{}, fmt.Errorf("ipam: node ID must be nonzero")
	}
	base := a.v6.Addr().As16()
	id := new(big.Int).SetUint64(nodeID).Bytes()
	copy(base[16-len(id):], id)
	addr := netip.AddrFrom16(base)
	if !a.v6.Contains(addr) {
		return netip.Addr{}, fmt.Errorf("ipam: node ID %d overflows prefix %v", nodeID, a.v6)
	}
	return addr, nil
}

// Release returns an address to the pool.
func (a *Allocator) Release(addr netip.Addr) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, addr.Unmap())
}

// lastAddr computes the highest address inside p.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	hostBits := 32 - p.Bits()
	for i := 0; i < hostBits; i++ {
		b[3-i/8] |= 1 << (i % 8)
	}
	return netip.AddrFrom4(b)
}
