// Package wgengine programs the WireGuard data plane.
//
// Two engines exist:
//
//   - kernel (Linux only): the interface is a kernel wireguard link,
//     configured over netlink via wgctrl. Fastest path; used whenever the
//     module is available.
//   - userspace (Linux fallback + macOS): an in-process wireguard-go
//     device on a TUN/utun interface, configured via its IPC interface.
//
// Mode "auto" tries kernel first and falls back to userspace.
package wgengine

import (
	"fmt"
	"net/netip"
)

// MTU is conservative for Phase 1; per-path PMTU probing raises it in
// Phase 5.
const MTU = 1280

// PeerConfig is one WireGuard peer.
type PeerConfig struct {
	PublicKey  [32]byte
	AllowedIPs []netip.Prefix
	Endpoint   netip.AddrPort // zero = no known endpoint yet
}

// Options configures an engine at creation. Addresses and Routes are
// applied once (they are stable for the life of a Phase-1 session); peers
// change with every netmap via SetPeers.
type Options struct {
	IfaceName  string // requested name; actual name may differ on macOS (utunN)
	PrivateKey [32]byte
	ListenPort uint16
	Addresses  []netip.Prefix // this node's overlay addresses (/32, /128)
	Routes     []netip.Prefix // overlay prefixes routed into the interface
	Mode       string         // "auto", "kernel", "userspace"
	Logf       func(format string, args ...any)
}

// Engine is a live WireGuard interface.
type Engine interface {
	// SetPeers replaces the peer set (full replacement, idempotent).
	SetPeers([]PeerConfig) error
	// IfName is the actual interface name (e.g. "overmesh0" or "utun4").
	IfName() string
	// Kind is "kernel" or "userspace".
	Kind() string
	// Close tears the interface down.
	Close() error
}

// New creates the engine for opts per the platform and requested mode.
func New(opts Options) (Engine, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.IfaceName == "" {
		opts.IfaceName = "overmesh0"
	}
	switch opts.Mode {
	case "", "auto":
		return newAuto(opts)
	case "kernel":
		return newKernel(opts)
	case "userspace":
		return newUserspace(opts)
	default:
		return nil, fmt.Errorf("wgengine: unknown mode %q", opts.Mode)
	}
}
