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

	"golang.zx2c4.com/wireguard/conn"

	"github.com/panagiotis1226/overmesh/internal/filter"
)

// MTU is conservative for Phase 1; per-path PMTU probing raises it in
// Phase 5.
const MTU = 1280

// PeerConfig is one WireGuard peer.
type PeerConfig struct {
	PublicKey  [32]byte
	AllowedIPs []netip.Prefix
	Endpoint   netip.AddrPort // zero = no known UDP endpoint
	// RelayEndpoint is a non-UDP endpoint string the Bind can parse
	// (magicsock's "relay:<hex>"); used when Endpoint is zero. Userspace
	// engine only — the kernel cannot reach the relay.
	RelayEndpoint string
}

// Options configures an engine at creation. Addresses and Routes are
// applied once (they are stable for the life of a session); peers change
// with every netmap via SetPeers, and per-peer endpoints move as
// magicsock picks better paths.
type Options struct {
	IfaceName  string // requested name; actual name may differ on macOS (utunN)
	PrivateKey [32]byte
	ListenPort uint16
	Addresses  []netip.Prefix // this node's overlay addresses (/32, /128)
	Routes     []netip.Prefix // overlay prefixes routed into the interface
	Mode       string         // "auto", "kernel", "userspace"
	// Bind, when set, replaces the default UDP socket of the userspace
	// engine — magicsock injects its shared STUN/WG socket here. Ignored
	// by the kernel engine.
	Bind conn.Bind
	Logf func(format string, args ...any)
}

// Engine is a live WireGuard interface.
type Engine interface {
	// SetPeers replaces the peer set (full replacement, idempotent).
	SetPeers([]PeerConfig) error
	// SetPeerEndpoint moves one peer's endpoint without touching the
	// rest of its config (magicsock path changes).
	SetPeerEndpoint(publicKey [32]byte, endpoint netip.AddrPort) error
	// SetFilter installs the inbound packet filter (nil allows all).
	// Only the userspace engine enforces it; the kernel engine logs a
	// warning and ignores it.
	SetFilter(f *filter.Filter)
	// IfName is the actual interface name (e.g. "overmesh0" or "utun4").
	IfName() string
	// Kind is "kernel" or "userspace".
	Kind() string
	// Close tears the interface down.
	Close() error
}

// New creates the engine for opts per the platform and requested mode.
// "auto" is the userspace engine: it is the only one that can share its
// socket with magicsock for NAT traversal. The kernel engine remains an
// explicit opt-in for LAN/server setups with static reachability
// (revisited in Phase 5's exit-node throughput work).
func New(opts Options) (Engine, error) {
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	if opts.IfaceName == "" {
		opts.IfaceName = "overmesh0"
	}
	switch opts.Mode {
	case "", "auto", "userspace":
		return newUserspace(opts)
	case "kernel":
		return newKernel(opts)
	default:
		return nil, fmt.Errorf("wgengine: unknown mode %q", opts.Mode)
	}
}
