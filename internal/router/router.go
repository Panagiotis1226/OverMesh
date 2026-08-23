// Package router programs the OS around the WireGuard interface for
// Phase 5's subnet-router and exit-node features:
//
//   - Advertiser (router side): IP forwarding + NAT so traffic from the
//     mesh can egress through this machine (exit node) or reach its LAN
//     (subnet router).
//   - ExitClient (client side): policy routing that sends ALL of this
//     machine's traffic into the tunnel — except the daemon's own
//     control/relay/WireGuard packets, which carry a socket mark and
//     bypass the tunnel (no routing loops, roaming keeps working).
//   - RouteSync: OS routes for peers' approved subnet routes.
//
// Linux is fully supported; macOS gets subnet-route consumption only in
// this phase (macOS as exit node/router arrives with the menu bar app).
package router

import (
	"net/netip"
)

// SocketMark tags the daemon's own sockets (WireGuard UDP, relay TCP,
// control-plane gRPC). The exit-node policy rules exempt marked traffic
// from the tunnel default route. 0x6f6d = "om".
const SocketMark = 0x6f6d

// FwdMark tags packets that ENTERED via the mesh interface on a
// router/exit node; the NAT rule masquerades exactly those.
const FwdMark = 0x6f6e

// Logf is the logging callback type used across this package.
type Logf func(format string, args ...any)

func hasV4(routes []netip.Prefix) bool {
	for _, r := range routes {
		if r.Addr().Is4() {
			return true
		}
	}
	return false
}

func hasV6(routes []netip.Prefix) bool {
	for _, r := range routes {
		if r.Addr().Is6() {
			return true
		}
	}
	return false
}
