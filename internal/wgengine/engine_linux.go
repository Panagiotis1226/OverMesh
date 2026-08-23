package wgengine

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/panagiotis1226/overmesh/internal/filter"
)

// tunName on Linux is used as requested.
func tunName(requested string) string { return requested }

// kernelEngine drives a kernel wireguard link via netlink + wgctrl.
type kernelEngine struct {
	name string
	wg   *wgctrl.Client
	link netlink.Link
}

func newKernel(opts Options) (Engine, error) {
	// Remove any stale interface from a previous run.
	if old, err := netlink.LinkByName(opts.IfaceName); err == nil {
		_ = netlink.LinkDel(old)
	}

	attrs := netlink.NewLinkAttrs()
	attrs.Name = opts.IfaceName
	attrs.MTU = opts.mtu()
	link := &netlink.Wireguard{LinkAttrs: attrs}
	if err := netlink.LinkAdd(link); err != nil {
		return nil, fmt.Errorf("wgengine: kernel link add: %w", err)
	}
	cleanup := func() { _ = netlink.LinkDel(link) }

	wg, err := wgctrl.New()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("wgengine: wgctrl: %w", err)
	}
	priv := wgtypes.Key(opts.PrivateKey)
	port := int(opts.ListenPort)
	if err := wg.ConfigureDevice(opts.IfaceName, wgtypes.Config{
		PrivateKey: &priv,
		ListenPort: &port,
	}); err != nil {
		wg.Close()
		cleanup()
		return nil, fmt.Errorf("wgengine: kernel device config: %w", err)
	}
	if err := configureInterface(opts.IfaceName, opts.mtu(), opts.Addresses, opts.Routes, opts.Logf); err != nil {
		wg.Close()
		cleanup()
		return nil, err
	}
	opts.Logf("wgengine: kernel WireGuard up on %s (port %d)", opts.IfaceName, opts.ListenPort)
	return &kernelEngine{name: opts.IfaceName, wg: wg, link: link}, nil
}

func (e *kernelEngine) SetPeers(peers []PeerConfig) error {
	cfg := wgtypes.Config{ReplacePeers: true}
	keepalive := keepaliveSeconds * time.Second
	for _, p := range peers {
		pc := wgtypes.PeerConfig{
			PublicKey:                   wgtypes.Key(p.PublicKey),
			ReplaceAllowedIPs:           true,
			PersistentKeepaliveInterval: &keepalive,
		}
		for _, ip := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, prefixToIPNet(ip))
		}
		if p.Endpoint.IsValid() {
			pc.Endpoint = net.UDPAddrFromAddrPort(p.Endpoint)
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	return e.wg.ConfigureDevice(e.name, cfg)
}

func (e *kernelEngine) SetPeerEndpoint(publicKey [32]byte, endpoint netip.AddrPort) error {
	return e.wg.ConfigureDevice(e.name, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  wgtypes.Key(publicKey),
			UpdateOnly: true,
			Endpoint:   net.UDPAddrFromAddrPort(endpoint),
		}},
	})
}

func (e *kernelEngine) SetPrivateKey(privateKey [32]byte) error {
	priv := wgtypes.Key(privateKey)
	return e.wg.ConfigureDevice(e.name, wgtypes.Config{PrivateKey: &priv})
}

// SetFilter is unenforceable on the kernel data plane (packets never
// transit this process); the daemon warns when rules exist in kernel
// mode.
func (e *kernelEngine) SetFilter(*filter.Filter) {}

func (e *kernelEngine) IfName() string { return e.name }
func (e *kernelEngine) Kind() string   { return "kernel" }

func (e *kernelEngine) Close() error {
	e.wg.Close()
	return netlink.LinkDel(e.link)
}

// configureInterface assigns overlay addresses, brings the link up, and
// installs the overlay routes. Shared by the kernel and userspace paths.
// IPv6 failures degrade to a warning: hosts with IPv6 disabled still get
// a working IPv4 mesh.
func configureInterface(name string, _ int, addrs, routes []netip.Prefix, logf func(string, ...any)) error {
	// (MTU is already set: netlink attrs for the kernel link, CreateTUN
	// for the userspace device.)
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("link %s: %w", name, err)
	}
	v6OK := true
	for _, a := range addrs {
		ipnet := prefixToIPNet(a)
		if err := netlink.AddrReplace(link, &netlink.Addr{IPNet: &ipnet}); err != nil {
			if a.Addr().Is6() {
				v6OK = false
				logf("wgengine: IPv6 unavailable on this host (%v); continuing IPv4-only", err)
				continue
			}
			return fmt.Errorf("addr %s: %w", a, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	for _, r := range routes {
		if r.Addr().Is6() && !v6OK {
			continue
		}
		ipnet := prefixToIPNet(r)
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &ipnet,
		}); err != nil {
			if r.Addr().Is6() {
				logf("wgengine: skipping IPv6 route %s: %v", r, err)
				continue
			}
			return fmt.Errorf("route %s: %w", r, err)
		}
	}
	return nil
}

func prefixToIPNet(p netip.Prefix) net.IPNet {
	addr := p.Addr()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return net.IPNet{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(p.Bits(), bits),
	}
}
