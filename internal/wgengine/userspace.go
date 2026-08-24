//go:build linux || darwin || windows

package wgengine

import (
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/panagiotis1226/overmesh/internal/filter"
)

// userspaceEngine runs wireguard-go in-process on a TUN device.
type userspaceEngine struct {
	dev    *device.Device
	ftun   *filterTUN
	name   string
	closed bool
}

func newUserspace(opts Options) (Engine, error) {
	var rawTun tun.Device
	var err error
	if opts.TUNFD > 0 {
		// Platform-provided tunnel (iOS packet tunnel, Android
		// VpnService): wrap the fd; the app owns interface config.
		rawTun, err = tunFromFD(opts.TUNFD, opts.mtu())
	} else {
		rawTun, err = tun.CreateTUN(tunName(opts.IfaceName), opts.mtu())
	}
	if err != nil {
		return nil, fmt.Errorf("wgengine: create tun: %w", err)
	}
	tundev := newFilterTUN(rawTun)
	name, err := tundev.Name()
	if err != nil {
		name = opts.IfaceName
	}

	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf: func(format string, args ...any) {
			opts.Logf("wg[%s]: "+format, append([]any{name}, args...)...)
		},
	}
	bind := opts.Bind
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	dev := device.NewDevice(tundev, bind, logger)

	if err := dev.IpcSet(uapiDeviceConfig(opts.PrivateKey, opts.ListenPort)); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgengine: device config: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgengine: device up: %w", err)
	}
	if opts.TUNFD <= 0 {
		if err := configureInterface(name, opts.mtu(), opts.Addresses, opts.Routes, opts.Logf); err != nil {
			dev.Close()
			return nil, fmt.Errorf("wgengine: interface config: %w", err)
		}
	}
	opts.Logf("wgengine: userspace WireGuard up on %s (port %d)", name, opts.ListenPort)
	return &userspaceEngine{dev: dev, ftun: tundev, name: name}, nil
}

func (e *userspaceEngine) SetFilter(f *filter.Filter) { e.ftun.setFilter(f) }

func (e *userspaceEngine) SetPeers(peers []PeerConfig) error {
	return e.dev.IpcSet(uapiPeersConfig(peers))
}

func (e *userspaceEngine) SetPeerEndpoint(publicKey [32]byte, endpoint netip.AddrPort) error {
	return e.dev.IpcSet(uapiPeerEndpoint(publicKey, endpoint))
}

func (e *userspaceEngine) SetPrivateKey(privateKey [32]byte) error {
	return e.dev.IpcSet(uapiPrivateKey(privateKey))
}

func (e *userspaceEngine) IfName() string { return e.name }
func (e *userspaceEngine) Kind() string   { return "userspace" }

func (e *userspaceEngine) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	e.dev.Close() // also closes the TUN device
	return nil
}
