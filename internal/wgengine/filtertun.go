//go:build linux || darwin

package wgengine

import (
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/panagiotis1226/overmesh/internal/filter"
)

// filterTUN wraps a tun.Device and drops inbound packets (peer ->
// WireGuard -> tun Write) that the network's access rules reject.
// Enforcement lives here because a packet's overlay source address is
// cryptographically bound to its sender by WireGuard.
type filterTUN struct {
	tun.Device
	f atomic.Pointer[filter.Filter]
}

func newFilterTUN(d tun.Device) *filterTUN { return &filterTUN{Device: d} }

// setFilter swaps the active rule set (nil = allow all).
func (t *filterTUN) setFilter(f *filter.Filter) { t.f.Store(f) }

// Write filters each decrypted inbound packet before it reaches the OS.
func (t *filterTUN) Write(bufs [][]byte, offset int) (int, error) {
	f := t.f.Load()
	if f == nil {
		return t.Device.Write(bufs, offset)
	}
	kept := bufs[:0]
	dropped := 0
	for _, buf := range bufs {
		if f.AllowsPacket(buf[offset:]) {
			kept = append(kept, buf)
		} else {
			dropped++
		}
	}
	if len(kept) == 0 {
		// Report the batch as consumed: a drop is not an error.
		return len(bufs), nil
	}
	n, err := t.Device.Write(kept, offset)
	return n + dropped, err
}
