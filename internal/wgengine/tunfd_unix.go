//go:build linux || darwin

package wgengine

import (
	"os"

	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD wraps a platform-provided tunnel file descriptor: a utun
// socket on iOS/macOS (build tag darwin covers ios), an attached
// /dev/net/tun fd on Android/Linux.
func tunFromFD(fd, mtu int) (tun.Device, error) {
	return tun.CreateTUNFromFile(os.NewFile(uintptr(fd), "tun"), mtu)
}
