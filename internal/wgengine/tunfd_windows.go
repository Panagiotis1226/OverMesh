package wgengine

import (
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// tunFromFD: no fd-based tunnel handoff on Windows (Wintun adapters
// are created by name).
func tunFromFD(fd, mtu int) (tun.Device, error) {
	return nil, errors.New("wgengine: TUNFD is not supported on Windows")
}
