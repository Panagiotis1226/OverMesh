package wgengine

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// keepaliveSeconds keeps NAT mappings warm; harmless on a LAN and
// necessary once Phase 2 punches holes.
const keepaliveSeconds = 25

// uapiDeviceConfig renders the one-time device config (key + port) in
// WireGuard's IPC ("UAPI") format, consumed by wireguard-go's IpcSet.
func uapiDeviceConfig(privateKey [32]byte, listenPort uint16) string {
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(privateKey[:]))
	fmt.Fprintf(&b, "listen_port=%d\n", listenPort)
	return b.String()
}

// uapiPrivateKey renders a private-key swap (node key rotation).
func uapiPrivateKey(privateKey [32]byte) string {
	return fmt.Sprintf("private_key=%s\n", hex.EncodeToString(privateKey[:]))
}

// uapiPeerEndpoint renders an endpoint move for one existing peer.
func uapiPeerEndpoint(publicKey [32]byte, endpoint fmt.Stringer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(publicKey[:]))
	b.WriteString("update_only=true\n")
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	return b.String()
}

// uapiPeersConfig renders a full peer replacement.
func uapiPeersConfig(peers []PeerConfig) string {
	var b strings.Builder
	b.WriteString("replace_peers=true\n")
	for _, p := range peers {
		fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(p.PublicKey[:]))
		b.WriteString("replace_allowed_ips=true\n")
		for _, ip := range p.AllowedIPs {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
		}
		if p.Endpoint.IsValid() {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		} else if p.RelayEndpoint != "" {
			// Parsed by the Bind's ParseEndpoint (magicsock relay form).
			fmt.Fprintf(&b, "endpoint=%s\n", p.RelayEndpoint)
		}
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepaliveSeconds)
	}
	return b.String()
}
