// Package relay implements OMR, the OverMesh Relay: a DERP-style TCP
// relay that forwards WireGuard datagrams between nodes that cannot reach
// each other directly (symmetric NATs, UDP-hostile networks). Frames are
// addressed by WireGuard node public key; payloads stay WG-encrypted end
// to end, so relays are dumb pipes that never see plaintext.
//
// The wire protocol runs over a single TCP (or TLS) stream reached via
// HTTP/1.1 upgrade ("Upgrade: overmesh-relay/1"), so the embedded relay
// shares the control plane's HTTP(S) port and standalone relays look like
// web servers to middleboxes.
//
// Handshake: server sends Challenge{ephemeral x25519 pub, nonce}; the
// client proves possession of its WireGuard node key by returning
// Auth{node pub, nacl-box(nonce) sealed client-node-priv -> server-eph-pub};
// the server opens the box with the claimed public key. Then Send/Recv
// frames flow until either side goes away.
package relay

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ProtocolName is the HTTP Upgrade token.
const ProtocolName = "overmesh-relay/1"

// UpgradePath is where the handler is mounted on shared HTTP servers.
const UpgradePath = "/relay"

// frame types
const (
	frameChallenge = 0x01 // server -> client: 32B eph pub + 24B nonce
	frameAuth      = 0x02 // client -> server: 32B node pub + sealed nonce
	frameOK        = 0x03 // server -> client: auth accepted
	frameSend      = 0x04 // client -> server: 32B dst pub + payload
	frameRecv      = 0x05 // server -> client: 32B src pub + payload
	framePing      = 0x06 // either direction
	framePong      = 0x07 // reply to ping
)

// maxFrameLen bounds a frame body: 32B key + a full-size WireGuard packet
// with generous slack.
const maxFrameLen = 4096

// writeFrame emits [type:1][len:2][body].
func writeFrame(w io.Writer, typ byte, body []byte) error {
	if len(body) > maxFrameLen {
		return fmt.Errorf("relay: frame too large (%d)", len(body))
	}
	hdr := [3]byte{typ}
	binary.BigEndian.PutUint16(hdr[1:], uint16(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// readFrame reads one frame into buf (which must be maxFrameLen long) and
// returns the type and body slice.
func readFrame(r io.Reader, buf []byte) (byte, []byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[1:]))
	if n > maxFrameLen {
		return 0, nil, fmt.Errorf("relay: oversized frame (%d)", n)
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, nil, err
	}
	return hdr[0], buf[:n], nil
}
