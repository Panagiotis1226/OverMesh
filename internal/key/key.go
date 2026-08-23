// Package key defines OverMesh's key types.
//
// Every node has two curve25519 key pairs:
//
//   - The machine key is the device's long-lived identity toward the
//     control plane. It is generated once at first run and never leaves
//     the device except as a public key.
//   - The node key is the WireGuard key used on the data plane. It can be
//     rotated without re-enrolling the device.
//
// Text forms are prefixed so keys can never be confused with one another
// in logs, databases, or API payloads: "mkey:<64 hex>" and
// "nodekey:<64 hex>".
package key

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const (
	machinePrefix = "mkey:"
	nodePrefix    = "nodekey:"
)

// MachinePrivate is a device identity private key.
type MachinePrivate struct{ k [32]byte }

// MachinePublic is a device identity public key.
type MachinePublic struct{ k [32]byte }

// NodePrivate is a WireGuard data-plane private key.
type NodePrivate struct{ k [32]byte }

// NodePublic is a WireGuard data-plane public key.
type NodePublic struct{ k [32]byte }

// NewMachine generates a new machine key pair.
func NewMachine() (MachinePrivate, error) {
	var p MachinePrivate
	if err := newClamped(&p.k); err != nil {
		return MachinePrivate{}, err
	}
	return p, nil
}

// NewNode generates a new node (WireGuard) key pair.
func NewNode() (NodePrivate, error) {
	var p NodePrivate
	if err := newClamped(&p.k); err != nil {
		return NodePrivate{}, err
	}
	return p, nil
}

// newClamped fills k with a curve25519 private key, clamped per RFC 7748
// (the same clamping WireGuard applies).
func newClamped(k *[32]byte) error {
	if _, err := rand.Read(k[:]); err != nil {
		return fmt.Errorf("generating key: %w", err)
	}
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return nil
}

// Public returns the corresponding public key.
func (p MachinePrivate) Public() MachinePublic {
	var pub MachinePublic
	curve25519.ScalarBaseMult(&pub.k, &p.k)
	return pub
}

// Public returns the corresponding public key.
func (p NodePrivate) Public() NodePublic {
	var pub NodePublic
	curve25519.ScalarBaseMult(&pub.k, &p.k)
	return pub
}

// Raw returns the private key bytes (for handing to WireGuard config).
func (p NodePrivate) Raw() [32]byte { return p.k }

// IsZero reports whether the key is the zero value.
func (p MachinePublic) IsZero() bool { return p.k == [32]byte{} }

// IsZero reports whether the key is the zero value.
func (p NodePublic) IsZero() bool { return p.k == [32]byte{} }

// Equal compares two public keys in constant time.
func (p MachinePublic) Equal(o MachinePublic) bool {
	return subtle.ConstantTimeCompare(p.k[:], o.k[:]) == 1
}

// Equal compares two public keys in constant time.
func (p NodePublic) Equal(o NodePublic) bool {
	return subtle.ConstantTimeCompare(p.k[:], o.k[:]) == 1
}

// Bytes returns the 32 public key bytes (wire form for protobuf fields).
func (p MachinePublic) Bytes() []byte { b := p.k; return b[:] }

// Bytes returns the 32 public key bytes (wire form for protobuf fields).
func (p NodePublic) Bytes() []byte { b := p.k; return b[:] }

// MachinePublicFromBytes parses the 32-byte wire form.
func MachinePublicFromBytes(b []byte) (MachinePublic, error) {
	var p MachinePublic
	if len(b) != 32 {
		return p, fmt.Errorf("machine key: want 32 bytes, got %d", len(b))
	}
	copy(p.k[:], b)
	return p, nil
}

// NodePublicFromBytes parses the 32-byte wire form.
func NodePublicFromBytes(b []byte) (NodePublic, error) {
	var p NodePublic
	if len(b) != 32 {
		return p, fmt.Errorf("node key: want 32 bytes, got %d", len(b))
	}
	copy(p.k[:], b)
	return p, nil
}

func (p MachinePublic) String() string { return machinePrefix + hex.EncodeToString(p.k[:]) }
func (p NodePublic) String() string    { return nodePrefix + hex.EncodeToString(p.k[:]) }

// MarshalText implements encoding.TextMarshaler.
func (p MachinePublic) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// MarshalText implements encoding.TextMarshaler.
func (p NodePublic) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *MachinePublic) UnmarshalText(b []byte) error {
	return unmarshalPrefixed(machinePrefix, b, &p.k)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *NodePublic) UnmarshalText(b []byte) error {
	return unmarshalPrefixed(nodePrefix, b, &p.k)
}

func unmarshalPrefixed(prefix string, b []byte, out *[32]byte) error {
	s := string(b)
	if len(s) != len(prefix)+64 || s[:len(prefix)] != prefix {
		return fmt.Errorf("invalid key %q: want %q + 64 hex chars", s, prefix)
	}
	raw, err := hex.DecodeString(s[len(prefix):])
	if err != nil {
		return fmt.Errorf("invalid key %q: %w", s, err)
	}
	copy(out[:], raw)
	return nil
}

// Private keys never implement MarshalText/String: they must not end up
// in logs or JSON by accident. Persistence goes through the explicit
// Hex()/FromHex functions below, used only by the daemon's 0600 state file.

// Hex returns the private key as bare hex for state-file persistence.
func (p MachinePrivate) Hex() string { return hex.EncodeToString(p.k[:]) }

// Hex returns the private key as bare hex for state-file persistence.
func (p NodePrivate) Hex() string { return hex.EncodeToString(p.k[:]) }

// MachinePrivateFromHex parses a persisted private key.
func MachinePrivateFromHex(s string) (MachinePrivate, error) {
	var p MachinePrivate
	if err := privFromHex(s, &p.k); err != nil {
		return p, fmt.Errorf("machine private key: %w", err)
	}
	return p, nil
}

// NodePrivateFromHex parses a persisted private key.
func NodePrivateFromHex(s string) (NodePrivate, error) {
	var p NodePrivate
	if err := privFromHex(s, &p.k); err != nil {
		return p, fmt.Errorf("node private key: %w", err)
	}
	return p, nil
}

func privFromHex(s string, out *[32]byte) error {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(raw) != 32 {
		return fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return nil
}
