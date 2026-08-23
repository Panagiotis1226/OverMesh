package key

import (
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateAndRoundTrip(t *testing.T) {
	mk, err := NewMachine()
	if err != nil {
		t.Fatal(err)
	}
	nk, err := NewNode()
	if err != nil {
		t.Fatal(err)
	}

	mpub, npub := mk.Public(), nk.Public()
	if mpub.IsZero() || npub.IsZero() {
		t.Fatal("generated public key is zero")
	}

	// Text round trip.
	mtxt, _ := mpub.MarshalText()
	var mpub2 MachinePublic
	if err := mpub2.UnmarshalText(mtxt); err != nil {
		t.Fatal(err)
	}
	if !mpub.Equal(mpub2) {
		t.Fatalf("machine key text round trip mismatch: %s != %s", mpub, mpub2)
	}

	ntxt, _ := npub.MarshalText()
	var npub2 NodePublic
	if err := npub2.UnmarshalText(ntxt); err != nil {
		t.Fatal(err)
	}
	if !npub.Equal(npub2) {
		t.Fatalf("node key text round trip mismatch: %s != %s", npub, npub2)
	}

	// Bytes round trip (protobuf wire form).
	npub3, err := NodePublicFromBytes(npub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !npub.Equal(npub3) {
		t.Fatal("node key bytes round trip mismatch")
	}
}

func TestPrefixesAreDistinct(t *testing.T) {
	mk, _ := NewMachine()
	nk, _ := NewNode()

	mtxt, _ := mk.Public().MarshalText()
	ntxt, _ := nk.Public().MarshalText()

	// A node key must not parse as a machine key and vice versa.
	var mp MachinePublic
	if err := mp.UnmarshalText(ntxt); err == nil {
		t.Fatal("machine key accepted a nodekey: prefix")
	}
	var np NodePublic
	if err := np.UnmarshalText(mtxt); err == nil {
		t.Fatal("node key accepted a mkey: prefix")
	}
}

func TestUnmarshalRejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"mkey:",
		"mkey:zzzz",
		"mkey:" + string(make([]byte, 64)),          // non-hex
		"nodekey:abcd",                              // too short
		"nodekey:" + string(make([]byte, 63)) + "g", // wrong length
	}
	for _, c := range cases {
		var mp MachinePublic
		if err := mp.UnmarshalText([]byte(c)); err == nil {
			t.Errorf("machine key accepted %q", c)
		}
	}
}

func TestClampingMatchesWireGuard(t *testing.T) {
	// The node private key must be usable directly as a WireGuard key:
	// clamped per RFC 7748 so ScalarBaseMult can't be given a bad scalar.
	nk, err := NewNode()
	if err != nil {
		t.Fatal(err)
	}
	raw := nk.Raw()
	if raw[0]&7 != 0 {
		t.Error("low 3 bits not cleared")
	}
	if raw[31]&128 != 0 {
		t.Error("high bit not cleared")
	}
	if raw[31]&64 == 0 {
		t.Error("bit 254 not set")
	}

	// Sanity: public derivation agrees with x/crypto directly.
	var want [32]byte
	curve25519.ScalarBaseMult(&want, &raw)
	got, _ := NodePublicFromBytes(want[:])
	if !nk.Public().Equal(got) {
		t.Fatal("public key derivation mismatch")
	}
}
