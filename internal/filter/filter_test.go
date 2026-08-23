package filter

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// v4pkt builds a minimal IPv4 packet.
func v4pkt(src string, proto uint8, dstPort uint16) []byte {
	p := make([]byte, 24)
	p[0] = 0x45 // v4, ihl 20
	p[9] = proto
	copy(p[12:16], netip.MustParseAddr(src).AsSlice())
	copy(p[16:20], netip.MustParseAddr("100.96.0.9").AsSlice())
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	return p
}

// v6pkt builds a minimal IPv6 packet.
func v6pkt(src string, proto uint8, dstPort uint16) []byte {
	p := make([]byte, 44)
	p[0] = 0x60
	p[6] = proto
	copy(p[8:24], netip.MustParseAddr(src).AsSlice())
	binary.BigEndian.PutUint16(p[42:44], dstPort)
	return p
}

func pfx(s string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(s)} }

func TestDisabledAllowsEverything(t *testing.T) {
	f := New(nil, false)
	if !f.AllowsPacket(v4pkt("100.96.0.1", protoTCP, 22)) {
		t.Fatal("disabled filter dropped a packet")
	}
	var nilf *Filter
	if !nilf.AllowsPacket(v4pkt("100.96.0.1", protoTCP, 22)) {
		t.Fatal("nil filter dropped a packet")
	}
}

func TestFirstMatchWinsAndImplicitDeny(t *testing.T) {
	f := New([]Rule{
		{Allow: false, Srcs: pfx("100.96.0.1/32"), Proto: "tcp", Ports: []PortRange{{22, 22}}},
		{Allow: true}, // any/any
	}, true)

	if f.AllowsPacket(v4pkt("100.96.0.1", protoTCP, 22)) {
		t.Fatal("deny ssh rule ignored")
	}
	if !f.AllowsPacket(v4pkt("100.96.0.1", protoTCP, 80)) {
		t.Fatal("port 80 should fall through to allow-any")
	}
	if !f.AllowsPacket(v4pkt("100.96.0.1", protoICMP4, 0)) {
		t.Fatal("ping should stay allowed while ssh is denied")
	}
	if !f.AllowsPacket(v4pkt("100.96.0.2", protoTCP, 22)) {
		t.Fatal("ssh from a different source should be allowed")
	}

	// Without the trailing allow-any: implicit deny.
	f2 := New([]Rule{
		{Allow: true, Proto: "icmp"},
	}, true)
	if !f2.AllowsPacket(v4pkt("100.96.0.1", protoICMP4, 0)) {
		t.Fatal("icmp allow rule ignored")
	}
	if f2.AllowsPacket(v4pkt("100.96.0.1", protoTCP, 80)) {
		t.Fatal("implicit deny missing")
	}
}

func TestIPv6AndICMPClass(t *testing.T) {
	f := New([]Rule{
		{Allow: true, Srcs: pfx("fdab:3f19::/48"), Proto: "icmp"},
	}, true)
	if !f.AllowsPacket(v6pkt("fdab:3f19::2", protoICMP6, 0)) {
		t.Fatal("icmpv6 from allowed prefix dropped")
	}
	if f.AllowsPacket(v6pkt("fdab:3f19::2", protoTCP, 443)) {
		t.Fatal("tcp matched an icmp rule")
	}
	if f.AllowsPacket(v6pkt("fd00::99", protoICMP6, 0)) {
		t.Fatal("src outside prefix allowed")
	}
}

func TestPortRangesAndPortlessProtocols(t *testing.T) {
	f := New([]Rule{
		{Allow: true, Proto: "udp", Ports: []PortRange{{8000, 9000}}},
	}, true)
	if !f.AllowsPacket(v4pkt("100.96.0.1", protoUDP, 8500)) {
		t.Fatal("in-range udp dropped")
	}
	if f.AllowsPacket(v4pkt("100.96.0.1", protoUDP, 7999)) {
		t.Fatal("out-of-range udp allowed")
	}
	// A ports-constrained rule must not match portless protocols.
	if f.AllowsPacket(v4pkt("100.96.0.1", protoICMP4, 0)) {
		t.Fatal("icmp matched a port-constrained rule")
	}
}

func TestGarbageFailsClosed(t *testing.T) {
	f := New([]Rule{{Allow: true}}, true)
	if f.AllowsPacket([]byte{0x00, 0x01}) {
		t.Fatal("garbage packet passed an enabled filter")
	}
	if f.AllowsPacket(nil) {
		t.Fatal("empty packet passed")
	}
}
