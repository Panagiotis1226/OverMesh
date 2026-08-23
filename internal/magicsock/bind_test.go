package magicsock

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/stun/v3"
	"golang.zx2c4.com/wireguard/conn"
)

func netipMustParseAddrPort(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// TestDemux proves the core magicsock property: STUN datagrams feed the
// ICE mux while everything else surfaces to WireGuard.
func TestDemux(t *testing.T) {
	b := NewBind(t.Logf)
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if len(fns) != 1 || port == 0 {
		t.Fatalf("unexpected open result: %d fns, port %d", len(fns), port)
	}

	select {
	case <-b.Ready():
	default:
		t.Fatal("Ready not closed after Open")
	}

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}

	// One STUN binding request, then one WireGuard-shaped packet.
	m := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if _, err := sender.WriteTo(m.Raw, dst); err != nil {
		t.Fatal(err)
	}
	wgPkt := []byte{0x04, 0, 0, 0, 9, 9, 9, 9} // WG transport header shape
	if _, err := sender.WriteTo(wgPkt, dst); err != nil {
		t.Fatal(err)
	}

	// The receive func must hand WireGuard ONLY the second packet.
	packets := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	eps := make([]conn.Endpoint, 1)
	done := make(chan error, 1)
	go func() {
		n, err := fns[0](packets, sizes, eps)
		if err == nil && n != 1 {
			t.Errorf("receive returned n=%d", n)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("receive timed out (STUN packet was not filtered?)")
	}
	if sizes[0] != len(wgPkt) || packets[0][0] != 0x04 {
		t.Fatalf("wireguard got wrong packet: %d bytes, first byte %#x", sizes[0], packets[0][0])
	}
	if got := eps[0].DstToString(); got != sender.LocalAddr().String() {
		t.Fatalf("endpoint = %s, want %s", got, sender.LocalAddr())
	}

	// The STUN packet went to the ICE mux side (pion's own read loop
	// consumes it from the virtual conn; muxConn delivery is unit-tested
	// below and exercised end-to-end by the phase2 integration test).
}

// TestMuxConnDelivery unit-tests the virtual PacketConn feeding the mux.
func TestMuxConnDelivery(t *testing.T) {
	real, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer real.Close()
	mc := newMuxConn(real, real.LocalAddr().(*net.UDPAddr))
	defer mc.Close()

	m := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	src := netipMustParseAddrPort("192.0.2.9:5555")
	mc.deliver(m.Raw, src)

	buf := make([]byte, 1500)
	n, from, err := mc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !stun.IsMessage(buf[:n]) {
		t.Fatal("delivered packet is not STUN")
	}
	if from.String() != src.String() {
		t.Fatalf("source = %s, want %s", from, src)
	}

	// Close unblocks readers with net.ErrClosed.
	mc.Close()
	if _, _, err := mc.ReadFrom(buf); err == nil {
		t.Fatal("ReadFrom after Close should fail")
	}
}

// TestEndpointRoundTrip checks ParseEndpoint/DstToString symmetry.
func TestEndpointRoundTrip(t *testing.T) {
	b := NewBind(t.Logf)
	ep, err := b.ParseEndpoint("192.0.2.7:4242")
	if err != nil {
		t.Fatal(err)
	}
	if ep.DstToString() != "192.0.2.7:4242" {
		t.Fatalf("round trip: %s", ep.DstToString())
	}
	if ep.DstIP().String() != "192.0.2.7" {
		t.Fatalf("DstIP: %s", ep.DstIP())
	}
}
