package magicsock

import (
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// TestRelayEndpointRoundTrip covers parse/format symmetry and Send/receive
// routing for the relay path.
func TestRelayEndpointRoundTrip(t *testing.T) {
	b := NewBind(t.Logf)
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	s := RelayEndpointString(key)

	ep, err := b.ParseEndpoint(s)
	if err != nil {
		t.Fatal(err)
	}
	if ep.DstToString() != s {
		t.Fatalf("round trip: %s != %s", ep.DstToString(), s)
	}
	if _, ok := ep.(relayEndpoint); !ok {
		t.Fatalf("parsed to %T, want relayEndpoint", ep)
	}
	if _, err := b.ParseEndpoint("relay:zznothex"); err == nil {
		t.Fatal("bad relay endpoint accepted")
	}
}

func TestRelaySendAndDeliver(t *testing.T) {
	b := NewBind(t.Logf)
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	var dst, src [32]byte
	dst[0], src[0] = 0xAA, 0xBB

	// Without a relay sender, Send drops silently (WG retransmits).
	ep, _ := b.ParseEndpoint(RelayEndpointString(dst))
	if err := b.Send([][]byte{[]byte("pkt")}, ep); err != nil {
		t.Fatalf("send without relay: %v", err)
	}

	// With a sender installed, frames flow to it.
	got := make(chan [32]byte, 1)
	b.SetRelaySender(func(d [32]byte, payload []byte) error {
		if string(payload) != "pkt2" {
			t.Errorf("payload %q", payload)
		}
		got <- d
		return nil
	})
	if err := b.Send([][]byte{[]byte("pkt2")}, ep); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-got:
		if d != dst {
			t.Fatalf("sent to %x", d[:2])
		}
	case <-time.After(time.Second):
		t.Fatal("relay sender never called")
	}

	// Inbound relay packets surface through the second ReceiveFunc with a
	// relay endpoint attributed to the source key.
	b.DeliverRelayPacket(src, []byte("inbound"))
	packets := [][]byte{make([]byte, 1500)}
	sizes := []int{0}
	eps := make([]conn.Endpoint, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err := fns[1](packets, sizes, eps)
		if err != nil || n != 1 {
			t.Errorf("receiveRelay: n=%d err=%v", n, err)
			return
		}
		if string(packets[0][:sizes[0]]) != "inbound" {
			t.Errorf("payload %q", packets[0][:sizes[0]])
		}
		if eps[0].DstToString() != RelayEndpointString(src) {
			t.Errorf("endpoint %s", eps[0].DstToString())
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receiveRelay timed out")
	}

	// Close unblocks a parked relay receiver with net.ErrClosed.
	errc := make(chan error, 1)
	go func() {
		_, err := fns[1](packets, sizes, eps)
		errc <- err
	}()
	time.Sleep(50 * time.Millisecond)
	b.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("receiveRelay returned nil after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not unblock receiveRelay")
	}
}
