package relay

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/panagiotis1226/overmesh/internal/key"
)

type recvRec struct {
	mu   sync.Mutex
	pkts [][]byte
	srcs [][32]byte
	ch   chan struct{}
}

func newRecvRec() *recvRec { return &recvRec{ch: make(chan struct{}, 64)} }

func (r *recvRec) cb(src [32]byte, payload []byte) {
	r.mu.Lock()
	r.pkts = append(r.pkts, payload)
	r.srcs = append(r.srcs, src)
	r.mu.Unlock()
	r.ch <- struct{}{}
}

func (r *recvRec) wait(t *testing.T) ([32]byte, []byte) {
	t.Helper()
	select {
	case <-r.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for relayed packet")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.srcs[len(r.srcs)-1], r.pkts[len(r.pkts)-1]
}

func testKeys(t *testing.T) ([32]byte, [32]byte) {
	t.Helper()
	nk, err := key.NewNode()
	if err != nil {
		t.Fatal(err)
	}
	var pub [32]byte
	copy(pub[:], nk.Public().Bytes())
	return nk.Raw(), pub
}

func startTestRelay(t *testing.T) string {
	t.Helper()
	srv := NewServer(t.Logf)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs.URL + UpgradePath
}

func waitConnected(t *testing.T, c *Client) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c.Connected() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("client never connected")
}

func TestRelayExchange(t *testing.T) {
	url := startTestRelay(t)
	aPriv, aPub := testKeys(t)
	bPriv, bPub := testKeys(t)

	aRecv, bRecv := newRecvRec(), newRecvRec()
	ca := NewClient(url, aPriv, aPub, aRecv.cb, t.Logf)
	defer ca.Close()
	cb := NewClient(url, bPriv, bPub, bRecv.cb, t.Logf)
	defer cb.Close()
	waitConnected(t, ca)
	waitConnected(t, cb)

	if err := ca.Send(bPub, []byte("wg-datagram-1")); err != nil {
		t.Fatal(err)
	}
	src, pkt := bRecv.wait(t)
	if src != aPub || string(pkt) != "wg-datagram-1" {
		t.Fatalf("b got %q from %x", pkt, src[:4])
	}

	if err := cb.Send(aPub, []byte("reply-2")); err != nil {
		t.Fatal(err)
	}
	src, pkt = aRecv.wait(t)
	if src != bPub || string(pkt) != "reply-2" {
		t.Fatalf("a got %q from %x", pkt, src[:4])
	}
}

func TestRelaySendToOfflinePeerIsDropped(t *testing.T) {
	url := startTestRelay(t)
	aPriv, aPub := testKeys(t)
	_, ghostPub := testKeys(t)

	ca := NewClient(url, aPriv, aPub, newRecvRec().cb, t.Logf)
	defer ca.Close()
	waitConnected(t, ca)

	// Must not error or wedge the connection.
	if err := ca.Send(ghostPub, []byte("into the void")); err != nil {
		t.Fatal(err)
	}
	if !ca.Connected() {
		t.Fatal("connection dropped by send-to-offline")
	}
}

func TestRelayNewestConnectionWins(t *testing.T) {
	url := startTestRelay(t)
	aPriv, aPub := testKeys(t)
	bPriv, bPub := testKeys(t)

	ca := NewClient(url, aPriv, aPub, newRecvRec().cb, t.Logf)
	defer ca.Close()
	waitConnected(t, ca)

	// Two clients with b's identity: the second replaces the first.
	old := NewClient(url, bPriv, bPub, newRecvRec().cb, t.Logf)
	waitConnected(t, old)
	fresh := newRecvRec()
	nu := NewClient(url, bPriv, bPub, fresh.cb, t.Logf)
	defer nu.Close()
	waitConnected(t, nu)
	old.Close() // old one is dead server-side already; stop its retries

	if err := ca.Send(bPub, []byte("to-the-new-one")); err != nil {
		t.Fatal(err)
	}
	if _, pkt := fresh.wait(t); string(pkt) != "to-the-new-one" {
		t.Fatalf("newest conn got %q", pkt)
	}
}

func TestRelayRejectsBadAuth(t *testing.T) {
	url := startTestRelay(t)
	// Private key that does not match the claimed public key.
	aPriv, _ := testKeys(t)
	_, wrongPub := testKeys(t)

	c := NewClient(url, aPriv, wrongPub, newRecvRec().cb, t.Logf)
	defer c.Close()
	time.Sleep(700 * time.Millisecond)
	if c.Connected() {
		t.Fatal("client with mismatched keypair authenticated")
	}
}

func TestRelayRejectsNonUpgradeRequests(t *testing.T) {
	url := startTestRelay(t)
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("plain GET got %d, want 426", resp.StatusCode)
	}
}
