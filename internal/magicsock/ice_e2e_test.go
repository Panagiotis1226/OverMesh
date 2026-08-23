package magicsock

import (
	"context"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"golang.zx2c4.com/wireguard/conn"
)

// newTestAgent builds a Bind (with the pump wireguard-go's device
// normally provides) and an agent over its mux.
func newTestAgent(t *testing.T, ctypes []ice.CandidateType, urls []*stun.URI) func(string, any) (*Bind, *ice.Agent) {
	return func(name string, _ any) (*Bind, *ice.Agent) {
		b := NewBind(t.Logf)
		fns, _, err := b.Open(0)
		if err != nil {
			t.Fatalf("%s open: %v", name, err)
		}
		t.Cleanup(func() { b.Close() })
		go func() {
			packets := [][]byte{make([]byte, 1500)}
			sizes := []int{0}
			eps := make([]conn.Endpoint, 1)
			for {
				if _, err := fns[0](packets, sizes, eps); err != nil {
					return
				}
			}
		}()
		a, err := ice.NewAgent(&ice.AgentConfig{
			NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4},
			CandidateTypes:   ctypes,
			Urls:             urls,
			UDPMux:           b.Mux(),
			UDPMuxSrflx:      b.Mux(),
			MulticastDNSMode: ice.MulticastDNSModeDisabled,
		})
		if err != nil {
			t.Fatalf("%s agent: %v", name, err)
		}
		t.Cleanup(func() { a.Close() })
		return b, a
	}
}

// TestICEOverBind proves two agents can complete ICE across two Binds on
// the same host — the full magicsock datapath (demux -> muxConn -> mux ->
// candidates) without NATs in the way. If this fails, the glue is broken;
// if it passes, connectivity failures are environmental.
func TestICEOverBind(t *testing.T) {
	mk := newTestAgent(t, []ice.CandidateType{ice.CandidateTypeHost}, nil)

	_, aA := mk("A", nil)
	_, aB := mk("B", nil)

	// Trickle candidates both ways.
	if err := aA.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		t.Logf("A candidate: %s", c)
		c2, err := ice.UnmarshalCandidate(c.Marshal())
		if err == nil {
			_ = aB.AddRemoteCandidate(c2)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := aB.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		t.Logf("B candidate: %s", c)
		c2, err := ice.UnmarshalCandidate(c.Marshal())
		if err == nil {
			_ = aA.AddRemoteCandidate(c2)
		}
	}); err != nil {
		t.Fatal(err)
	}

	ufragA, pwdA, _ := aA.GetLocalUserCredentials()
	ufragB, pwdB, _ := aB.GetLocalUserCredentials()
	if err := aA.GatherCandidates(); err != nil {
		t.Fatal(err)
	}
	if err := aB.GatherCandidates(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	errB := make(chan error, 1)
	go func() {
		_, err := aB.Accept(ctx, ufragA, pwdA)
		errB <- err
	}()
	if _, err := aA.Dial(ctx, ufragB, pwdB); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := <-errB; err != nil {
		t.Fatalf("Accept: %v", err)
	}

	pair, err := aA.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		t.Fatalf("no selected pair: %v", err)
	}
	t.Logf("selected pair: %s -> %s", pair.Local, pair.Remote)
}
