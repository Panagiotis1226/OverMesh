package magicsock

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"

	"github.com/panagiotis1226/overmesh/internal/stunserver"
)

// TestICEOverBindWithSrflx is TestICEOverBind plus the daemon's full
// agent config: STUN URLs + srflx candidates over the UniversalUDPMux.
// Isolates whether srflx gathering breaks the connectivity that
// host-only agents achieve.
func TestICEOverBindWithSrflx(t *testing.T) {
	srv, err := stunserver.Listen("127.0.0.1:0", t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	uri, err := stun.ParseURI(fmt.Sprintf("stun:%s", srv.Addr()))
	if err != nil {
		t.Fatal(err)
	}

	mk := newTestAgent(t,
		[]ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive},
		[]*stun.URI{uri})
	_, aA := mk("A", nil)
	_, aB := mk("B", nil)

	relay := func(dst *ice.Agent, tag string) func(ice.Candidate) {
		return func(c ice.Candidate) {
			if c == nil {
				return
			}
			t.Logf("%s candidate: %s", tag, c)
			c2, err := ice.UnmarshalCandidate(c.Marshal())
			if err == nil {
				_ = dst.AddRemoteCandidate(c2)
			}
		}
	}
	if err := aA.OnCandidate(relay(aB, "A")); err != nil {
		t.Fatal(err)
	}
	if err := aB.OnCandidate(relay(aA, "B")); err != nil {
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
