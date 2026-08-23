package coord

import (
	"errors"
	"io"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/key"
	"github.com/panagiotis1226/overmesh/internal/store"
)

// signalSubscribe registers a node's signal inbox. Mirrors the netmap
// subscriber pattern: one stream per node, a new one replaces the old.
func (c *Coordinator) signalSubscribe(mkey key.MachinePublic) (store.Node, chan *overmeshv1.SignalEnvelope, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.st.NodeByMachineKey(mkey.String())
	if err != nil {
		return store.Node{}, nil, nil, err
	}
	if old, ok := c.sigSubs[n.ID]; ok {
		close(old)
	}
	ch := make(chan *overmeshv1.SignalEnvelope, 32)
	c.sigSubs[n.ID] = ch
	unsub := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if cur, ok := c.sigSubs[n.ID]; ok && cur == ch {
			delete(c.sigSubs, n.ID)
		}
	}
	return n, ch, unsub, nil
}

// routeSignal delivers env to its destination node if that node holds an
// open signal stream and is in the same network as the sender.
func (c *Coordinator) routeSignal(from store.Node, env *overmeshv1.SignalEnvelope) {
	c.mu.Lock()
	defer c.mu.Unlock()
	dst, err := c.st.NodeByID(int64(env.GetToNodeId()))
	if err != nil || dst.NetworkID != from.NetworkID {
		return // unknown or cross-network destination: drop silently
	}
	ch, ok := c.sigSubs[dst.ID]
	if !ok {
		return // peer not connected; sender will retry
	}
	out := &overmeshv1.SignalEnvelope{
		ToNodeId:   env.GetToNodeId(),
		FromNodeId: uint64(from.ID), // server-stamped, never client-claimed
		Kind:       env.GetKind(),
		Payload:    env.GetPayload(),
		Session:    env.GetSession(),
	}
	select {
	case ch <- out:
	default: // slow receiver: drop; ICE retransmits/retries at its layer
	}
}

// SignalStream implements the RPC: HELLO authenticates, then envelopes
// flow both ways until either side goes away.
func (s *Service) SignalStream(stream overmeshv1.CoordinationService_SignalStreamServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetKind() != overmeshv1.SignalKind_SIGNAL_KIND_HELLO {
		return status.Error(codes.InvalidArgument, "first envelope must be HELLO")
	}
	mkey, err := key.MachinePublicFromBytes(first.GetMachineKey())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	n, inbox, unsub, err := s.C.signalSubscribe(mkey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return status.Error(codes.NotFound, "unknown node: register first")
		}
		return status.Error(codes.Internal, err.Error())
	}
	defer unsub()

	// Uplink: route envelopes from this node to their destinations.
	recvErr := make(chan error, 1)
	go func() {
		for {
			env, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			s.C.routeSignal(n, env)
		}
	}()

	// Downlink: deliver this node's inbox.
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case env, ok := <-inbox:
			if !ok {
				return status.Error(codes.Aborted, "signal stream replaced")
			}
			if err := stream.Send(env); err != nil {
				return err
			}
		}
	}
}
