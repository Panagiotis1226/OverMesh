package coord

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/key"
	"github.com/panagiotis1226/overmesh/internal/store"
)

// Service implements overmeshv1.CoordinationServiceServer on top of a
// Coordinator.
type Service struct {
	overmeshv1.UnimplementedCoordinationServiceServer
	C *Coordinator
}

// RegisterNode implements the RPC.
func (s *Service) RegisterNode(ctx context.Context, req *overmeshv1.RegisterNodeRequest) (*overmeshv1.RegisterNodeResponse, error) {
	mkey, err := key.MachinePublicFromBytes(req.GetMachineKey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	nkey, err := key.NodePublicFromBytes(req.GetNodeKey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if mkey.IsZero() || nkey.IsZero() {
		return nil, status.Error(codes.InvalidArgument, "zero key")
	}

	n, nw, err := s.C.Register(mkey, nkey, req.GetSetupKey(), req.GetHostname(), req.GetOs())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	return &overmeshv1.RegisterNodeResponse{
		NodeId:      uint64(n.ID),
		NetworkId:   nw.Name,
		OverlayIpv4: n.IPv4.String() + "/32",
		OverlayIpv6: n.IPv6.String() + "/128",
		Hostname:    n.Hostname,
	}, nil
}

// UpdateEndpoints implements the RPC.
func (s *Service) UpdateEndpoints(ctx context.Context, req *overmeshv1.UpdateEndpointsRequest) (*overmeshv1.UpdateEndpointsResponse, error) {
	mkey, err := key.MachinePublicFromBytes(req.GetMachineKey())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.C.UpdateEndpoints(mkey, req.GetEndpoints()); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "unknown node")
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &overmeshv1.UpdateEndpointsResponse{}, nil
}

// StreamNetMap implements the RPC: prime with the current map, then push
// on every change until the client goes away or the node is deleted.
func (s *Service) StreamNetMap(req *overmeshv1.StreamNetMapRequest, stream overmeshv1.CoordinationService_StreamNetMapServer) error {
	mkey, err := key.MachinePublicFromBytes(req.GetMachineKey())
	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	_, ch, unsub, err := s.C.Subscribe(mkey)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return status.Error(codes.NotFound, "unknown node: register first")
		}
		return status.Error(codes.Internal, err.Error())
	}
	defer unsub()

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case nm, ok := <-ch:
			if !ok {
				// Node was deleted (or replaced by a newer stream).
				return status.Error(codes.NotFound, "node removed from network")
			}
			if err := stream.Send(nm); err != nil {
				return err
			}
		}
	}
}
