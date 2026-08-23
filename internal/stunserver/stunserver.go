// Package stunserver is the control plane's embedded STUN binding
// responder: nodes ask it "what address do you see me as?" to discover
// their NAT mapping. Nothing more — no TURN, no auth (binding requests
// carry no secrets and the reply only echoes the observed address).
package stunserver

import (
	"errors"
	"fmt"
	"net"

	"github.com/pion/stun/v2"
)

// Server answers STUN binding requests on one UDP socket.
type Server struct {
	conn net.PacketConn
	logf func(string, ...any)
}

// Listen binds addr (e.g. ":3478") and starts answering until Close.
func Listen(addr string, logf func(string, ...any)) (*Server, error) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("stunserver: %w", err)
	}
	s := &Server{conn: conn, logf: logf}
	go s.serve()
	return s, nil
}

// Addr returns the bound address.
func (s *Server) Addr() net.Addr { return s.conn.LocalAddr() }

// Close stops the server.
func (s *Server) Close() error { return s.conn.Close() }

func (s *Server) serve() {
	buf := make([]byte, 1500)
	for {
		n, src, err := s.conn.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.logf("stunserver: read: %v", err)
			}
			return
		}
		if !stun.IsMessage(buf[:n]) {
			continue
		}
		m := &stun.Message{Raw: append([]byte{}, buf[:n]...)}
		if err := m.Decode(); err != nil || m.Type != stun.BindingRequest {
			continue
		}
		udp, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		resp, err := stun.Build(m, stun.BindingSuccess,
			&stun.XORMappedAddress{IP: udp.IP, Port: udp.Port},
			stun.Fingerprint,
		)
		if err != nil {
			continue
		}
		if _, err := s.conn.WriteTo(resp.Raw, src); err != nil {
			s.logf("stunserver: write to %s: %v", src, err)
		}
	}
}
