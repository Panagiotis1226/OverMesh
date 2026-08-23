package relay

import (
	"bufio"
	"crypto/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Server relays frames between authenticated clients. It is stateless
// beyond the live connection registry, so any number of relays can run
// side by side.
type Server struct {
	logf func(string, ...any)

	mu    sync.Mutex
	conns map[[32]byte]*serverConn // node public key -> newest connection
}

// NewServer builds a relay server.
func NewServer(logf func(string, ...any)) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Server{logf: logf, conns: make(map[[32]byte]*serverConn)}
}

type outFrame struct {
	typ  byte
	body []byte
}

type serverConn struct {
	key   [32]byte
	conn  net.Conn
	sendq chan outFrame // all writes flow through one writer goroutine
	done  chan struct{}
	once  sync.Once
}

func (c *serverConn) close() {
	c.once.Do(func() {
		close(c.done)
		c.conn.Close()
	})
}

// Handler returns the HTTP upgrade handler to mount at UpgradePath.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != ProtocolName {
			http.Error(w, "this is the OverMesh relay endpoint; speak "+ProtocolName, http.StatusUpgradeRequired)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + ProtocolName + "\r\nConnection: Upgrade\r\n\r\n"
		if _, err := brw.WriteString(resp); err != nil || brw.Flush() != nil {
			conn.Close()
			return
		}
		go s.serveConn(conn, brw.Reader)
	})
}

// serveConn authenticates one client and pumps frames until it drops.
func (s *Server) serveConn(conn net.Conn, br *bufio.Reader) {
	defer conn.Close()

	key, err := s.handshake(conn, br)
	if err != nil {
		s.logf("relay: handshake from %s failed: %v", conn.RemoteAddr(), err)
		return
	}

	sc := &serverConn{
		key:  key,
		conn: conn,
		// Bounded queue: a stalled client drops frames rather than
		// stalling senders (WireGuard handles loss).
		sendq: make(chan outFrame, 256),
		done:  make(chan struct{}),
	}

	// Register; newest connection for a key wins.
	s.mu.Lock()
	if old, ok := s.conns[key]; ok {
		old.close()
	}
	s.conns[key] = sc
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if cur, ok := s.conns[key]; ok && cur == sc {
			delete(s.conns, key)
		}
		s.mu.Unlock()
		sc.close()
	}()

	// Writer: the only goroutine that writes post-handshake frames.
	go func() {
		for {
			select {
			case <-sc.done:
				return
			case f := <-sc.sendq:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := writeFrame(conn, f.typ, f.body); err != nil {
					sc.close()
					return
				}
			}
		}
	}()

	// Reader: routes Send frames, answers pings.
	buf := make([]byte, maxFrameLen)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		typ, body, err := readFrame(br, buf)
		if err != nil {
			return
		}
		switch typ {
		case framePing:
			select {
			case sc.sendq <- outFrame{typ: framePong}:
			default:
			}
		case frameSend:
			if len(body) < 32 {
				continue
			}
			var dst [32]byte
			copy(dst[:], body[:32])
			s.forward(key, dst, body[32:])
		}
	}
}

// forward queues a payload from src for dst, prefixed with src's key.
func (s *Server) forward(src, dst [32]byte, payload []byte) {
	s.mu.Lock()
	target, ok := s.conns[dst]
	s.mu.Unlock()
	if !ok {
		return // recipient not connected here; sender's WG retries
	}
	body := make([]byte, 32+len(payload))
	copy(body[:32], src[:])
	copy(body[32:], payload)
	select {
	case target.sendq <- outFrame{typ: frameRecv, body: body}:
	default: // queue full: drop (never stall the relay on one client)
	}
}

// handshake proves the client holds the private half of the node key it
// claims.
func (s *Server) handshake(conn net.Conn, br *bufio.Reader) ([32]byte, error) {
	var zero [32]byte
	ephPub, ephPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return zero, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return zero, err
	}

	challenge := make([]byte, 32+24)
	copy(challenge[:32], ephPub[:])
	copy(challenge[32:], nonce[:])
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := writeFrame(conn, frameChallenge, challenge); err != nil {
		return zero, err
	}

	buf := make([]byte, maxFrameLen)
	typ, body, err := readFrame(br, buf)
	if err != nil {
		return zero, err
	}
	if typ != frameAuth || len(body) < 32+box.Overhead {
		return zero, errBadAuth
	}
	var clientPub [32]byte
	copy(clientPub[:], body[:32])
	opened, ok := box.Open(nil, body[32:], &nonce, &clientPub, ephPriv)
	if !ok || len(opened) != 24 || string(opened) != string(nonce[:]) {
		return zero, errBadAuth
	}
	if err := writeFrame(conn, frameOK, nil); err != nil {
		return zero, err
	}
	_ = conn.SetDeadline(time.Time{})
	s.logf("relay: client %x… connected from %s", clientPub[:6], conn.RemoteAddr())
	return clientPub, nil
}

var errBadAuth = &badAuthError{}

type badAuthError struct{}

func (*badAuthError) Error() string { return "relay: bad auth" }
