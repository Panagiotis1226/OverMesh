// Package magicsock is OverMesh's "smart socket": one UDP socket carries
// WireGuard data, STUN discovery, and ICE connectivity checks. Inbound
// datagrams are demultiplexed by shape — STUN messages (RFC 5389 magic
// cookie) feed pion's UDP mux for ICE, everything else is WireGuard.
// Because ICE candidates therefore live on the WireGuard port itself, a
// punched hole is immediately usable by setting the peer's WireGuard
// endpoint to the selected remote address: same socket, same mapping.
package magicsock

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	"golang.zx2c4.com/wireguard/conn"
)

// Bind implements wireguard-go's conn.Bind on a single dual-stack UDP
// socket. Create with NewBind, hand to the userspace engine, and read
// Ready() before using the ICE mux.
type Bind struct {
	logf func(string, ...any)

	mu     sync.Mutex
	pc     *net.UDPConn
	mux    *ice.UniversalUDPMuxDefault
	muxway *muxConn
	ready  chan struct{}
	wgPkts atomic.Uint64 // non-STUN packets surfaced to WireGuard (stats)
}

// NewBind returns an unopened Bind; wireguard-go calls Open when the
// device comes up.
func NewBind(logf func(string, ...any)) *Bind {
	return &Bind{logf: logf, ready: make(chan struct{})}
}

// Ready is closed once Open has run and Mux is usable. wireguard-go
// closes and reopens the bind across device down/up cycles, so callers
// should re-take the channel per wait rather than caching it.
func (b *Bind) Ready() <-chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ready
}

// Mux returns the ICE mux (host + srflx candidates over the shared
// socket). Only valid after Ready.
func (b *Bind) Mux() *ice.UniversalUDPMuxDefault {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.mux
}

// LocalPort reports the bound UDP port (valid after Ready).
func (b *Bind) LocalPort() uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc == nil {
		return 0
	}
	return uint16(b.pc.LocalAddr().(*net.UDPAddr).Port)
}

// Open implements conn.Bind.
func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	// One dual-stack socket ("udp" + wildcard binds v4 and v6).
	pc, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.pc = pc
	actual := uint16(pc.LocalAddr().(*net.UDPAddr).Port)

	// The mux must see ONE concrete listen address: a wildcard makes it
	// fabricate host candidates for every local address (loopback
	// included), yielding multiple muxed conns per ufrag and inbound
	// checks routed to conns no candidate reads.
	b.muxway = newMuxConn(pc, primaryLocalAddr(actual))
	b.mux = ice.NewUniversalUDPMuxDefault(ice.UniversalUDPMuxParams{UDPConn: b.muxway})

	// wireguard-go's BindUpdate always calls Close before (re)opening, so
	// Close re-arms the channel and Open closes it unconditionally.
	select {
	case <-b.ready:
	default:
		close(b.ready)
	}
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

// receive reads one datagram and routes it: STUN -> ICE mux (and keep
// reading), anything else -> WireGuard.
func (b *Bind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.mu.Lock()
	pc, muxway := b.pc, b.muxway
	b.mu.Unlock()
	if pc == nil {
		return 0, net.ErrClosed
	}
	for {
		n, addr, err := pc.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		if stun.IsMessage(packets[0][:n]) {
			muxway.deliver(packets[0][:n], addr)
			continue
		}
		b.wgPkts.Add(1)
		sizes[0] = n
		eps[0] = endpoint(addr.Addr().Unmap()).withPort(addr.Port())
		return 1, nil
	}
}

// Send implements conn.Bind.
func (b *Bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	e, ok := ep.(endpointWithPort)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	for _, buf := range bufs {
		if _, err := pc.WriteToUDPAddrPort(buf, netip.AddrPort(e)); err != nil {
			return err
		}
	}
	return nil
}

// Close implements conn.Bind. wireguard-go calls it both on device down
// and as the first step of every BindUpdate, so it must leave the Bind
// reopenable: the ready channel is re-armed for the next Open.
func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	var err error
	if b.mux != nil {
		_ = b.mux.Close()
		b.mux = nil
	}
	if b.muxway != nil {
		b.muxway.close()
		b.muxway = nil
	}
	if b.pc != nil {
		err = b.pc.Close()
		b.pc = nil
	}
	select {
	case <-b.ready: // was closed (open state): re-arm
		b.ready = make(chan struct{})
	default: // never opened: keep the existing armed channel
	}
	return err
}

// SetMark implements conn.Bind (no-op; SO_MARK arrives with policy
// routing work in Phase 5).
func (b *Bind) SetMark(uint32) error { return nil }

// BatchSize implements conn.Bind.
func (b *Bind) BatchSize() int { return 1 }

// ParseEndpoint implements conn.Bind.
func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return endpointWithPort(ap), nil
}

// --- endpoint ---

type endpointWithPort netip.AddrPort

func endpoint(a netip.Addr) endpointBuilder { return endpointBuilder(a) }

type endpointBuilder netip.Addr

func (e endpointBuilder) withPort(p uint16) endpointWithPort {
	return endpointWithPort(netip.AddrPortFrom(netip.Addr(e), p))
}

func (e endpointWithPort) ClearSrc()           {}
func (e endpointWithPort) SrcToString() string { return "" }
func (e endpointWithPort) DstToString() string { return netip.AddrPort(e).String() }
func (e endpointWithPort) DstToBytes() []byte {
	b, _ := netip.AddrPort(e).MarshalBinary()
	return b
}
func (e endpointWithPort) DstIP() netip.Addr { return netip.AddrPort(e).Addr() }
func (e endpointWithPort) SrcIP() netip.Addr { return netip.Addr{} }

// --- virtual PacketConn feeding the ICE mux ---

type muxPacket struct {
	data []byte
	addr netip.AddrPort
}

// muxConn is the net.PacketConn pion's mux reads: ReadFrom yields the
// STUN datagrams the Bind classified, WriteTo goes out the real socket.
type muxConn struct {
	real  *net.UDPConn
	local *net.UDPAddr // concrete (non-wildcard) address reported to the mux
	ch    chan muxPacket
	done  chan struct{}
	once  sync.Once
}

func newMuxConn(real *net.UDPConn, local *net.UDPAddr) *muxConn {
	return &muxConn{real: real, local: local, ch: make(chan muxPacket, 64), done: make(chan struct{})}
}

// primaryLocalAddr picks this host's primary global-unicast IPv4 address
// for the ICE host candidate. srflx candidates cover NAT reachability;
// additional host addresses on multi-homed machines are a later
// refinement.
func primaryLocalAddr(port uint16) *net.UDPAddr {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := ifc.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip, ok := netip.AddrFromSlice(ipnet.IP)
				if !ok {
					continue
				}
				ip = ip.Unmap()
				if ip.Is4() && ip.IsGlobalUnicast() && !inOverlay(ip) {
					return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port))
				}
			}
		}
	}
	// Last resort: loopback beats a wildcard (never expanded by the mux).
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port))
}

func inOverlay(a netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}

func (m *muxConn) deliver(data []byte, addr netip.AddrPort) {
	pkt := muxPacket{data: append([]byte{}, data...), addr: addr}
	select {
	case m.ch <- pkt:
	case <-m.done:
	default: // mux stalled: drop; STUN retransmits
	}
}

func (m *muxConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-m.ch:
		n := copy(p, pkt.data)
		return n, net.UDPAddrFromAddrPort(pkt.addr), nil
	case <-m.done:
		return 0, nil, net.ErrClosed
	}
}

func (m *muxConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("muxConn: non-UDP address")
	}
	ap := ua.AddrPort()
	// A 4-byte IP in a 16-byte slice becomes a 4-in-6 mapped address,
	// which a v4 socket refuses to send to; unmap it.
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	return m.real.WriteToUDPAddrPort(p, ap)
}

func (m *muxConn) close()       { m.once.Do(func() { close(m.done) }) }
func (m *muxConn) Close() error { m.close(); return nil }

func (m *muxConn) LocalAddr() net.Addr { return m.local }

// The ICE mux does not rely on deadlines; satisfy the interface.
func (m *muxConn) SetDeadline(time.Time) error      { return nil }
func (m *muxConn) SetReadDeadline(time.Time) error  { return nil }
func (m *muxConn) SetWriteDeadline(time.Time) error { return nil }
