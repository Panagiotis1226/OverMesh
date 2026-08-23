// Package daemon is overmeshd's core: it registers with the control
// plane, keeps netmap + signaling streams open, runs magicsock's NAT
// traversal, and programs the WireGuard engine to match. The CLI drives
// it through the unix-socket control API in control.go.
//
// Locking rule: methods never call into ConnMgr while holding d.mu —
// ConnMgr invokes the path callback (which takes d.mu) from its own
// goroutines and sometimes synchronously from its API.
package daemon

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/magicsock"
	"github.com/panagiotis1226/overmesh/internal/version"
	"github.com/panagiotis1226/overmesh/internal/wgengine"
)

// Options configures a Daemon.
type Options struct {
	StateDir   string
	ListenPort uint16 // WireGuard UDP port
	IfaceName  string
	WGMode     string // auto|kernel|userspace
	UseTLS     bool   // TLS to the control plane
}

// PeerStatus is one peer as shown by `overmesh status`.
type PeerStatus struct {
	Hostname  string   `json:"hostname"`
	IPv4      string   `json:"ipv4"`
	IPv6      string   `json:"ipv6"`
	Online    bool     `json:"online"`
	Path      string   `json:"path"`             // direct | lan | connecting | none
	Endpoint  string   `json:"endpoint,omitempty"`
	RTTms     int64    `json:"rtt_ms,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`
}

// Status is the daemon's answer to `overmesh status`.
type Status struct {
	Version  string       `json:"version"`
	Running  bool         `json:"running"`
	Server   string       `json:"server,omitempty"`
	Network  string       `json:"network,omitempty"`
	Hostname string       `json:"hostname,omitempty"`
	IPv4     string       `json:"ipv4,omitempty"`
	IPv6     string       `json:"ipv6,omitempty"`
	Iface    string       `json:"iface,omitempty"`
	Engine   string       `json:"engine,omitempty"`
	Conn     string       `json:"conn,omitempty"` // connected | reconnecting
	Peers    []PeerStatus `json:"peers,omitempty"`
}

// peerInfo is what the daemon remembers about a peer across netmaps and
// path updates.
type peerInfo struct {
	nodeID    uint64
	hostname  string
	pubKey    [32]byte
	allowed   []netip.Prefix
	ipv4      string
	ipv6      string
	online    bool
	staticEPs []string // netmap-reported LAN/public hints
	path      magicsock.PathState
	pathEP    netip.AddrPort
	rtt       time.Duration
}

// Daemon is the running node agent.
type Daemon struct {
	opts  Options
	state *State

	mu      sync.Mutex
	cancel  context.CancelFunc // stops the session goroutine
	engine  wgengine.Engine
	connmgr *magicsock.ConnMgr
	peers   map[uint64]*peerInfo
	status  Status
	stopped chan struct{} // closed when the session goroutine exits
}

// New loads state and returns a Daemon (not yet connected).
func New(opts Options) (*Daemon, error) {
	st, err := LoadOrCreateState(opts.StateDir)
	if err != nil {
		return nil, err
	}
	d := &Daemon{opts: opts, state: st, peers: make(map[uint64]*peerInfo)}
	d.status = Status{Version: version.Long()}
	return d, nil
}

// MaybeAutoUp resumes the previous session if one was up when the daemon
// last stopped.
func (d *Daemon) MaybeAutoUp() {
	if d.state.DesiredUp && d.state.Server != "" {
		log.Printf("daemon: resuming session with %s", d.state.Server)
		if err := d.Up(d.state.Server, ""); err != nil {
			log.Printf("daemon: auto-up failed: %v", err)
		}
	}
}

func (d *Daemon) dial(server string) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	if d.opts.UseTLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	return grpc.NewClient(server,
		grpc.WithTransportCredentials(creds),
		// Detect dead connections fast: after roaming (new local
		// address) the old TCP conn silently blackholes, and without
		// keepalives the netmap/signal streams would hang for minutes.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	)
}

// Up joins (or rejoins) the mesh: register, bring up WireGuard +
// magicsock, stream netmaps and signals. setupKey may be empty when the
// machine is already enrolled.
func (d *Daemon) Up(server, setupKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cancel != nil {
		return fmt.Errorf("already up (overmesh down first)")
	}

	conn, err := d.dial(server)
	if err != nil {
		return fmt.Errorf("dial %s: %w", server, err)
	}
	client := overmeshv1.NewCoordinationServiceClient(conn)

	// OM_HOSTNAME overrides the OS hostname (useful in tests and
	// containers where every instance reports the same name).
	hostname := os.Getenv("OM_HOSTNAME")
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	resp, err := client.RegisterNode(ctx, &overmeshv1.RegisterNodeRequest{
		MachineKey:    d.state.MachineKey().Public().Bytes(),
		NodeKey:       d.state.NodeKey().Public().Bytes(),
		SetupKey:      setupKey,
		Hostname:      hostname,
		Os:            runtime.GOOS,
		ClientVersion: version.Long(),
	})
	cancel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("registration failed: %w", err)
	}

	selfV4, err := netip.ParsePrefix(resp.GetOverlayIpv4())
	if err != nil {
		conn.Close()
		return fmt.Errorf("bad overlay ipv4 from server: %w", err)
	}
	selfV6, err := netip.ParsePrefix(resp.GetOverlayIpv6())
	if err != nil {
		conn.Close()
		return fmt.Errorf("bad overlay ipv6 from server: %w", err)
	}

	log.Printf("daemon: registered as %q (node %d) in network %q: %s %s",
		resp.GetHostname(), resp.GetNodeId(), resp.GetNetworkId(), selfV4, selfV6)

	d.state.Server = server
	d.state.DesiredUp = true
	if err := d.state.Save(d.opts.StateDir); err != nil {
		conn.Close()
		return err
	}

	d.peers = make(map[uint64]*peerInfo)
	d.status = Status{
		Version:  version.Long(),
		Running:  true,
		Server:   server,
		Network:  resp.GetNetworkId(),
		Hostname: resp.GetHostname(),
		IPv4:     selfV4.Addr().String(),
		IPv6:     selfV6.Addr().String(),
		Conn:     "connecting",
	}

	sctx, scancel := context.WithCancel(context.Background())
	d.cancel = scancel
	d.stopped = make(chan struct{})
	go d.session(sctx, conn, client, resp.GetNodeId(), selfV4, selfV6)
	return nil
}

// session owns the gRPC connection, the engine, magicsock, and the
// reconnect loop.
func (d *Daemon) session(ctx context.Context, conn *grpc.ClientConn, client overmeshv1.CoordinationServiceClient, selfNode uint64, selfV4, selfV6 netip.Prefix) {
	defer close(d.stopped)
	defer conn.Close()

	// magicsock's shared socket only exists on the userspace engine; the
	// kernel engine (explicit opt-in) runs Phase-1 static endpoints only.
	var bind *magicsock.Bind
	engOpts := wgengine.Options{
		IfaceName:  d.opts.IfaceName,
		PrivateKey: d.state.NodeKey().Raw(),
		ListenPort: d.opts.ListenPort,
		Addresses:  []netip.Prefix{selfV4, selfV6},
		Routes:     overlayRoutes(selfV4, selfV6),
		Mode:       d.opts.WGMode,
		Logf:       log.Printf,
	}
	if d.opts.WGMode != "kernel" {
		bind = magicsock.NewBind(log.Printf)
		engOpts.Bind = bind
	}

	eng, err := wgengine.New(engOpts)
	if err != nil {
		log.Printf("daemon: engine: %v", err)
		d.setConn("error: " + err.Error())
		return
	}
	defer eng.Close()

	var cm *magicsock.ConnMgr
	sig := &signaler{}
	if bind != nil {
		cm = magicsock.NewConnMgr(selfNode, bind, sig, d.onPathUpdate, log.Printf)
		defer cm.Close()
	}

	d.mu.Lock()
	d.engine = eng
	d.connmgr = cm
	d.status.Iface = eng.IfName()
	d.status.Engine = eng.Kind()
	d.mu.Unlock()

	// Signaling stream (its own reconnect loop) + roaming watcher.
	if cm != nil {
		go d.runSignaling(ctx, client, sig, cm)
		go d.watchRoaming(ctx, cm)
	}

	backoff := time.Second
	for ctx.Err() == nil {
		if err := d.runNetMapStream(ctx, client, eng, cm); err != nil && ctx.Err() == nil {
			log.Printf("daemon: netmap stream: %v (retrying in %v)", err, backoff)
			d.setConn("reconnecting")
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			continue
		}
		backoff = time.Second
	}
}

// runNetMapStream reports endpoints, opens the netmap stream, and applies
// maps until the stream breaks.
func (d *Daemon) runNetMapStream(ctx context.Context, client overmeshv1.CoordinationServiceClient, eng wgengine.Engine, cm *magicsock.ConnMgr) error {
	mkey := d.state.MachineKey().Public().Bytes()

	eps := localEndpoints(d.opts.ListenPort)
	epCtx, epCancel := context.WithTimeout(ctx, 10*time.Second)
	_, err := client.UpdateEndpoints(epCtx, &overmeshv1.UpdateEndpointsRequest{
		MachineKey: mkey,
		Endpoints:  eps,
	})
	epCancel()
	if err != nil {
		return fmt.Errorf("update endpoints: %w", err)
	}

	stream, err := client.StreamNetMap(ctx, &overmeshv1.StreamNetMapRequest{MachineKey: mkey})
	if err != nil {
		return err
	}
	d.setConn("connected")
	for {
		nm, err := stream.Recv()
		if err != nil {
			return err
		}
		if err := d.applyNetMap(nm, eng, cm); err != nil {
			log.Printf("daemon: apply netmap seq %d: %v", nm.GetSeq(), err)
		}
	}
}

// applyNetMap merges the netmap into peer state, programs the engine, and
// updates magicsock's negotiation set.
func (d *Daemon) applyNetMap(nm *overmeshv1.NetMap, eng wgengine.Engine, cm *magicsock.ConnMgr) error {
	stunHosts := d.resolveStunServers(nm.GetStunServers())

	d.mu.Lock()
	seen := make(map[uint64]bool)
	online := make(map[uint64]bool)
	for _, p := range nm.GetPeers() {
		if len(p.GetNodeKey()) != 32 {
			continue
		}
		id := p.GetNodeId()
		seen[id] = true
		pi, ok := d.peers[id]
		if !ok {
			pi = &peerInfo{nodeID: id, path: magicsock.PathNone}
			d.peers[id] = pi
		}
		copy(pi.pubKey[:], p.GetNodeKey())
		pi.hostname = p.GetHostname()
		pi.online = p.GetOnline()
		pi.staticEPs = p.GetEndpoints()
		pi.allowed = pi.allowed[:0]
		pi.ipv4, pi.ipv6 = "", ""
		for _, cidr := range p.GetOverlayIps() {
			pfx, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			pi.allowed = append(pi.allowed, pfx)
			if pfx.Addr().Is4() {
				pi.ipv4 = pfx.Addr().String()
			} else {
				pi.ipv6 = pfx.Addr().String()
			}
		}
		if pi.online {
			online[id] = true
		}
	}
	for id := range d.peers {
		if !seen[id] {
			delete(d.peers, id)
		}
	}
	peerCfgs := d.buildPeerConfigsLocked()
	d.refreshPeerStatusLocked()
	d.mu.Unlock()

	if err := eng.SetPeers(peerCfgs); err != nil {
		return err
	}
	if cm != nil {
		cm.SetStunServers(stunHosts)
		cm.SetPeers(online)
	}
	log.Printf("daemon: applied netmap seq %d (%d peers)", nm.GetSeq(), len(seen))
	return nil
}

// buildPeerConfigsLocked renders engine peer configs from current state:
// magicsock's chosen endpoint wins; otherwise the first static hint.
// Held: d.mu.
func (d *Daemon) buildPeerConfigsLocked() []wgengine.PeerConfig {
	var out []wgengine.PeerConfig
	for _, pi := range d.peers {
		pc := wgengine.PeerConfig{PublicKey: pi.pubKey, AllowedIPs: append([]netip.Prefix(nil), pi.allowed...)}
		if pi.path == magicsock.PathDirect && pi.pathEP.IsValid() {
			pc.Endpoint = pi.pathEP
		} else {
			for _, e := range pi.staticEPs {
				if ap, err := netip.ParseAddrPort(e); err == nil {
					pc.Endpoint = ap
					break
				}
			}
		}
		// A peer with no endpoint at all is unreachable; programming it
		// would burn WireGuard's handshake retry timer for nothing.
		if pc.Endpoint.IsValid() {
			out = append(out, pc)
		}
	}
	return out
}

// onPathUpdate is magicsock's callback: apply the new path to WireGuard
// and to status. Runs on ConnMgr goroutines.
func (d *Daemon) onPathUpdate(u magicsock.PathUpdate) {
	d.mu.Lock()
	pi, ok := d.peers[u.NodeID]
	if !ok {
		d.mu.Unlock()
		return
	}
	pi.path = u.State
	pi.pathEP = u.Endpoint
	pi.rtt = u.RTT
	eng := d.engine
	pub := pi.pubKey
	host := pi.hostname
	d.refreshPeerStatusLocked()
	d.mu.Unlock()

	if u.State == magicsock.PathDirect && u.Endpoint.IsValid() && eng != nil {
		if err := eng.SetPeerEndpoint(pub, u.Endpoint); err != nil {
			log.Printf("daemon: move %s endpoint to %s: %v", host, u.Endpoint, err)
		} else {
			log.Printf("daemon: %s now direct via %s (rtt %v)", host, u.Endpoint, u.RTT)
		}
	}
}

// refreshPeerStatusLocked rebuilds the status peer list. Held: d.mu.
func (d *Daemon) refreshPeerStatusLocked() {
	var ps []PeerStatus
	for _, pi := range d.peers {
		s := PeerStatus{
			Hostname:  pi.hostname,
			IPv4:      pi.ipv4,
			IPv6:      pi.ipv6,
			Online:    pi.online,
			Endpoints: pi.staticEPs,
		}
		switch pi.path {
		case magicsock.PathDirect:
			s.Path = "direct"
			s.Endpoint = pi.pathEP.String()
			s.RTTms = pi.rtt.Milliseconds()
		case magicsock.PathConnecting:
			s.Path = "connecting"
		default:
			// With NAT traversal active, a failed negotiation is "none"
			// (the relay picks these up in Phase 3). Without it (kernel
			// engine), a static hint is the Phase-1 LAN path.
			if d.connmgr == nil && len(pi.staticEPs) > 0 {
				s.Path = "lan"
			} else {
				s.Path = "none"
			}
		}
		if !pi.online {
			s.Path = "none"
		}
		ps = append(ps, s)
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].Hostname < ps[j].Hostname })
	d.status.Peers = ps
}

// resolveStunServers fills empty-host entries (":3478") with the control
// plane's host.
func (d *Daemon) resolveStunServers(servers []string) []string {
	serverHost, _, err := net.SplitHostPort(d.state.Server)
	if err != nil {
		serverHost = d.state.Server
	}
	var out []string
	for _, s := range servers {
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			continue
		}
		if host == "" {
			host = serverHost
		}
		out = append(out, net.JoinHostPort(host, port))
	}
	return out
}

// --- signaling ---

// signaler sends envelopes over the current SignalStream; the stream is
// swapped on reconnect.
type signaler struct {
	mu     sync.Mutex
	stream overmeshv1.CoordinationService_SignalStreamClient
}

func (s *signaler) setStream(st overmeshv1.CoordinationService_SignalStreamClient) {
	s.mu.Lock()
	s.stream = st
	s.mu.Unlock()
}

func (s *signaler) send(env *overmeshv1.SignalEnvelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stream == nil {
		return fmt.Errorf("signal stream not connected")
	}
	return s.stream.Send(env)
}

func (s *signaler) SendOffer(to, session uint64, ufrag, pwd string) error {
	return s.send(&overmeshv1.SignalEnvelope{
		ToNodeId: to, Session: session,
		Kind:    overmeshv1.SignalKind_SIGNAL_KIND_OFFER,
		Payload: ufrag + "\n" + pwd,
	})
}

func (s *signaler) SendAnswer(to, session uint64, ufrag, pwd string) error {
	return s.send(&overmeshv1.SignalEnvelope{
		ToNodeId: to, Session: session,
		Kind:    overmeshv1.SignalKind_SIGNAL_KIND_ANSWER,
		Payload: ufrag + "\n" + pwd,
	})
}

func (s *signaler) SendCandidate(to, session uint64, candidate string) error {
	return s.send(&overmeshv1.SignalEnvelope{
		ToNodeId: to, Session: session,
		Kind:    overmeshv1.SignalKind_SIGNAL_KIND_CANDIDATE,
		Payload: candidate,
	})
}

// runSignaling keeps a SignalStream open and dispatches inbound envelopes
// to the connection manager.
func (d *Daemon) runSignaling(ctx context.Context, client overmeshv1.CoordinationServiceClient, sig *signaler, cm *magicsock.ConnMgr) {
	mkey := d.state.MachineKey().Public().Bytes()
	backoff := time.Second
	for ctx.Err() == nil {
		stream, err := client.SignalStream(ctx)
		if err == nil {
			err = stream.Send(&overmeshv1.SignalEnvelope{
				MachineKey: mkey,
				Kind:       overmeshv1.SignalKind_SIGNAL_KIND_HELLO,
			})
		}
		if err == nil {
			sig.setStream(stream)
			backoff = time.Second
			err = d.receiveSignals(stream, cm)
			sig.setStream(nil)
		}
		if ctx.Err() != nil {
			return
		}
		log.Printf("daemon: signal stream: %v (retrying in %v)", err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (d *Daemon) receiveSignals(stream overmeshv1.CoordinationService_SignalStreamClient, cm *magicsock.ConnMgr) error {
	for {
		env, err := stream.Recv()
		if err != nil {
			return err
		}
		from, session := env.GetFromNodeId(), env.GetSession()
		switch env.GetKind() {
		case overmeshv1.SignalKind_SIGNAL_KIND_OFFER:
			if ufrag, pwd, ok := splitCreds(env.GetPayload()); ok {
				cm.HandleOffer(from, session, ufrag, pwd)
			}
		case overmeshv1.SignalKind_SIGNAL_KIND_ANSWER:
			if ufrag, pwd, ok := splitCreds(env.GetPayload()); ok {
				cm.HandleAnswer(from, session, ufrag, pwd)
			}
		case overmeshv1.SignalKind_SIGNAL_KIND_CANDIDATE:
			cm.HandleCandidate(from, session, env.GetPayload())
		}
	}
}

func splitCreds(payload string) (ufrag, pwd string, ok bool) {
	parts := strings.SplitN(payload, "\n", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// watchRoaming restarts NAT traversal when the local address set changes
// (Wi-Fi to hotspot, docking, VPN up/down...).
func (d *Daemon) watchRoaming(ctx context.Context, cm *magicsock.ConnMgr) {
	last := strings.Join(localEndpoints(d.opts.ListenPort), ",")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur := strings.Join(localEndpoints(d.opts.ListenPort), ",")
			if cur != last {
				log.Printf("daemon: local addresses changed, re-punching all peers")
				last = cur
				cm.Restart()
			}
		}
	}
}

// Down tears the session and interface down.
func (d *Daemon) Down() error {
	d.mu.Lock()
	if d.cancel == nil {
		d.mu.Unlock()
		return fmt.Errorf("not up")
	}
	cancel, stopped := d.cancel, d.stopped
	d.cancel = nil
	d.mu.Unlock()

	cancel()
	<-stopped // engine + connmgr are closed by the session goroutine

	d.mu.Lock()
	d.engine = nil
	d.connmgr = nil
	d.peers = make(map[uint64]*peerInfo)
	d.state.DesiredUp = false
	_ = d.state.Save(d.opts.StateDir)
	d.status = Status{Version: version.Long()}
	d.mu.Unlock()
	return nil
}

// Status returns a snapshot for the CLI.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.status
}

func (d *Daemon) setConn(s string) {
	d.mu.Lock()
	d.status.Conn = s
	d.mu.Unlock()
}

// overlayRoutes derives the network-wide prefixes to route into the
// interface from this node's own addresses. Phase 1/2 heuristic: the
// default prefix sizes; the netmap carries explicit routes from Phase 5.
func overlayRoutes(selfV4, selfV6 netip.Prefix) []netip.Prefix {
	v4 := netip.PrefixFrom(selfV4.Addr(), 11).Masked()
	v6 := netip.PrefixFrom(selfV6.Addr(), 48).Masked()
	return []netip.Prefix{v4, v6}
}

// localEndpoints lists this host's global unicast addresses as "ip:port"
// candidates for peers on the same LAN (or with a public IP).
func localEndpoints(port uint16) []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
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
			addr, ok := netip.AddrFromSlice(ipnet.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			// Skip loopback/link-local and our own overlay range.
			if !addr.IsGlobalUnicast() || inOverlayRange(addr) {
				continue
			}
			out = append(out, netip.AddrPortFrom(addr, port).String())
		}
	}
	sort.Strings(out)
	return out
}

func inOverlayRange(a netip.Addr) bool {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	ula := netip.MustParsePrefix("fc00::/7")
	return cgnat.Contains(a) || ula.Contains(a)
}
