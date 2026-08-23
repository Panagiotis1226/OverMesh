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
	"net/url"
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
	"github.com/panagiotis1226/overmesh/internal/filter"
	"github.com/panagiotis1226/overmesh/internal/magicsock"
	"github.com/panagiotis1226/overmesh/internal/meshdns"
	"github.com/panagiotis1226/overmesh/internal/overdrop"
	"github.com/panagiotis1226/overmesh/internal/relay"
	"github.com/panagiotis1226/overmesh/internal/router"
	"github.com/panagiotis1226/overmesh/internal/version"
	"github.com/panagiotis1226/overmesh/internal/wgengine"
)

// Options configures a Daemon.
type Options struct {
	StateDir   string
	ListenPort uint16 // WireGuard UDP port
	IfaceName  string
	WGMode     string // auto|kernel|userspace
	MTU        int    // 0 = wgengine.DefaultMTU
	UseTLS     bool   // TLS to the control plane
	// OverDrop file receiving. Zero values in Overdrop* mean enabled,
	// StateDir/overdrop, DefaultPort.
	OverdropOff  bool
	OverdropDir  string
	OverdropPort uint16
}

func (o Options) overdropDir() string {
	if o.OverdropDir != "" {
		return o.OverdropDir
	}
	return o.StateDir + "/overdrop"
}

func (o Options) overdropPort() uint16 {
	if o.OverdropPort != 0 {
		return o.OverdropPort
	}
	return overdrop.DefaultPort
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
	// Routes this peer serves for the mesh (approved subnet routes).
	Routes []string `json:"routes,omitempty"`
	// OffersExit is true when the peer is an approved exit node.
	OffersExit bool `json:"offers_exit,omitempty"`
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
	Conn     string       `json:"conn,omitempty"`  // connected | reconnecting
	Relay    string       `json:"relay,omitempty"` // home relay URL when connected
	Domain   string       `json:"domain,omitempty"` // overlay DNS zone, e.g. default.mesh
	// AdvertisedRoutes: what this node offers; ApprovedRoutes: the
	// admin-approved subset it is actively serving.
	AdvertisedRoutes []string `json:"advertised_routes,omitempty"`
	ApprovedRoutes   []string `json:"approved_routes,omitempty"`
	// ExitNode is the requested exit peer; ExitNodeActive reports
	// whether its routes are currently installed.
	ExitNode       string `json:"exit_node,omitempty"`
	ExitNodeActive bool   `json:"exit_node_active,omitempty"`
	// OverdropDir is where received files land ("" = receiving off).
	OverdropDir string       `json:"overdrop_dir,omitempty"`
	Peers       []PeerStatus `json:"peers,omitempty"`
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
	// Approved routes this peer serves: subnets always go into
	// AllowedIPs + the OS table; exit (default) routes only when this
	// peer is the selected exit node.
	subnetRoutes []netip.Prefix
	exitRoutes   []netip.Prefix
}

// Daemon is the running node agent.
type Daemon struct {
	opts  Options
	state *State

	mu        sync.Mutex
	cancel    context.CancelFunc // stops the session goroutine
	engine    wgengine.Engine
	connmgr   *magicsock.ConnMgr
	bind      *magicsock.Bind
	relayCli  *relay.Client
	dnsSrv    *meshdns.Server
	dnsOSDone bool
	selfV4    netip.Addr
	kernWarn  bool
	speedHint bool // logged the kernel-WG throughput tip once
	peers     map[uint64]*peerInfo
	status    Status
	stopped   chan struct{} // closed when the session goroutine exits

	// Phase 5 routing state.
	adv        *router.Advertiser // forwarding+NAT when we are a router
	exitCli    *router.ExitClient // policy routing when we USE an exit
	routeSync  *router.RouteSync  // OS routes for peers' subnet routes
	exitNode   string             // desired exit peer hostname ("" = none)
	exitPeerID uint64             // peer currently serving as our exit (0 = none)

	// Phase 6: OverDrop receiver.
	dropSrv *overdrop.Server
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
		if err := d.Up(UpConfig{
			Server:          d.state.Server,
			AdvertiseRoutes: d.state.AdvertiseRoutes,
			ExitNode:        d.state.ExitNode,
		}); err != nil {
			log.Printf("daemon: auto-up failed: %v", err)
		}
	}
}

func (d *Daemon) dial(server string) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	if d.opts.UseTLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	// The daemon's own control traffic carries the socket mark so it
	// bypasses exit-node policy routing (no loops through the tunnel).
	markedDialer := &net.Dialer{Control: router.MarkControl}
	return grpc.NewClient(server,
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return markedDialer.DialContext(ctx, "tcp", addr)
		}),
		// Detect dead connections: after roaming (new local address)
		// the old TCP conn silently blackholes, and without keepalives
		// the netmap/signal streams would hang for minutes. The timeout
		// must tolerate a busy peer, though — an overloaded machine
		// that answers late is not a dead path, and tearing the streams
		// down mid-ICE costs a full retry cycle.
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                15 * time.Second,
			Timeout:             15 * time.Second,
			PermitWithoutStream: true,
		}),
	)
}

// UpConfig is everything `overmesh up` can ask for.
type UpConfig struct {
	Server   string
	SetupKey string // empty when already enrolled
	// AdvertiseRoutes: CIDRs to offer as a router (0.0.0.0/0 + ::/0 =
	// exit node); admin approval in the web UI activates them.
	AdvertiseRoutes []string
	// ExitNode: hostname of the peer to send all traffic through.
	ExitNode string
}

// Up joins (or rejoins) the mesh: register, bring up WireGuard +
// magicsock, stream netmaps and signals.
func (d *Daemon) Up(cfg UpConfig) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cancel != nil {
		return fmt.Errorf("already up (overmesh down first)")
	}
	if cfg.ExitNode != "" && runtime.GOOS != "linux" {
		return fmt.Errorf("using an exit node is only supported on Linux for now")
	}
	server := cfg.Server

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
		MachineKey:       d.state.MachineKey().Public().Bytes(),
		NodeKey:          d.state.NodeKey().Public().Bytes(),
		SetupKey:         cfg.SetupKey,
		Hostname:         hostname,
		Os:               runtime.GOOS,
		ClientVersion:    version.Long(),
		AdvertisedRoutes: cfg.AdvertiseRoutes,
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
	d.state.AdvertiseRoutes = cfg.AdvertiseRoutes
	d.state.ExitNode = cfg.ExitNode
	if err := d.state.Save(d.opts.StateDir); err != nil {
		conn.Close()
		return err
	}

	d.peers = make(map[uint64]*peerInfo)
	d.selfV4 = selfV4.Addr()
	d.exitNode = cfg.ExitNode
	d.exitPeerID = 0
	d.status = Status{
		Version:          version.Long(),
		Running:          true,
		Server:           server,
		Network:          resp.GetNetworkId(),
		Hostname:         resp.GetHostname(),
		IPv4:             selfV4.Addr().String(),
		IPv6:             selfV6.Addr().String(),
		Conn:             "connecting",
		AdvertisedRoutes: cfg.AdvertiseRoutes,
		ExitNode:         cfg.ExitNode,
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
		MTU:        d.opts.MTU,
		Logf:       log.Printf,
	}
	if d.opts.WGMode != "kernel" {
		bind = magicsock.NewBind(log.Printf)
		// Mark WireGuard's socket so its packets bypass exit-node
		// policy routing.
		bind.SetSocketControl(router.MarkControl)
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
	d.bind = bind
	d.adv = router.NewAdvertiser(log.Printf)
	d.exitCli = router.NewExitClient(log.Printf)
	d.routeSync = router.NewRouteSync(log.Printf)
	d.status.Iface = eng.IfName()
	d.status.Engine = eng.Kind()
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		rc := d.relayCli
		ds := d.dnsSrv
		osDone := d.dnsOSDone
		adv, ec, rs := d.adv, d.exitCli, d.routeSync
		drop := d.dropSrv
		d.relayCli, d.dnsSrv, d.dnsOSDone = nil, nil, false
		d.adv, d.exitCli, d.routeSync = nil, nil, nil
		d.dropSrv = nil
		d.exitPeerID = 0
		d.mu.Unlock()
		if drop != nil {
			drop.Close()
		}
		if rc != nil {
			rc.Close()
		}
		if ds != nil {
			ds.Close()
		}
		if osDone {
			meshdns.DeconfigureOS(eng.IfName(), log.Printf)
		}
		if ec != nil {
			ec.Remove()
		}
		if rs != nil {
			rs.Close()
		}
		if adv != nil {
			adv.Close()
		}
	}()

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
	if cm != nil {
		d.ensureRelay(d.resolveRelayURLs(nm.GetRelays()))
	}

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
		pi.subnetRoutes, pi.exitRoutes = pi.subnetRoutes[:0], pi.exitRoutes[:0]
		for _, cidr := range p.GetAllowedRoutes() {
			pfx, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			if pfx.Bits() == 0 {
				pi.exitRoutes = append(pi.exitRoutes, pfx)
			} else {
				pi.subnetRoutes = append(pi.subnetRoutes, pfx)
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
	d.selectExitPeerLocked()
	peerCfgs := d.buildPeerConfigsLocked()
	d.refreshPeerStatusLocked()
	d.mu.Unlock()

	if err := eng.SetPeers(peerCfgs); err != nil {
		return err
	}
	d.applyFilter(nm, eng)
	d.applyDNS(nm, eng)
	d.applyRoutes(nm, eng)
	d.applyOverdrop()
	if cm != nil {
		cm.SetStunServers(stunHosts)
		cm.SetPeers(online)
	}
	log.Printf("daemon: applied netmap seq %d (%d peers)", nm.GetSeq(), len(seen))
	return nil
}

// applyFilter installs the netmap's compiled access rules.
func (d *Daemon) applyFilter(nm *overmeshv1.NetMap, eng wgengine.Engine) {
	eng.SetFilter(filter.FromProto(nm.GetFilter(), nm.GetFilterEnabled()))
	if nm.GetFilterEnabled() && eng.Kind() == "kernel" {
		d.mu.Lock()
		warned := d.kernWarn
		d.kernWarn = true
		d.mu.Unlock()
		if !warned {
			log.Print("daemon: WARNING network has access rules but the kernel engine cannot enforce them; use -wg-mode auto for enforcement")
		}
	}
}

// applyDNS runs the overlay resolver and keeps its records in sync with
// the netmap; the zone is installed as an OS search domain so bare
// hostnames work ("ping ps-iphone").
func (d *Daemon) applyDNS(nm *overmeshv1.NetMap, eng wgengine.Engine) {
	domain := nm.GetDns().GetDomain()
	if domain == "" {
		return
	}

	records := map[string][]netip.Addr{}
	add := func(name string, ips []string) {
		var addrs []netip.Addr
		for _, s := range ips {
			if p, err := netip.ParsePrefix(s); err == nil {
				addrs = append(addrs, p.Addr())
			} else if a, err := netip.ParseAddr(s); err == nil {
				addrs = append(addrs, a)
			}
		}
		if name != "" && len(addrs) > 0 {
			records[name] = addrs
		}
	}
	add(nm.GetSelf().GetHostname(), nm.GetSelf().GetOverlayIps())
	for _, p := range nm.GetPeers() {
		add(p.GetHostname(), p.GetOverlayIps())
	}

	d.mu.Lock()
	srv := d.dnsSrv
	selfV4 := d.selfV4
	needStart := srv == nil && selfV4.IsValid()
	if needStart {
		srv = meshdns.NewServer(log.Printf)
		d.dnsSrv = srv
	}
	d.status.Domain = domain
	d.mu.Unlock()

	srv.SetRecords(domain, records)
	if needStart {
		if err := srv.Start(selfV4); err != nil {
			log.Printf("daemon: overlay DNS: %v", err)
			return
		}
		if err := meshdns.ConfigureOS(eng.IfName(), domain, selfV4, log.Printf); err != nil {
			log.Printf("daemon: OS DNS config: %v (names still resolve as <host>.%s via the resolver)", err, domain)
		} else {
			d.mu.Lock()
			d.dnsOSDone = true
			d.mu.Unlock()
		}
	}
}

// selectExitPeerLocked resolves the desired exit-node hostname against
// the current peer set. Held: d.mu.
func (d *Daemon) selectExitPeerLocked() {
	d.exitPeerID = 0
	if d.exitNode == "" {
		return
	}
	for _, pi := range d.peers {
		if strings.EqualFold(pi.hostname, d.exitNode) && len(pi.exitRoutes) > 0 {
			d.exitPeerID = pi.nodeID
			return
		}
	}
}

// applyRoutes programs the OS around the netmap's route information:
// forwarding+NAT when this node is an approved router, OS routes for
// peers' subnet routes, and exit-node policy routing when selected.
func (d *Daemon) applyRoutes(nm *overmeshv1.NetMap, eng wgengine.Engine) {
	var approved []netip.Prefix
	for _, cidr := range nm.GetSelf().GetApprovedRoutes() {
		if pfx, err := netip.ParsePrefix(cidr); err == nil {
			approved = append(approved, pfx)
		}
	}

	d.mu.Lock()
	adv, ec, rs := d.adv, d.exitCli, d.routeSync
	exitID := d.exitPeerID
	exitWanted := d.exitNode
	var subnets []netip.Prefix
	var exitV6 bool
	for _, pi := range d.peers {
		subnets = append(subnets, pi.subnetRoutes...)
		if pi.nodeID == exitID {
			for _, r := range pi.exitRoutes {
				if r.Addr().Is6() {
					exitV6 = true
				}
			}
		}
	}
	var approvedStr []string
	for _, p := range approved {
		approvedStr = append(approvedStr, p.String())
	}
	d.status.ApprovedRoutes = approvedStr
	d.status.ExitNodeActive = exitID != 0
	d.mu.Unlock()

	if adv != nil {
		if err := adv.Apply(eng.IfName(), approved); err != nil {
			log.Printf("daemon: router config: %v", err)
		}
	}
	if len(approved) > 0 && eng.Kind() == "userspace" && runtime.GOOS == "linux" {
		d.mu.Lock()
		hinted := d.speedHint
		d.speedHint = true
		d.mu.Unlock()
		if !hinted {
			log.Print("daemon: tip: for maximum router/exit-node throughput on a server with a static endpoint, restart with -wg-mode kernel (kernel WireGuard)")
		}
	}
	if rs != nil {
		rs.Sync(eng.IfName(), subnets)
	}
	if ec != nil {
		switch {
		case exitID != 0:
			if err := ec.Apply(eng.IfName(), exitV6); err != nil {
				log.Printf("daemon: exit-node routing: %v", err)
			}
		default:
			ec.Remove()
			if exitWanted != "" {
				log.Printf("daemon: exit node %q not available (offline, unknown, or not an approved exit node)", exitWanted)
			}
		}
	}
}

// SetExitNode switches the exit node at runtime ("" turns it off).
func (d *Daemon) SetExitNode(name string) error {
	if name != "" && runtime.GOOS != "linux" {
		return fmt.Errorf("using an exit node is only supported on Linux for now")
	}
	d.mu.Lock()
	if d.cancel == nil {
		d.mu.Unlock()
		return fmt.Errorf("not up")
	}
	d.exitNode = name
	d.state.ExitNode = name
	_ = d.state.Save(d.opts.StateDir)
	d.status.ExitNode = name
	d.selectExitPeerLocked()
	found := d.exitPeerID != 0
	eng := d.engine
	ec := d.exitCli
	exitID := d.exitPeerID
	var exitV6 bool
	if pi, ok := d.peers[exitID]; ok {
		for _, r := range pi.exitRoutes {
			if r.Addr().Is6() {
				exitV6 = true
			}
		}
	}
	d.status.ExitNodeActive = found
	cfgs := d.buildPeerConfigsLocked()
	d.refreshPeerStatusLocked()
	d.mu.Unlock()

	if name != "" && !found {
		return fmt.Errorf("no approved exit node named %q in the netmap (approve its exit route in the web UI first)", name)
	}
	if eng != nil {
		if err := eng.SetPeers(cfgs); err != nil {
			return err
		}
	}
	if ec != nil {
		if found {
			if err := ec.Apply(eng.IfName(), exitV6); err != nil {
				return err
			}
		} else {
			ec.Remove()
		}
	}
	return nil
}

// applyOverdrop starts the file receiver once the overlay is up. The
// sender of every transfer is identified by its overlay source address,
// which WireGuard's cryptokey routing binds to exactly one peer.
func (d *Daemon) applyOverdrop() {
	if d.opts.OverdropOff {
		return
	}
	d.mu.Lock()
	if d.dropSrv != nil || !d.selfV4.IsValid() {
		d.mu.Unlock()
		return
	}
	srv := overdrop.NewServer(d.opts.overdropDir(), d.peerNameByAddr, log.Printf)
	d.dropSrv = srv
	selfV4 := d.selfV4
	d.mu.Unlock()

	if err := srv.Start(selfV4, d.opts.overdropPort()); err != nil {
		log.Printf("daemon: overdrop: %v", err)
		d.mu.Lock()
		d.dropSrv = nil
		d.mu.Unlock()
		return
	}
	d.mu.Lock()
	d.status.OverdropDir = d.opts.overdropDir()
	d.mu.Unlock()
}

// peerNameByAddr resolves an overlay address to the peer's hostname
// ("" = not a known peer; the transfer is rejected).
func (d *Daemon) peerNameByAddr(addr netip.Addr) string {
	s := addr.String()
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, pi := range d.peers {
		if pi.ipv4 == s || pi.ipv6 == s {
			return pi.hostname
		}
	}
	return ""
}

// InboxDir returns the OverDrop inbox path ("" when receiving is off).
func (d *Daemon) InboxDir() string {
	if d.opts.OverdropOff {
		return ""
	}
	return d.opts.overdropDir()
}

// buildPeerConfigsLocked renders engine peer configs from current state,
// applying the path ladder: ICE direct > relay > static LAN hint.
// Held: d.mu.
func (d *Daemon) buildPeerConfigsLocked() []wgengine.PeerConfig {
	relayUp := d.relayCli != nil && d.relayCli.Connected()
	var out []wgengine.PeerConfig
	for _, pi := range d.peers {
		pc := wgengine.PeerConfig{PublicKey: pi.pubKey, AllowedIPs: append([]netip.Prefix(nil), pi.allowed...)}
		pc.AllowedIPs = append(pc.AllowedIPs, pi.subnetRoutes...)
		if pi.nodeID == d.exitPeerID {
			pc.AllowedIPs = append(pc.AllowedIPs, pi.exitRoutes...)
		}
		switch {
		case pi.path == magicsock.PathDirect && pi.pathEP.IsValid():
			pc.Endpoint = pi.pathEP
		case relayUp && pi.online:
			// Guaranteed fallback: the relay carries traffic instantly
			// while (and whenever) no direct path exists.
			pc.RelayEndpoint = magicsock.RelayEndpointString(pi.pubKey)
		default:
			for _, e := range pi.staticEPs {
				if ap, err := netip.ParseAddrPort(e); err == nil {
					pc.Endpoint = ap
					break
				}
			}
		}
		// A peer with no endpoint at all is unreachable; programming it
		// would burn WireGuard's handshake retry timer for nothing.
		if pc.Endpoint.IsValid() || pc.RelayEndpoint != "" {
			out = append(out, pc)
		}
	}
	return out
}

// resolveRelayURLs fills empty-host relay URLs with the control plane's
// host (same convention as STUN entries).
func (d *Daemon) resolveRelayURLs(relays []string) []string {
	serverHost, _, err := net.SplitHostPort(d.state.Server)
	if err != nil {
		serverHost = d.state.Server
	}
	var out []string
	for _, r := range relays {
		u, err := url.Parse(r)
		if err != nil {
			continue
		}
		if u.Hostname() == "" {
			if p := u.Port(); p != "" {
				u.Host = net.JoinHostPort(serverHost, p)
			} else {
				u.Host = serverHost
			}
		}
		out = append(out, u.String())
	}
	return out
}

// ensureRelay keeps one client connected to the home relay (first URL).
func (d *Daemon) ensureRelay(urls []string) {
	d.mu.Lock()
	cur := d.relayCli
	bind := d.bind
	d.mu.Unlock()
	if bind == nil {
		return
	}

	if len(urls) == 0 {
		if cur != nil {
			log.Print("daemon: relay removed from netmap, disconnecting")
			bind.SetRelaySender(nil)
			cur.Close()
			d.mu.Lock()
			d.relayCli = nil
			d.mu.Unlock()
			d.syncPeers()
		}
		return
	}
	home := urls[0]
	if cur != nil && cur.URL() == home {
		return
	}
	if cur != nil {
		cur.Close()
	}

	var pub [32]byte
	copy(pub[:], d.state.NodeKey().Public().Bytes())
	cli := relay.NewClient(home, d.state.NodeKey().Raw(), pub,
		bind.DeliverRelayPacket, log.Printf, router.MarkControl)
	bind.SetRelaySender(cli.Send)
	d.mu.Lock()
	d.relayCli = cli
	d.mu.Unlock()
	log.Printf("daemon: home relay %s", home)

	// Re-sync peers once the relay link comes up so relay endpoints get
	// programmed promptly (and again if it later reconnects).
	go func() {
		for i := 0; i < 100; i++ {
			d.mu.Lock()
			stillCurrent := d.relayCli == cli
			d.mu.Unlock()
			if !stillCurrent {
				return
			}
			if cli.Connected() {
				d.syncPeers()
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
}

// syncPeers recomputes and applies engine peer configs plus status.
func (d *Daemon) syncPeers() {
	d.mu.Lock()
	eng := d.engine
	var cfgs []wgengine.PeerConfig
	if eng != nil {
		cfgs = d.buildPeerConfigsLocked()
		d.refreshPeerStatusLocked()
	}
	d.mu.Unlock()
	if eng != nil {
		if err := eng.SetPeers(cfgs); err != nil {
			log.Printf("daemon: sync peers: %v", err)
		}
	}
}

// onPathUpdate is magicsock's callback: record the peer's new path and
// re-apply the full path ladder (direct > relay > static) to WireGuard.
// Runs on ConnMgr goroutines.
func (d *Daemon) onPathUpdate(u magicsock.PathUpdate) {
	d.mu.Lock()
	pi, ok := d.peers[u.NodeID]
	if !ok {
		d.mu.Unlock()
		return
	}
	changed := pi.path != u.State || pi.pathEP != u.Endpoint
	pi.path = u.State
	pi.pathEP = u.Endpoint
	pi.rtt = u.RTT
	host := pi.hostname
	d.mu.Unlock()

	if !changed {
		return
	}
	switch u.State {
	case magicsock.PathDirect:
		log.Printf("daemon: %s now direct via %s (rtt %v)", host, u.Endpoint, u.RTT)
	case magicsock.PathNone:
		log.Printf("daemon: %s lost its direct path, falling back", host)
	}
	d.syncPeers()
}

// refreshPeerStatusLocked rebuilds the status peer list. Held: d.mu.
func (d *Daemon) refreshPeerStatusLocked() {
	relayUp := d.relayCli != nil && d.relayCli.Connected()
	if relayUp {
		d.status.Relay = d.relayCli.URL()
	} else {
		d.status.Relay = ""
	}
	var ps []PeerStatus
	for _, pi := range d.peers {
		s := PeerStatus{
			Hostname:   pi.hostname,
			IPv4:       pi.ipv4,
			IPv6:       pi.ipv6,
			Online:     pi.online,
			Endpoints:  pi.staticEPs,
			OffersExit: len(pi.exitRoutes) > 0,
		}
		for _, r := range pi.subnetRoutes {
			s.Routes = append(s.Routes, r.String())
		}
		switch {
		case pi.path == magicsock.PathDirect:
			s.Path = "direct"
			s.Endpoint = pi.pathEP.String()
			s.RTTms = pi.rtt.Milliseconds()
		case relayUp && pi.online:
			// Connectivity via relay right now; "connecting" only shows
			// when there is no relay to lean on.
			s.Path = "relay"
		case pi.path == magicsock.PathConnecting:
			s.Path = "connecting"
		default:
			// Without NAT traversal (kernel engine), a static hint is
			// the Phase-1 LAN path.
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
