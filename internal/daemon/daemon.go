// Package daemon is overmeshd's core: it registers with the control
// plane, keeps a netmap stream open, and programs the WireGuard engine to
// match. The CLI drives it through the unix-socket control API in
// control.go.
package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/version"
	"github.com/panagiotis1226/overmesh/internal/wgengine"
)

// Options configures a Daemon.
type Options struct {
	StateDir   string
	ListenPort uint16 // WireGuard UDP port
	IfaceName  string
	WGMode     string // auto|kernel|userspace
}

// PeerStatus is one peer as shown by `overmesh status`.
type PeerStatus struct {
	Hostname  string   `json:"hostname"`
	IPv4      string   `json:"ipv4"`
	IPv6      string   `json:"ipv6"`
	Online    bool     `json:"online"`
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

// Daemon is the running node agent.
type Daemon struct {
	opts  Options
	state *State

	mu      sync.Mutex
	cancel  context.CancelFunc // stops the session goroutine
	engine  wgengine.Engine
	status  Status
	stopped chan struct{} // closed when the session goroutine exits
}

// New loads state and returns a Daemon (not yet connected).
func New(opts Options) (*Daemon, error) {
	st, err := LoadOrCreateState(opts.StateDir)
	if err != nil {
		return nil, err
	}
	d := &Daemon{opts: opts, state: st}
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

// Up joins (or rejoins) the mesh: register, bring up WireGuard, stream
// netmaps. setupKey may be empty when the machine is already enrolled.
func (d *Daemon) Up(server, setupKey string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cancel != nil {
		return fmt.Errorf("already up (overmesh down first)")
	}

	// Register synchronously so the caller gets a real error for a bad
	// key/server; everything after that runs in the background session.
	conn, err := grpc.NewClient(server, grpc.WithTransportCredentials(insecure.NewCredentials()))
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

	log.Printf("daemon: registered as %q in network %q: %s %s",
		resp.GetHostname(), resp.GetNetworkId(), selfV4, selfV6)

	d.state.Server = server
	d.state.DesiredUp = true
	if err := d.state.Save(d.opts.StateDir); err != nil {
		conn.Close()
		return err
	}

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
	go d.session(sctx, conn, client, selfV4, selfV6)
	return nil
}

// session owns the gRPC connection, the engine, and the reconnect loop.
func (d *Daemon) session(ctx context.Context, conn *grpc.ClientConn, client overmeshv1.CoordinationServiceClient, selfV4, selfV6 netip.Prefix) {
	defer close(d.stopped)
	defer conn.Close()

	// Bring up WireGuard once; peers are synced per netmap.
	eng, err := wgengine.New(wgengine.Options{
		IfaceName:  d.opts.IfaceName,
		PrivateKey: d.state.NodeKey().Raw(),
		ListenPort: d.opts.ListenPort,
		Addresses:  []netip.Prefix{selfV4, selfV6},
		Routes:     overlayRoutes(selfV4, selfV6),
		Mode:       d.opts.WGMode,
		Logf:       log.Printf,
	})
	if err != nil {
		log.Printf("daemon: engine: %v", err)
		d.setConn("error: " + err.Error())
		return
	}
	defer eng.Close()
	d.mu.Lock()
	d.engine = eng
	d.status.Iface = eng.IfName()
	d.status.Engine = eng.Kind()
	d.mu.Unlock()

	backoff := time.Second
	for ctx.Err() == nil {
		if err := d.runStream(ctx, client, eng); err != nil && ctx.Err() == nil {
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

// runStream reports endpoints, opens the netmap stream, and applies maps
// until the stream breaks.
func (d *Daemon) runStream(ctx context.Context, client overmeshv1.CoordinationServiceClient, eng wgengine.Engine) error {
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
		if err := d.applyNetMap(nm, eng); err != nil {
			log.Printf("daemon: apply netmap seq %d: %v", nm.GetSeq(), err)
		}
	}
}

// applyNetMap turns a netmap into engine peer config + status.
func (d *Daemon) applyNetMap(nm *overmeshv1.NetMap, eng wgengine.Engine) error {
	var peers []wgengine.PeerConfig
	var pstats []PeerStatus
	for _, p := range nm.GetPeers() {
		if len(p.GetNodeKey()) != 32 {
			continue
		}
		pc := wgengine.PeerConfig{}
		copy(pc.PublicKey[:], p.GetNodeKey())

		ps := PeerStatus{Hostname: p.GetHostname(), Online: p.GetOnline(), Endpoints: p.GetEndpoints()}
		for _, cidr := range p.GetOverlayIps() {
			pfx, err := netip.ParsePrefix(cidr)
			if err != nil {
				continue
			}
			pc.AllowedIPs = append(pc.AllowedIPs, pfx)
			if pfx.Addr().Is4() {
				ps.IPv4 = pfx.Addr().String()
			} else {
				ps.IPv6 = pfx.Addr().String()
			}
		}
		// Phase 1 path selection: first parseable endpoint wins. Phase 2
		// replaces this with real probing and holepunching.
		for _, e := range p.GetEndpoints() {
			if ap, err := netip.ParseAddrPort(e); err == nil {
				pc.Endpoint = ap
				break
			}
		}
		// A peer with no endpoint is unreachable in Phase 1; programming
		// it anyway makes WireGuard burn a handshake attempt (and its 5s
		// retry timer) the moment the keepalive fires. Leave it out until
		// a netmap brings an endpoint.
		if pc.Endpoint.IsValid() {
			peers = append(peers, pc)
		}
		pstats = append(pstats, ps)
	}
	sort.Slice(pstats, func(i, j int) bool { return pstats[i].Hostname < pstats[j].Hostname })

	if err := eng.SetPeers(peers); err != nil {
		return err
	}
	d.mu.Lock()
	d.status.Peers = pstats
	d.mu.Unlock()
	log.Printf("daemon: applied netmap seq %d (%d peers)", nm.GetSeq(), len(peers))
	return nil
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
	<-stopped // engine is closed by the session goroutine

	d.mu.Lock()
	d.engine = nil
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
// interface from this node's own addresses. Phase 1 heuristic: route the
// default prefixes; the netmap carries explicit routes from Phase 5 on.
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
