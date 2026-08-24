// Package mobilecore is OverMesh's embeddable engine for mobile apps,
// designed for gomobile bind (iOS packet-tunnel extensions and, later,
// Android VpnService). The platform app owns the tunnel interface —
// it hands this core an open tunnel file descriptor and programs
// addresses/routes/DNS from the OnNetMap callback; the core runs
// everything else: registration, netmap + signal streams, NAT
// holepunching (magicsock), the guaranteed relay fallback, the inbound
// packet filter (ACLs), the overlay DNS resolver, and OverDrop
// receiving.
//
// The exported surface sticks to gomobile-bindable types: strings
// (JSON for anything structured), ints, bools, and small interfaces.
package mobilecore

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/netip"
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
	"github.com/panagiotis1226/overmesh/internal/meshdns"
	"github.com/panagiotis1226/overmesh/internal/overdrop"
	"github.com/panagiotis1226/overmesh/internal/relay"
	"github.com/panagiotis1226/overmesh/internal/version"
	"github.com/panagiotis1226/overmesh/internal/wgengine"
)

// Events is implemented by the platform app (Swift/Kotlin via
// gomobile) to receive state changes and network configuration.
type Events interface {
	// OnState reports lifecycle transitions: "registering",
	// "connecting", "connected", "reconnecting", "stopped".
	OnState(state string)
	// OnNetMap delivers the tunnel configuration the PLATFORM must
	// program (NEPacketTunnelNetworkSettings / VpnService.Builder):
	//   {"ipv4":"100.96.0.7","ipv4_prefix":11,
	//    "ipv6":"fdab:...","ipv6_prefix":48,
	//    "routes":["100.96.0.0/11","fdab:3f19::/48","10.0.0.0/24"],
	//    "dns_server":"100.96.0.7","dns_domain":"default.mesh",
	//    "mtu":1280}
	// Called on the first netmap and whenever routes change. After
	// applying the settings, the app MUST call
	// Core.NetworkSettingsApplied() so in-tunnel services (overlay
	// DNS, OverDrop) can bind to the tunnel address.
	OnNetMap(netmapJSON string)
}

// Config is the JSON accepted by Start.
type config struct {
	Server   string `json:"server"`    // control plane host:port (gRPC)
	SetupKey string `json:"setup_key"` // empty when already enrolled
	Hostname string `json:"hostname"`  // device name, e.g. "ps-iphone"
	TLS      bool   `json:"tls"`
}

// Core is one OverMesh node embedded in a mobile app.
type Core struct {
	stateDir string

	mu         sync.Mutex
	st         *state
	cancel     context.CancelFunc
	stopped    chan struct{}
	events     Events
	engine     wgengine.Engine
	bind       *magicsock.Bind
	connmgr    *magicsock.ConnMgr
	relayCli   *relay.Client
	dnsSrv     *meshdns.Server
	dnsStarted bool
	dropSrv    *overdrop.Server
	server     string
	selfV4     netip.Prefix
	selfV6     netip.Prefix
	selfID     uint64
	hostname   string
	network    string
	domain     string
	conn       string // connecting|connected|reconnecting
	peers      map[uint64]*peerInfo
	lastRelays []string
	lastNetMap string // last JSON handed to OnNetMap (dedupe)
	inTunnelUp bool   // NetworkSettingsApplied received
	foreground bool
}

type peerInfo struct {
	nodeID       uint64
	hostname     string
	pubKey       [32]byte
	allowed      []netip.Prefix
	subnetRoutes []netip.Prefix
	ipv4, ipv6   string
	online       bool
	staticEPs    []string
	path         magicsock.PathState
	pathEP       netip.AddrPort
	rtt          time.Duration
}

// NewCore loads (or creates) the device identity under stateDir — use
// the app's private data directory; the keys inside are the device's
// permanent identity.
func NewCore(stateDir string) (*Core, error) {
	st, err := loadOrCreateState(stateDir)
	if err != nil {
		return nil, err
	}
	return &Core{stateDir: stateDir, st: st, peers: make(map[uint64]*peerInfo)}, nil
}

// Start joins the mesh over the platform-provided tunnel fd. cfgJSON
// fields: server, setup_key, hostname, tls.
func (c *Core) Start(cfgJSON string, tunFD int, ev Events) error {
	var cfg config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return fmt.Errorf("bad config: %w", err)
	}
	if cfg.Server == "" {
		return fmt.Errorf("config needs \"server\"")
	}
	if tunFD <= 0 {
		return fmt.Errorf("tunFD must be an open tunnel descriptor")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		return fmt.Errorf("already started")
	}
	c.events = ev
	c.server = cfg.Server
	c.conn = "connecting"
	c.peers = make(map[uint64]*peerInfo)
	c.lastNetMap = ""
	c.inTunnelUp = false

	c.emit("registering")
	conn, err := c.dial(cfg.Server, cfg.TLS)
	if err != nil {
		return fmt.Errorf("dial %s: %w", cfg.Server, err)
	}
	client := overmeshv1.NewCoordinationServiceClient(conn)

	hostname := cfg.Hostname
	if hostname == "" {
		hostname = "mobile"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	resp, err := client.RegisterNode(ctx, &overmeshv1.RegisterNodeRequest{
		MachineKey:    c.st.machine.Public().Bytes(),
		NodeKey:       c.st.node.Public().Bytes(),
		SetupKey:      cfg.SetupKey,
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
		return fmt.Errorf("bad overlay ipv4: %w", err)
	}
	selfV6, err := netip.ParsePrefix(resp.GetOverlayIpv6())
	if err != nil {
		conn.Close()
		return fmt.Errorf("bad overlay ipv6: %w", err)
	}
	c.selfV4, c.selfV6 = selfV4, selfV6
	c.selfID = resp.GetNodeId()
	c.hostname = resp.GetHostname()
	c.network = resp.GetNetworkId()

	// Data plane over the platform's tunnel fd.
	bind := magicsock.NewBind(logf)
	eng, err := wgengine.New(wgengine.Options{
		PrivateKey: c.st.node.Raw(),
		Addresses:  []netip.Prefix{selfV4, selfV6},
		Mode:       "userspace",
		TUNFD:      tunFD,
		Bind:       bind,
		Logf:       logf,
	})
	if err != nil {
		conn.Close()
		return fmt.Errorf("engine: %w", err)
	}
	c.engine = eng
	c.bind = bind

	sig := &signaler{}
	c.connmgr = magicsock.NewConnMgr(c.selfID, bind, sig, c.onPathUpdate, logf)

	sctx, scancel := context.WithCancel(context.Background())
	c.cancel = scancel
	c.stopped = make(chan struct{})
	go c.session(sctx, conn, client, sig)
	return nil
}

// Stop leaves the mesh and releases everything except the identity.
func (c *Core) Stop() {
	c.mu.Lock()
	cancel, stopped := c.cancel, c.stopped
	c.cancel = nil
	c.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-stopped

	c.mu.Lock()
	eng, cm := c.engine, c.connmgr
	rc, ds, drop := c.relayCli, c.dnsSrv, c.dropSrv
	c.engine, c.connmgr, c.relayCli, c.dnsSrv, c.dropSrv = nil, nil, nil, nil, nil
	c.conn = ""
	c.peers = make(map[uint64]*peerInfo)
	ev := c.events
	c.mu.Unlock()

	if cm != nil {
		cm.Close()
	}
	if rc != nil {
		rc.Close()
	}
	if ds != nil {
		ds.Close()
	}
	if drop != nil {
		drop.Close()
	}
	if eng != nil {
		_ = eng.Close()
	}
	if ev != nil {
		ev.OnState("stopped")
	}
}

// NetworkSettingsApplied tells the core the platform finished
// programming the tunnel (addresses/routes/DNS are live), so services
// that bind to the tunnel address (overlay DNS, OverDrop) can start.
func (c *Core) NetworkSettingsApplied() {
	c.mu.Lock()
	if c.inTunnelUp || !c.selfV4.IsValid() {
		c.mu.Unlock()
		return
	}
	c.inTunnelUp = true
	c.mu.Unlock()
	c.startInTunnelServices()
}

// SetForeground hints the app state; in the background WireGuard's
// keepalives already carry the tunnel, and the netmap stream is push
// based (no polling), so this is currently informational.
func (c *Core) SetForeground(fg bool) {
	c.mu.Lock()
	c.foreground = fg
	c.mu.Unlock()
}

// Hostname returns the control-plane-assigned device name.
func (c *Core) Hostname() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hostname
}

func (c *Core) emit(state string) {
	if c.events != nil {
		go c.events.OnState(state)
	}
}

func (c *Core) dial(server string, useTLS bool) (*grpc.ClientConn, error) {
	creds := insecure.NewCredentials()
	if useTLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	return grpc.NewClient(server,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                15 * time.Second,
			Timeout:             15 * time.Second,
			PermitWithoutStream: true,
		}),
	)
}

func logf(format string, args ...any) {
	// gomobile surfaces stderr in the Xcode/logcat console.
	fmt.Printf("overmesh: "+format+"\n", args...)
}

// --- status ---

type peerStatusJSON struct {
	Hostname string `json:"hostname"`
	IPv4     string `json:"ipv4"`
	IPv6     string `json:"ipv6"`
	Online   bool   `json:"online"`
	Path     string `json:"path"`
	RTTms    int64  `json:"rtt_ms,omitempty"`
}

// StatusJSON is a snapshot for the app UI.
func (c *Core) StatusJSON() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	relayUp := c.relayCli != nil && c.relayCli.Connected()
	peers := make([]peerStatusJSON, 0, len(c.peers))
	for _, pi := range c.peers {
		p := peerStatusJSON{
			Hostname: pi.hostname, IPv4: pi.ipv4, IPv6: pi.ipv6, Online: pi.online,
		}
		switch {
		case pi.path == magicsock.PathDirect:
			p.Path = "direct"
			p.RTTms = pi.rtt.Milliseconds()
		case relayUp && pi.online:
			p.Path = "relay"
		case pi.path == magicsock.PathConnecting:
			p.Path = "connecting"
		default:
			p.Path = "none"
		}
		if !pi.online {
			p.Path = "none"
		}
		peers = append(peers, p)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Hostname < peers[j].Hostname })
	out := map[string]any{
		"running":  c.cancel != nil,
		"hostname": c.hostname,
		"network":  c.network,
		"conn":     c.conn,
		"domain":   c.domain,
		"peers":    peers,
	}
	if c.selfV4.IsValid() {
		out["ipv4"] = c.selfV4.Addr().String()
		out["ipv6"] = c.selfV6.Addr().String()
	}
	if relayUp {
		out["relay"] = c.relayCli.URL()
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// splitCreds splits "ufrag\npwd" signal payloads.
func splitCreds(payload string) (ufrag, pwd string, ok bool) {
	parts := strings.SplitN(payload, "\n", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
