package mobilecore

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/filter"
	"github.com/panagiotis1226/overmesh/internal/magicsock"
	"github.com/panagiotis1226/overmesh/internal/meshdns"
	"github.com/panagiotis1226/overmesh/internal/overdrop"
	"github.com/panagiotis1226/overmesh/internal/relay"
	"github.com/panagiotis1226/overmesh/internal/wgengine"
)

// session owns the control-plane streams and the reconnect loop.
func (c *Core) session(ctx context.Context, conn *grpc.ClientConn, client overmeshv1.CoordinationServiceClient, sig *signaler) {
	defer close(c.stopped)
	defer conn.Close()

	go c.runSignaling(ctx, client, sig)

	backoff := time.Second
	for ctx.Err() == nil {
		if err := c.runNetMapStream(ctx, client); err != nil && ctx.Err() == nil {
			logf("netmap stream: %v (retrying in %v)", err, backoff)
			c.setConn("reconnecting")
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

func (c *Core) setConn(s string) {
	c.mu.Lock()
	changed := c.conn != s
	c.conn = s
	c.mu.Unlock()
	if changed {
		c.emit(s)
	}
}

func (c *Core) runNetMapStream(ctx context.Context, client overmeshv1.CoordinationServiceClient) error {
	mkey := c.st.machine.Public().Bytes()
	stream, err := client.StreamNetMap(ctx, &overmeshv1.StreamNetMapRequest{MachineKey: mkey})
	if err != nil {
		return err
	}
	c.setConn("connected")
	for {
		nm, err := stream.Recv()
		if err != nil {
			return err
		}
		c.applyNetMap(nm)
	}
}

// applyNetMap mirrors the daemon's netmap application, minus OS
// routing/DNS (the platform app handles those via OnNetMap).
func (c *Core) applyNetMap(nm *overmeshv1.NetMap) {
	stun := c.resolveHosts(nm.GetStunServers())
	relays := c.resolveRelayURLs(nm.GetRelays())

	c.mu.Lock()
	seen := make(map[uint64]bool)
	online := make(map[uint64]bool)
	for _, p := range nm.GetPeers() {
		if len(p.GetNodeKey()) != 32 {
			continue
		}
		id := p.GetNodeId()
		seen[id] = true
		pi, ok := c.peers[id]
		if !ok {
			pi = &peerInfo{nodeID: id, path: magicsock.PathNone}
			c.peers[id] = pi
		}
		copy(pi.pubKey[:], p.GetNodeKey())
		pi.hostname = p.GetHostname()
		pi.online = p.GetOnline()
		pi.staticEPs = p.GetEndpoints()
		pi.allowed = pi.allowed[:0]
		pi.subnetRoutes = pi.subnetRoutes[:0]
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
		for _, cidr := range p.GetAllowedRoutes() {
			pfx, err := netip.ParsePrefix(cidr)
			if err != nil || pfx.Bits() == 0 {
				continue // exit nodes are not consumable on mobile yet
			}
			pi.subnetRoutes = append(pi.subnetRoutes, pfx)
		}
		if pi.online {
			online[id] = true
		}
	}
	for id := range c.peers {
		if !seen[id] {
			delete(c.peers, id)
		}
	}
	c.domain = nm.GetDns().GetDomain()
	peerCfgs := c.buildPeerConfigsLocked()
	eng := c.engine
	cm := c.connmgr
	netmapJSON := c.tunnelSettingsLocked()
	changedSettings := netmapJSON != c.lastNetMap
	c.lastNetMap = netmapJSON
	ev := c.events
	c.mu.Unlock()

	if eng != nil {
		if err := eng.SetPeers(peerCfgs); err != nil {
			logf("set peers: %v", err)
		}
		eng.SetFilter(filter.FromProto(nm.GetFilter(), nm.GetFilterEnabled()))
	}
	c.ensureRelay(relays)
	if cm != nil {
		cm.SetStunServers(stun)
		cm.SetPeers(online)
	}
	c.updateDNSRecords(nm)
	if changedSettings && ev != nil {
		go ev.OnNetMap(netmapJSON)
	}
	logf("applied netmap seq %d (%d peers)", nm.GetSeq(), len(seen))
}

// tunnelSettingsLocked renders the JSON the platform app programs into
// the OS tunnel settings. Held: c.mu.
func (c *Core) tunnelSettingsLocked() string {
	routes := []string{
		netip.PrefixFrom(c.selfV4.Addr(), 11).Masked().String(),
		netip.PrefixFrom(c.selfV6.Addr(), 48).Masked().String(),
	}
	seen := map[string]bool{routes[0]: true, routes[1]: true}
	for _, pi := range c.peers {
		for _, r := range pi.subnetRoutes {
			if s := r.String(); !seen[s] {
				seen[s] = true
				routes = append(routes, s)
			}
		}
	}
	sort.Strings(routes[2:]) // stable JSON so lastNetMap dedupe works
	out := map[string]any{
		"ipv4":        c.selfV4.Addr().String(),
		"ipv4_prefix": 11,
		"ipv6":        c.selfV6.Addr().String(),
		"ipv6_prefix": 48,
		"routes":      routes,
		"dns_server":  c.selfV4.Addr().String(),
		"dns_domain":  c.domain,
		"mtu":         wgengine.DefaultMTU,
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// buildPeerConfigsLocked: the same path ladder as the daemon —
// direct > relay > static hint. Held: c.mu.
func (c *Core) buildPeerConfigsLocked() []wgengine.PeerConfig {
	relayUp := c.relayCli != nil && c.relayCli.Connected()
	var out []wgengine.PeerConfig
	for _, pi := range c.peers {
		pc := wgengine.PeerConfig{PublicKey: pi.pubKey, AllowedIPs: append([]netip.Prefix(nil), pi.allowed...)}
		pc.AllowedIPs = append(pc.AllowedIPs, pi.subnetRoutes...)
		switch {
		case pi.path == magicsock.PathDirect && pi.pathEP.IsValid():
			pc.Endpoint = pi.pathEP
		case relayUp && pi.online:
			pc.RelayEndpoint = magicsock.RelayEndpointString(pi.pubKey)
		default:
			for _, e := range pi.staticEPs {
				if ap, err := netip.ParseAddrPort(e); err == nil {
					pc.Endpoint = ap
					break
				}
			}
		}
		if pc.Endpoint.IsValid() || pc.RelayEndpoint != "" {
			out = append(out, pc)
		}
	}
	return out
}

func (c *Core) syncPeers() {
	c.mu.Lock()
	eng := c.engine
	var cfgs []wgengine.PeerConfig
	if eng != nil {
		cfgs = c.buildPeerConfigsLocked()
	}
	c.mu.Unlock()
	if eng != nil {
		if err := eng.SetPeers(cfgs); err != nil {
			logf("sync peers: %v", err)
		}
	}
}

func (c *Core) onPathUpdate(u magicsock.PathUpdate) {
	c.mu.Lock()
	pi, ok := c.peers[u.NodeID]
	if !ok {
		c.mu.Unlock()
		return
	}
	changed := pi.path != u.State || pi.pathEP != u.Endpoint
	pi.path = u.State
	pi.pathEP = u.Endpoint
	pi.rtt = u.RTT
	c.mu.Unlock()
	if changed {
		c.syncPeers()
	}
}

// --- relay lifecycle (same conventions as the daemon) ---

func (c *Core) resolveHosts(servers []string) []string {
	serverHost, _, err := net.SplitHostPort(c.server)
	if err != nil {
		serverHost = c.server
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

func (c *Core) resolveRelayURLs(relays []string) []string {
	serverHost, _, err := net.SplitHostPort(c.server)
	if err != nil {
		serverHost = c.server
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

func (c *Core) ensureRelay(urls []string) {
	c.mu.Lock()
	cur := c.relayCli
	bind := c.bind
	c.lastRelays = urls
	c.mu.Unlock()
	if bind == nil {
		return
	}
	if len(urls) == 0 {
		if cur != nil {
			bind.SetRelaySender(nil)
			cur.Close()
			c.mu.Lock()
			c.relayCli = nil
			c.mu.Unlock()
			c.syncPeers()
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
	copy(pub[:], c.st.node.Public().Bytes())
	cli := relay.NewClient(home, c.st.node.Raw(), pub, bind.DeliverRelayPacket, logf, nil)
	bind.SetRelaySender(cli.Send)
	c.mu.Lock()
	c.relayCli = cli
	c.mu.Unlock()
	go func() {
		for i := 0; i < 100; i++ {
			c.mu.Lock()
			still := c.relayCli == cli
			c.mu.Unlock()
			if !still {
				return
			}
			if cli.Connected() {
				c.syncPeers()
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
	}()
}

// --- in-tunnel services: overlay DNS + OverDrop ---

// updateDNSRecords keeps the resolver's zone current (started lazily
// once the platform confirms the tunnel settings are applied).
func (c *Core) updateDNSRecords(nm *overmeshv1.NetMap) {
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

	c.mu.Lock()
	srv := c.dnsSrv
	if srv == nil {
		srv = meshdns.NewServer(logf)
		c.dnsSrv = srv
	}
	up := c.inTunnelUp
	c.mu.Unlock()
	srv.SetRecords(domain, records)
	if up {
		c.startInTunnelServices() // idempotent late start
	}
}

// startInTunnelServices binds the overlay resolver and the OverDrop
// receiver to the tunnel address; safe to call repeatedly.
func (c *Core) startInTunnelServices() {
	c.mu.Lock()
	selfV4 := c.selfV4
	srv := c.dnsSrv
	startDNS := srv != nil && !c.dnsStarted && selfV4.IsValid()
	if startDNS {
		c.dnsStarted = true
	}
	drop := c.dropSrv
	needDrop := drop == nil && selfV4.IsValid()
	if needDrop {
		drop = overdrop.NewServer(c.stateDir+"/overdrop", c.peerNameByAddr, logf)
		c.dropSrv = drop
	}
	c.mu.Unlock()

	if srv != nil && startDNS {
		if err := srv.Start(selfV4.Addr()); err != nil {
			logf("overlay dns: %v", err)
			c.mu.Lock()
			c.dnsStarted = false
			c.mu.Unlock()
		}
	}
	if needDrop {
		if err := drop.Start(selfV4.Addr(), overdrop.DefaultPort); err != nil {
			logf("overdrop: %v", err)
			c.mu.Lock()
			c.dropSrv = nil
			c.mu.Unlock()
		}
	}
}

func (c *Core) peerNameByAddr(addr netip.Addr) string {
	s := addr.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, pi := range c.peers {
		if pi.ipv4 == s || pi.ipv6 == s {
			return pi.hostname
		}
	}
	return ""
}

// --- signaling (compact copy of the daemon's) ---

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
		Kind: overmeshv1.SignalKind_SIGNAL_KIND_OFFER, Payload: ufrag + "\n" + pwd,
	})
}

func (s *signaler) SendAnswer(to, session uint64, ufrag, pwd string) error {
	return s.send(&overmeshv1.SignalEnvelope{
		ToNodeId: to, Session: session,
		Kind: overmeshv1.SignalKind_SIGNAL_KIND_ANSWER, Payload: ufrag + "\n" + pwd,
	})
}

func (s *signaler) SendCandidate(to, session uint64, candidate string) error {
	return s.send(&overmeshv1.SignalEnvelope{
		ToNodeId: to, Session: session,
		Kind: overmeshv1.SignalKind_SIGNAL_KIND_CANDIDATE, Payload: candidate,
	})
}

func (c *Core) runSignaling(ctx context.Context, client overmeshv1.CoordinationServiceClient, sig *signaler) {
	mkey := c.st.machine.Public().Bytes()
	backoff := time.Second
	for ctx.Err() == nil {
		stream, err := client.SignalStream(ctx)
		if err == nil {
			err = stream.Send(&overmeshv1.SignalEnvelope{
				MachineKey: mkey, Kind: overmeshv1.SignalKind_SIGNAL_KIND_HELLO,
			})
		}
		if err == nil {
			sig.setStream(stream)
			backoff = time.Second
			err = c.receiveSignals(stream)
			sig.setStream(nil)
		}
		if ctx.Err() != nil {
			return
		}
		logf("signal stream: %v (retrying in %v)", err, backoff)
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

func (c *Core) receiveSignals(stream overmeshv1.CoordinationService_SignalStreamClient) error {
	for {
		env, err := stream.Recv()
		if err != nil {
			return err
		}
		c.mu.Lock()
		cm := c.connmgr
		c.mu.Unlock()
		if cm == nil {
			continue
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
