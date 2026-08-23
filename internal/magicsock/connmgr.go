package magicsock

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
)

// PathState is what a peer's connection looks like right now.
type PathState string

const (
	PathNone       PathState = "none"       // no working path (relay arrives in Phase 3)
	PathConnecting PathState = "connecting" // ICE negotiation in flight
	PathDirect     PathState = "direct"     // holepunched/direct path selected
)

// PathUpdate is emitted whenever a peer's path changes.
type PathUpdate struct {
	NodeID   uint64
	State    PathState
	Endpoint netip.AddrPort // valid when State == PathDirect
	RTT      time.Duration  // 0 if unknown
}

// Signaler sends signaling envelopes to a peer through the control plane.
type Signaler interface {
	SendOffer(toNode uint64, session uint64, ufrag, pwd string) error
	SendAnswer(toNode uint64, session uint64, ufrag, pwd string) error
	SendCandidate(toNode uint64, session uint64, candidate string) error
}

// ConnMgr runs one ICE negotiation per peer over the shared Bind and
// reports path decisions. The daemon feeds it netmap peers and inbound
// signaling; it calls back with PathUpdates to apply to WireGuard.
type ConnMgr struct {
	selfNode uint64
	bind     *Bind
	signaler Signaler
	onPath   func(PathUpdate)
	logf     func(string, ...any)

	mu       sync.Mutex
	stun     []*stun.URI
	peers    map[uint64]*peerConn
	closed   bool
	restarts uint64 // bumped on roaming to invalidate old sessions
}

// peerConn is the per-peer negotiation state.
type peerConn struct {
	nodeID  uint64
	session uint64 // current ICE session epoch (initiator-chosen)
	agent   *ice.Agent
	cancel  context.CancelFunc
	state   PathState
	// answer credentials arriving before the agent exists are stashed:
	pendingRemote []string // candidates received before agent creation
}

// NewConnMgr builds a manager; Start begins negotiating.
func NewConnMgr(selfNode uint64, bind *Bind, signaler Signaler, onPath func(PathUpdate), logf func(string, ...any)) *ConnMgr {
	return &ConnMgr{
		selfNode: selfNode,
		bind:     bind,
		signaler: signaler,
		onPath:   onPath,
		logf:     logf,
		peers:    make(map[uint64]*peerConn),
	}
}

// SetStunServers configures STUN URIs ("host:port" strings).
func (m *ConnMgr) SetStunServers(servers []string) {
	var uris []*stun.URI
	for _, s := range servers {
		if u, err := stun.ParseURI("stun:" + s); err == nil {
			uris = append(uris, u)
		}
	}
	m.mu.Lock()
	m.stun = uris
	m.mu.Unlock()
}

// SetPeers reconciles the negotiation set with the current netmap: start
// ICE toward new online peers (when we are the initiator), tear down
// removed ones. Peers where the REMOTE side initiates are handled
// lazily on their offer.
func (m *ConnMgr) SetPeers(online map[uint64]bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	// Tear down peers no longer present/online.
	for id, pc := range m.peers {
		if !online[id] {
			m.teardownLocked(pc)
			delete(m.peers, id)
			m.onPath(PathUpdate{NodeID: id, State: PathNone})
		}
	}
	// Initiate toward new peers where we hold the lower node ID.
	for id := range online {
		if _, exists := m.peers[id]; exists || m.selfNode >= id {
			continue
		}
		m.startInitiatorLocked(id)
	}
}

// Restart tears down and re-initiates every negotiation (roaming: local
// addresses changed). Responder-side peers re-negotiate when the remote
// initiator notices its own change or its consent checks fail.
func (m *ConnMgr) Restart() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.restarts++
	for id, pc := range m.peers {
		m.teardownLocked(pc)
		delete(m.peers, id)
		if m.selfNode < id {
			m.startInitiatorLocked(id)
		} else {
			m.onPath(PathUpdate{NodeID: id, State: PathConnecting})
		}
	}
}

// Close stops everything.
func (m *ConnMgr) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for id, pc := range m.peers {
		m.teardownLocked(pc)
		delete(m.peers, id)
	}
}

func (m *ConnMgr) teardownLocked(pc *peerConn) {
	if pc.cancel != nil {
		pc.cancel()
	}
	if pc.agent != nil {
		_ = pc.agent.Close()
	}
}

// --- initiator side ---

func (m *ConnMgr) startInitiatorLocked(peerID uint64) {
	session := uint64(time.Now().UnixNano())
	pc := &peerConn{nodeID: peerID, session: session, state: PathConnecting}
	m.peers[peerID] = pc
	m.onPath(PathUpdate{NodeID: peerID, State: PathConnecting})
	go m.runInitiator(peerID, session)
}

func (m *ConnMgr) runInitiator(peerID, session uint64) {
	backoff := 2 * time.Second
	for {
		ok, retry := m.negotiate(peerID, session, true, "", "")
		if ok || !retry {
			return
		}
		m.logf("magicsock: negotiation with node %d failed, retrying in %v", peerID, backoff)
		time.Sleep(backoff)
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		m.mu.Lock()
		pc, exists := m.peers[peerID]
		stale := !exists || pc.session != session || m.closed
		if !stale {
			// New attempt = new session so the peer discards old state.
			session = uint64(time.Now().UnixNano())
			pc.session = session
			pc.pendingRemote = nil
		}
		m.mu.Unlock()
		if stale {
			return
		}
	}
}

// --- responder side ---

// HandleOffer reacts to a remote-initiated negotiation.
func (m *ConnMgr) HandleOffer(fromNode, session uint64, ufrag, pwd string) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if pc, exists := m.peers[fromNode]; exists {
		if pc.session >= session {
			m.mu.Unlock()
			return // stale or duplicate offer
		}
		m.teardownLocked(pc)
		delete(m.peers, fromNode)
	}
	pc := &peerConn{nodeID: fromNode, session: session, state: PathConnecting}
	m.peers[fromNode] = pc
	m.onPath(PathUpdate{NodeID: fromNode, State: PathConnecting})
	m.mu.Unlock()

	go m.negotiate(fromNode, session, false, ufrag, pwd)
}

// HandleAnswer feeds the initiator the responder's credentials.
func (m *ConnMgr) HandleAnswer(fromNode, session uint64, ufrag, pwd string) {
	m.mu.Lock()
	pc, exists := m.peers[fromNode]
	var ch chan [2]string
	if exists && pc.session == session {
		ch = answerChans[answerKey{fromNode, session}]
	}
	m.mu.Unlock()
	if ch != nil {
		select {
		case ch <- [2]string{ufrag, pwd}:
		default:
		}
	}
}

// HandleCandidate feeds a trickled remote candidate into the negotiation.
func (m *ConnMgr) HandleCandidate(fromNode, session uint64, candidate string) {
	m.mu.Lock()
	pc, exists := m.peers[fromNode]
	if !exists || pc.session != session {
		m.mu.Unlock()
		return
	}
	agent := pc.agent
	if agent == nil {
		pc.pendingRemote = append(pc.pendingRemote, candidate)
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	m.addRemoteCandidate(agent, candidate)
}

func (m *ConnMgr) addRemoteCandidate(agent *ice.Agent, raw string) {
	c, err := ice.UnmarshalCandidate(raw)
	if err != nil {
		m.logf("magicsock: bad remote candidate %q: %v", raw, err)
		return
	}
	if isLoopbackCandidate(c) { // defense against older/foreign senders
		return
	}
	m.logf("magicsock: remote candidate: %s", c.String())
	if err := agent.AddRemoteCandidate(c); err != nil {
		m.logf("magicsock: add remote candidate: %v", err)
	}
}

func isLoopbackCandidate(c ice.Candidate) bool {
	if ap, err := netip.ParseAddr(c.Address()); err == nil {
		return ap.IsLoopback()
	}
	return false
}

// answerChans lets the initiator goroutine wait for its answer without
// holding the manager lock.
type answerKey struct{ node, session uint64 }

var (
	answerMu    sync.Mutex
	answerChans = map[answerKey]chan [2]string{}
)

// negotiate runs one full ICE session with peerID. Returns (established,
// shouldRetry).
func (m *ConnMgr) negotiate(peerID, session uint64, initiator bool, remoteUfrag, remotePwd string) (bool, bool) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false, false
	}
	stunURIs := m.stun
	m.mu.Unlock()

	role := "responder"
	if initiator {
		role = "initiator"
	}
	m.logf("magicsock: negotiating with node %d as %s (session %d)", peerID, role, session)

	// The shared socket must be open before candidates can exist.
	select {
	case <-m.bind.Ready():
	case <-time.After(30 * time.Second):
		m.logf("magicsock: bind never became ready")
		return false, true
	}
	m.logf("magicsock: [%d] bind ready, creating agent", peerID)

	agent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:   []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeServerReflexive},
		Urls:           stunURIs,
		UDPMux:         m.bind.Mux(),
		UDPMuxSrflx:    m.bind.Mux(),
		// Real addresses in candidates: mDNS-obfuscated host candidates
		// (<uuid>.local) don't resolve across routed networks.
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
	})
	if err != nil {
		m.logf("magicsock: ice agent: %v", err)
		return false, true
	}

	// Attach the agent (and any candidates that raced ahead of it).
	m.mu.Lock()
	pc, exists := m.peers[peerID]
	if !exists || pc.session != session {
		m.mu.Unlock()
		_ = agent.Close()
		return false, false
	}
	pc.agent = agent
	pending := pc.pendingRemote
	pc.pendingRemote = nil
	m.mu.Unlock()
	for _, c := range pending {
		m.addRemoteCandidate(agent, c)
	}

	ufrag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		m.logf("magicsock: local credentials: %v", err)
		_ = agent.Close()
		return false, true
	}

	_ = agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		// Loopback candidates are poison: every node listens on the same
		// port, so a peer "connecting" to 127.0.0.1 reaches itself.
		if isLoopbackCandidate(c) {
			return
		}
		m.logf("magicsock: [%d] local candidate: %s", peerID, c.String())
		if err := m.signaler.SendCandidate(peerID, session, c.Marshal()); err != nil {
			m.logf("magicsock: send candidate to %d: %v", peerID, err)
		}
	})
	_ = agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		ap, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", remote.Address(), remote.Port()))
		if err != nil {
			return
		}
		m.onPath(PathUpdate{NodeID: peerID, State: PathDirect, Endpoint: ap, RTT: m.pairRTT(agent)})
	})
	_ = agent.OnConnectionStateChange(func(s ice.ConnectionState) {
		m.logf("magicsock: [%d] ice state: %s", peerID, s)
		switch s {
		case ice.ConnectionStateFailed, ice.ConnectionStateDisconnected:
			m.onPath(PathUpdate{NodeID: peerID, State: PathNone})
		}
	})

	// Exchange credentials.
	var answerCh chan [2]string
	if initiator {
		answerCh = make(chan [2]string, 1)
		answerMu.Lock()
		answerChans[answerKey{peerID, session}] = answerCh
		answerMu.Unlock()
		defer func() {
			answerMu.Lock()
			delete(answerChans, answerKey{peerID, session})
			answerMu.Unlock()
		}()
		if err := m.signaler.SendOffer(peerID, session, ufrag, pwd); err != nil {
			m.logf("magicsock: send offer to node %d: %v", peerID, err)
			_ = agent.Close()
			return false, true
		}
		m.logf("magicsock: [%d] offer sent, gathering", peerID)
	} else {
		if err := m.signaler.SendAnswer(peerID, session, ufrag, pwd); err != nil {
			m.logf("magicsock: send answer to node %d: %v", peerID, err)
			_ = agent.Close()
			return false, true
		}
	}

	if err := agent.GatherCandidates(); err != nil {
		m.logf("magicsock: gather candidates: %v", err)
		_ = agent.Close()
		return false, true
	}

	if initiator {
		m.logf("magicsock: [%d] waiting for answer", peerID)
		select {
		case creds := <-answerCh:
			remoteUfrag, remotePwd = creds[0], creds[1]
		case <-time.After(20 * time.Second):
			m.logf("magicsock: no answer from node %d", peerID)
			_ = agent.Close()
			return false, true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	m.mu.Lock()
	if pc, ok := m.peers[peerID]; ok && pc.session == session {
		pc.cancel = cancel
	}
	m.mu.Unlock()
	defer cancel()

	var conn *ice.Conn
	if initiator {
		conn, err = agent.Dial(ctx, remoteUfrag, remotePwd)
	} else {
		conn, err = agent.Accept(ctx, remoteUfrag, remotePwd)
	}
	if err != nil {
		m.logf("magicsock: ice with node %d failed: %v", peerID, err)
		m.onPath(PathUpdate{NodeID: peerID, State: PathNone})
		_ = agent.Close()
		return false, true
	}
	_ = conn // the selected pair drives WG; the ice.Conn itself stays idle

	if pair, err := agent.GetSelectedCandidatePair(); err == nil && pair != nil {
		if ap, err := netip.ParseAddrPort(fmt.Sprintf("%s:%d", pair.Remote.Address(), pair.Remote.Port())); err == nil {
			m.onPath(PathUpdate{NodeID: peerID, State: PathDirect, Endpoint: ap, RTT: m.pairRTT(agent)})
			m.logf("magicsock: direct path to node %d via %s (%s)", peerID, ap, pair.Remote.Type())
		}
	}
	return true, false
}

func (m *ConnMgr) pairRTT(agent *ice.Agent) time.Duration {
	for _, s := range agent.GetCandidatePairsStats() {
		if s.State == ice.CandidatePairStateSucceeded && s.CurrentRoundTripTime > 0 {
			return time.Duration(s.CurrentRoundTripTime * float64(time.Second))
		}
	}
	return 0
}
