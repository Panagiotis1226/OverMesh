// Package coord is the control plane's coordination engine: node
// registration, overlay address assignment, and netmap computation +
// push. The gRPC service in service.go is a thin shim over Coordinator.
package coord

import (
	"fmt"
	"log"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/ipam"
	"github.com/panagiotis1226/overmesh/internal/key"
	"github.com/panagiotis1226/overmesh/internal/store"
)

// Coordinator owns the in-memory view of the mesh: per-network IPAM,
// which nodes are online (= have an open netmap stream), and the
// subscriber channels netmap updates are pushed through.
type Coordinator struct {
	st *store.Store

	mu     sync.Mutex
	ipams  map[int64]*ipam.Allocator          // networkID -> allocator
	subs   map[int64]chan *overmeshv1.NetMap  // nodeID -> push channel
	online map[int64]bool                     // nodeID -> stream open
	seq    map[int64]uint64                   // networkID -> netmap sequence
}

// New loads existing state (nodes' addresses into IPAM) and returns a
// ready Coordinator.
func New(st *store.Store) (*Coordinator, error) {
	c := &Coordinator{
		st:     st,
		ipams:  make(map[int64]*ipam.Allocator),
		subs:   make(map[int64]chan *overmeshv1.NetMap),
		online: make(map[int64]bool),
		seq:    make(map[int64]uint64),
	}
	return c, nil
}

// allocatorFor returns (creating if needed) the IPAM allocator for a
// network, seeded with every address already assigned. Callers hold c.mu.
func (c *Coordinator) allocatorFor(nw store.Network) (*ipam.Allocator, error) {
	if a, ok := c.ipams[nw.ID]; ok {
		return a, nil
	}
	a, err := ipam.New(nw.V4Prefix, nw.V6Prefix)
	if err != nil {
		return nil, err
	}
	nodes, err := c.st.NodesInNetwork(nw.ID)
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		a.MarkUsed(n.IPv4)
	}
	c.ipams[nw.ID] = a
	return a, nil
}

// Register implements node registration: known machine keys re-register
// (refreshing hostname/OS/node key), unknown ones must present a valid
// setup key and get addresses allocated.
func (c *Coordinator) Register(mkey key.MachinePublic, nkey key.NodePublic, setupKey, hostname, osName string) (store.Node, store.Network, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	hostname = sanitizeHostname(hostname)

	if n, err := c.st.NodeByMachineKey(mkey.String()); err == nil {
		// Re-registration. Keep the stored hostname unless the caller's
		// (sanitized) name changed and is free.
		newName := n.Hostname
		if hostname != "" && hostname != n.Hostname {
			if taken, _ := c.st.HostnameTaken(n.NetworkID, hostname); !taken {
				newName = hostname
			}
		}
		if err := c.st.UpdateNodeOnRegister(n.ID, nkey.String(), newName, osName); err != nil {
			return store.Node{}, store.Network{}, err
		}
		n.NodeKey = nkey.String()
		n.Hostname = newName
		n.OS = osName
		nw, err := c.st.NetworkByID(n.NetworkID)
		if err != nil {
			return store.Node{}, store.Network{}, err
		}
		c.notifyNetworkLocked(n.NetworkID)
		return n, nw, nil
	} else if err != store.ErrNotFound {
		return store.Node{}, store.Network{}, err
	}

	// New node: needs a setup key.
	if setupKey == "" {
		return store.Node{}, store.Network{}, fmt.Errorf("unknown device: a setup key is required to join")
	}
	nw, err := c.st.UseSetupKey(setupKey)
	if err != nil {
		return store.Node{}, store.Network{}, err
	}
	alloc, err := c.allocatorFor(nw)
	if err != nil {
		return store.Node{}, store.Network{}, err
	}
	v4, err := alloc.AllocateV4()
	if err != nil {
		return store.Node{}, store.Network{}, err
	}
	if hostname == "" {
		hostname = "node"
	}
	hostname = c.dedupeHostname(nw.ID, hostname)

	n, err := c.st.CreateNode(store.Node{
		NetworkID:  nw.ID,
		Hostname:   hostname,
		MachineKey: mkey.String(),
		NodeKey:    nkey.String(),
		IPv4:       v4,
		IPv6:       v4, // placeholder until we know the node ID
		OS:         osName,
	})
	if err != nil {
		alloc.Release(v4)
		return store.Node{}, store.Network{}, err
	}
	// IPv6 derives from the node ID, which we only have post-insert.
	v6, err := alloc.AllocateV6For(uint64(n.ID))
	if err != nil {
		return store.Node{}, store.Network{}, err
	}
	n.IPv6 = v6
	if err := c.st.UpdateNodeIPv6(n.ID, v6); err != nil {
		return store.Node{}, store.Network{}, err
	}

	log.Printf("coord: registered %s (%s, %s) in %s as %s/%s", n.Hostname, osName, mkey, nw.Name, n.IPv4, n.IPv6)
	c.notifyNetworkLocked(nw.ID)
	return n, nw, nil
}

// dedupeHostname appends -2, -3, ... until the name is free. Held: c.mu.
func (c *Coordinator) dedupeHostname(networkID int64, base string) string {
	name := base
	for i := 2; ; i++ {
		taken, err := c.st.HostnameTaken(networkID, name)
		if err != nil || !taken {
			return name
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
}

var hostnameRe = regexp.MustCompile(`[^a-z0-9-]+`)

// sanitizeHostname lowercases and strips anything not [a-z0-9-]; these
// names become DNS labels in Phase 4.
func sanitizeHostname(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = hostnameRe.ReplaceAllString(h, "-")
	h = strings.Trim(h, "-")
	if len(h) > 63 {
		h = h[:63]
	}
	return h
}

// UpdateEndpoints stores a node's reachable endpoints and pushes updated
// netmaps to its network.
func (c *Coordinator) UpdateEndpoints(mkey key.MachinePublic, endpoints []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.st.NodeByMachineKey(mkey.String())
	if err != nil {
		return err
	}
	for _, e := range endpoints {
		if _, err := netip.ParseAddrPort(e); err != nil {
			return fmt.Errorf("bad endpoint %q: %w", e, err)
		}
	}
	if err := c.st.UpdateNodeEndpoints(n.ID, endpoints); err != nil {
		return err
	}
	c.notifyNetworkLocked(n.NetworkID)
	return nil
}

// Subscribe marks the node online and returns its node record, a channel
// of netmap pushes (primed with the current map), and an unsubscribe
// function. The channel is closed when the node is deleted server-side.
func (c *Coordinator) Subscribe(mkey key.MachinePublic) (store.Node, <-chan *overmeshv1.NetMap, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	n, err := c.st.NodeByMachineKey(mkey.String())
	if err != nil {
		return store.Node{}, nil, nil, err
	}

	// One stream per node: a new stream replaces (closes) the old one.
	if old, ok := c.subs[n.ID]; ok {
		close(old)
	}
	ch := make(chan *overmeshv1.NetMap, 8)
	c.subs[n.ID] = ch
	c.online[n.ID] = true
	_ = c.st.TouchNode(n.ID)

	// Prime with the current map, then fan out the online-status change.
	if nm, err := c.buildNetMapLocked(n); err == nil {
		ch <- nm
	}
	c.notifyNetworkLocked(n.NetworkID)

	unsub := func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if cur, ok := c.subs[n.ID]; ok && cur == ch {
			delete(c.subs, n.ID)
			c.online[n.ID] = false
			_ = c.st.TouchNode(n.ID)
			c.notifyNetworkLocked(n.NetworkID)
		}
	}
	return n, ch, unsub, nil
}

// DeleteNode removes a node (admin action), kicks its stream, frees its
// address, and notifies the network.
func (c *Coordinator) DeleteNode(id int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.st.NodeByID(id)
	if err != nil {
		return err
	}
	if err := c.st.DeleteNode(id); err != nil {
		return err
	}
	if ch, ok := c.subs[id]; ok {
		close(ch)
		delete(c.subs, id)
	}
	delete(c.online, id)
	if nw, err := c.st.NetworkByID(n.NetworkID); err == nil {
		if alloc, err := c.allocatorFor(nw); err == nil {
			alloc.Release(n.IPv4)
		}
	}
	c.notifyNetworkLocked(n.NetworkID)
	return nil
}

// Online reports whether the node currently holds a netmap stream.
func (c *Coordinator) Online(nodeID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.online[nodeID]
}

// notifyNetworkLocked recomputes and pushes a netmap to every subscribed
// node in the network. Held: c.mu.
func (c *Coordinator) notifyNetworkLocked(networkID int64) {
	c.seq[networkID]++
	nodes, err := c.st.NodesInNetwork(networkID)
	if err != nil {
		log.Printf("coord: notify %d: %v", networkID, err)
		return
	}
	for _, n := range nodes {
		ch, ok := c.subs[n.ID]
		if !ok {
			continue
		}
		nm, err := c.buildNetMapLocked(n)
		if err != nil {
			log.Printf("coord: netmap for %d: %v", n.ID, err)
			continue
		}
		// Non-blocking: a stalled client drops intermediate maps and
		// catches up on the next push (maps are complete, not deltas).
		select {
		case ch <- nm:
		default:
		}
	}
}

// buildNetMapLocked assembles the complete netmap for node n. Held: c.mu.
func (c *Coordinator) buildNetMapLocked(n store.Node) (*overmeshv1.NetMap, error) {
	nw, err := c.st.NetworkByID(n.NetworkID)
	if err != nil {
		return nil, err
	}
	nodes, err := c.st.NodesInNetwork(n.NetworkID)
	if err != nil {
		return nil, err
	}
	nm := &overmeshv1.NetMap{
		Seq: c.seq[n.NetworkID],
		Self: &overmeshv1.Node{
			NodeId:     uint64(n.ID),
			Hostname:   n.Hostname,
			NetworkId:  nw.Name,
			OverlayIps: overlayCIDRs(n),
		},
	}
	for _, p := range nodes {
		if p.ID == n.ID {
			continue
		}
		nkey, err := parseNodeKey(p.NodeKey)
		if err != nil {
			continue
		}
		nm.Peers = append(nm.Peers, &overmeshv1.Peer{
			NodeId:     uint64(p.ID),
			Hostname:   p.Hostname,
			NodeKey:    nkey,
			OverlayIps: overlayCIDRs(p),
			Endpoints:  p.Endpoints,
			Online:     c.online[p.ID],
		})
	}
	return nm, nil
}

func overlayCIDRs(n store.Node) []string {
	return []string{n.IPv4.String() + "/32", n.IPv6.String() + "/128"}
}

func parseNodeKey(s string) ([]byte, error) {
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(s)); err != nil {
		return nil, err
	}
	return k.Bytes(), nil
}
