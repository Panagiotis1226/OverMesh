package coord

import (
	"fmt"
	"strconv"
	"strings"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/store"
)

// CompileFilterForNode renders the network's ordered access rules into
// the inbound filter for one receiving node. Used for netmap delivery
// and by the admin API's dry-run tester, so both always agree.
//
// Semantics: with zero rules, filtering is disabled (allow all). With
// rules, first match wins and no match means deny — the daemon's filter
// implements that implicit deny when enabled.
func (c *Coordinator) CompileFilterForNode(dst store.Node) ([]*overmeshv1.FilterRule, bool, error) {
	rules, err := c.st.ACL(dst.NetworkID)
	if err != nil {
		return nil, false, err
	}
	if len(rules) == 0 {
		return nil, false, nil
	}
	nodes, err := c.st.NodesInNetwork(dst.NetworkID)
	if err != nil {
		return nil, false, err
	}
	byID := make(map[int64]store.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	var out []*overmeshv1.FilterRule
	for _, r := range rules {
		if !idListMatches(r.DstIDs, dst.ID) {
			continue // rule does not apply to traffic arriving at dst
		}
		fr := &overmeshv1.FilterRule{Allow: r.Action == "allow", Protocol: r.Protocol}
		if len(r.SrcIDs) > 0 {
			for _, id := range r.SrcIDs {
				src, ok := byID[id]
				if !ok {
					continue // deleted device
				}
				fr.SrcCidrs = append(fr.SrcCidrs,
					src.IPv4.String()+"/32", src.IPv6.String()+"/128")
			}
			if len(fr.SrcCidrs) == 0 {
				continue // sources all gone: rule can never match
			}
		}
		for _, spec := range r.Ports {
			pr, err := ParsePortSpec(spec)
			if err != nil {
				continue // validated at save time; skip defensively
			}
			fr.DstPorts = append(fr.DstPorts, pr)
		}
		out = append(out, fr)
	}
	return out, true, nil
}

func idListMatches(ids []int64, id int64) bool {
	if len(ids) == 0 {
		return true // empty = any
	}
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// ParsePortSpec parses "443" or "8000-9000".
func ParsePortSpec(spec string) (*overmeshv1.PortRange, error) {
	spec = strings.TrimSpace(spec)
	first, last, ok := strings.Cut(spec, "-")
	f, err := strconv.ParseUint(strings.TrimSpace(first), 10, 16)
	if err != nil || f == 0 {
		return nil, fmt.Errorf("bad port %q", spec)
	}
	l := f
	if ok {
		l, err = strconv.ParseUint(strings.TrimSpace(last), 10, 16)
		if err != nil || l < f {
			return nil, fmt.Errorf("bad port range %q", spec)
		}
	}
	return &overmeshv1.PortRange{First: uint32(f), Last: uint32(l)}, nil
}

// ACLChanged pushes fresh netmaps (with recompiled filters) to every node
// in the network.
func (c *Coordinator) ACLChanged(networkID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notifyNetworkLocked(networkID)
}

// NodeForCheck exposes a node lookup for the admin API's dry-run tester.
func (c *Coordinator) NodeForCheck(id int64) (store.Node, error) {
	return c.st.NodeByID(id)
}
