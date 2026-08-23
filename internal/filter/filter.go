// Package filter enforces the network's access rules on the receiving
// node. WireGuard's cryptokey routing guarantees a packet's overlay
// source address belongs to the peer that sent it, so filtering inbound
// by (src, protocol, dst port) is sound — the Tailscale model.
package filter

import (
	"encoding/binary"
	"net/netip"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
)

// Protocol numbers we classify.
const (
	protoICMP4 = 1
	protoTCP   = 6
	protoUDP   = 17
	protoICMP6 = 58
)

// PortRange is inclusive.
type PortRange struct{ First, Last uint16 }

// Rule matches inbound packets; first match wins.
type Rule struct {
	Allow bool
	Srcs  []netip.Prefix // empty = any source
	Proto string         // "" any | "tcp" | "udp" | "icmp"
	Ports []PortRange    // empty = all ports (tcp/udp only)
}

// Filter is an immutable compiled rule set; nil *Filter allows all.
type Filter struct {
	enabled bool
	rules   []Rule
}

// New builds a filter. When enabled is false everything passes.
func New(rules []Rule, enabled bool) *Filter {
	return &Filter{enabled: enabled, rules: rules}
}

// FromProto converts netmap filter rules.
func FromProto(rules []*overmeshv1.FilterRule, enabled bool) *Filter {
	out := make([]Rule, 0, len(rules))
	for _, pr := range rules {
		r := Rule{Allow: pr.GetAllow(), Proto: pr.GetProtocol()}
		for _, c := range pr.GetSrcCidrs() {
			if p, err := netip.ParsePrefix(c); err == nil {
				r.Srcs = append(r.Srcs, p)
			}
		}
		for _, p := range pr.GetDstPorts() {
			r.Ports = append(r.Ports, PortRange{First: uint16(p.GetFirst()), Last: uint16(p.GetLast())})
		}
		out = append(out, r)
	}
	return New(out, enabled)
}

// Check evaluates the rules for a hypothetical packet — the web UI's
// dry-run tester ("can A reach B:22?"). protoName: "tcp"|"udp"|"icmp".
func (f *Filter) Check(src netip.Addr, protoName string, port uint16) bool {
	if f == nil || !f.enabled {
		return true
	}
	var proto uint8
	switch protoName {
	case "tcp":
		proto = protoTCP
	case "udp":
		proto = protoUDP
	case "icmp":
		proto = protoICMP4
		if src.Is6() {
			proto = protoICMP6
		}
	default:
		return false
	}
	return f.allows(src, proto, port)
}

// AllowsPacket parses an inbound overlay IP packet and applies the rules.
// Unparseable packets are dropped when filtering is on (fail closed).
func (f *Filter) AllowsPacket(pkt []byte) bool {
	if f == nil || !f.enabled {
		return true
	}
	src, proto, dstPort, ok := parse(pkt)
	if !ok {
		return false
	}
	return f.allows(src, proto, dstPort)
}

// allows applies first-match-wins; no match = deny (the implicit rule
// when filtering is enabled).
func (f *Filter) allows(src netip.Addr, proto uint8, dstPort uint16) bool {
	for _, r := range f.rules {
		if !r.matchesProto(proto) || !r.matchesSrc(src) || !r.matchesPort(proto, dstPort) {
			continue
		}
		return r.Allow
	}
	return false
}

func (r *Rule) matchesSrc(src netip.Addr) bool {
	if len(r.Srcs) == 0 {
		return true
	}
	for _, p := range r.Srcs {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

func (r *Rule) matchesProto(proto uint8) bool {
	switch r.Proto {
	case "":
		return true
	case "tcp":
		return proto == protoTCP
	case "udp":
		return proto == protoUDP
	case "icmp":
		return proto == protoICMP4 || proto == protoICMP6
	}
	return false
}

func (r *Rule) matchesPort(proto uint8, port uint16) bool {
	if len(r.Ports) == 0 {
		return true
	}
	// Port constraints only make sense for tcp/udp; a rule with ports
	// never matches portless protocols.
	if proto != protoTCP && proto != protoUDP {
		return false
	}
	for _, pr := range r.Ports {
		if port >= pr.First && port <= pr.Last {
			return true
		}
	}
	return false
}

// parse extracts (src, protocol, dst port) from an IPv4/IPv6 packet.
// dstPort is 0 for portless protocols.
func parse(pkt []byte) (src netip.Addr, proto uint8, dstPort uint16, ok bool) {
	if len(pkt) < 1 {
		return
	}
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return
		}
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return
		}
		proto = pkt[9]
		a, _ := netip.AddrFromSlice(pkt[12:16])
		src = a
		if proto == protoTCP || proto == protoUDP {
			if len(pkt) < ihl+4 {
				return
			}
			dstPort = binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
		}
		// Fragments past the first carry no L4 header; match them by
		// protocol only (dstPort 0) — conservative but functional.
		if frag := binary.BigEndian.Uint16(pkt[6:8]) & 0x1fff; frag != 0 {
			dstPort = 0
		}
		return src, proto, dstPort, true
	case 6:
		if len(pkt) < 40 {
			return
		}
		proto = pkt[6] // next header; extension chains fall through as-is
		a, _ := netip.AddrFromSlice(pkt[8:24])
		src = a
		if proto == protoTCP || proto == protoUDP {
			if len(pkt) < 44 {
				return
			}
			dstPort = binary.BigEndian.Uint16(pkt[42:44])
		}
		return src, proto, dstPort, true
	}
	return
}
