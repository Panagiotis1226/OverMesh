package daemon

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/pion/stun/v3"
)

// NetcheckReport is the result of live connectivity probes from this
// node: control plane, STUN (NAT discovery), and every advertised
// relay. `overmesh netcheck` renders it; bugreport embeds it.
type NetcheckReport struct {
	Server           string  `json:"server"`
	ControlReachable bool    `json:"control_reachable"`
	ControlRTTMs     float64 `json:"control_rtt_ms"`
	ControlError     string  `json:"control_error,omitempty"`

	Stun []StunCheck `json:"stun,omitempty"`
	// UDPBlocked: every STUN probe failed — direct paths are unlikely
	// and traffic will ride the relay's TCP fallback.
	UDPBlocked bool `json:"udp_blocked"`

	Relays []RelayCheck `json:"relays,omitempty"`
}

type StunCheck struct {
	Server     string  `json:"server"`
	MappedAddr string  `json:"mapped_addr,omitempty"`
	RTTMs      float64 `json:"rtt_ms"`
	Error      string  `json:"error,omitempty"`
}

type RelayCheck struct {
	URL       string  `json:"url"`
	Reachable bool    `json:"reachable"`
	RTTMs     float64 `json:"rtt_ms"`
	Error     string  `json:"error,omitempty"`
}

const probeTimeout = 3 * time.Second

// Netcheck probes the control plane, STUN servers, and relays this
// node knows from its latest netmap. Safe to run while connected; all
// probes use fresh sockets.
func (d *Daemon) Netcheck() NetcheckReport {
	d.mu.Lock()
	server := d.state.Server
	stunServers := append([]string(nil), d.lastStun...)
	relays := append([]string(nil), d.lastRelays...)
	d.mu.Unlock()

	rep := NetcheckReport{Server: server}

	if server != "" {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", server, probeTimeout)
		if err != nil {
			rep.ControlError = err.Error()
		} else {
			conn.Close()
			rep.ControlReachable = true
			rep.ControlRTTMs = msSince(start)
		}
	}

	failed := 0
	for _, s := range stunServers {
		c := probeStun(s)
		if c.Error != "" {
			failed++
		}
		rep.Stun = append(rep.Stun, c)
	}
	rep.UDPBlocked = len(stunServers) > 0 && failed == len(stunServers)

	for _, r := range relays {
		rep.Relays = append(rep.Relays, probeRelay(r))
	}
	return rep
}

// probeStun sends one binding request and reports our reflexive
// (public) UDP endpoint as that server sees it.
func probeStun(server string) StunCheck {
	c := StunCheck{Server: server}
	conn, err := net.DialTimeout("udp", server, probeTimeout)
	if err != nil {
		c.Error = err.Error()
		return c
	}
	defer conn.Close()

	msg := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	start := time.Now()
	_ = conn.SetDeadline(time.Now().Add(probeTimeout))
	if _, err := conn.Write(msg.Raw); err != nil {
		c.Error = err.Error()
		return c
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		c.Error = err.Error()
		return c
	}
	resp := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
	if err := resp.Decode(); err != nil {
		c.Error = err.Error()
		return c
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(resp); err != nil {
		c.Error = err.Error()
		return c
	}
	c.MappedAddr = fmt.Sprintf("%s:%d", xor.IP, xor.Port)
	c.RTTMs = msSince(start)
	return c
}

// probeRelay measures a TCP connect to the relay's host:port — the
// same reachability the guaranteed fallback path depends on.
func probeRelay(relayURL string) RelayCheck {
	c := RelayCheck{URL: relayURL}
	u, err := url.Parse(relayURL)
	if err != nil {
		c.Error = err.Error()
		return c
	}
	host := u.Host
	if u.Port() == "" {
		switch u.Scheme {
		case "https":
			host = net.JoinHostPort(u.Hostname(), "443")
		default:
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", host, probeTimeout)
	if err != nil {
		c.Error = err.Error()
		return c
	}
	conn.Close()
	c.Reachable = true
	c.RTTMs = msSince(start)
	return c
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000
}
