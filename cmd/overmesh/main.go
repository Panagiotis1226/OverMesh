// Command overmesh is the user-facing CLI. It drives the local overmeshd
// daemon over its unix control socket.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/panagiotis1226/overmesh/internal/daemon"
	"github.com/panagiotis1226/overmesh/internal/overdrop"
	"github.com/panagiotis1226/overmesh/internal/version"
)

const usage = `overmesh — self-hosted WireGuard mesh VPN

Usage:
  overmesh up -server <host:port> [-key sk-...]   join the mesh
      [-advertise-routes 10.0.0.0/24,...]         offer LAN subnets to the mesh
      [-advertise-exit-node]                      offer to be an exit node
      [-exit-node <peer-hostname>]                send all traffic via that peer
  overmesh down                                   leave the mesh
  overmesh status                                 show self + peers
  overmesh ping <peer-hostname|ip> [-c N]         ping a peer over the overlay
  overmesh exit-node <peer-hostname|off>          switch exit node on the fly
  overmesh drop <file> <peer-hostname>            send a file (resumable)
  overmesh inbox                                  list received files
  overmesh rotate-key                             rotate the WireGuard node key
  overmesh netcheck                               probe control plane, STUN, relays
  overmesh bugreport                              print a diagnostic bundle
  overmesh version

Routers and exit nodes must be approved in the web UI before they carry
traffic (Devices table, routes column).

Global flag: -socket <path> to reach a non-default overmeshd socket.
The daemon (overmeshd) must be running; it needs root.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "version", "-version", "--version":
		fmt.Println("overmesh", version.Long())
	case "up":
		err = cmdUp(args)
	case "down":
		err = cmdDown(args)
	case "status":
		err = cmdStatus(args)
	case "ping":
		err = cmdPing(args)
	case "exit-node":
		err = cmdExitNode(args)
	case "drop":
		err = cmdDrop(args)
	case "inbox":
		err = cmdInbox(args)
	case "rotate-key":
		err = cmdRotateKey(args)
	case "netcheck":
		err = cmdNetcheck(args)
	case "bugreport":
		err = cmdBugreport(args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "overmesh:", err)
		os.Exit(1)
	}
}

// client returns an HTTP client that dials the daemon's unix socket.
func client(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 30 * time.Second,
	}
}

func call(socket, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, "http://overmeshd"+path, rd)
	if err != nil {
		return err
	}
	resp, err := client(socket).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach overmeshd at %s (is it running? does it need sudo?): %w", socket, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func cmdUp(args []string) error {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	server := fs.String("server", "", "control plane gRPC address (host:port)")
	key := fs.String("key", "", "setup key (sk-...), required on first join")
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	advRoutes := fs.String("advertise-routes", "", "comma-separated CIDRs to offer as a subnet router")
	advExit := fs.Bool("advertise-exit-node", false, "offer to route ALL mesh traffic to the internet")
	exitNode := fs.String("exit-node", "", "send all traffic through this peer (Linux)")
	_ = fs.Parse(args)
	if *server == "" {
		return fmt.Errorf("-server is required")
	}

	var routes []string
	for _, r := range strings.Split(*advRoutes, ",") {
		if r = strings.TrimSpace(r); r != "" {
			routes = append(routes, r)
		}
	}
	if *advExit {
		routes = append(routes, "0.0.0.0/0", "::/0")
	}

	req := map[string]any{
		"server": *server, "key": *key,
		"advertise_routes": routes, "exit_node": *exitNode,
	}
	var st daemon.Status
	if err := call(*socket, "POST", "/up", req, &st); err != nil {
		return err
	}
	fmt.Printf("joined %q as %s\n  overlay: %s  %s\n", st.Network, st.Hostname, st.IPv4, st.IPv6)
	if len(routes) > 0 {
		fmt.Printf("  offering routes: %s (awaiting admin approval in the web UI)\n", strings.Join(routes, ", "))
	}
	if *exitNode != "" {
		fmt.Printf("  exit node requested: %s\n", *exitNode)
	}
	return nil
}

func cmdExitNode(args []string) error {
	fs := flag.NewFlagSet("exit-node", flag.ExitOnError)
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: overmesh exit-node <peer-hostname|off>")
	}
	name := fs.Arg(0)
	if name == "off" || name == "none" {
		name = ""
	}
	var st daemon.Status
	if err := call(*socket, "POST", "/exitnode", map[string]string{"name": name}, &st); err != nil {
		return err
	}
	if name == "" {
		fmt.Println("exit node off")
	} else {
		fmt.Printf("all traffic now routes via %s\n", name)
	}
	return nil
}

func cmdDown(args []string) error {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	_ = fs.Parse(args)
	if err := call(*socket, "POST", "/down", struct{}{}, nil); err != nil {
		return err
	}
	fmt.Println("down")
	return nil
}

func getStatus(socket string) (daemon.Status, error) {
	var st daemon.Status
	err := call(socket, "GET", "/status", nil, &st)
	return st, err
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	jsonOut := fs.Bool("json", false, "raw JSON output")
	_ = fs.Parse(args)

	st, err := getStatus(*socket)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	if !st.Running {
		fmt.Println("not connected (overmesh up -server ... -key ... to join)")
		return nil
	}
	fmt.Printf("%s @ %s  [%s]\n", st.Hostname, st.Network, st.Conn)
	fmt.Printf("  self    %-16s %s\n", st.IPv4, st.IPv6)
	fmt.Printf("  iface   %s (%s engine)   server %s\n", st.Iface, st.Engine, st.Server)
	if st.Relay != "" {
		fmt.Printf("  relay   %s\n", st.Relay)
	}
	if st.Domain != "" {
		fmt.Printf("  dns     %s (peers reachable by bare hostname)\n", st.Domain)
	}
	if len(st.AdvertisedRoutes) > 0 {
		fmt.Printf("  routes  offering %s", strings.Join(st.AdvertisedRoutes, ", "))
		if len(st.ApprovedRoutes) > 0 {
			fmt.Printf("  (approved: %s)", strings.Join(st.ApprovedRoutes, ", "))
		} else {
			fmt.Print("  (none approved yet)")
		}
		fmt.Println()
	}
	if st.ExitNode != "" {
		state := "waiting for approval/peer"
		if st.ExitNodeActive {
			state = "active"
		}
		fmt.Printf("  exit    via %s [%s]\n", st.ExitNode, state)
	}
	if len(st.Peers) == 0 {
		fmt.Println("  no peers yet")
		return nil
	}
	fmt.Printf("\n  %-20s %-16s %-28s %-8s %s\n", "PEER", "IPV4", "IPV6", "STATE", "PATH")
	for _, p := range st.Peers {
		state := "offline"
		if p.Online {
			state = "online"
		}
		path := p.Path
		if p.Path == "direct" && p.Endpoint != "" {
			path = fmt.Sprintf("direct %s", p.Endpoint)
			if p.RTTms > 0 {
				path += fmt.Sprintf(" (%dms)", p.RTTms)
			}
		}
		if p.OffersExit {
			path += "  [exit node]"
		}
		if len(p.Routes) > 0 {
			path += "  [routes " + strings.Join(p.Routes, ",") + "]"
		}
		fmt.Printf("  %-20s %-16s %-28s %-8s %s\n", p.Hostname, p.IPv4, p.IPv6, state, path)
	}
	return nil
}

func cmdDrop(args []string) error {
	fs := flag.NewFlagSet("drop", flag.ExitOnError)
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	port := fs.Uint("port", overdrop.DefaultPort, "receiver port on the peer")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		return fmt.Errorf("usage: overmesh drop <file> <peer-hostname>")
	}
	file, target := fs.Arg(0), fs.Arg(1)

	st, err := getStatus(*socket)
	if err != nil {
		return err
	}
	var dstIP string
	for _, p := range st.Peers {
		if strings.EqualFold(p.Hostname, target) {
			dstIP = p.IPv4
			if !p.Online {
				return fmt.Errorf("%s is offline", p.Hostname)
			}
			break
		}
	}
	if dstIP == "" {
		return fmt.Errorf("no peer named %q (see overmesh status)", target)
	}
	dst, err := netip.ParseAddr(dstIP)
	if err != nil {
		return err
	}

	start := time.Now()
	var lastLine int
	err = overdrop.Send(dst, uint16(*port), file, func(sent, total int64) {
		pct := 0
		if total > 0 {
			pct = int(sent * 100 / total)
		}
		line := fmt.Sprintf("\r%s -> %s  %d%%  (%s / %s)", filepath.Base(file), target,
			pct, humanBytes(sent), humanBytes(total))
		fmt.Print(line)
		if pad := lastLine - len(line); pad > 0 {
			fmt.Print(strings.Repeat(" ", pad))
		}
		lastLine = len(line)
	})
	fmt.Println()
	if err != nil {
		return err
	}
	fmt.Printf("sent in %s\n", time.Since(start).Round(time.Millisecond))
	return nil
}

func cmdInbox(args []string) error {
	fs := flag.NewFlagSet("inbox", flag.ExitOnError)
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	_ = fs.Parse(args)

	var resp struct {
		Dir   string               `json:"dir"`
		Files []overdrop.InboxFile `json:"files"`
	}
	if err := call(*socket, "GET", "/inbox", nil, &resp); err != nil {
		return err
	}
	if resp.Dir == "" {
		fmt.Println("overdrop receiving is disabled on this daemon (-overdrop=false)")
		return nil
	}
	fmt.Printf("inbox: %s\n", resp.Dir)
	if len(resp.Files) == 0 {
		fmt.Println("  empty — files sent to this device with 'overmesh drop' land here")
		return nil
	}
	fmt.Printf("  %-20s %-34s %10s  %s\n", "FROM", "FILE", "SIZE", "STATE")
	for _, f := range resp.Files {
		state := "complete"
		if f.Partial {
			state = "partial (sender can resume)"
		}
		fmt.Printf("  %-20s %-34s %10s  %s\n", f.From, f.Name, humanBytes(f.Size), state)
	}
	return nil
}

func cmdRotateKey(args []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	_ = fs.Parse(args)
	if err := call(*socket, "POST", "/rotatekey", struct{}{}, nil); err != nil {
		return err
	}
	fmt.Println("node key rotated — peers pick the new key up within seconds")
	return nil
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func cmdPing(args []string) error {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	count := fs.Int("c", 4, "packet count")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: overmesh ping <peer-hostname|ip>")
	}
	target := fs.Arg(0)

	st, err := getStatus(*socket)
	if err != nil {
		return err
	}
	addr := target
	for _, p := range st.Peers {
		if strings.EqualFold(p.Hostname, target) {
			addr = p.IPv4
			break
		}
	}

	// Overlay reachability is exactly what the system ping measures once
	// the address routes into the WireGuard interface.
	ping, err := exec.LookPath("ping")
	if err != nil {
		return fmt.Errorf("no ping binary on PATH")
	}
	cmd := exec.Command(ping, "-c", fmt.Sprint(*count), addr)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}
