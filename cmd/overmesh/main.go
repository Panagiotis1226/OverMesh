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
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/panagiotis1226/overmesh/internal/daemon"
	"github.com/panagiotis1226/overmesh/internal/version"
)

const usage = `overmesh — self-hosted WireGuard mesh VPN

Usage:
  overmesh up -server <host:port> [-key sk-...]   join the mesh
  overmesh down                                   leave the mesh
  overmesh status                                 show self + peers
  overmesh ping <peer-hostname|ip> [-c N]         ping a peer over the overlay
  overmesh version

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
	case "drop":
		err = fmt.Errorf("overmesh drop arrives in Phase 6 (see docs/PLAN.md)")
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
	_ = fs.Parse(args)
	if *server == "" {
		return fmt.Errorf("-server is required")
	}
	var st daemon.Status
	if err := call(*socket, "POST", "/up", map[string]string{"server": *server, "key": *key}, &st); err != nil {
		return err
	}
	fmt.Printf("joined %q as %s\n  overlay: %s  %s\n", st.Network, st.Hostname, st.IPv4, st.IPv6)
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
		fmt.Printf("  %-20s %-16s %-28s %-8s %s\n", p.Hostname, p.IPv4, p.IPv6, state, path)
	}
	return nil
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
