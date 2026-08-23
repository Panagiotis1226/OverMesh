// Command overmeshd is the OverMesh node daemon: it registers with the
// control plane, keeps a netmap stream open, and programs WireGuard to
// match. It is driven by the overmesh CLI over a local unix socket.
//
// Needs root (TUN/netlink). Phase 1 talks to the control plane in the
// clear — LAN/trusted networks only; TLS lands in Phase 2.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/panagiotis1226/overmesh/internal/daemon"
	"github.com/panagiotis1226/overmesh/internal/version"
)

func main() {
	// Catch the classic mixup before flag parsing: CLI subcommands typed
	// at the daemon binary.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "up", "down", "status", "ping", "drop":
			fmt.Fprintf(os.Stderr, "overmeshd is the background daemon; did you mean:  overmesh %s\n", strings.Join(os.Args[1:], " "))
			os.Exit(2)
		}
	}

	var (
		stateDir    = flag.String("state-dir", defaultStateDir(), "directory for keys and session state")
		socket      = flag.String("socket", daemon.DefaultSocketPath(), "control socket path for the overmesh CLI")
		listenPort  = flag.Uint("port", 41642, "WireGuard UDP listen port")
		iface       = flag.String("iface", "overmesh0", "interface name (macOS always gets utunN)")
		wgMode      = flag.String("wg-mode", "auto", "WireGuard engine: auto (userspace + NAT traversal) | kernel (LAN/static only) | userspace")
		useTLS      = flag.Bool("tls", false, "connect to the control plane over TLS")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("overmeshd", version.Long())
		return
	}

	d, err := daemon.New(daemon.Options{
		StateDir:   *stateDir,
		ListenPort: uint16(*listenPort),
		IfaceName:  *iface,
		WGMode:     *wgMode,
		UseTLS:     *useTLS,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("overmeshd %s: control socket %s, state %s", version.Long(), *socket, *stateDir)
	d.MaybeAutoUp()

	// Tear the tunnel down cleanly on SIGINT/SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		log.Print("overmeshd: shutting down")
		_ = d.Down()
		os.Remove(*socket)
		os.Exit(0)
	}()

	if err := d.ServeControl(*socket); err != nil {
		log.Fatal(err)
	}
}

func defaultStateDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/overmesh"
	}
	home, _ := os.UserHomeDir()
	return home + "/.overmesh"
}
