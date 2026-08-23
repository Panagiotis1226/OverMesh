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
	"runtime"
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
		socketGroup = flag.String("socket-group", "", "make the control socket group-accessible (e.g. 'admin' on macOS for the menu bar app)")
		listenPort  = flag.Uint("port", 41642, "WireGuard UDP listen port")
		iface       = flag.String("iface", "overmesh0", "interface name (macOS always gets utunN)")
		wgMode      = flag.String("wg-mode", "auto", "WireGuard engine: auto (userspace + NAT traversal) | kernel (fastest; LAN/static-endpoint servers, e.g. dedicated exit nodes)")
		mtu         = flag.Int("mtu", 0, "tunnel MTU (default 1280 = safe anywhere; 1420 on a normal 1500 underlay for more throughput)")
		overdropOn  = flag.Bool("overdrop", true, "receive files sent with 'overmesh drop'")
		overdropDir = flag.String("overdrop-dir", "", "OverDrop inbox directory (default <state-dir>/overdrop)")
		useTLS      = flag.Bool("tls", false, "connect to the control plane over TLS")
		serviceCmd  = flag.String("service", "", "Windows service control: install|uninstall|start|stop")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("overmeshd", version.Long())
		return
	}
	if *serviceCmd != "" {
		if err := serviceCommand(*serviceCmd); err != nil {
			log.Fatal(err)
		}
		return
	}

	d, err := daemon.New(daemon.Options{
		StateDir:    *stateDir,
		ListenPort:  uint16(*listenPort),
		IfaceName:   *iface,
		WGMode:      *wgMode,
		MTU:         *mtu,
		UseTLS:      *useTLS,
		OverdropOff: !*overdropOn,
		OverdropDir: *overdropDir,
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("overmeshd %s: control socket %s, state %s", version.Long(), *socket, *stateDir)

	start := func() {
		d.MaybeAutoUp()
		if err := d.ServeControl(*socket, *socketGroup); err != nil {
			log.Fatal(err)
		}
	}
	shutdown := func() {
		log.Print("overmeshd: shutting down")
		_ = d.Down()
		os.Remove(*socket)
		os.Exit(0)
	}

	// Launched by the Windows service manager? Run under its control.
	if runAsServiceIfNeeded(start, shutdown) {
		return
	}

	// Console run: tear the tunnel down cleanly on SIGINT/SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		shutdown()
	}()
	start()
}

func defaultStateDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return pd + `\OverMesh`
	}
	if os.Geteuid() == 0 {
		return "/var/lib/overmesh"
	}
	home, _ := os.UserHomeDir()
	return home + "/.overmesh"
}
