// Command om-mobileharness exercises internal/mobilecore exactly the
// way a mobile app does — but on Linux, where CI can prove the whole
// path: it opens a TUN fd itself (the platform normally does this),
// hands the fd to mobilecore, and programs addresses/routes from the
// OnNetMap callback like an iOS packet-tunnel provider would.
//
// linux-only test scaffolding; not shipped.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/panagiotis1226/overmesh/internal/mobilecore"
)

type events struct {
	tunName string
	core    *mobilecore.Core
}

func (e *events) OnState(state string) { log.Printf("harness: state=%s", state) }

// OnNetMap: do what NEPacketTunnelNetworkSettings does — addresses,
// routes, DNS — then confirm to the core.
func (e *events) OnNetMap(netmapJSON string) {
	log.Printf("harness: netmap settings: %s", netmapJSON)
	var s struct {
		IPv4       string   `json:"ipv4"`
		IPv4Prefix int      `json:"ipv4_prefix"`
		IPv6       string   `json:"ipv6"`
		IPv6Prefix int      `json:"ipv6_prefix"`
		Routes     []string `json:"routes"`
		MTU        int      `json:"mtu"`
	}
	if err := json.Unmarshal([]byte(netmapJSON), &s); err != nil {
		log.Printf("harness: bad netmap json: %v", err)
		return
	}
	run := func(args ...string) {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			msg := strings.TrimSpace(string(out))
			if !strings.Contains(msg, "File exists") {
				log.Printf("harness: ip %v: %v: %s", args, err, msg)
			}
		}
	}
	run("addr", "replace", fmt.Sprintf("%s/32", s.IPv4), "dev", e.tunName)
	run("-6", "addr", "replace", fmt.Sprintf("%s/128", s.IPv6), "dev", e.tunName)
	run("link", "set", e.tunName, "up", "mtu", fmt.Sprint(s.MTU))
	for _, r := range s.Routes {
		if strings.Contains(r, ":") {
			run("-6", "route", "replace", r, "dev", e.tunName)
		} else {
			run("route", "replace", r, "dev", e.tunName)
		}
	}
	log.Print("harness: settings applied")
	e.core.NetworkSettingsApplied()
}

// openTUN opens /dev/net/tun and attaches name (IFF_TUN|IFF_NO_PI) —
// the part iOS/Android do for the app.
func openTUN(name string) (int, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return -1, err
	}
	var ifr [unix.IFNAMSIZ + 64]byte
	copy(ifr[:], name)
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF,
		uintptr(unsafe.Pointer(&ifr[0]))); errno != 0 {
		unix.Close(fd)
		return -1, errno
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func main() {
	var (
		stateDir   = flag.String("state-dir", "", "identity/state directory")
		server     = flag.String("server", "", "control plane host:port")
		key        = flag.String("key", "", "setup key")
		hostname   = flag.String("hostname", "mobile-sim", "device name")
		tunName    = flag.String("tun", "omtun0", "tun interface name")
		statusFile = flag.String("status-file", "", "write StatusJSON here every 2s")
	)
	flag.Parse()
	if *stateDir == "" || *server == "" {
		log.Fatal("need -state-dir and -server")
	}

	fd, err := openTUN(*tunName)
	if err != nil {
		log.Fatalf("open tun: %v", err)
	}

	core, err := mobilecore.NewCore(*stateDir)
	if err != nil {
		log.Fatal(err)
	}
	ev := &events{tunName: *tunName, core: core}
	cfg, _ := json.Marshal(map[string]any{
		"server": *server, "setup_key": *key, "hostname": *hostname,
	})
	if err := core.Start(string(cfg), fd, ev); err != nil {
		log.Fatalf("start: %v", err)
	}
	log.Printf("harness: started as %q", core.Hostname())

	go func() {
		for {
			time.Sleep(2 * time.Second)
			if *statusFile != "" {
				_ = os.WriteFile(*statusFile, []byte(core.StatusJSON()), 0o644)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	core.Stop()
	log.Print("harness: stopped")
}
