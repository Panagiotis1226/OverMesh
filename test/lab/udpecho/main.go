// Command om-lab-udpecho is the NAT lab's mapping observer — a mini STUN.
//
// Server mode listens on two UDP ports and answers every datagram with the
// source "ip:port" it observed. Probe mode sends to both ports from ONE
// socket and compares the two observed mappings:
//
//   - same mapping for both destinations  -> endpoint-independent mapping
//     (cone NAT: holepunching will work)
//   - different mappings                  -> endpoint-dependent mapping
//     (symmetric NAT: direct holepunching won't work, relay needed)
//
// This is exactly the distinction Phase 2's real NAT traversal cares
// about, so the lab verifies it from day one.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		listen = flag.String("listen", "", "server mode: comma-separated UDP addresses to listen on")
		probe  = flag.String("probe", "", "probe mode: comma-separated UDP server addresses to probe")
	)
	flag.Parse()

	switch {
	case *listen != "":
		runServer(strings.Split(*listen, ","))
	case *probe != "":
		if err := runProbe(strings.Split(*probe, ",")); err != nil {
			log.Fatal(err)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: om-lab-udpecho -listen a:p,a:p | -probe a:p,a:p")
		os.Exit(2)
	}
}

func runServer(addrs []string) {
	for _, a := range addrs {
		conn, err := net.ListenPacket("udp", strings.TrimSpace(a))
		if err != nil {
			log.Fatalf("listen %s: %v", a, err)
		}
		log.Printf("udpecho listening on %s", conn.LocalAddr())
		go func(c net.PacketConn) {
			buf := make([]byte, 1500)
			for {
				n, src, err := c.ReadFrom(buf)
				if err != nil {
					return
				}
				_ = n
				if _, err := c.WriteTo([]byte(src.String()), src); err != nil {
					log.Printf("reply to %s: %v", src, err)
				}
			}
		}(conn)
	}
	select {}
}

func runProbe(addrs []string) error {
	// One socket for all probes: mapping differences across destinations
	// are then the NAT's doing, not ours.
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}
	defer conn.Close()

	mappings := make([]string, 0, len(addrs))
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		dst, err := net.ResolveUDPAddr("udp", a)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", a, err)
		}

		var mapped string
		// A few retries: first datagram through a fresh conntrack entry
		// can race the reply timeout on slow CI machines.
		for attempt := 0; attempt < 3 && mapped == ""; attempt++ {
			if _, err := conn.WriteTo([]byte("probe"), dst); err != nil {
				return fmt.Errorf("send to %s: %w", a, err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1500)
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			if from.String() != dst.String() {
				continue // stray datagram
			}
			mapped = string(buf[:n])
		}
		if mapped == "" {
			return fmt.Errorf("no reply from %s", a)
		}
		fmt.Printf("mapped@%s=%s\n", a, mapped)
		mappings = append(mappings, mapped)
	}

	verdict := "endpoint-independent"
	for _, m := range mappings[1:] {
		if m != mappings[0] {
			verdict = "endpoint-dependent"
		}
	}
	fmt.Printf("verdict=%s\n", verdict)
	return nil
}
