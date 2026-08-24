package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/panagiotis1226/overmesh/internal/daemon"
	"github.com/panagiotis1226/overmesh/internal/version"
)

func getNetcheck(socket string) (daemon.NetcheckReport, error) {
	var rep daemon.NetcheckReport
	err := call(socket, "GET", "/netcheck", nil, &rep)
	return rep, err
}

func cmdNetcheck(args []string) error {
	fs := flag.NewFlagSet("netcheck", flag.ExitOnError)
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	jsonOut := fs.Bool("json", false, "raw JSON output")
	_ = fs.Parse(args)

	rep, err := getNetcheck(*socket)
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	okBad := func(ok bool, ms float64, detail string) string {
		if ok {
			return fmt.Sprintf("ok (%.1f ms)%s", ms, detail)
		}
		return "FAILED"
	}
	if rep.Server == "" {
		fmt.Println("not connected — join first (overmesh up), then netcheck probes the mesh's servers")
		return nil
	}
	fmt.Printf("control  %-40s %s\n", rep.Server, okBad(rep.ControlReachable, rep.ControlRTTMs, ""))
	if rep.ControlError != "" {
		fmt.Printf("         %s\n", rep.ControlError)
	}
	for _, s := range rep.Stun {
		if s.Error != "" {
			fmt.Printf("stun     %-40s FAILED: %s\n", s.Server, s.Error)
		} else {
			fmt.Printf("stun     %-40s ok (%.1f ms), public endpoint %s\n", s.Server, s.RTTMs, s.MappedAddr)
		}
	}
	if rep.UDPBlocked {
		fmt.Println("udp      BLOCKED — direct paths unlikely; traffic will use the relay's TCP fallback")
	} else if len(rep.Stun) > 0 {
		fmt.Println("udp      ok — direct WireGuard paths possible")
	}
	for _, r := range rep.Relays {
		if r.Error != "" {
			fmt.Printf("relay    %-40s FAILED: %s\n", r.URL, r.Error)
		} else {
			fmt.Printf("relay    %-40s %s\n", r.URL, okBad(r.Reachable, r.RTTMs, ""))
		}
	}
	return nil
}

// cmdBugreport prints a single self-contained diagnostic bundle for
// pasting into an issue. It contains no private keys: the daemon's
// Status and Netcheck are already secret-free.
func cmdBugreport(args []string) error {
	fs := flag.NewFlagSet("bugreport", flag.ExitOnError)
	socket := fs.String("socket", daemon.DefaultSocketPath(), "daemon control socket")
	outFile := fs.String("o", "", "write to a file instead of stdout")
	_ = fs.Parse(args)

	var b strings.Builder
	fmt.Fprintf(&b, "== overmesh bugreport ==\n")
	fmt.Fprintf(&b, "generated: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "cli: %s (%s/%s, %s)\n", version.Long(), runtime.GOOS, runtime.GOARCH, runtime.Version())
	if out, err := exec.Command("uname", "-a").Output(); err == nil {
		fmt.Fprintf(&b, "os: %s", out)
	}

	fmt.Fprintf(&b, "\n== status ==\n")
	if st, err := getStatus(*socket); err != nil {
		fmt.Fprintf(&b, "unavailable: %v\n", err)
	} else if data, err := json.MarshalIndent(st, "", "  "); err == nil {
		b.Write(data)
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "\n== netcheck ==\n")
	if rep, err := getNetcheck(*socket); err != nil {
		fmt.Fprintf(&b, "unavailable: %v\n", err)
	} else if data, err := json.MarshalIndent(rep, "", "  "); err == nil {
		b.Write(data)
		b.WriteString("\n")
	}

	if *outFile != "" {
		if err := os.WriteFile(*outFile, []byte(b.String()), 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", *outFile)
		return nil
	}
	fmt.Print(b.String())
	return nil
}
