// Command overmesh is the user-facing CLI. It talks to the local
// overmeshd daemon (over a unix socket from Phase 1 on).
package main

import (
	"fmt"
	"os"

	"github.com/panagiotis1226/overmesh/internal/version"
)

const usage = `overmesh — self-hosted WireGuard mesh VPN

Usage:
  overmesh <command>

Commands:
  version   print the CLI version
  up        join a network            (Phase 1)
  status    show mesh state           (Phase 1)
  ping      ping a peer over the mesh (Phase 1)
  drop      send a file to a peer     (Phase 6)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version", "-version", "--version":
		fmt.Println("overmesh", version.Long())
	case "up", "status", "ping", "drop":
		fmt.Fprintf(os.Stderr, "overmesh %s: %q is planned but not implemented yet — see docs/PLAN.md for its phase\n", version.Long(), os.Args[1])
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}
