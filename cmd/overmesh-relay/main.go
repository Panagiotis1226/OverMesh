// Command overmesh-relay is the standalone OMR relay (DERP-style).
// The relay protocol lands in Phase 3; the same code will also run
// embedded inside overmesh-server.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/panagiotis1226/overmesh/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("overmesh-relay", version.Long())
		return
	}
	log.Print("overmesh-relay ", version.Long())
	log.Print("the OMR relay protocol lands in Phase 3; this binary exists so packaging and CI cover it from day one")
	os.Exit(2)
}
