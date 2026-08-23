// Command overmeshd is the OverMesh node daemon.
//
// Phase 0 walking skeleton: -probe dials the control plane's gRPC endpoint
// and calls RegisterNode with freshly generated keys, expecting an
// Unimplemented answer — proving client → network → server → protobuf all
// work before Phase 1 implements real registration and WireGuard
// programming.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/key"
	"github.com/panagiotis1226/overmesh/internal/version"
)

func main() {
	var (
		server      = flag.String("server", "127.0.0.1:41641", "control plane gRPC address")
		probe       = flag.Bool("probe", false, "probe the control plane and exit (Phase 0 smoke test)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("overmeshd", version.Long())
		return
	}
	if !*probe {
		log.Print("overmeshd ", version.Long())
		log.Print("the long-running daemon arrives in Phase 1; for now run with -probe to smoke-test a control plane")
		os.Exit(2)
	}

	if err := runProbe(*server); err != nil {
		log.Fatal(err)
	}
}

func runProbe(server string) error {
	mk, err := key.NewMachine()
	if err != nil {
		return err
	}
	nk, err := key.NewNode()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()

	log.Printf("overmeshd %s probing control plane at %s", version.Long(), server)
	log.Printf("machine key: %s", mk.Public())
	log.Printf("node key:    %s", nk.Public())

	// Phase 0 runs in the clear on localhost; TLS to the control plane
	// lands with real registration in Phase 1.
	conn, err := grpc.NewClient(server, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := overmeshv1.NewCoordinationServiceClient(conn)
	_, err = client.RegisterNode(ctx, &overmeshv1.RegisterNodeRequest{
		MachineKey:    mk.Public().Bytes(),
		NodeKey:       nk.Public().Bytes(),
		Hostname:      hostname,
		Os:            runtime.GOOS,
		ClientVersion: version.Long(),
	})
	switch status.Code(err) {
	case codes.Unimplemented:
		log.Print("control plane reachable ✔ (RegisterNode answered Unimplemented — real registration lands in Phase 1)")
		return nil
	case codes.OK:
		log.Print("control plane reachable ✔ (RegisterNode succeeded)")
		return nil
	default:
		return fmt.Errorf("control plane unreachable: %w", err)
	}
}
