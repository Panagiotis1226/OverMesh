// Command overmesh-server is the OverMesh control plane.
//
// Phase 0 walking skeleton: serves HTTP (/healthz and a placeholder index)
// and a gRPC CoordinationService whose methods answer Unimplemented. This
// proves the whole toolchain — protobuf, gRPC plumbing, binary packaging —
// end to end before Phase 1 adds real registration and netmaps.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/version"
)

func main() {
	var (
		httpAddr    = flag.String("http", ":8080", "HTTP listen address (health, and the web UI from Phase 1)")
		grpcAddr    = flag.String("grpc", ":41641", "gRPC listen address for node coordination")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("overmesh-server", version.Long())
		return
	}

	if err := run(*httpAddr, *grpcAddr); err != nil {
		log.Fatal(err)
	}
}

func run(httpAddr, grpcAddr string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// gRPC: register the generated service so clients get a proper
	// Unimplemented status instead of a connection error.
	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	grpcSrv := grpc.NewServer()
	overmeshv1.RegisterCoordinationServiceServer(grpcSrv, overmeshv1.UnimplementedCoordinationServiceServer{})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok overmesh-server %s\n", version.Long())
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "OverMesh control plane %s\nWeb UI arrives in Phase 1.\n", version.Long())
	})
	httpSrv := &http.Server{
		Addr:              httpAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 2)
	go func() {
		log.Printf("overmesh-server %s: gRPC coordination on %s", version.Long(), grpcAddr)
		errc <- grpcSrv.Serve(grpcLis)
	}()
	go func() {
		log.Printf("overmesh-server %s: HTTP on %s (try /healthz)", version.Long(), httpAddr)
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errc <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Print("shutting down")
	case err := <-errc:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	grpcSrv.GracefulStop()
	return nil
}
