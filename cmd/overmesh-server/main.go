// Command overmesh-server is the OverMesh control plane: node
// registration and netmap coordination over gRPC, plus the admin API and
// embedded web UI over HTTP.
//
// Phase 1 listens in the clear — fine on a trusted LAN or behind a TLS
// reverse proxy. Native TLS for both listeners lands in Phase 2 alongside
// internet-facing NAT traversal.
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
	"path/filepath"
	"syscall"
	"time"

	"google.golang.org/grpc"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/adminapi"
	"github.com/panagiotis1226/overmesh/internal/coord"
	"github.com/panagiotis1226/overmesh/internal/ipam"
	"github.com/panagiotis1226/overmesh/internal/store"
	"github.com/panagiotis1226/overmesh/internal/version"
	"github.com/panagiotis1226/overmesh/webui"
)

func main() {
	var (
		httpAddr    = flag.String("http", ":8080", "HTTP listen address (web UI + admin API)")
		grpcAddr    = flag.String("grpc", ":41641", "gRPC listen address for node coordination")
		stateDir    = flag.String("state-dir", "overmesh-server-data", "directory for the database")
		adminPw     = flag.String("admin-password", "", "set/rotate the admin password (otherwise kept, or generated and logged on first run)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("overmesh-server", version.Long())
		return
	}
	if err := run(*httpAddr, *grpcAddr, *stateDir, *adminPw); err != nil {
		log.Fatal(err)
	}
}

func run(httpAddr, grpcAddr, stateDir, adminPw string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(stateDir, "server.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	nw, err := st.EnsureNetwork("default", ipam.DefaultIPv4Prefix, ipam.DefaultIPv6Prefix)
	if err != nil {
		return err
	}
	if err := adminapi.EnsureAdminPassword(st, adminPw); err != nil {
		return err
	}
	c, err := coord.New(st)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	grpcSrv := grpc.NewServer()
	overmeshv1.RegisterCoordinationServiceServer(grpcSrv, &coord.Service{C: c})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok overmesh-server %s\n", version.Long())
	})
	adminapi.New(st, c, nw).Register(mux)
	mux.Handle("/", webui.Handler())

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
		log.Printf("overmesh-server %s: web UI + API on http://%s (network %q, %s + %s)",
			version.Long(), httpAddr, nw.Name, nw.V4Prefix, nw.V6Prefix)
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
