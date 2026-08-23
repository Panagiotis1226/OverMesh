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
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	overmeshv1 "github.com/panagiotis1226/overmesh/gen/overmeshv1"
	"github.com/panagiotis1226/overmesh/internal/adminapi"
	"github.com/panagiotis1226/overmesh/internal/coord"
	"github.com/panagiotis1226/overmesh/internal/ipam"
	"github.com/panagiotis1226/overmesh/internal/store"
	"github.com/panagiotis1226/overmesh/internal/stunserver"
	"github.com/panagiotis1226/overmesh/internal/version"
	"github.com/panagiotis1226/overmesh/webui"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.httpAddr, "http", ":8080", "HTTP listen address (web UI + admin API)")
	flag.StringVar(&cfg.grpcAddr, "grpc", ":41641", "gRPC listen address for node coordination")
	flag.StringVar(&cfg.stunAddr, "stun", ":3478", "UDP listen address for the embedded STUN server (empty disables)")
	flag.StringVar(&cfg.stunAdvertise, "stun-advertise", "", "address nodes should use for STUN (default: control-plane host + stun port)")
	flag.StringVar(&cfg.extraStun, "stun-extra", "", "comma-separated additional STUN servers to advertise")
	flag.StringVar(&cfg.stateDir, "state-dir", "overmesh-server-data", "directory for the database")
	flag.StringVar(&cfg.adminPw, "admin-password", "", "set/rotate the admin password (otherwise kept, or generated and logged on first run)")
	flag.StringVar(&cfg.tlsCert, "tls-cert", "", "TLS certificate file; with -tls-key, gRPC and HTTP serve TLS")
	flag.StringVar(&cfg.tlsKey, "tls-key", "", "TLS key file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("overmesh-server", version.Long())
		return
	}
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

type config struct {
	httpAddr, grpcAddr      string
	stunAddr, stunAdvertise string
	extraStun               string
	stateDir, adminPw       string
	tlsCert, tlsKey         string
}

func run(cfg config) error {
	httpAddr, grpcAddr, stateDir, adminPw := cfg.httpAddr, cfg.grpcAddr, cfg.stateDir, cfg.adminPw
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

	// Embedded STUN server for NAT endpoint discovery.
	if cfg.stunAddr != "" {
		stun, err := stunserver.Listen(cfg.stunAddr, log.Printf)
		if err != nil {
			return err
		}
		defer stun.Close()
		advertise := cfg.stunAdvertise
		if advertise == "" {
			// Nodes substitute the control-plane host for an empty host
			// ("":3478" -> "<server-host>:3478").
			_, port, _ := net.SplitHostPort(cfg.stunAddr)
			advertise = ":" + port
		}
		c.StunServers = append(c.StunServers, advertise)
		log.Printf("overmesh-server: STUN on %s (advertised as %q)", cfg.stunAddr, advertise)
	}
	if cfg.extraStun != "" {
		for _, s := range strings.Split(cfg.extraStun, ",") {
			if s = strings.TrimSpace(s); s != "" {
				c.StunServers = append(c.StunServers, s)
			}
		}
	}

	// Optional TLS for both listeners (bring your own certificate; a
	// TLS-terminating reverse proxy works too).
	var tlsConf *tls.Config
	if cfg.tlsCert != "" || cfg.tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.tlsCert, cfg.tlsKey)
		if err != nil {
			return fmt.Errorf("loading TLS keypair: %w", err)
		}
		tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	} else {
		log.Print("overmesh-server: WARNING serving in the clear; use -tls-cert/-tls-key or a TLS reverse proxy when exposed to the internet")
	}

	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	// Clients ping every ~10s to detect dead paths after roaming; the
	// default enforcement (5 min) would GOAWAY them for it.
	grpcOpts := []grpc.ServerOption{
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if tlsConf != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConf)))
	}
	grpcSrv := grpc.NewServer(grpcOpts...)
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
		TLSConfig:         tlsConf,
	}

	scheme := "http"
	if tlsConf != nil {
		scheme = "https"
	}
	errc := make(chan error, 2)
	go func() {
		log.Printf("overmesh-server %s: gRPC coordination on %s (tls=%v)", version.Long(), grpcAddr, tlsConf != nil)
		errc <- grpcSrv.Serve(grpcLis)
	}()
	go func() {
		log.Printf("overmesh-server %s: web UI + API on %s://%s (network %q, %s + %s)",
			version.Long(), scheme, httpAddr, nw.Name, nw.V4Prefix, nw.V6Prefix)
		var err error
		if tlsConf != nil {
			err = httpSrv.ListenAndServeTLS("", "")
		} else {
			err = httpSrv.ListenAndServe()
		}
		if !errors.Is(err, http.ErrServerClosed) {
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
