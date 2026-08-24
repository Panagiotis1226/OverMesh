// Command overmesh-relay is a standalone OMR relay: the same DERP-style
// forwarder that overmesh-server embeds, deployable independently for
// multi-region setups. Relays are stateless — run as many as you like and
// advertise them via the control plane's -relay-extra flag.
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/panagiotis1226/overmesh/internal/relay"
	"github.com/panagiotis1226/overmesh/internal/version"
)

func main() {
	var (
		listen      = flag.String("listen", ":3443", "HTTP listen address (relay served at /relay)")
		tlsCert     = flag.String("tls-cert", "", "TLS certificate file (with -tls-key, serve TLS)")
		tlsKey      = flag.String("tls-key", "", "TLS key file")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("overmesh-relay", version.Long())
		return
	}

	rs := relay.NewServer(log.Printf)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok overmesh-relay %s\n", version.Long())
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		st := rs.Stats()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "overmesh_build_info{version=%q} 1\n", version.Long())
		fmt.Fprintf(w, "overmesh_relay_clients %d\n", st.Clients)
		fmt.Fprintf(w, "overmesh_relay_frames_forwarded_total %d\n", st.FramesForwarded)
		fmt.Fprintf(w, "overmesh_relay_bytes_forwarded_total %d\n", st.BytesForwarded)
		fmt.Fprintf(w, "overmesh_relay_frames_dropped_total %d\n", st.FramesDropped)
	})
	mux.Handle(relay.UpgradePath, rs.Handler())

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var err error
	if *tlsCert != "" || *tlsKey != "" {
		cert, cerr := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
		if cerr != nil {
			log.Fatalf("loading TLS keypair: %v", cerr)
		}
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		log.Printf("overmesh-relay %s: listening on https://%s%s", version.Long(), *listen, relay.UpgradePath)
		err = srv.ListenAndServeTLS("", "")
	} else {
		log.Printf("overmesh-relay %s: listening on http://%s%s (WireGuard payloads stay end-to-end encrypted; TLS still recommended on the internet)", version.Long(), *listen, relay.UpgradePath)
		err = srv.ListenAndServe()
	}
	if !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
