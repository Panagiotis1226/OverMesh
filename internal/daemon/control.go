package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
)

// DefaultSocketPath is where the daemon listens and the CLI connects,
// overridable on both via -socket.
func DefaultSocketPath() string {
	if runtime.GOOS == "darwin" {
		return "/var/run/overmesh.sock"
	}
	if os.Geteuid() == 0 {
		return "/run/overmesh.sock"
	}
	home, _ := os.UserHomeDir()
	return home + "/.overmesh/overmesh.sock"
}

// ServeControl exposes the daemon's control API on a unix socket
// (root-owned, 0600): the local CLI is the only intended client.
func (d *Daemon) ServeControl(socketPath string) error {
	// Refuse to steal a socket from a live daemon; clean up a dead one's.
	if _, err := os.Stat(socketPath); err == nil {
		if conn, err := net.Dial("unix", socketPath); err == nil {
			conn.Close()
			return fmt.Errorf("another overmeshd is already running on %s", socketPath)
		}
		_ = os.Remove(socketPath)
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		lis.Close()
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.Status())
	})
	mux.HandleFunc("POST /up", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Server string `json:"server"`
			Key    string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		if req.Server == "" {
			httpErr(w, http.StatusBadRequest, "server address required")
			return
		}
		if err := d.Up(req.Server, req.Key); err != nil {
			httpErr(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, d.Status())
	})
	mux.HandleFunc("POST /down", func(w http.ResponseWriter, r *http.Request) {
		if err := d.Down(); err != nil {
			httpErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})

	srv := &http.Server{Handler: mux}
	err = srv.Serve(lis)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
