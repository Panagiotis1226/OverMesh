package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/panagiotis1226/overmesh/internal/overdrop"
)

// DefaultSocketPath is where the daemon listens and the CLI connects,
// overridable on both via -socket. (Go supports AF_UNIX sockets on
// Windows 10 1803+.)
func DefaultSocketPath() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return pd + `\OverMesh\overmesh.sock`
	}
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
// (root-owned, 0600 by default): the local CLI is the intended client.
// groupName, when non-empty, makes the socket group-accessible (0660,
// chgrp) so GUI clients like the macOS menu bar app can talk to the
// daemon without sudo — members of that group fully control the mesh.
func (d *Daemon) ServeControl(socketPath, groupName string) error {
	// Refuse to steal a socket from a live daemon; clean up a dead one's.
	if _, err := os.Stat(socketPath); err == nil {
		if conn, err := net.Dial("unix", socketPath); err == nil {
			conn.Close()
			return fmt.Errorf("another overmeshd is already running on %s", socketPath)
		}
		_ = os.Remove(socketPath)
	}

	// The socket's parent directory may not exist yet (fresh install).
	if dir := filepath.Dir(socketPath); dir != "." {
		_ = os.MkdirAll(dir, 0o700)
	}
	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		// chmod/chown semantics don't carry over; ProgramData ACLs
		// already restrict writes to administrators.
		if groupName != "" {
			log.Print("overmeshd: -socket-group is not applicable on Windows (ignored)")
		}
	} else {
		mode := os.FileMode(0o600)
		if groupName != "" {
			g, err := user.LookupGroup(groupName)
			if err != nil {
				lis.Close()
				return fmt.Errorf("-socket-group %q: %w", groupName, err)
			}
			gid, err := strconv.Atoi(g.Gid)
			if err != nil {
				lis.Close()
				return fmt.Errorf("-socket-group %q: bad gid %q", groupName, g.Gid)
			}
			if err := os.Chown(socketPath, -1, gid); err != nil {
				lis.Close()
				return err
			}
			mode = 0o660
		}
		if err := os.Chmod(socketPath, mode); err != nil {
			lis.Close()
			return err
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.Status())
	})
	mux.HandleFunc("GET /netcheck", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, d.Netcheck())
	})
	mux.HandleFunc("POST /up", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Server          string   `json:"server"`
			Key             string   `json:"key"`
			AdvertiseRoutes []string `json:"advertise_routes"`
			ExitNode        string   `json:"exit_node"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		if req.Server == "" {
			httpErr(w, http.StatusBadRequest, "server address required")
			return
		}
		err := d.Up(UpConfig{
			Server:          req.Server,
			SetupKey:        req.Key,
			AdvertiseRoutes: req.AdvertiseRoutes,
			ExitNode:        req.ExitNode,
		})
		if err != nil {
			httpErr(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, d.Status())
	})
	mux.HandleFunc("POST /exitnode", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"` // "" turns the exit node off
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpErr(w, http.StatusBadRequest, "bad request body")
			return
		}
		if err := d.SetExitNode(req.Name); err != nil {
			httpErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, d.Status())
	})
	mux.HandleFunc("GET /inbox", func(w http.ResponseWriter, r *http.Request) {
		dir := d.InboxDir()
		if dir == "" {
			writeJSON(w, map[string]any{"dir": "", "files": []any{}})
			return
		}
		files, err := overdrop.ListInbox(dir)
		if err != nil {
			httpErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if files == nil {
			files = []overdrop.InboxFile{}
		}
		writeJSON(w, map[string]any{"dir": dir, "files": files})
	})
	mux.HandleFunc("POST /rotatekey", func(w http.ResponseWriter, r *http.Request) {
		if err := d.RotateNodeKey(); err != nil {
			httpErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
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
