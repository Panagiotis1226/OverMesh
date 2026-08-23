// Package adminapi is the control plane's admin surface: session login
// plus the JSON API the embedded web UI (and scripts) drive — devices and
// setup keys in Phase 1, ACLs/DNS/routes in later phases.
package adminapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/panagiotis1226/overmesh/internal/coord"
	"github.com/panagiotis1226/overmesh/internal/filter"
	"github.com/panagiotis1226/overmesh/internal/store"
	"github.com/panagiotis1226/overmesh/internal/version"
)

const (
	sessionCookie = "om_session"
	sessionTTL    = 12 * time.Hour
	adminHashKey  = "admin_password_hash"
)

// API serves the admin HTTP endpoints.
type API struct {
	st  *store.Store
	c   *coord.Coordinator
	nw  store.Network // Phase 1: the single default network

	mu       sync.Mutex
	sessions map[string]time.Time // token -> expiry
}

// New builds the API for the given (single, Phase 1) network.
func New(st *store.Store, c *coord.Coordinator, nw store.Network) *API {
	return &API{st: st, c: c, nw: nw, sessions: make(map[string]time.Time)}
}

// EnsureAdminPassword makes sure an admin password exists: uses explicit
// if non-empty (setting/rotating it), otherwise keeps the stored one,
// otherwise generates one and logs it once.
func EnsureAdminPassword(st *store.Store, explicit string) error {
	if explicit != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(explicit), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		return st.SetSetting(adminHashKey, string(hash))
	}
	if _, err := st.Setting(adminHashKey); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	pw := hex.EncodeToString(raw)
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := st.SetSetting(adminHashKey, string(hash)); err != nil {
		return err
	}
	log.Printf("adminapi: generated admin password: %s", pw)
	log.Printf("adminapi: (write it down — it is only shown once; restart with -admin-password to change it)")
	return nil
}

// Register mounts the API under /api/ on mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/logout", a.handleLogout)
	mux.HandleFunc("GET /api/status", a.auth(a.handleStatus))
	mux.HandleFunc("GET /api/devices", a.auth(a.handleDevices))
	mux.HandleFunc("DELETE /api/devices/{id}", a.auth(a.handleDeleteDevice))
	mux.HandleFunc("GET /api/setupkeys", a.auth(a.handleSetupKeys))
	mux.HandleFunc("POST /api/setupkeys", a.auth(a.handleCreateSetupKey))
	mux.HandleFunc("DELETE /api/setupkeys/{id}", a.auth(a.handleRevokeSetupKey))
	mux.HandleFunc("GET /api/acl", a.auth(a.handleGetACL))
	mux.HandleFunc("PUT /api/acl", a.auth(a.handleSetACL))
	mux.HandleFunc("POST /api/acl/check", a.auth(a.handleCheckACL))
}

// --- access rules (the web UI is the editor; no config files) ---

func (a *API) handleGetACL(w http.ResponseWriter, r *http.Request) {
	rules, err := a.st.ACL(a.nw.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"rules": rules})
}

func (a *API) handleSetACL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rules []store.ACLRule `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	for _, rule := range req.Rules {
		for _, spec := range rule.Ports {
			if _, err := coord.ParsePortSpec(spec); err != nil {
				httpError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		if len(rule.Ports) > 0 && rule.Protocol != "tcp" && rule.Protocol != "udp" {
			httpError(w, http.StatusBadRequest, "ports require protocol tcp or udp")
			return
		}
	}
	if err := a.st.SetACL(a.nw.ID, req.Rules); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Push recompiled filters to every connected node immediately.
	a.c.ACLChanged(a.nw.ID)
	writeJSON(w, map[string]any{"ok": true})
}

// handleCheckACL answers the dry-run tester using the exact filter the
// destination node would receive.
func (a *API) handleCheckACL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SrcID    int64  `json:"src_id"`
		DstID    int64  `json:"dst_id"`
		Protocol string `json:"protocol"` // tcp|udp|icmp
		Port     uint16 `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	src, err := a.c.NodeForCheck(req.SrcID)
	if err != nil {
		httpError(w, http.StatusNotFound, "unknown source device")
		return
	}
	dst, err := a.c.NodeForCheck(req.DstID)
	if err != nil {
		httpError(w, http.StatusNotFound, "unknown destination device")
		return
	}
	rules, enabled, err := a.c.CompileFilterForNode(dst)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	f := filter.FromProto(rules, enabled)
	allowed := f.Check(src.IPv4, req.Protocol, req.Port)
	writeJSON(w, map[string]any{"allowed": allowed})
}

// --- auth ---

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	hash, err := a.st.Setting(adminHashKey)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "admin password not initialized")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil {
		// Constant small delay blunts online brute force a little.
		time.Sleep(500 * time.Millisecond)
		httpError(w, http.StatusUnauthorized, "wrong password")
		return
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		httpError(w, http.StatusInternalServerError, "entropy failure")
		return
	}
	token := hex.EncodeToString(raw)
	a.mu.Lock()
	a.gcSessionsLocked()
	a.sessions[token] = time.Now().Add(sessionTTL)
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, map[string]any{"ok": true})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		delete(a.sessions, ck.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]any{"ok": true})
}

func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(sessionCookie)
		if err != nil {
			httpError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		a.mu.Lock()
		exp, ok := a.sessions[ck.Value]
		valid := ok && time.Now().Before(exp)
		a.mu.Unlock()
		if !valid {
			httpError(w, http.StatusUnauthorized, "session expired")
			return
		}
		next(w, r)
	}
}

func (a *API) gcSessionsLocked() {
	now := time.Now()
	for t, exp := range a.sessions {
		if now.After(exp) {
			delete(a.sessions, t)
		}
	}
}

// --- handlers ---

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request) {
	domain := ""
	if a.c.DNSBase != "" {
		domain = a.nw.Name + "." + a.c.DNSBase
	}
	writeJSON(w, map[string]any{
		"version":    version.Long(),
		"network":    a.nw.Name,
		"v4_prefix":  a.nw.V4Prefix.String(),
		"v6_prefix":  a.nw.V6Prefix.String(),
		"dns_domain": domain,
	})
}

type deviceJSON struct {
	ID       int64  `json:"id"`
	Hostname string `json:"hostname"`
	IPv4     string `json:"ipv4"`
	IPv6     string `json:"ipv6"`
	OS       string `json:"os"`
	Online   bool   `json:"online"`
	LastSeen int64  `json:"last_seen"` // unix seconds, 0 = never
	Created  int64  `json:"created"`
}

func (a *API) handleDevices(w http.ResponseWriter, r *http.Request) {
	nodes, err := a.st.NodesInNetwork(a.nw.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]deviceJSON, 0, len(nodes))
	for _, n := range nodes {
		d := deviceJSON{
			ID: n.ID, Hostname: n.Hostname,
			IPv4: n.IPv4.String(), IPv6: n.IPv6.String(),
			OS: n.OS, Online: a.c.Online(n.ID), Created: n.CreatedAt.Unix(),
		}
		if !n.LastSeen.IsZero() {
			d.LastSeen = n.LastSeen.Unix()
		}
		out = append(out, d)
	}
	writeJSON(w, out)
}

func (a *API) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad device id")
		return
	}
	if err := a.c.DeleteNode(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpError(w, http.StatusNotFound, "no such device")
			return
		}
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

type setupKeyJSON struct {
	ID        int64  `json:"id"`
	Key       string `json:"key"`
	Reusable  bool   `json:"reusable"`
	Revoked   bool   `json:"revoked"`
	Expired   bool   `json:"expired"`
	ExpiresAt int64  `json:"expires_at"` // unix seconds, 0 = never
	UsedCount int    `json:"used_count"`
	Created   int64  `json:"created"`
}

func (a *API) handleSetupKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := a.st.SetupKeys(a.nw.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]setupKeyJSON, 0, len(keys))
	for _, k := range keys {
		j := setupKeyJSON{
			ID: k.ID, Key: k.Key, Reusable: k.Reusable, Revoked: k.Revoked,
			UsedCount: k.UsedCount, Created: k.CreatedAt.Unix(),
		}
		if !k.ExpiresAt.IsZero() {
			j.ExpiresAt = k.ExpiresAt.Unix()
			j.Expired = time.Now().After(k.ExpiresAt)
		}
		out = append(out, j)
	}
	writeJSON(w, out)
}

func (a *API) handleCreateSetupKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reusable     bool `json:"reusable"`
		ExpiresHours int  `json:"expires_hours"` // 0 = never
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	var exp time.Time
	if req.ExpiresHours > 0 {
		exp = time.Now().Add(time.Duration(req.ExpiresHours) * time.Hour)
	}
	k, err := a.st.NewSetupKey(a.nw.ID, req.Reusable, exp)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, setupKeyJSON{
		ID: k.ID, Key: k.Key, Reusable: k.Reusable,
		ExpiresAt: unixOrZero(k.ExpiresAt), Created: k.CreatedAt.Unix(),
	})
}

func (a *API) handleRevokeSetupKey(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad key id")
		return
	}
	if err := a.st.RevokeSetupKey(id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpError(w, http.StatusNotFound, "no such key")
			return
		}
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// --- helpers ---

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": strings.TrimSpace(msg)})
}
