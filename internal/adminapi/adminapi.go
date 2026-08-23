// Package adminapi is the control plane's admin surface: session login
// plus the JSON API the embedded web UI (and scripts) drive — devices and
// setup keys in Phase 1, ACLs/DNS/routes in later phases.
package adminapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/panagiotis1226/overmesh/internal/coord"
	"github.com/panagiotis1226/overmesh/internal/filter"
	"github.com/panagiotis1226/overmesh/internal/store"
	"github.com/panagiotis1226/overmesh/internal/version"
)

const (
	sessionCookie    = "om_session"
	sessionTTL       = 12 * time.Hour
	legacyHashKey    = "admin_password_hash" // pre-Phase-7 single admin
	signupEnabledKey = "signup_enabled"
)

type session struct {
	user store.User
	exp  time.Time
}

// API serves the admin HTTP endpoints.
type API struct {
	st *store.Store
	c  *coord.Coordinator
	nw store.Network // Phase 1: the single default network

	mu       sync.Mutex
	sessions map[string]session // token -> identity + expiry
}

// New builds the API for the given (single, Phase 1) network.
func New(st *store.Store, c *coord.Coordinator, nw store.Network) *API {
	return &API{st: st, c: c, nw: nw, sessions: make(map[string]session)}
}

// EnsureAdminPassword guarantees a usable admin ACCOUNT exists.
// Explicit (the -admin-password flag) creates user "admin" or resets
// its password — the recovery path. Otherwise an existing admin
// account is kept; a pre-Phase-7 database migrates its single admin
// hash into user "admin"; a brand-new install gets a generated
// password logged once.
func EnsureAdminPassword(st *store.Store, explicit string) error {
	legacyHash := ""
	if h, err := st.Setting(legacyHashKey); err == nil {
		legacyHash = h
	}
	needGenerated, err := st.EnsureAdminUser(explicit, legacyHash)
	if err != nil {
		return err
	}
	if !needGenerated {
		return nil
	}
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	pw := hex.EncodeToString(raw)
	if _, err := st.CreateUser("admin", pw, store.RoleAdmin); err != nil {
		return err
	}
	log.Printf("adminapi: created user 'admin' with password: %s", pw)
	log.Printf("adminapi: (write it down — it is only shown once; restart with -admin-password to change it)")
	return nil
}

// Register mounts the API under /api/ on mux. Authorization model:
// members see and manage only what they own (devices, setup keys);
// everything network-shaping (ACLs, route approvals, users, signup
// toggle, audit) is admin-only.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("POST /api/signup", a.handleSignup)
	mux.HandleFunc("GET /api/authinfo", a.handleAuthInfo)
	mux.HandleFunc("POST /api/logout", a.handleLogout)
	mux.HandleFunc("GET /api/status", a.auth(a.handleStatus))
	mux.HandleFunc("GET /api/devices", a.auth(a.handleDevices))
	mux.HandleFunc("DELETE /api/devices/{id}", a.auth(a.handleDeleteDevice))
	mux.HandleFunc("GET /api/setupkeys", a.auth(a.handleSetupKeys))
	mux.HandleFunc("POST /api/setupkeys", a.auth(a.handleCreateSetupKey))
	mux.HandleFunc("DELETE /api/setupkeys/{id}", a.auth(a.handleRevokeSetupKey))
	mux.HandleFunc("PUT /api/devices/{id}/routes", a.admin(a.handleSetRouteApproval))
	mux.HandleFunc("GET /api/acl", a.admin(a.handleGetACL))
	mux.HandleFunc("PUT /api/acl", a.admin(a.handleSetACL))
	mux.HandleFunc("POST /api/acl/check", a.admin(a.handleCheckACL))
	mux.HandleFunc("GET /api/users", a.admin(a.handleUsers))
	mux.HandleFunc("POST /api/users", a.admin(a.handleCreateUser))
	mux.HandleFunc("PUT /api/users/{id}", a.admin(a.handleUpdateUser))
	mux.HandleFunc("DELETE /api/users/{id}", a.admin(a.handleDeleteUser))
	mux.HandleFunc("PUT /api/settings/signup", a.admin(a.handleSignupToggle))
	mux.HandleFunc("GET /api/audit", a.admin(a.handleAudit))
}

// --- users (admin only) ---

func (a *API) handleUsers(w http.ResponseWriter, r *http.Request, _ store.User) {
	users, err := a.st.Users()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if users == nil {
		users = []store.User{}
	}
	writeJSON(w, users)
}

func (a *API) handleCreateUser(w http.ResponseWriter, r *http.Request, actor store.User) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	if req.Role == "" {
		req.Role = store.RoleMember
	}
	u, err := a.st.CreateUser(req.Username, req.Password, req.Role)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = a.st.Audit(actor.Username, "user.create", u.Username, "role="+u.Role)
	writeJSON(w, u)
}

// handleUpdateUser changes role, disabled state, and/or password.
func (a *API) handleUpdateUser(w http.ResponseWriter, r *http.Request, actor store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad user id")
		return
	}
	var req struct {
		Role     *string `json:"role"`
		Disabled *bool   `json:"disabled"`
		Password *string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	target, err := a.st.UserByID(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "no such user")
		return
	}
	// Never let the last enabled admin lock everyone out.
	demoting := (req.Role != nil && *req.Role != store.RoleAdmin) ||
		(req.Disabled != nil && *req.Disabled)
	if target.Role == store.RoleAdmin && demoting {
		if n, _ := a.st.AdminCount(); n <= 1 {
			httpError(w, http.StatusConflict, "cannot demote or disable the last admin")
			return
		}
	}
	if req.Role != nil {
		if err := a.st.SetUserRole(id, *req.Role); err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = a.st.Audit(actor.Username, "user.role", target.Username, "role="+*req.Role)
	}
	if req.Disabled != nil {
		if err := a.st.SetUserDisabled(id, *req.Disabled); err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		action := "user.enable"
		if *req.Disabled {
			action = "user.disable"
		}
		_ = a.st.Audit(actor.Username, action, target.Username, "")
	}
	if req.Password != nil {
		if err := a.st.SetUserPassword(id, *req.Password); err != nil {
			httpError(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = a.st.Audit(actor.Username, "user.password-reset", target.Username, "")
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (a *API) handleDeleteUser(w http.ResponseWriter, r *http.Request, actor store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad user id")
		return
	}
	target, err := a.st.UserByID(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "no such user")
		return
	}
	if target.Role == store.RoleAdmin {
		if n, _ := a.st.AdminCount(); n <= 1 {
			httpError(w, http.StatusConflict, "cannot delete the last admin")
			return
		}
	}
	if err := a.st.DeleteUser(id); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = a.st.Audit(actor.Username, "user.delete", target.Username, "")
	writeJSON(w, map[string]any{"ok": true})
}

func (a *API) handleSignupToggle(w http.ResponseWriter, r *http.Request, actor store.User) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	v := "0"
	if req.Enabled {
		v = "1"
	}
	if err := a.st.SetSetting(signupEnabledKey, v); err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = a.st.Audit(actor.Username, "settings.signup", "", "enabled="+v)
	writeJSON(w, map[string]any{"ok": true, "enabled": req.Enabled})
}

func (a *API) handleAudit(w http.ResponseWriter, r *http.Request, _ store.User) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := a.st.AuditLog(limit)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	writeJSON(w, entries)
}

// --- access rules (the web UI is the editor; no config files) ---

func (a *API) handleGetACL(w http.ResponseWriter, r *http.Request, _ store.User) {
	rules, err := a.st.ACL(a.nw.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"rules": rules})
}

func (a *API) handleSetACL(w http.ResponseWriter, r *http.Request, actor store.User) {
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
	_ = a.st.Audit(actor.Username, "acl.save", "", fmt.Sprintf("%d rules", len(req.Rules)))
	writeJSON(w, map[string]any{"ok": true})
}

// handleCheckACL answers the dry-run tester using the exact filter the
// destination node would receive.
func (a *API) handleCheckACL(w http.ResponseWriter, r *http.Request, _ store.User) {
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

// signupEnabled reads the toggle (default off).
func (a *API) signupEnabled() bool {
	v, err := a.st.Setting(signupEnabledKey)
	return err == nil && v == "1"
}

// startSession issues a cookie-backed session for u.
func (a *API) startSession(w http.ResponseWriter, u store.User) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := hex.EncodeToString(raw)
	a.mu.Lock()
	a.gcSessionsLocked()
	a.sessions[token] = session{user: u, exp: time.Now().Add(sessionTTL)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	return nil
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	if req.Username == "" {
		// Pre-Phase-7 clients/scripts sent only a password; that was
		// always the admin.
		req.Username = "admin"
	}
	u, err := a.st.CheckPassword(req.Username, req.Password)
	if err != nil {
		// Constant small delay blunts online brute force a little.
		time.Sleep(500 * time.Millisecond)
		_ = a.st.Audit(req.Username, "login.failed", "", "")
		httpError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}
	if err := a.startSession(w, u); err != nil {
		httpError(w, http.StatusInternalServerError, "entropy failure")
		return
	}
	_ = a.st.Audit(u.Username, "login", "", "")
	writeJSON(w, map[string]any{"ok": true, "username": u.Username, "role": u.Role})
}

// handleSignup self-registers a member account — only when an admin
// has enabled the toggle.
func (a *API) handleSignup(w http.ResponseWriter, r *http.Request) {
	if !a.signupEnabled() {
		httpError(w, http.StatusNotFound, "signup is disabled on this server")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	u, err := a.st.CreateUser(req.Username, req.Password, store.RoleMember)
	if err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = a.st.Audit(u.Username, "user.signup", "", "")
	if err := a.startSession(w, u); err != nil {
		httpError(w, http.StatusInternalServerError, "entropy failure")
		return
	}
	writeJSON(w, map[string]any{"ok": true, "username": u.Username, "role": u.Role})
}

// handleAuthInfo is the one unauthenticated endpoint: the login page
// needs to know whether to offer signup.
func (a *API) handleAuthInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"signup_enabled": a.signupEnabled()})
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

// sessionUser resolves the request's account (ok=false: not logged in).
func (a *API) sessionUser(r *http.Request) (store.User, bool) {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return store.User{}, false
	}
	a.mu.Lock()
	s, ok := a.sessions[ck.Value]
	a.mu.Unlock()
	if !ok || time.Now().After(s.exp) {
		return store.User{}, false
	}
	return s.user, true
}

type userHandler func(w http.ResponseWriter, r *http.Request, u store.User)

// auth requires any logged-in account.
func (a *API) auth(next userHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := a.sessionUser(r)
		if !ok {
			httpError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		next(w, r, u)
	}
}

// admin requires an admin account.
func (a *API) admin(next userHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := a.sessionUser(r)
		if !ok {
			httpError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		if u.Role != store.RoleAdmin {
			httpError(w, http.StatusForbidden, "admin access required")
			return
		}
		next(w, r, u)
	}
}

func (a *API) gcSessionsLocked() {
	now := time.Now()
	for t, s := range a.sessions {
		if now.After(s.exp) {
			delete(a.sessions, t)
		}
	}
}

// --- handlers ---

func (a *API) handleStatus(w http.ResponseWriter, r *http.Request, u store.User) {
	domain := ""
	if a.c.DNSBase != "" {
		domain = a.nw.Name + "." + a.c.DNSBase
	}
	writeJSON(w, map[string]any{
		"version":        version.Long(),
		"network":        a.nw.Name,
		"v4_prefix":      a.nw.V4Prefix.String(),
		"v6_prefix":      a.nw.V6Prefix.String(),
		"dns_domain":     domain,
		"username":       u.Username,
		"role":           u.Role,
		"signup_enabled": a.signupEnabled(),
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
	// Advertised routes with approval state; a default route
	// (0.0.0.0/0 / ::/0) is an exit-node offer.
	Routes []store.Route `json:"routes"`
	// Owner is the username whose setup key enrolled the device
	// ("admin" for pre-account devices).
	Owner string `json:"owner"`
}

func (a *API) handleDevices(w http.ResponseWriter, r *http.Request, u store.User) {
	nodes, err := a.st.NodesInNetwork(a.nw.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	names := a.ownerNames(nodes)
	out := make([]deviceJSON, 0, len(nodes))
	for _, n := range nodes {
		// Members see only their own devices.
		if u.Role != store.RoleAdmin && n.OwnerUserID != u.ID {
			continue
		}
		d := deviceJSON{
			ID: n.ID, Hostname: n.Hostname,
			IPv4: n.IPv4.String(), IPv6: n.IPv6.String(),
			OS: n.OS, Online: a.c.Online(n.ID), Created: n.CreatedAt.Unix(),
			Owner: names[n.OwnerUserID],
		}
		if !n.LastSeen.IsZero() {
			d.LastSeen = n.LastSeen.Unix()
		}
		if routes, err := a.st.NodeRoutes(n.ID); err == nil {
			d.Routes = routes
		}
		out = append(out, d)
	}
	writeJSON(w, out)
}

// ownerNames maps the owner ids present in nodes to usernames.
func (a *API) ownerNames(nodes []store.Node) map[int64]string {
	names := map[int64]string{0: "admin"}
	for _, n := range nodes {
		if _, ok := names[n.OwnerUserID]; ok {
			continue
		}
		if u, err := a.st.UserByID(n.OwnerUserID); err == nil {
			names[n.OwnerUserID] = u.Username
		} else {
			names[n.OwnerUserID] = "?"
		}
	}
	return names
}

func (a *API) handleDeleteDevice(w http.ResponseWriter, r *http.Request, u store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad device id")
		return
	}
	n, err := a.st.NodeByID(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "no such device")
		return
	}
	if u.Role != store.RoleAdmin && n.OwnerUserID != u.ID {
		httpError(w, http.StatusForbidden, "not your device")
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
	_ = a.st.Audit(u.Username, "device.delete", n.Hostname, "")
	writeJSON(w, map[string]any{"ok": true})
}

// handleSetRouteApproval flips approval on one advertised route; the
// coordinator pushes new netmaps so the change is live immediately.
func (a *API) handleSetRouteApproval(w http.ResponseWriter, r *http.Request, actor store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad device id")
		return
	}
	var req struct {
		Route    string `json:"route"`
		Approved bool   `json:"approved"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpError(w, http.StatusBadRequest, "bad request body")
		return
	}
	if err := a.c.SetRouteApproved(id, req.Route, req.Approved); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpError(w, http.StatusNotFound, "no such device or route")
			return
		}
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	action := "route.revoke"
	if req.Approved {
		action = "route.approve"
	}
	_ = a.st.Audit(actor.Username, action, fmt.Sprintf("device#%d", id), req.Route)
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
	Owner     string `json:"owner"`
}

func (a *API) handleSetupKeys(w http.ResponseWriter, r *http.Request, u store.User) {
	keys, err := a.st.SetupKeys(a.nw.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	names := map[int64]string{0: "admin"}
	out := make([]setupKeyJSON, 0, len(keys))
	for _, k := range keys {
		// Members see only their own keys.
		if u.Role != store.RoleAdmin && k.OwnerUserID != u.ID {
			continue
		}
		if _, ok := names[k.OwnerUserID]; !ok {
			if ou, err := a.st.UserByID(k.OwnerUserID); err == nil {
				names[k.OwnerUserID] = ou.Username
			} else {
				names[k.OwnerUserID] = "?"
			}
		}
		j := setupKeyJSON{
			ID: k.ID, Key: k.Key, Reusable: k.Reusable, Revoked: k.Revoked,
			UsedCount: k.UsedCount, Created: k.CreatedAt.Unix(),
			Owner: names[k.OwnerUserID],
		}
		if !k.ExpiresAt.IsZero() {
			j.ExpiresAt = k.ExpiresAt.Unix()
			j.Expired = time.Now().After(k.ExpiresAt)
		}
		out = append(out, j)
	}
	writeJSON(w, out)
}

func (a *API) handleCreateSetupKey(w http.ResponseWriter, r *http.Request, u store.User) {
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
	k, err := a.st.NewSetupKey(a.nw.ID, req.Reusable, exp, u.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = a.st.Audit(u.Username, "setupkey.create", "", fmt.Sprintf("reusable=%v", req.Reusable))
	writeJSON(w, setupKeyJSON{
		ID: k.ID, Key: k.Key, Reusable: k.Reusable,
		ExpiresAt: unixOrZero(k.ExpiresAt), Created: k.CreatedAt.Unix(),
		Owner: u.Username,
	})
}

func (a *API) handleRevokeSetupKey(w http.ResponseWriter, r *http.Request, u store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, "bad key id")
		return
	}
	k, err := a.st.SetupKeyByID(id)
	if err != nil {
		httpError(w, http.StatusNotFound, "no such key")
		return
	}
	if u.Role != store.RoleAdmin && k.OwnerUserID != u.ID {
		httpError(w, http.StatusForbidden, "not your key")
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
	_ = a.st.Audit(u.Username, "setupkey.revoke", "", "")
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
