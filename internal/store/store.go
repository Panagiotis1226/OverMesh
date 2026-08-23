// Package store is the control plane's persistence layer: a single SQLite
// database (pure-Go driver, so every binary stays CGO-free and
// cross-compilable). Postgres support arrives with the HA work in a later
// phase.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// ErrNotFound is returned when a lookup matches nothing.
var ErrNotFound = errors.New("store: not found")

const schema = `
CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS networks (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT UNIQUE NOT NULL,
  v4_prefix  TEXT NOT NULL,
  v6_prefix  TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  network_id  INTEGER NOT NULL REFERENCES networks(id),
  hostname    TEXT NOT NULL,
  machine_key TEXT UNIQUE NOT NULL,
  node_key    TEXT NOT NULL,
  ipv4        TEXT NOT NULL,
  ipv6        TEXT NOT NULL,
  os          TEXT NOT NULL DEFAULT '',
  endpoints   TEXT NOT NULL DEFAULT '[]',
  created_at  INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS setup_keys (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  network_id INTEGER NOT NULL REFERENCES networks(id),
  key        TEXT UNIQUE NOT NULL,
  reusable   INTEGER NOT NULL DEFAULT 1,
  revoked    INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL DEFAULT 0,
  used_count INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
`

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// Network is a mesh network (Phase 1 auto-creates one named "default").
type Network struct {
	ID       int64
	Name     string
	V4Prefix netip.Prefix
	V6Prefix netip.Prefix
}

// Node is a registered device.
type Node struct {
	ID         int64
	NetworkID  int64
	Hostname   string
	MachineKey string // "mkey:<hex>"
	NodeKey    string // "nodekey:<hex>"
	IPv4       netip.Addr
	IPv6       netip.Addr
	OS         string
	Endpoints  []string
	CreatedAt  time.Time
	LastSeen   time.Time
	// OwnerUserID is the account whose setup key enrolled the device
	// (0 = legacy/unowned; only admins see those).
	OwnerUserID int64
}

// SetupKey is a pre-auth key that lets a device join a network.
type SetupKey struct {
	ID        int64
	NetworkID int64
	Key       string
	Reusable  bool
	Revoked   bool
	ExpiresAt time.Time // zero = never
	UsedCount int
	CreatedAt time.Time
	// OwnerUserID: devices enrolled with this key belong to this
	// account (0 = legacy/admin).
	OwnerUserID int64
}

// Open opens (creating if needed) the database at path.
func Open(path string) (*Store, error) {
	// _pragma busy_timeout keeps concurrent gRPC/HTTP handlers from
	// tripping over SQLITE_BUSY; WAL lets readers run during writes.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	// modernc/sqlite serializes writes; a single connection avoids
	// SQLITE_BUSY entirely at Phase-1 scale.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema + aclSchema + routesSchema + usersSchema + auditSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating schema: %w", err)
	}
	return &Store{db: db}, nil
}

// migrate applies additive column changes to databases created by
// earlier phases. SQLite has no ADD COLUMN IF NOT EXISTS, so probe.
func migrate(db *sql.DB) error {
	for _, m := range []struct{ table, column, ddl string }{
		{"nodes", "owner_user_id",
			`ALTER TABLE nodes ADD COLUMN owner_user_id INTEGER NOT NULL DEFAULT 0`},
		{"setup_keys", "owner_user_id",
			`ALTER TABLE setup_keys ADD COLUMN owner_user_id INTEGER NOT NULL DEFAULT 0`},
	} {
		var n int
		err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`,
			m.table, m.column).Scan(&n)
		if err != nil {
			return err
		}
		if n == 0 {
			if _, err := db.Exec(m.ddl); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// --- settings ---

// Setting returns the value for key, or ErrNotFound.
func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

// SetSetting inserts or updates a setting.
func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// --- networks ---

// EnsureNetwork returns the network with name, creating it with the given
// prefixes if it does not exist.
func (s *Store) EnsureNetwork(name string, v4, v6 netip.Prefix) (Network, error) {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO networks (name, v4_prefix, v6_prefix, created_at)
		VALUES (?, ?, ?, ?)`, name, v4.String(), v6.String(), time.Now().Unix())
	if err != nil {
		return Network{}, err
	}
	return s.NetworkByName(name)
}

// NetworkByName looks a network up by name.
func (s *Store) NetworkByName(name string) (Network, error) {
	var n Network
	var v4s, v6s string
	err := s.db.QueryRow(`SELECT id, name, v4_prefix, v6_prefix FROM networks WHERE name = ?`, name).
		Scan(&n.ID, &n.Name, &v4s, &v6s)
	if errors.Is(err, sql.ErrNoRows) {
		return n, ErrNotFound
	}
	if err != nil {
		return n, err
	}
	return n, parsePrefixes(&n, v4s, v6s)
}

// NetworkByID looks a network up by ID.
func (s *Store) NetworkByID(id int64) (Network, error) {
	var n Network
	var v4s, v6s string
	err := s.db.QueryRow(`SELECT id, name, v4_prefix, v6_prefix FROM networks WHERE id = ?`, id).
		Scan(&n.ID, &n.Name, &v4s, &v6s)
	if errors.Is(err, sql.ErrNoRows) {
		return n, ErrNotFound
	}
	if err != nil {
		return n, err
	}
	return n, parsePrefixes(&n, v4s, v6s)
}

func parsePrefixes(n *Network, v4s, v6s string) error {
	var err error
	if n.V4Prefix, err = netip.ParsePrefix(v4s); err != nil {
		return fmt.Errorf("network %s: bad v4 prefix: %w", n.Name, err)
	}
	if n.V6Prefix, err = netip.ParsePrefix(v6s); err != nil {
		return fmt.Errorf("network %s: bad v6 prefix: %w", n.Name, err)
	}
	return nil
}

// --- nodes ---

// CreateNode inserts a new node and returns it with its assigned ID.
func (s *Store) CreateNode(n Node) (Node, error) {
	eps, _ := json.Marshal(n.Endpoints)
	if n.Endpoints == nil {
		eps = []byte("[]")
	}
	now := time.Now()
	res, err := s.db.Exec(`INSERT INTO nodes
		(network_id, hostname, machine_key, node_key, ipv4, ipv6, os, endpoints, created_at, last_seen, owner_user_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
		n.NetworkID, n.Hostname, n.MachineKey, n.NodeKey,
		n.IPv4.String(), n.IPv6.String(), n.OS, string(eps), now.Unix(), n.OwnerUserID)
	if err != nil {
		return Node{}, err
	}
	n.ID, _ = res.LastInsertId()
	n.CreatedAt = now
	return n, nil
}

// NodeByMachineKey returns the node registered with the given machine key.
func (s *Store) NodeByMachineKey(mkey string) (Node, error) {
	return s.scanNode(`SELECT ` + nodeCols + ` FROM nodes WHERE machine_key = ?`, mkey)
}

// NodeByID returns the node with the given ID.
func (s *Store) NodeByID(id int64) (Node, error) {
	return s.scanNode(`SELECT ` + nodeCols + ` FROM nodes WHERE id = ?`, id)
}

const nodeCols = `id, network_id, hostname, machine_key, node_key, ipv4, ipv6, os, endpoints, created_at, last_seen, owner_user_id`

func (s *Store) scanNode(q string, args ...any) (Node, error) {
	var n Node
	var ipv4, ipv6, eps string
	var created, seen int64
	err := s.db.QueryRow(q, args...).Scan(&n.ID, &n.NetworkID, &n.Hostname, &n.MachineKey,
		&n.NodeKey, &ipv4, &ipv6, &n.OS, &eps, &created, &seen, &n.OwnerUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return n, ErrNotFound
	}
	if err != nil {
		return n, err
	}
	return n, hydrateNode(&n, ipv4, ipv6, eps, created, seen)
}

func hydrateNode(n *Node, ipv4, ipv6, eps string, created, seen int64) error {
	var err error
	if n.IPv4, err = netip.ParseAddr(ipv4); err != nil {
		return fmt.Errorf("node %d: bad ipv4: %w", n.ID, err)
	}
	if n.IPv6, err = netip.ParseAddr(ipv6); err != nil {
		return fmt.Errorf("node %d: bad ipv6: %w", n.ID, err)
	}
	if err := json.Unmarshal([]byte(eps), &n.Endpoints); err != nil {
		n.Endpoints = nil
	}
	n.CreatedAt = time.Unix(created, 0)
	if seen > 0 {
		n.LastSeen = time.Unix(seen, 0)
	}
	return nil
}

// NodesInNetwork lists all nodes in a network.
func (s *Store) NodesInNetwork(networkID int64) ([]Node, error) {
	rows, err := s.db.Query(`SELECT `+nodeCols+` FROM nodes WHERE network_id = ? ORDER BY id`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Node
	for rows.Next() {
		var n Node
		var ipv4, ipv6, eps string
		var created, seen int64
		if err := rows.Scan(&n.ID, &n.NetworkID, &n.Hostname, &n.MachineKey, &n.NodeKey,
			&ipv4, &ipv6, &n.OS, &eps, &created, &seen, &n.OwnerUserID); err != nil {
			return nil, err
		}
		if err := hydrateNode(&n, ipv4, ipv6, eps, created, seen); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteNode removes a node.
func (s *Store) DeleteNode(id int64) error {
	res, err := s.db.Exec(`DELETE FROM nodes WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateNodeEndpoints replaces a node's reported endpoints.
func (s *Store) UpdateNodeEndpoints(id int64, endpoints []string) error {
	eps, _ := json.Marshal(endpoints)
	if endpoints == nil {
		eps = []byte("[]")
	}
	_, err := s.db.Exec(`UPDATE nodes SET endpoints = ? WHERE id = ?`, string(eps), id)
	return err
}

// UpdateNodeIPv6 sets a node's IPv6 address (assigned after insert, since
// it derives from the row ID).
func (s *Store) UpdateNodeIPv6(id int64, addr netip.Addr) error {
	_, err := s.db.Exec(`UPDATE nodes SET ipv6 = ? WHERE id = ?`, addr.String(), id)
	return err
}

// UpdateNodeOnRegister refreshes the mutable fields a re-registration may change.
func (s *Store) UpdateNodeOnRegister(id int64, nodeKey, hostname, osName string) error {
	_, err := s.db.Exec(`UPDATE nodes SET node_key = ?, hostname = ?, os = ? WHERE id = ?`,
		nodeKey, hostname, osName, id)
	return err
}

// TouchNode updates last_seen to now.
func (s *Store) TouchNode(id int64) error {
	_, err := s.db.Exec(`UPDATE nodes SET last_seen = ? WHERE id = ?`, time.Now().Unix(), id)
	return err
}

// HostnameTaken reports whether a hostname is already used in the network.
func (s *Store) HostnameTaken(networkID int64, hostname string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM nodes WHERE network_id = ? AND hostname = ?`,
		networkID, hostname).Scan(&n)
	return n > 0, err
}

// --- setup keys ---

// NewSetupKey generates, stores, and returns a fresh setup key owned by
// ownerUserID (devices enrolled with it belong to that account; 0 =
// legacy/admin).
func (s *Store) NewSetupKey(networkID int64, reusable bool, expiresAt time.Time, ownerUserID int64) (SetupKey, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return SetupKey{}, err
	}
	k := SetupKey{
		NetworkID:   networkID,
		Key:         "sk-" + hex.EncodeToString(raw),
		Reusable:    reusable,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
		OwnerUserID: ownerUserID,
	}
	var exp int64
	if !expiresAt.IsZero() {
		exp = expiresAt.Unix()
	}
	res, err := s.db.Exec(`INSERT INTO setup_keys (network_id, key, reusable, revoked, expires_at, used_count, created_at, owner_user_id)
		VALUES (?, ?, ?, 0, ?, 0, ?, ?)`, networkID, k.Key, boolInt(reusable), exp, k.CreatedAt.Unix(), ownerUserID)
	if err != nil {
		return SetupKey{}, err
	}
	k.ID, _ = res.LastInsertId()
	return k, nil
}

const setupKeyCols = `id, network_id, key, reusable, revoked, expires_at, used_count, created_at, owner_user_id`

// SetupKeys lists all setup keys in a network, newest first.
func (s *Store) SetupKeys(networkID int64) ([]SetupKey, error) {
	rows, err := s.db.Query(`SELECT `+setupKeyCols+`
		FROM setup_keys WHERE network_id = ? ORDER BY id DESC`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SetupKey
	for rows.Next() {
		k, err := scanSetupKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

type rowScanner interface{ Scan(...any) error }

func scanSetupKey(r rowScanner) (SetupKey, error) {
	var k SetupKey
	var reusable, revoked int
	var exp, created int64
	if err := r.Scan(&k.ID, &k.NetworkID, &k.Key, &reusable, &revoked, &exp, &k.UsedCount, &created, &k.OwnerUserID); err != nil {
		return k, err
	}
	k.Reusable = reusable != 0
	k.Revoked = revoked != 0
	if exp > 0 {
		k.ExpiresAt = time.Unix(exp, 0)
	}
	k.CreatedAt = time.Unix(created, 0)
	return k, nil
}

// RevokeSetupKey marks a key revoked.
func (s *Store) RevokeSetupKey(id int64) error {
	res, err := s.db.Exec(`UPDATE setup_keys SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UseSetupKey validates key and atomically records the use. It returns
// the key's network and owning user (0 = legacy/admin), or an error
// describing why the key is unusable.
func (s *Store) UseSetupKey(keyStr string) (Network, int64, error) {
	keyStr = strings.TrimSpace(keyStr)
	row := s.db.QueryRow(`SELECT `+setupKeyCols+` FROM setup_keys WHERE key = ?`, keyStr)
	k, err := scanSetupKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Network{}, 0, errors.New("unknown setup key")
	}
	if err != nil {
		return Network{}, 0, err
	}
	switch {
	case k.Revoked:
		return Network{}, 0, errors.New("setup key has been revoked")
	case !k.ExpiresAt.IsZero() && time.Now().After(k.ExpiresAt):
		return Network{}, 0, errors.New("setup key has expired")
	case !k.Reusable && k.UsedCount > 0:
		return Network{}, 0, errors.New("setup key was single-use and is spent")
	}
	if _, err := s.db.Exec(`UPDATE setup_keys SET used_count = used_count + 1 WHERE id = ?`, k.ID); err != nil {
		return Network{}, 0, err
	}
	nw, err := s.NetworkByID(k.NetworkID)
	return nw, k.OwnerUserID, err
}

// SetupKeyByID returns one setup key.
func (s *Store) SetupKeyByID(id int64) (SetupKey, error) {
	row := s.db.QueryRow(`SELECT `+setupKeyCols+` FROM setup_keys WHERE id = ?`, id)
	k, err := scanSetupKey(row)
	if errors.Is(err, sql.ErrNoRows) {
		return SetupKey{}, ErrNotFound
	}
	return k, err
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
