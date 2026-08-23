package store

import (
	"database/sql"
	"net/netip"
	"strings"
)

// Advertised routes (Phase 5): a node OFFERS to route CIDRs for the mesh
// (a default route = exit-node offer). Offers are inert until an admin
// approves them; approval is remembered per (node, route) so a daemon
// restart or re-registration doesn't demote an approved router.
const routesSchema = `
CREATE TABLE IF NOT EXISTS node_routes (
  node_id  INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  route    TEXT NOT NULL,
  approved INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (node_id, route)
);
`

// Route is one advertised route and its approval state.
type Route struct {
	Route    string `json:"route"`
	Approved bool   `json:"approved"`
}

// IsExit reports whether the route is a default route (exit-node offer).
func IsExitRoute(route string) bool {
	return route == "0.0.0.0/0" || route == "::/0"
}

// NormalizeRoute canonicalizes a CIDR ("10.0.0.1/24" -> "10.0.0.0/24");
// it returns an error for anything unparseable.
func NormalizeRoute(route string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(route))
	if err != nil {
		return "", err
	}
	return p.Masked().String(), nil
}

// SetAdvertisedRoutes replaces a node's offer set, preserving the approval
// state of routes that remain advertised.
func (s *Store) SetAdvertisedRoutes(nodeID int64, routes []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	keep := make(map[string]bool, len(routes))
	for _, r := range routes {
		keep[r] = true
		if _, err := tx.Exec(`INSERT OR IGNORE INTO node_routes (node_id, route, approved)
			VALUES (?, ?, 0)`, nodeID, r); err != nil {
			return err
		}
	}
	rows, err := tx.Query(`SELECT route FROM node_routes WHERE node_id = ?`, nodeID)
	if err != nil {
		return err
	}
	var drop []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			rows.Close()
			return err
		}
		if !keep[r] {
			drop = append(drop, r)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range drop {
		if _, err := tx.Exec(`DELETE FROM node_routes WHERE node_id = ? AND route = ?`, nodeID, r); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// NodeRoutes lists a node's advertised routes with approval state,
// deterministic order.
func (s *Store) NodeRoutes(nodeID int64) ([]Route, error) {
	rows, err := s.db.Query(`SELECT route, approved FROM node_routes WHERE node_id = ? ORDER BY route`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRoutes(rows)
}

// ApprovedNodeRoutes lists only the approved routes of a node.
func (s *Store) ApprovedNodeRoutes(nodeID int64) ([]string, error) {
	all, err := s.NodeRoutes(nodeID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, r := range all {
		if r.Approved {
			out = append(out, r.Route)
		}
	}
	return out, nil
}

// SetRouteApproved flips approval for one advertised route.
func (s *Store) SetRouteApproved(nodeID int64, route string, approved bool) error {
	res, err := s.db.Exec(`UPDATE node_routes SET approved = ? WHERE node_id = ? AND route = ?`,
		boolInt(approved), nodeID, route)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanRoutes(rows *sql.Rows) ([]Route, error) {
	var out []Route
	for rows.Next() {
		var r Route
		var approved int
		if err := rows.Scan(&r.Route, &approved); err != nil {
			return nil, err
		}
		r.Approved = approved != 0
		out = append(out, r)
	}
	return out, rows.Err()
}
