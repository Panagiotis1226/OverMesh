package store

import (
	"encoding/json"
	"fmt"
	"time"
)

// ACLRule is one ordered access rule, exactly as the web UI edits it.
// Semantics: rules are evaluated top-down on the receiving node, first
// match wins; with zero rules everything is allowed; with rules present,
// no match means deny.
type ACLRule struct {
	ID     int64  `json:"id"`
	Action string `json:"action"` // "allow" | "deny"
	// Device IDs; empty means "any device".
	SrcIDs []int64 `json:"src_ids"`
	DstIDs []int64 `json:"dst_ids"`
	// "" = any protocol; otherwise "tcp", "udp", "icmp".
	Protocol string `json:"protocol"`
	// Port specs for tcp/udp: "22", "8000-9000". Empty = all ports.
	Ports []string `json:"ports"`
}

const aclSchema = `
CREATE TABLE IF NOT EXISTS acl_rules (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  network_id INTEGER NOT NULL REFERENCES networks(id),
  position   INTEGER NOT NULL,
  action     TEXT NOT NULL,
  src_ids    TEXT NOT NULL DEFAULT '[]',
  dst_ids    TEXT NOT NULL DEFAULT '[]',
  protocol   TEXT NOT NULL DEFAULT '',
  ports      TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);
`

// ACL returns the network's rules in evaluation order.
func (s *Store) ACL(networkID int64) ([]ACLRule, error) {
	rows, err := s.db.Query(`SELECT id, action, src_ids, dst_ids, protocol, ports
		FROM acl_rules WHERE network_id = ? ORDER BY position`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ACLRule{}
	for rows.Next() {
		var r ACLRule
		var src, dst, ports string
		if err := rows.Scan(&r.ID, &r.Action, &src, &dst, &r.Protocol, &ports); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(src), &r.SrcIDs)
		_ = json.Unmarshal([]byte(dst), &r.DstIDs)
		_ = json.Unmarshal([]byte(ports), &r.Ports)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetACL replaces the network's rule list atomically (the web UI edits
// the whole ordered list and saves it in one shot).
func (s *Store) SetACL(networkID int64, rules []ACLRule) error {
	for _, r := range rules {
		if r.Action != "allow" && r.Action != "deny" {
			return fmt.Errorf("rule action must be allow or deny, got %q", r.Action)
		}
		switch r.Protocol {
		case "", "tcp", "udp", "icmp":
		default:
			return fmt.Errorf("unknown protocol %q", r.Protocol)
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM acl_rules WHERE network_id = ?`, networkID); err != nil {
		return err
	}
	now := time.Now().Unix()
	for i, r := range rules {
		src, _ := json.Marshal(orEmpty(r.SrcIDs))
		dst, _ := json.Marshal(orEmpty(r.DstIDs))
		ports, _ := json.Marshal(orEmptyS(r.Ports))
		if _, err := tx.Exec(`INSERT INTO acl_rules
			(network_id, position, action, src_ids, dst_ids, protocol, ports, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			networkID, i, r.Action, string(src), string(dst), r.Protocol, string(ports), now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func orEmpty(v []int64) []int64 {
	if v == nil {
		return []int64{}
	}
	return v
}

func orEmptyS(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
