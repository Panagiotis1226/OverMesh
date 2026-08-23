package store

import "time"

// Audit log (Phase 7): an append-only trail of security-relevant
// control-plane actions, shown read-only in the web UI.
const auditSchema = `
CREATE TABLE IF NOT EXISTS audit_log (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts       INTEGER NOT NULL,
  username TEXT NOT NULL,
  action   TEXT NOT NULL,
  target   TEXT NOT NULL DEFAULT '',
  details  TEXT NOT NULL DEFAULT ''
);
`

// AuditEntry is one recorded action.
type AuditEntry struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	Username string `json:"username"`
	Action   string `json:"action"`
	Target   string `json:"target,omitempty"`
	Details  string `json:"details,omitempty"`
}

// Audit appends an entry; failures are returned but callers generally
// log-and-continue (an audit hiccup must not block the action itself).
func (s *Store) Audit(username, action, target, details string) error {
	_, err := s.db.Exec(`INSERT INTO audit_log (ts, username, action, target, details)
		VALUES (?, ?, ?, ?, ?)`, time.Now().Unix(), username, action, target, details)
	return err
}

// AuditLog returns the newest entries, newest first.
func (s *Store) AuditLog(limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id, ts, username, action, target, details
		FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Username, &e.Action, &e.Target, &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
