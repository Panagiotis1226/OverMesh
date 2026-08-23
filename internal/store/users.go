package store

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Users (Phase 7): local accounts with two roles. 'admin' controls the
// whole network; 'member' sees and manages only their own devices and
// setup keys. No OIDC/SSO — accounts live in this database.
const usersSchema = `
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'member',
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL
);
`

const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// User is one account (the password hash never leaves this package).
type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	Disabled  bool   `json:"disabled"`
	CreatedAt int64  `json:"created"`
}

var usernameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

// NormalizeUsername lowercases and validates a username.
func NormalizeUsername(u string) (string, error) {
	u = strings.ToLower(strings.TrimSpace(u))
	if !usernameRe.MatchString(u) {
		return "", errors.New("usernames are 1-32 chars: a-z 0-9 . _ - (must start alphanumeric)")
	}
	return u, nil
}

// CreateUser adds an account. The password is bcrypt-hashed here.
func (s *Store) CreateUser(username, password, role string) (User, error) {
	username, err := NormalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	if role != RoleAdmin && role != RoleMember {
		return User{}, fmt.Errorf("bad role %q", role)
	}
	if len(password) < 8 {
		return User{}, errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO users (username, password_hash, role, disabled, created_at)
		VALUES (?, ?, ?, 0, ?)`, username, string(hash), role, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, fmt.Errorf("username %q is taken", username)
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Username: username, Role: role, CreatedAt: now}, nil
}

// createUserWithHash seeds an account from an existing bcrypt hash
// (the legacy admin-password migration).
func (s *Store) createUserWithHash(username, hash, role string) (User, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO users (username, password_hash, role, disabled, created_at)
		VALUES (?, ?, ?, 0, ?)`, username, hash, role, now)
	if err != nil {
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Username: username, Role: role, CreatedAt: now}, nil
}

// EnsureAdminUser guarantees an enabled admin account exists:
//   - explicitPassword set: create user "admin" with it, or reset the
//     existing admin's password to it (the -admin-password flag stays
//     the recovery path).
//   - otherwise: keep whatever admin exists; if none, migrate the
//     legacy single-admin hash (legacyHash) or, failing that, report
//     that a generated password is needed via needGenerated=true.
func (s *Store) EnsureAdminUser(explicitPassword, legacyHash string) (needGenerated bool, err error) {
	if explicitPassword != "" {
		u, err := s.UserByName("admin")
		if errors.Is(err, ErrNotFound) {
			_, err = s.CreateUser("admin", explicitPassword, RoleAdmin)
			return false, err
		}
		if err != nil {
			return false, err
		}
		return false, s.SetUserPassword(u.ID, explicitPassword)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n); err != nil {
		return false, err
	}
	if n > 0 {
		return false, nil
	}
	if legacyHash != "" {
		_, err := s.createUserWithHash("admin", legacyHash, RoleAdmin)
		return false, err
	}
	return true, nil
}

// CheckPassword verifies credentials and returns the account.
func (s *Store) CheckPassword(username, password string) (User, error) {
	username, err := NormalizeUsername(username)
	if err != nil {
		return User{}, err
	}
	var u User
	var hash string
	var disabled int
	err = s.db.QueryRow(`SELECT id, username, password_hash, role, disabled, created_at
		FROM users WHERE username = ?`, username).
		Scan(&u.ID, &u.Username, &hash, &u.Role, &disabled, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.Disabled = disabled != 0
	if u.Disabled {
		return User{}, errors.New("account is disabled")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return User{}, errors.New("wrong password")
	}
	return u, nil
}

const userCols = `id, username, role, disabled, created_at`

func scanUser(r rowScanner) (User, error) {
	var u User
	var disabled int
	if err := r.Scan(&u.ID, &u.Username, &u.Role, &disabled, &u.CreatedAt); err != nil {
		return u, err
	}
	u.Disabled = disabled != 0
	return u, nil
}

// UserByName looks an account up by username.
func (s *Store) UserByName(username string) (User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, username))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// UserByID looks an account up by id.
func (s *Store) UserByID(id int64) (User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// Users lists every account.
func (s *Store) Users() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// SetUserDisabled enables/disables an account.
func (s *Store) SetUserDisabled(id int64, disabled bool) error {
	res, err := s.db.Exec(`UPDATE users SET disabled = ? WHERE id = ?`, boolInt(disabled), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserRole changes an account's role.
func (s *Store) SetUserRole(id int64, role string) error {
	if role != RoleAdmin && role != RoleMember {
		return fmt.Errorf("bad role %q", role)
	}
	res, err := s.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, role, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// SetUserPassword resets an account's password.
func (s *Store) SetUserPassword(id int64, password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, string(hash), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser removes an account; their devices and keys stay (owned by
// a now-dangling id, treated as admin-visible only).
func (s *Store) DeleteUser(id int64) error {
	res, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AdminCount reports how many enabled admin accounts exist (guards
// against disabling/deleting the last one).
func (s *Store) AdminCount() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, err
}
