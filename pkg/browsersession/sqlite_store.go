package browsersession

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type SQLiteStore struct {
	db       *sql.DB
	now      func() time.Time
	generate func() (string, error)
}

func NewSQLiteStore(ctx context.Context, db *sql.DB, now func() time.Time) (*SQLiteStore, error) {
	if db == nil {
		return nil, fmt.Errorf("sqlite database is required")
	}
	if now == nil {
		now = time.Now
	}
	store := &SQLiteStore{
		db:       db,
		now:      now,
		generate: randomCode,
	}
	if err := store.migrate(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) SetCodeGeneratorForTest(generate func() (string, error)) {
	if generate == nil {
		s.generate = randomCode
		return
	}
	s.generate = generate
}

func (s *SQLiteStore) ConsumeSessionID(ctx context.Context, sessionID string, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sessionID == "" {
		return ErrReplay
	}
	now := s.now().UnixNano()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM browser_session_replays WHERE expires_at_unix_nano <= ?`, now); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO browser_session_replays(session_id, expires_at_unix_nano, consumed_at_unix_nano)
		 VALUES (?, ?, ?)`,
		sessionID, expiresAt.UnixNano(), now,
	)
	if err != nil {
		return ErrReplay
	}
	return nil
}

func (s *SQLiteStore) Create(ctx context.Context, grant BrowserGrant, ttl time.Duration) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if ttl <= 0 {
		return "", ErrInvalidCode
	}
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		return "", err
	}
	expiresAt := s.now().Add(ttl).UnixNano()
	for attempts := 0; attempts < 3; attempts++ {
		code, err := s.generate()
		if err != nil || code == "" {
			return "", ErrCodeGeneration
		}
		_, err = s.db.ExecContext(ctx,
			`INSERT INTO browser_login_codes(code_hash, grant_json, expires_at_unix_nano, created_at_unix_nano)
			 VALUES (?, ?, ?, ?)`,
			loginCodeHash(code), string(grantJSON), expiresAt, s.now().UnixNano(),
		)
		if err == nil {
			return code, nil
		}
	}
	return "", ErrCodeGeneration
}

func (s *SQLiteStore) Consume(ctx context.Context, rawCode string) (BrowserGrant, error) {
	if err := ctx.Err(); err != nil {
		return BrowserGrant{}, err
	}
	if rawCode == "" {
		return BrowserGrant{}, ErrInvalidCode
	}
	var grantJSON string
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM browser_login_codes
		 WHERE code_hash = ? AND expires_at_unix_nano > ?
		 RETURNING grant_json`,
		loginCodeHash(rawCode), s.now().UnixNano(),
	).Scan(&grantJSON)
	if err == sql.ErrNoRows {
		return BrowserGrant{}, ErrInvalidCode
	}
	if err != nil {
		return BrowserGrant{}, err
	}
	var grant BrowserGrant
	if err := json.Unmarshal([]byte(grantJSON), &grant); err != nil {
		return BrowserGrant{}, err
	}
	return grant, nil
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS browser_session_replays (
			session_id TEXT PRIMARY KEY,
			expires_at_unix_nano INTEGER NOT NULL,
			consumed_at_unix_nano INTEGER NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS browser_login_codes (
			code_hash TEXT PRIMARY KEY,
			grant_json TEXT NOT NULL,
			expires_at_unix_nano INTEGER NOT NULL,
			created_at_unix_nano INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_browser_session_replays_expires_at
			ON browser_session_replays(expires_at_unix_nano)`,
		`CREATE INDEX IF NOT EXISTS idx_browser_login_codes_expires_at
			ON browser_login_codes(expires_at_unix_nano)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	return nil
}

func loginCodeHash(rawCode string) string {
	sum := sha256.Sum256([]byte(rawCode))
	return hex.EncodeToString(sum[:])
}
