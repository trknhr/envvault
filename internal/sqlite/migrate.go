package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	_ "modernc.org/sqlite"
)

const targetVersion = 1

type Options struct {
	Path           string
	RepositoryRoot string
	Now            func() time.Time
}

func Migrate(ctx context.Context, options Options) error {
	if options.Path == "" {
		return clerr.New(clerr.ConfigInvalid, "sqlite path is required")
	}
	if err := rejectRepositoryPath(options.Path, options.RepositoryRoot); err != nil {
		return err
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}

	existed, err := fileExists(options.Path)
	if err != nil {
		return err
	}
	if err := prepareDBFile(options.Path); err != nil {
		return err
	}

	db, err := sql.Open("sqlite", options.Path)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "open sqlite database", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "ping sqlite database", err)
	}

	current, err := currentVersion(ctx, db)
	if err != nil {
		return err
	}
	if existed && current < targetVersion {
		if err := backupDB(options.Path, now()); err != nil {
			return err
		}
	}
	if current >= targetVersion {
		return nil
	}
	if err := applyV1(ctx, db); err != nil {
		return err
	}
	if err := os.Chmod(options.Path, 0o600); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "set sqlite permissions", err)
	}
	return nil
}

func prepareDBFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create sqlite directory", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "set sqlite directory permissions", err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create sqlite database", err)
	}
	if err := file.Close(); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "close sqlite database", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "set sqlite permissions", err)
	}
	return nil
}

func currentVersion(ctx context.Context, db *sql.DB) (int, error) {
	var name string
	err := db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, clerr.Wrap(clerr.ConfigInvalid, "inspect sqlite migrations", err)
	}

	var version sql.NullInt64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		return 0, clerr.Wrap(clerr.ConfigInvalid, "read sqlite migration version", err)
	}
	if !version.Valid {
		return 0, nil
	}
	return int(version.Int64), nil
}

func applyV1(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "begin sqlite migration", err)
	}
	defer tx.Rollback()

	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS talos_parent_keys (
			id TEXT PRIMARY KEY,
			profile TEXT NOT NULL UNIQUE,
			scopes_json TEXT NOT NULL,
			status TEXT NOT NULL,
			expires_at TEXT,
			metadata_json TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS runtime_metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`INSERT OR IGNORE INTO schema_migrations(version, applied_at)
			VALUES (1, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))`,
		`PRAGMA user_version = 1`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return clerr.Wrap(clerr.ConfigInvalid, "apply sqlite migration", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "commit sqlite migration", err)
	}
	return nil
}

func backupDB(path string, now time.Time) error {
	backup := path + ".backup-" + now.UTC().Format("20060102T150405Z")
	src, err := os.Open(path)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "open sqlite backup source", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create sqlite backup", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "write sqlite backup", err)
	}
	if err := dst.Close(); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "close sqlite backup", err)
	}
	return nil
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, clerr.Wrap(clerr.ConfigInvalid, "inspect sqlite database", err)
}

func rejectRepositoryPath(path, repoRoot string) error {
	if repoRoot == "" {
		return nil
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "resolve sqlite path", err)
	}
	absRepo, err := filepath.Abs(repoRoot)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "resolve repository root", err)
	}
	rel, err := filepath.Rel(absRepo, absPath)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "compare sqlite path", err)
	}
	if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..") {
		return clerr.New(clerr.ConfigInvalid, "sqlite database must not be stored under repository root")
	}
	return nil
}
