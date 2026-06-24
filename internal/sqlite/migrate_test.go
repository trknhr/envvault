package sqlite_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/sqlite"
	_ "modernc.org/sqlite"
)

func TestMigrateCreatesPrivateSQLiteWithMetadataOnlySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "credlease.db")

	if err := sqlite.Migrate(context.Background(), sqlite.Options{Path: path}); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("db mode = %v, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat(dir) error = %v", err)
	}
	if runtime.GOOS != "windows" && dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode = %v, want 0700", dirInfo.Mode().Perm())
	}

	db := openDB(t, path)
	defer db.Close()

	assertTableExists(t, db, "schema_migrations")
	assertTableExists(t, db, "talos_parent_keys")
	assertTableExists(t, db, "runtime_metadata")
	assertColumnAbsent(t, db, "talos_parent_keys", "secret")
	assertColumnAbsent(t, db, "talos_parent_keys", "raw_parent_key")
	assertColumnAbsent(t, db, "talos_parent_keys", "credential")

	var version int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("query version error = %v", err)
	}
	if version == 0 {
		t.Fatal("migration version = 0, want applied migration")
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credlease.db")
	if err := sqlite.Migrate(context.Background(), sqlite.Options{Path: path}); err != nil {
		t.Fatalf("first Migrate() error = %v", err)
	}
	if err := sqlite.Migrate(context.Background(), sqlite.Options{Path: path}); err != nil {
		t.Fatalf("second Migrate() error = %v", err)
	}

	db := openDB(t, path)
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&count); err != nil {
		t.Fatalf("query migration count error = %v", err)
	}
	if count != 1 {
		t.Fatalf("migration rows for version 1 = %d, want 1", count)
	}
}

func TestMigrateBacksUpExistingDatabaseBeforeUpgrade(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credlease.db")
	db := openDB(t, path)
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("create migration table error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (0, '2026-06-22T12:00:00Z')`); err != nil {
		t.Fatalf("insert old migration error = %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE legacy_marker (value TEXT NOT NULL)`); err != nil {
		t.Fatalf("create legacy table error = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO legacy_marker(value) VALUES ('kept')`); err != nil {
		t.Fatalf("insert legacy marker error = %v", err)
	}
	db.Close()

	if err := sqlite.Migrate(context.Background(), sqlite.Options{Path: path}); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "credlease.db.backup-*"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("backup files = %v, want one", matches)
	}
	backup := openDB(t, matches[0])
	defer backup.Close()
	var value string
	if err := backup.QueryRow(`SELECT value FROM legacy_marker`).Scan(&value); err != nil {
		t.Fatalf("backup legacy query error = %v", err)
	}
	if value != "kept" {
		t.Fatalf("backup marker = %q, want kept", value)
	}
}

func TestMigrateRejectsRepositoryLocalPath(t *testing.T) {
	repo := t.TempDir()
	path := filepath.Join(repo, ".credlease", "credlease.db")

	err := sqlite.Migrate(context.Background(), sqlite.Options{Path: path, RepositoryRoot: repo})
	if err == nil {
		t.Fatal("Migrate() error = nil, want repository path rejection")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.ConfigInvalid {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.ConfigInvalid)
	}
}

func openDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	return db
}

func assertTableExists(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	var got string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&got)
	if err != nil {
		t.Fatalf("table %s missing: %v", table, err)
	}
}

func assertColumnAbsent(t *testing.T, db *sql.DB, table string, forbidden string) {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatalf("table_info(%s) error = %v", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			t.Fatalf("Scan() error = %v", err)
		}
		if strings.EqualFold(name, forbidden) {
			t.Fatalf("table %s contains forbidden raw-secret column %q", table, name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("Rows() error = %v", err)
	}
}
