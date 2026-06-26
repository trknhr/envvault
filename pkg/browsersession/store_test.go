package browsersession_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/pkg/browsersession"
	_ "modernc.org/sqlite"
)

func TestMemoryReplayStoreRejectsDuplicateSessionIDUntilExpiry(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	store := browsersession.NewMemoryReplayStore(func() time.Time { return now })

	if err := store.ConsumeSessionID(context.Background(), "session-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("first ConsumeSessionID() error = %v", err)
	}
	if err := store.ConsumeSessionID(context.Background(), "session-1", now.Add(time.Minute)); err == nil {
		t.Fatal("second ConsumeSessionID() error = nil, want replay error")
	}

	now = now.Add(2 * time.Minute)
	if err := store.ConsumeSessionID(context.Background(), "session-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("ConsumeSessionID() after expiry error = %v", err)
	}
}

func TestMemoryLoginCodeStoreConsumesCodeOnce(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	store := browsersession.NewMemoryLoginCodeStore(func() time.Time { return now })
	store.SetCodeGeneratorForTest(func() (string, error) { return "opaque-code", nil })
	grant := browsersession.BrowserGrant{
		Profile:   "admin-web/dev",
		Resource:  "https://admin.dev.example.com",
		SessionID: "session-1",
		Purpose:   "browser-bootstrap",
	}

	code, err := store.Create(context.Background(), grant, 30*time.Second)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if code != "opaque-code" {
		t.Fatalf("code = %q, want opaque-code", code)
	}

	got, err := store.Consume(context.Background(), code)
	if err != nil {
		t.Fatalf("first Consume() error = %v", err)
	}
	if got.SessionID != "session-1" {
		t.Fatalf("SessionID = %q, want session-1", got.SessionID)
	}
	if _, err := store.Consume(context.Background(), code); err == nil {
		t.Fatal("second Consume() error = nil, want single-use error")
	}
}

func TestMemoryLoginCodeStoreRejectsExpiredCode(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	store := browsersession.NewMemoryLoginCodeStore(func() time.Time { return now })
	store.SetCodeGeneratorForTest(func() (string, error) { return "opaque-code", nil })

	code, err := store.Create(context.Background(), browsersession.BrowserGrant{SessionID: "session-1"}, 2*time.Second)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	now = now.Add(3 * time.Second)

	if _, err := store.Consume(context.Background(), code); err == nil {
		t.Fatal("Consume() error = nil, want expired-code error")
	}
}

func TestSQLiteStoreConsumesSessionIDAndLoginCodeOnceWithoutRawCodePersistence(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "browser-session.sqlite")
	db := openSQLiteStoreDB(t, path)
	defer db.Close()
	store, err := browsersession.NewSQLiteStore(context.Background(), db, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	store.SetCodeGeneratorForTest(func() (string, error) { return "opaque-code", nil })

	if err := store.ConsumeSessionID(context.Background(), "session-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("first ConsumeSessionID() error = %v", err)
	}
	if err := store.ConsumeSessionID(context.Background(), "session-1", now.Add(time.Minute)); !errors.Is(err, browsersession.ErrReplay) {
		t.Fatalf("second ConsumeSessionID() error = %v, want ErrReplay", err)
	}
	grant := browsersession.BrowserGrant{
		Profile:   "admin-web/dev",
		Resource:  "https://admin.dev.example.com",
		Scopes:    []string{"browser:session:create"},
		SessionID: "session-1",
		Purpose:   "browser-bootstrap",
		ExpiresAt: now.Add(time.Minute),
	}
	code, err := store.Create(context.Background(), grant, 30*time.Second)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if code != "opaque-code" {
		t.Fatalf("code = %q, want opaque-code", code)
	}

	rawDB, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if strings.Contains(string(rawDB), "opaque-code") {
		t.Fatalf("sqlite store persisted raw login code")
	}

	got, err := store.Consume(context.Background(), code)
	if err != nil {
		t.Fatalf("first Consume() error = %v", err)
	}
	if got.SessionID != "session-1" || got.Profile != "admin-web/dev" {
		t.Fatalf("grant = %#v, want persisted browser grant", got)
	}
	if _, err := store.Consume(context.Background(), code); !errors.Is(err, browsersession.ErrInvalidCode) {
		t.Fatalf("second Consume() error = %v, want ErrInvalidCode", err)
	}
}

func TestSQLiteStorePersistsReplayAndLoginCodesAcrossInstances(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "browser-session.sqlite")
	firstDB := openSQLiteStoreDB(t, path)
	first, err := browsersession.NewSQLiteStore(context.Background(), firstDB, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSQLiteStore(first) error = %v", err)
	}
	first.SetCodeGeneratorForTest(func() (string, error) { return "persistent-code", nil })
	if err := first.ConsumeSessionID(context.Background(), "session-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("ConsumeSessionID(first) error = %v", err)
	}
	code, err := first.Create(context.Background(), browsersession.BrowserGrant{
		Profile:   "admin-web/dev",
		SessionID: "session-1",
		Purpose:   "browser-bootstrap",
	}, time.Minute)
	if err != nil {
		t.Fatalf("Create(first) error = %v", err)
	}
	firstDB.Close()

	secondDB := openSQLiteStoreDB(t, path)
	defer secondDB.Close()
	second, err := browsersession.NewSQLiteStore(context.Background(), secondDB, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSQLiteStore(second) error = %v", err)
	}
	if err := second.ConsumeSessionID(context.Background(), "session-1", now.Add(time.Minute)); !errors.Is(err, browsersession.ErrReplay) {
		t.Fatalf("ConsumeSessionID(second) error = %v, want persisted replay rejection", err)
	}
	got, err := second.Consume(context.Background(), code)
	if err != nil {
		t.Fatalf("Consume(second) error = %v", err)
	}
	if got.SessionID != "session-1" {
		t.Fatalf("SessionID = %q, want persisted grant", got.SessionID)
	}
}

func TestSQLiteStorePrunesExpiredReplayAndRejectsExpiredCode(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	db := openSQLiteStoreDB(t, filepath.Join(t.TempDir(), "browser-session.sqlite"))
	defer db.Close()
	store, err := browsersession.NewSQLiteStore(context.Background(), db, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	store.SetCodeGeneratorForTest(func() (string, error) { return "expired-code", nil })

	if err := store.ConsumeSessionID(context.Background(), "session-1", now.Add(time.Second)); err != nil {
		t.Fatalf("ConsumeSessionID(first) error = %v", err)
	}
	code, err := store.Create(context.Background(), browsersession.BrowserGrant{SessionID: "session-1"}, time.Second)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	now = now.Add(2 * time.Second)

	if err := store.ConsumeSessionID(context.Background(), "session-1", now.Add(time.Minute)); err != nil {
		t.Fatalf("ConsumeSessionID(after expiry) error = %v", err)
	}
	if _, err := store.Consume(context.Background(), code); !errors.Is(err, browsersession.ErrInvalidCode) {
		t.Fatalf("Consume(expired) error = %v, want ErrInvalidCode", err)
	}
}

func openSQLiteStoreDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("Open(%s) error = %v", path, err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Ping(%s) error = %v", path, err)
	}
	return db
}
