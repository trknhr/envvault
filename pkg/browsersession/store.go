package browsersession

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	ErrReplay         = errors.New("browser session replay")
	ErrInvalidCode    = errors.New("browser login code invalid")
	ErrCodeGeneration = errors.New("browser login code generation failed")
)

type BrowserGrant struct {
	Profile   string
	Resource  string
	Scopes    []string
	SessionID string
	Purpose   string
	ExpiresAt time.Time
}

type BrowserReplayStore interface {
	ConsumeSessionID(ctx context.Context, sessionID string, expiresAt time.Time) error
}

type BrowserLoginCodeStore interface {
	Create(ctx context.Context, grant BrowserGrant, ttl time.Duration) (rawCode string, err error)
	Consume(ctx context.Context, rawCode string) (BrowserGrant, error)
}

type MemoryReplayStore struct {
	mu       sync.Mutex
	now      func() time.Time
	consumed map[string]time.Time
}

func NewMemoryReplayStore(now func() time.Time) *MemoryReplayStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryReplayStore{now: now, consumed: map[string]time.Time{}}
}

func (s *MemoryReplayStore) ConsumeSessionID(ctx context.Context, sessionID string, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for id, expiry := range s.consumed {
		if !expiry.After(now) {
			delete(s.consumed, id)
		}
	}
	if sessionID == "" {
		return ErrReplay
	}
	if expiry, exists := s.consumed[sessionID]; exists && expiry.After(now) {
		return ErrReplay
	}
	s.consumed[sessionID] = expiresAt
	return nil
}

type MemoryLoginCodeStore struct {
	mu       sync.Mutex
	now      func() time.Time
	generate func() (string, error)
	codes    map[string]loginCodeEntry
}

type loginCodeEntry struct {
	grant     BrowserGrant
	expiresAt time.Time
}

func NewMemoryLoginCodeStore(now func() time.Time) *MemoryLoginCodeStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryLoginCodeStore{
		now:      now,
		generate: randomCode,
		codes:    map[string]loginCodeEntry{},
	}
}

func (s *MemoryLoginCodeStore) SetCodeGeneratorForTest(generate func() (string, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.generate = generate
}

func (s *MemoryLoginCodeStore) Create(ctx context.Context, grant BrowserGrant, ttl time.Duration) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if ttl <= 0 {
		return "", ErrInvalidCode
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	code, err := s.generate()
	if err != nil {
		return "", ErrCodeGeneration
	}
	if code == "" {
		return "", ErrCodeGeneration
	}
	s.codes[code] = loginCodeEntry{grant: grant, expiresAt: s.now().Add(ttl)}
	return code, nil
}

func (s *MemoryLoginCodeStore) Consume(ctx context.Context, rawCode string) (BrowserGrant, error) {
	if err := ctx.Err(); err != nil {
		return BrowserGrant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.codes[rawCode]
	if !exists {
		return BrowserGrant{}, ErrInvalidCode
	}
	delete(s.codes, rawCode)
	if !entry.expiresAt.After(s.now()) {
		return BrowserGrant{}, ErrInvalidCode
	}
	return entry.grant, nil
}

func randomCode() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
