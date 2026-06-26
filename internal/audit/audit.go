package audit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
)

const (
	EventCredentialIssued        = "credential_issued"
	EventBrowserSessionRequested = "browser_session_requested"

	ResultSuccess = "success"
	ResultFailure = "failure"
)

type Event struct {
	Time       time.Time  `json:"time"`
	Event      string     `json:"event"`
	Profile    string     `json:"profile,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Resource   string     `json:"resource,omitempty"`
	Scopes     []string   `json:"scopes,omitempty"`
	TTLSeconds int64      `json:"ttl_seconds,omitempty"`
	SessionID  string     `json:"session_id,omitempty"`
	ProjectID  string     `json:"project_id,omitempty"`
	Result     string     `json:"result,omitempty"`
	ErrorCode  clerr.Code `json:"error_code,omitempty"`
}

type Recorder interface {
	Record(ctx context.Context, event Event) error
}

type FileRecorder struct {
	Path string
	Now  func() time.Time

	mu sync.Mutex
}

func (r *FileRecorder) Record(ctx context.Context, event Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.Path == "" {
		return clerr.New(clerr.ConfigInvalid, "audit path is required")
	}
	if event.Event == "" {
		return clerr.New(clerr.ConfigInvalid, "audit event is required")
	}
	if event.Time.IsZero() {
		event.Time = r.now()
	}
	event.Time = event.Time.UTC()
	event.Scopes = append([]string(nil), event.Scopes...)

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(r.Path), 0o700); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create audit directory", err)
	}
	file, err := os.OpenFile(r.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "open audit file", err)
	}
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "secure audit file", err)
	}

	encoder := json.NewEncoder(file)
	if err := encoder.Encode(event); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "write audit event", err)
	}
	return nil
}

func (r *FileRecorder) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
