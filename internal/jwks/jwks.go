package jwks

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/trknhr/envvault/internal/clerr"
)

func Export(path string, body []byte) error {
	if err := validate(body); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create jwks directory", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".envvault-jwks-*")
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create temporary jwks", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "set jwks permissions", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "write jwks", err)
	}
	if err := tmp.Close(); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "close jwks", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "replace jwks", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "set final jwks permissions", err)
	}
	return nil
}

func validate(body []byte) error {
	var parsed struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "parse jwks", err)
	}
	if parsed.Keys == nil {
		return clerr.New(clerr.ConfigInvalid, "jwks keys array is required")
	}
	for _, key := range parsed.Keys {
		for _, field := range privateJWKFields {
			if _, exists := key[field]; exists {
				return clerr.New(clerr.ConfigInvalid, "jwks must not contain private key material")
			}
		}
	}
	return nil
}

var privateJWKFields = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
