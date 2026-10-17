package transfer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
	"gopkg.in/yaml.v3"
)

// Credential is one raw secret addressed by the name used in envvault:// references.
type Credential struct {
	Name  string
	Value []byte
}

// Bundle is the decrypted export: credential values plus the profiles that use them.
// Talos installation keys and profile parent keys are not included.
type Bundle struct {
	Credentials []Credential
	Profiles    map[string]config.Profile
}

func (b *Bundle) Zero() {
	if b == nil {
		return
	}
	for i := range b.Credentials {
		keyring.Zero(b.Credentials[i].Value)
		b.Credentials[i].Value = nil
	}
}

type payload struct {
	Version      int                 `json:"version"`
	Credentials  []payloadCredential `json:"credentials"`
	ProfilesYAML string              `json:"profiles_yaml,omitempty"`
}

type payloadCredential struct {
	Name  string `json:"name"`
	Value []byte `json:"value"`
}

// Collect reads the credential values named by the config and copies profile metadata.
func Collect(ctx context.Context, secrets keyring.Store, cfg config.File) (Bundle, error) {
	if secrets == nil {
		return Bundle{}, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
	}
	names := credentialNames(cfg)
	bundle := Bundle{
		Credentials: make([]Credential, 0, len(names)),
		Profiles:    cloneProfiles(cfg.Profiles),
	}
	for _, name := range names {
		value, err := secrets.Get(ctx, keyring.CredentialValue(name))
		if err != nil {
			bundle.Zero()
			if clerrIsNotFound(err) {
				return Bundle{}, clerr.New(clerr.ConfigInvalid, "credential "+name+" is not in the OS credential store")
			}
			return Bundle{}, err
		}
		if len(value) == 0 {
			keyring.Zero(value)
			bundle.Zero()
			return Bundle{}, clerr.New(clerr.ConfigInvalid, "credential "+name+" is empty")
		}
		bundle.Credentials = append(bundle.Credentials, Credential{Name: name, Value: value})
	}
	if len(bundle.Credentials) == 0 && len(bundle.Profiles) == 0 {
		return Bundle{}, clerr.New(clerr.ConfigInvalid, "nothing to export")
	}
	return bundle, nil
}

func credentialNames(cfg config.File) []string {
	seen := map[string]struct{}{}
	for _, name := range cfg.CredentialNames() {
		name = strings.TrimSpace(name)
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	for _, stored := range cfg.Profiles {
		name := strings.TrimSpace(stored.CredentialName)
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func cloneProfiles(in map[string]config.Profile) map[string]config.Profile {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]config.Profile, len(in))
	for name, stored := range in {
		out[name] = stored
	}
	return out
}

func (b Bundle) marshal() ([]byte, error) {
	body := payload{Version: payloadVersion, Credentials: make([]payloadCredential, 0, len(b.Credentials))}
	seen := map[string]struct{}{}
	for _, credential := range b.Credentials {
		name := strings.TrimSpace(credential.Name)
		if !validName(name) {
			return nil, clerr.New(clerr.ConfigInvalid, "export credential name is invalid")
		}
		if _, ok := seen[name]; ok {
			return nil, clerr.New(clerr.ConfigInvalid, "export credential name is duplicated")
		}
		seen[name] = struct{}{}
		body.Credentials = append(body.Credentials, payloadCredential{
			Name:  name,
			Value: credential.Value,
		})
	}
	if len(b.Profiles) > 0 {
		raw, err := yaml.Marshal(b.Profiles)
		if err != nil {
			return nil, clerr.New(clerr.ConfigInvalid, "encode export profiles")
		}
		body.ProfilesYAML = string(raw)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, clerr.New(clerr.ConfigInvalid, "export payload is invalid")
	}
	return encoded, nil
}

func unmarshalBundle(plaintext []byte) (Bundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	var body payload
	if err := decoder.Decode(&body); err != nil || decoder.More() {
		return Bundle{}, clerr.New(clerr.ConfigInvalid, "export payload is invalid")
	}
	if body.Version != payloadVersion {
		return Bundle{}, clerr.New(clerr.ConfigInvalid, "unsupported export version")
	}
	bundle := Bundle{Credentials: make([]Credential, 0, len(body.Credentials))}
	seen := map[string]struct{}{}
	for _, credential := range body.Credentials {
		name := strings.TrimSpace(credential.Name)
		if !validName(name) || len(credential.Value) == 0 {
			keyring.Zero(credential.Value)
			bundle.Zero()
			return Bundle{}, clerr.New(clerr.ConfigInvalid, "export payload is invalid")
		}
		if _, ok := seen[name]; ok {
			keyring.Zero(credential.Value)
			bundle.Zero()
			return Bundle{}, clerr.New(clerr.ConfigInvalid, "export payload is invalid")
		}
		seen[name] = struct{}{}
		value := append([]byte(nil), credential.Value...)
		keyring.Zero(credential.Value)
		bundle.Credentials = append(bundle.Credentials, Credential{Name: name, Value: value})
	}
	if strings.TrimSpace(body.ProfilesYAML) != "" {
		var profiles map[string]config.Profile
		if err := yaml.Unmarshal([]byte(body.ProfilesYAML), &profiles); err != nil {
			bundle.Zero()
			return Bundle{}, clerr.New(clerr.ConfigInvalid, "export profiles are invalid")
		}
		for name := range profiles {
			if !validName(name) {
				bundle.Zero()
				return Bundle{}, clerr.New(clerr.ConfigInvalid, "export profiles are invalid")
			}
		}
		bundle.Profiles = profiles
	}
	return bundle, nil
}

func validName(name string) bool {
	if strings.TrimSpace(name) == "" || strings.TrimSpace(name) != name {
		return false
	}
	return !strings.ContainsAny(name, "\r\n\x00")
}

func clerrIsNotFound(err error) bool {
	return errors.Is(err, keyring.ErrNotFound)
}
