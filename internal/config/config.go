package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/profile"
	"gopkg.in/yaml.v3"
)

type Duration time.Duration

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

func (d Duration) MarshalYAML() (any, error) {
	return time.Duration(d).String(), nil
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

type File struct {
	Version      int                `yaml:"version"`
	Installation Installation       `yaml:"installation"`
	Runtime      Runtime            `yaml:"runtime"`
	Defaults     Defaults           `yaml:"defaults"`
	Profiles     map[string]Profile `yaml:"profiles"`
}

type Installation struct {
	ID string `yaml:"id"`
}

type Runtime struct {
	Talos TalosRuntime `yaml:"talos"`
}

type TalosRuntime struct {
	Mode      string `yaml:"mode"`
	Version   string `yaml:"version"`
	Lifecycle string `yaml:"lifecycle"`
}

type Defaults struct {
	TokenTTL    Duration `yaml:"token_ttl"`
	MaxTokenTTL Duration `yaml:"max_token_ttl"`
}

type Profile struct {
	Kind     profile.Kind      `yaml:"kind"`
	Issuer   string            `yaml:"issuer"`
	Resource string            `yaml:"resource"`
	Scopes   []string          `yaml:"scopes"`
	Claims   map[string]string `yaml:"claims,omitempty"`

	TokenTTL    Duration `yaml:"token_ttl,omitempty"`
	MaxTokenTTL Duration `yaml:"max_token_ttl,omitempty"`

	BootstrapTokenTTL Duration `yaml:"bootstrap_token_ttl,omitempty"`
	LoginCodeTTL      Duration `yaml:"login_code_ttl,omitempty"`
	WebSessionTTL     Duration `yaml:"web_session_ttl,omitempty"`
	ExchangeURL       string   `yaml:"exchange_url,omitempty"`
	CompleteURL       string   `yaml:"complete_url,omitempty"`
	PostLoginURL      string   `yaml:"post_login_url,omitempty"`
	AllowedHosts      []string `yaml:"allowed_hosts,omitempty"`

	CredentialName string   `yaml:"credential,omitempty"`
	AuthMode       string   `yaml:"auth_mode,omitempty"`
	Provider       string   `yaml:"provider,omitempty"`
	TargetURL      string   `yaml:"target_url,omitempty"`
	AllowedPaths   []string `yaml:"allowed_paths,omitempty"`
	AllowedMethods []string `yaml:"allowed_methods,omitempty"`
	LocalTokenTTL  Duration `yaml:"local_token_ttl,omitempty"`

	ProjectBinding ProjectBinding `yaml:"project_binding,omitempty"`
}

type ProjectBinding struct {
	Mode      profile.ProjectBindingMode `yaml:"mode"`
	PathHash  string                     `yaml:"path_hash,omitempty"`
	GitRoot   string                     `yaml:"git_root,omitempty"`
	GitRemote string                     `yaml:"git_remote,omitempty"`
}

func Load(path string) (File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return File{}, clerr.Wrap(clerr.ConfigInvalid, "read config", err)
	}

	var cfg File
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return File{}, clerr.Wrap(clerr.ConfigInvalid, "parse config", err)
	}
	if err := cfg.Validate(); err != nil {
		return File{}, err
	}
	return cfg, nil
}

func Save(path string, cfg File) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "marshal config", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create config directory", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".envvault-config-*")
	if err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "create temporary config", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "set config permissions", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.ConfigInvalid, "write config", err)
	}
	if err := tmp.Close(); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "close config", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "replace config", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "set final config permissions", err)
	}
	return nil
}

func (f File) Validate() error {
	if f.Version != 1 {
		return clerr.New(clerr.ConfigInvalid, "config version must be 1")
	}
	if f.Installation.ID == "" {
		return clerr.New(clerr.ConfigInvalid, "installation id is required")
	}
	if f.Runtime.Talos.Mode != "managed" {
		return clerr.New(clerr.ConfigInvalid, "runtime.talos.mode must be managed")
	}
	if f.Runtime.Talos.Lifecycle != "on-demand" {
		return clerr.New(clerr.ConfigInvalid, "runtime.talos.lifecycle must be on-demand")
	}
	if f.Defaults.TokenTTL.Duration() <= 0 {
		return clerr.New(clerr.ConfigInvalid, "defaults.token_ttl must be positive")
	}
	if f.Defaults.MaxTokenTTL.Duration() <= 0 {
		return clerr.New(clerr.ConfigInvalid, "defaults.max_token_ttl must be positive")
	}
	if f.Defaults.TokenTTL.Duration() > f.Defaults.MaxTokenTTL.Duration() {
		return clerr.New(clerr.ConfigInvalid, "defaults.token_ttl exceeds defaults.max_token_ttl")
	}
	if f.Profiles == nil {
		f.Profiles = map[string]Profile{}
	}
	for name := range f.Profiles {
		if _, err := f.Profile(name); err != nil {
			return err
		}
	}
	return nil
}

func (f File) Profile(name string) (profile.Profile, error) {
	stored, ok := f.Profiles[name]
	if !ok {
		return profile.Profile{}, clerr.New(clerr.ProfileNotFound, name)
	}
	if stored.Kind != profile.KindProviderProxy && stored.Kind != profile.KindInject && stored.Issuer != "talos" {
		return profile.Profile{}, clerr.New(clerr.ConfigInvalid, "profile issuer must be talos")
	}

	p := stored.toProfile(name, f.Defaults)
	if err := p.Validate(); err != nil {
		return profile.Profile{}, err
	}
	return p, nil
}

func (p Profile) toProfile(name string, defaults Defaults) profile.Profile {
	tokenTTL := p.TokenTTL.Duration()
	if tokenTTL == 0 {
		tokenTTL = defaults.TokenTTL.Duration()
	}
	maxTokenTTL := p.MaxTokenTTL.Duration()
	if maxTokenTTL == 0 {
		maxTokenTTL = defaults.MaxTokenTTL.Duration()
	}

	return profile.Profile{
		Name:     name,
		Kind:     p.Kind,
		Resource: p.Resource,
		Scopes:   append([]string(nil), p.Scopes...),
		Claims:   cloneStringMap(p.Claims),
		ProjectBinding: profile.ProjectBinding{
			Mode:      p.ProjectBinding.Mode,
			PathHash:  p.ProjectBinding.PathHash,
			GitRoot:   p.ProjectBinding.GitRoot,
			GitRemote: p.ProjectBinding.GitRemote,
		},
		TokenTTL:          tokenTTL,
		MaxTokenTTL:       maxTokenTTL,
		BootstrapTokenTTL: p.BootstrapTokenTTL.Duration(),
		LoginCodeTTL:      p.LoginCodeTTL.Duration(),
		WebSessionTTL:     p.WebSessionTTL.Duration(),
		ExchangeURL:       p.ExchangeURL,
		CompleteURL:       p.CompleteURL,
		PostLoginURL:      p.PostLoginURL,
		AllowedHosts:      append([]string(nil), p.AllowedHosts...),
		CredentialName:    p.CredentialName,
		AuthMode:          p.AuthMode,
		Provider:          p.Provider,
		TargetURL:         p.TargetURL,
		AllowedPaths:      append([]string(nil), p.AllowedPaths...),
		AllowedMethods:    append([]string(nil), p.AllowedMethods...),
		LocalTokenTTL:     p.LocalTokenTTL.Duration(),
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
