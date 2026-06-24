package profilemgr

import (
	"context"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/config"
	"github.com/trknhr/credlease/internal/issuer/talos"
	"github.com/trknhr/credlease/internal/keyring"
	"github.com/trknhr/credlease/internal/profile"
)

const defaultParentKeyTTL = 2160 * time.Hour

type ParentKeyIssuer interface {
	IssueParentKey(ctx context.Context, request talos.ParentKeyRequest) (talos.ParentKey, error)
}

type Manager struct {
	configPath   string
	secrets      keyring.Store
	parentIssuer ParentKeyIssuer
	parentKeyTTL time.Duration
}

type ProcessRequest struct {
	Name           string
	Resource       string
	Scopes         []string
	TokenTTL       time.Duration
	MaxTokenTTL    time.Duration
	Claims         map[string]string
	ProjectBinding profile.ProjectBinding
}

type BrowserSessionRequest struct {
	Name              string
	Resource          string
	Scopes            []string
	BootstrapTokenTTL time.Duration
	LoginCodeTTL      time.Duration
	WebSessionTTL     time.Duration
	ExchangeURL       string
	CompleteURL       string
	PostLoginURL      string
	AllowedHosts      []string
	ProjectBinding    profile.ProjectBinding
}

func New(configPath string, secrets keyring.Store, parentIssuer ParentKeyIssuer) *Manager {
	return &Manager{
		configPath:   configPath,
		secrets:      secrets,
		parentIssuer: parentIssuer,
		parentKeyTTL: defaultParentKeyTTL,
	}
}

func (m *Manager) AddProcess(ctx context.Context, request ProcessRequest) (profile.Profile, error) {
	stored := config.Profile{
		Kind:           profile.KindProcess,
		Issuer:         "talos",
		Resource:       request.Resource,
		Scopes:         append([]string(nil), request.Scopes...),
		Claims:         cloneStringMap(request.Claims),
		TokenTTL:       config.Duration(request.TokenTTL),
		MaxTokenTTL:    config.Duration(request.MaxTokenTTL),
		ProjectBinding: toConfigProjectBinding(request.ProjectBinding),
	}
	return m.addProfile(ctx, request.Name, stored)
}

func (m *Manager) AddBrowserSession(ctx context.Context, request BrowserSessionRequest) (profile.Profile, error) {
	stored := config.Profile{
		Kind:              profile.KindBrowserSession,
		Issuer:            "talos",
		Resource:          request.Resource,
		Scopes:            append([]string(nil), request.Scopes...),
		BootstrapTokenTTL: config.Duration(request.BootstrapTokenTTL),
		LoginCodeTTL:      config.Duration(request.LoginCodeTTL),
		WebSessionTTL:     config.Duration(request.WebSessionTTL),
		ExchangeURL:       request.ExchangeURL,
		CompleteURL:       request.CompleteURL,
		PostLoginURL:      request.PostLoginURL,
		AllowedHosts:      append([]string(nil), request.AllowedHosts...),
		ProjectBinding:    toConfigProjectBinding(request.ProjectBinding),
	}
	return m.addProfile(ctx, request.Name, stored)
}

func (m *Manager) addProfile(ctx context.Context, name string, stored config.Profile) (profile.Profile, error) {
	cfg, err := config.Load(m.configPath)
	if err != nil {
		return profile.Profile{}, err
	}
	if _, exists := cfg.Profiles[name]; exists {
		return profile.Profile{}, clerr.New(clerr.ConfigInvalid, "profile already exists")
	}

	p := config.File{
		Version:      cfg.Version,
		Installation: cfg.Installation,
		Runtime:      cfg.Runtime,
		Defaults:     cfg.Defaults,
		Profiles: map[string]config.Profile{
			name: stored,
		},
	}
	resolved, err := p.Profile(name)
	if err != nil {
		return profile.Profile{}, err
	}

	parent, err := m.parentIssuer.IssueParentKey(ctx, talos.ParentKeyRequest{
		Profile:        resolved.Name,
		InstallationID: cfg.Installation.ID,
		Scopes:         append([]string(nil), resolved.Scopes...),
		TTL:            m.parentKeyTTL,
	})
	if err != nil {
		return profile.Profile{}, err
	}

	parentSecret := []byte(parent.Secret)
	defer zero(parentSecret)
	if err := m.secrets.Put(ctx, keyring.ProfileParentKey(resolved.Name), parentSecret); err != nil {
		return profile.Profile{}, err
	}

	if cfg.Profiles == nil {
		cfg.Profiles = map[string]config.Profile{}
	}
	cfg.Profiles[name] = stored
	if err := config.Save(m.configPath, cfg); err != nil {
		_ = m.secrets.Delete(ctx, keyring.ProfileParentKey(resolved.Name))
		return profile.Profile{}, err
	}

	return resolved, nil
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

func toConfigProjectBinding(binding profile.ProjectBinding) config.ProjectBinding {
	return config.ProjectBinding{
		Mode:      binding.Mode,
		PathHash:  binding.PathHash,
		GitRoot:   binding.GitRoot,
		GitRemote: binding.GitRemote,
	}
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
