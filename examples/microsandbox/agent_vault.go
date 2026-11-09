package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/trknhr/envvault/internal/authstate"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/compatprofile"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
)

const agentCatalogPath = "/etc/envvault/credentials.json"

// This reads public metadata only. Values are acquired separately, after the
// request has passed both network policy and the saved destination rules.
type agentVault struct {
	filename string
	dataDir  string
	identity projectbinding.Identity
}

type agentVaultSnapshot struct {
	references []string
	routes     []agentCredential
}

func defaultAgentVault(repoDir string) (*agentVault, error) {
	paths, err := config.DefaultPaths()
	if err != nil {
		return nil, err
	}
	if err := protectAgentVaultPath(paths.ConfigFile, repoDir); err != nil {
		return nil, err
	}
	if err := protectAgentVaultPath(paths.DataDir, repoDir); err != nil {
		return nil, err
	}
	identity, err := projectbinding.Detect(context.Background(), repoDir)
	if err != nil {
		return nil, err
	}
	return &agentVault{filename: paths.ConfigFile, dataDir: paths.DataDir, identity: identity}, nil
}

func protectAgentVaultPath(filename, repoDir string) error {
	root, err := filepath.EvalSymlinks(repoDir)
	if err != nil {
		return err
	}
	inside := func(candidate string) bool {
		rel, err := filepath.Rel(root, candidate)
		return err != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
	}
	if inside(filename) {
		return errors.New("EnvVault host configuration must be outside the guest workspace")
	}
	candidate := filename
	for {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			if inside(resolved) {
				return errors.New("EnvVault host configuration resolves inside the guest workspace")
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return errors.New("EnvVault host configuration path is unavailable")
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return errors.New("EnvVault host configuration path is unavailable")
		}
		candidate = parent
	}
}

func (v *agentVault) load() (agentVaultSnapshot, error) {
	var result agentVaultSnapshot
	if _, err := os.Stat(v.filename); os.IsNotExist(err) {
		return result, nil
	}
	cfg, err := config.Load(v.filename)
	if err != nil {
		return result, errors.New("EnvVault metadata unavailable")
	}
	known := make(map[string]bool)
	for _, name := range cfg.CredentialNames() {
		reference := envref.Format(name, envref.PartDefault)
		parsed, recognized, err := envref.ParseValue(reference)
		if err == nil && recognized && parsed.Part == envref.PartDefault && parsed.Profile == name && !strings.ContainsAny(reference, "\r\n\x00") {
			known[reference] = true
			result.references = append(result.references, reference)
		}
	}
	for name, id := range cfg.AuthProfiles {
		metadata, err := (authstate.Store{Dir: filepath.Join(v.dataDir, "auth-profiles"), Keys: keyring.NewOSStore()}).ReadMetadata(id)
		if err != nil || metadata.Name != name {
			return result, errors.New("host authentication metadata unavailable")
		}
		reference := envref.Format(name, envref.PartDefault)
		known[reference] = true
		result.references = append(result.references, reference)
	}
	sort.Strings(result.references)
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		candidate, err := cfg.Profile(name)
		if err != nil {
			return agentVaultSnapshot{}, errors.New("EnvVault profile unavailable")
		}
		if candidate.Kind != profile.KindProviderProxy || projectbinding.Check(candidate.ProjectBinding, v.identity) != nil {
			continue
		}
		translated, err := compatprofile.FromProviderProxyProfile(candidate)
		if err != nil {
			return agentVaultSnapshot{}, errors.New("EnvVault proxy profile cannot be translated")
		}
		httpPolicy := translated.Protocol.HTTP
		reference := translated.Authentication.Credential.Ref
		// This launcher supports public DNS HTTPS:443 and bearer profiles.
		// Unsupported routes are not silently broadened to another destination.
		if !known[reference] || httpPolicy.Scheme != connection.HTTPSchemeHTTPS || translated.Destination.Port != 443 || !validAgentHost(translated.Destination.Host) {
			continue
		}
		binding := agentCredential{Reference: reference, Host: translated.Destination.Host, Header: httpPolicy.Auth.Header,
			Methods: append([]string(nil), httpPolicy.AllowedMethods...)}
		for _, allowed := range httpPolicy.AllowedPaths {
			binding.Paths = append(binding.Paths, path.Join(httpPolicy.BasePath, allowed))
		}
		for _, allowed := range binding.Paths {
			if !safeAgentCredentialPath(allowed) || strings.Contains(allowed, "*") {
				return agentVaultSnapshot{}, errors.New("EnvVault proxy path is unsupported")
			}
		}
		result.routes = append(result.routes, binding)
	}
	return result, nil
}

func (p *agentProxy) policy() (agentPolicy, error) {
	policy, err := readAgentPolicy(p.policyPath)
	if err != nil || !policy.EnvVault || p.vault == nil {
		return policy, err
	}
	snapshot, err := p.vault.load()
	if err != nil {
		return agentPolicy{}, err
	}
	policy.vaultReferences, policy.vaultRoutes = snapshot.references, snapshot.routes
	return policy, nil
}

func (p agentPolicy) routes(host string) []agentCredential {
	var routes []agentCredential
	for _, route := range p.vaultRoutes {
		if route.Host == host {
			routes = append(routes, route)
		}
	}
	return routes
}

func (p agentPolicy) credentialCatalog() []byte {
	// Only public references and applicable destination rules cross into the VM.
	refs := append([]string(nil), p.vaultReferences...)
	routes := append([]agentCredential(nil), p.vaultRoutes...)
	for _, binding := range p.Credentials {
		refs = append(refs, binding.Reference)
		routes = append(routes, binding)
	}
	sort.Strings(refs)
	unique := make([]string, 0, len(refs))
	for _, ref := range refs {
		if len(unique) == 0 || unique[len(unique)-1] != ref {
			unique = append(unique, ref)
		}
	}
	data, _ := json.MarshalIndent(struct {
		References []string          `json:"references"`
		Routes     []agentCredential `json:"routes"`
		Scope      string            `json:"scope"`
	}{unique, routes, p.EnvVaultScope}, "", "  ")
	return append(data, '\n')
}

func (p agentPolicy) networkBinding(request *http.Request) (*agentCredential, error) {
	var binding *agentCredential
	for header, values := range request.Header {
		for _, value := range values {
			if !strings.Contains(value, "envvault://") {
				continue
			}
			if binding != nil || len(values) != 1 {
				return nil, errors.New("ambiguous credential reference")
			}
			reference := value
			raw := true
			switch strings.ToLower(header) {
			case "authorization":
				switch {
				case strings.HasPrefix(value, "Bearer "):
					reference = strings.TrimPrefix(value, "Bearer ")
				case strings.HasPrefix(value, "token "):
					reference = strings.TrimPrefix(value, "token ")
				default:
					return nil, errors.New("unsupported authentication scheme")
				}
				raw = false
			case "x-api-key", "api-key", "x-goog-api-key":
			default:
				return nil, errors.New("unsupported credential header")
			}
			parsed, recognized, err := envref.ParseValue(reference)
			if err != nil || !recognized || parsed.Part != envref.PartDefault {
				return nil, errors.New("invalid credential reference")
			}
			known := false
			for _, candidate := range p.vaultReferences {
				known = known || candidate == reference
			}
			if !known {
				return nil, errors.New("unknown credential reference")
			}
			binding = &agentCredential{Reference: reference, Host: request.URL.Hostname(), Header: header,
				Methods: []string{request.Method}, Paths: []string{request.URL.Path}, rawHeader: raw}
		}
	}
	return binding, nil
}

func (p agentPolicy) autoBinding(request *http.Request) (*agentCredential, bool) {
	routes := p.routes(request.URL.Hostname())
	if len(routes) == 0 {
		return nil, false
	}
	for i := range routes {
		binding := &routes[i]
		if binding.matchesReference(request) && binding.allows(request) {
			return binding, true
		}
	}
	return nil, true
}
