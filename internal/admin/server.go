package admin

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
)

const defaultProxyLocalTokenTTL = 10 * time.Minute

type Server struct {
	ConfigPath string
	Secrets    keyring.Store
	Token      string
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/profiles", s.handleProfiles)
	mux.HandleFunc("/api/proxies", s.handleProxies)
	mux.HandleFunc("/api/credentials", s.handleCredentials)
	mux.HandleFunc("/api/inject-profiles", s.handleInjectProfiles)
	mux.HandleFunc("/api/proxy-profiles", s.handleProxyProfiles)
	return s.secure(mux)
}

func (s Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLocalHost(r.Host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !isLocalOrigin(r.Header.Get("Origin")) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.authorized(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s Server) authorized(r *http.Request) bool {
	if s.Token == "" {
		return false
	}
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	return strings.TrimSpace(strings.TrimPrefix(value, prefix)) == s.Token
}

func (s Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = adminHTML.Execute(w, nil)
}

func (s Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s Server) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := config.LoadOrDefault(s.ConfigPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profileSummaries(cfg, nil)})
}

func (s Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleProxyList(w, r)
	case http.MethodPost:
		s.handleProxyCreate(w, r)
	default:
		w.Header().Set("Allow", strings.Join([]string{http.MethodGet, http.MethodPost}, ", "))
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s Server) handleProxyList(w http.ResponseWriter, _ *http.Request) {
	cfg, err := config.LoadOrDefault(s.ConfigPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"proxies": profileSummaries(cfg, func(stored config.Profile) bool {
			return stored.Kind == profile.KindProviderProxy
		}),
	})
}

func (s Server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleCredentialList(w, r)
	case http.MethodPost:
		s.handleCredentialCreate(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s Server) handleCredentialList(w http.ResponseWriter, r *http.Request) {
	cfg, err := config.LoadOrDefault(s.ConfigPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"credentials": cfg.CredentialNames()})
}

func (s Server) handleCredentialCreate(w http.ResponseWriter, r *http.Request) {
	if s.Secrets == nil {
		writeError(w, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable"))
		return
	}
	var request credentialRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, err)
		return
	}
	if strings.TrimSpace(request.Name) == "" {
		writeError(w, clerr.New(clerr.ConfigInvalid, "credential name is required"))
		return
	}
	value := []byte(strings.TrimSpace(request.Value))
	defer keyring.Zero(value)
	if len(value) == 0 {
		writeError(w, clerr.New(clerr.ConfigInvalid, "credential value is required"))
		return
	}
	if err := s.Secrets.Put(r.Context(), keyring.CredentialValue(request.Name), value); err != nil {
		writeError(w, err)
		return
	}
	cfg, err := config.LoadOrDefault(s.ConfigPath)
	if err != nil {
		_ = s.Secrets.Delete(r.Context(), keyring.CredentialValue(request.Name))
		writeError(w, err)
		return
	}
	cfg.AddCredential(request.Name)
	if err := config.Save(s.ConfigPath, cfg); err != nil {
		_ = s.Secrets.Delete(r.Context(), keyring.CredentialValue(request.Name))
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": request.Name})
}

func (s Server) handleInjectProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request injectProfileRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, err)
		return
	}
	stored := config.Profile{
		Kind:           profile.KindInject,
		CredentialName: request.CredentialName,
		ProjectBinding: projectBinding(request.ProjectBinding),
	}
	if err := s.addProfile(r.Context(), request.Name, stored); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"name": request.Name})
}

func (s Server) handleProxyProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.handleProxyCreate(w, r)
}

func (s Server) handleProxyCreate(w http.ResponseWriter, r *http.Request) {
	var request proxyProfileRequest
	if err := readJSON(r, &request); err != nil {
		writeError(w, err)
		return
	}
	provider := request.Provider
	if provider == "" {
		provider = "generic"
	}
	authMode := request.AuthMode
	if authMode == "" {
		authMode = "bearer"
	}
	stored := config.Profile{
		Kind:           profile.KindProviderProxy,
		CredentialName: request.CredentialName,
		AuthMode:       authMode,
		Provider:       provider,
		TargetURL:      request.TargetURL,
		AllowedPaths:   append([]string(nil), request.AllowedPaths...),
		AllowedMethods: append([]string(nil), request.AllowedMethods...),
		LocalTokenTTL:  config.Duration(defaultProxyLocalTokenTTL),
		ProjectBinding: projectBinding(request.ProjectBinding),
	}
	if err := s.addProfile(r.Context(), request.Name, stored); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"name":   request.Name,
		"dotenv": envref.ProxyDotenv(request.Name),
	})
}

func (s Server) addProfile(_ context.Context, name string, stored config.Profile) error {
	if strings.TrimSpace(name) == "" {
		return clerr.New(clerr.ConfigInvalid, "profile name is required")
	}
	cfg, err := config.LoadOrDefault(s.ConfigPath)
	if err != nil {
		return err
	}
	if err := cfg.AddProfile(name, stored); err != nil {
		return err
	}
	return config.Save(s.ConfigPath, cfg)
}

func profileSummaries(cfg config.File, include func(config.Profile) bool) []profileSummary {
	summaries := make([]profileSummary, 0, len(cfg.Profiles))
	for name, stored := range cfg.Profiles {
		if include != nil && !include(stored) {
			continue
		}
		summaries = append(summaries, profileSummary{
			Name:           name,
			Kind:           string(stored.Kind),
			CredentialName: stored.CredentialName,
			Provider:       stored.Provider,
			TargetURL:      stored.TargetURL,
			AllowedPaths:   append([]string(nil), stored.AllowedPaths...),
			AllowedMethods: append([]string(nil), stored.AllowedMethods...),
			ProjectBinding: string(stored.ProjectBinding.Mode),
			Dotenv:         profileDotenv(name, stored),
		})
	}
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].Name < summaries[j].Name
	})
	return summaries
}

type profileSummary struct {
	Name           string   `json:"name"`
	Kind           string   `json:"kind"`
	CredentialName string   `json:"credential,omitempty"`
	Provider       string   `json:"provider,omitempty"`
	TargetURL      string   `json:"target_url,omitempty"`
	AllowedPaths   []string `json:"allowed_paths,omitempty"`
	AllowedMethods []string `json:"allowed_methods,omitempty"`
	ProjectBinding string   `json:"project_binding,omitempty"`
	Dotenv         string   `json:"dotenv,omitempty"`
}

func profileDotenv(name string, stored config.Profile) string {
	if stored.Kind != profile.KindProviderProxy {
		return ""
	}
	return envref.ProxyDotenv(name)
}

type credentialRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type injectProfileRequest struct {
	Name           string `json:"name"`
	CredentialName string `json:"credential"`
	ProjectBinding string `json:"project_binding"`
}

type proxyProfileRequest struct {
	Name           string   `json:"name"`
	CredentialName string   `json:"credential"`
	AuthMode       string   `json:"auth_mode"`
	Provider       string   `json:"provider"`
	TargetURL      string   `json:"target_url"`
	AllowedPaths   []string `json:"allowed_paths"`
	AllowedMethods []string `json:"allowed_methods"`
	ProjectBinding string   `json:"project_binding"`
}

func projectBinding(mode string) config.ProjectBinding {
	if mode == "" {
		mode = string(profile.ProjectBindingNone)
	}
	return config.ProjectBinding{Mode: profile.ProjectBindingMode(mode)}
}

func readJSON(r *http.Request, out any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return clerr.Wrap(clerr.ConfigInvalid, "parse request json", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		http.Error(w, "write response", http.StatusInternalServerError)
	}
}

func writeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if code, ok := clerr.CodeOf(err); ok {
		switch code {
		case clerr.ConfigInvalid, clerr.ProfileNotFound, clerr.ProfileKindMismatch, clerr.ProjectNotTrusted, clerr.ReferenceInvalid:
			status = http.StatusBadRequest
		case clerr.KeyringUnavailable, clerr.KeyringLocked, clerr.ParentKeyMissing:
			status = http.StatusServiceUnavailable
		}
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func isLocalHost(hostport string) bool {
	if hostport == "" {
		return true
	}
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLocalOrigin(origin string) bool {
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return isLocalHost(parsed.Host)
}
