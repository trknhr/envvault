package admin

import (
	"context"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
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
	profiles := make([]profileSummary, 0, len(cfg.Profiles))
	for name, stored := range cfg.Profiles {
		profiles = append(profiles, profileSummary{
			Name:           name,
			Kind:           string(stored.Kind),
			CredentialName: stored.CredentialName,
			Provider:       stored.Provider,
			TargetURL:      stored.TargetURL,
			AllowedPaths:   append([]string(nil), stored.AllowedPaths...),
			AllowedMethods: append([]string(nil), stored.AllowedMethods...),
			ProjectBinding: string(stored.ProjectBinding.Mode),
		})
	}
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
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
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
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
	defer zero(value)
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
	writeJSON(w, http.StatusCreated, map[string]string{"name": request.Name})
}

func (s Server) addProfile(_ context.Context, name string, stored config.Profile) error {
	if strings.TrimSpace(name) == "" {
		return clerr.New(clerr.ConfigInvalid, "profile name is required")
	}
	cfg, err := config.LoadOrDefault(s.ConfigPath)
	if err != nil {
		return err
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]config.Profile{}
	}
	if _, exists := cfg.Profiles[name]; exists {
		return clerr.New(clerr.ConfigInvalid, "profile already exists")
	}
	cfg.Profiles[name] = stored
	return config.Save(s.ConfigPath, cfg)
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

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

var adminHTML = template.Must(template.New("admin").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EnvVault</title>
  <style>
    :root {
      color-scheme: light;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f7f8fa;
      color: #171a1f;
    }
    * { box-sizing: border-box; }
    body { margin: 0; }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 56px;
      padding: 0 24px;
      border-bottom: 1px solid #d9dde5;
      background: #ffffff;
    }
    h1 { margin: 0; font-size: 18px; font-weight: 650; }
    main {
      display: grid;
      grid-template-columns: minmax(260px, 420px) minmax(320px, 1fr);
      gap: 24px;
      width: min(1180px, calc(100vw - 32px));
      margin: 24px auto;
    }
    section {
      border: 1px solid #d9dde5;
      border-radius: 8px;
      background: #ffffff;
    }
    section h2 {
      margin: 0;
      padding: 14px 16px;
      border-bottom: 1px solid #e6e9ef;
      font-size: 14px;
      font-weight: 650;
    }
    form {
      display: grid;
      gap: 10px;
      padding: 14px 16px 16px;
    }
    label {
      display: grid;
      gap: 4px;
      font-size: 12px;
      font-weight: 600;
      color: #4a5567;
    }
    input, select {
      width: 100%;
      min-height: 34px;
      border: 1px solid #c9cfda;
      border-radius: 6px;
      padding: 7px 9px;
      font: inherit;
      color: #171a1f;
      background: #ffffff;
    }
    button {
      min-height: 34px;
      border: 1px solid #1f6feb;
      border-radius: 6px;
      padding: 7px 10px;
      font: inherit;
      font-weight: 650;
      color: #ffffff;
      background: #1f6feb;
      cursor: pointer;
    }
    button.secondary {
      border-color: #c9cfda;
      color: #171a1f;
      background: #ffffff;
    }
    .stack { display: grid; gap: 16px; }
    .toolbar {
      display: flex;
      justify-content: flex-end;
      padding: 12px 16px;
      border-bottom: 1px solid #e6e9ef;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
      font-size: 13px;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid #edf0f5;
      text-align: left;
      vertical-align: top;
      overflow-wrap: anywhere;
    }
    th {
      color: #4a5567;
      font-size: 12px;
      font-weight: 650;
      background: #fbfcfd;
    }
    #status {
      min-width: 160px;
      color: #4a5567;
      font-size: 13px;
      text-align: right;
    }
    @media (max-width: 820px) {
      header { padding: 0 16px; }
      main {
        grid-template-columns: 1fr;
        width: min(100vw - 24px, 680px);
        margin: 16px auto;
      }
    }
  </style>
</head>
<body>
  <header>
    <h1>EnvVault</h1>
    <div id="status"></div>
  </header>
  <main>
    <div class="stack">
      <section>
        <h2>Credential</h2>
        <form id="credential-form">
          <label>Name<input name="name" autocomplete="off" placeholder="openai-key/dev"></label>
          <label>Value<input name="value" autocomplete="off" type="password"></label>
          <button type="submit">Add Credential</button>
        </form>
      </section>
      <section>
        <h2>Inject Profile</h2>
        <form id="inject-profile-form">
          <label>Name<input name="name" autocomplete="off" placeholder="database/dev"></label>
          <label>Credential<input name="credential" autocomplete="off" list="credential-options" placeholder="database-url/dev"></label>
          <label>Project Binding
            <select name="project_binding">
              <option value="none">none</option>
            </select>
          </label>
          <button type="submit">Add Inject Profile</button>
        </form>
      </section>
      <section>
        <h2>Proxy Profile</h2>
        <form id="proxy-profile-form">
          <label>Name<input name="name" autocomplete="off" placeholder="openai/dev"></label>
          <label>Credential<input name="credential" autocomplete="off" list="credential-options" placeholder="openai-key/dev"></label>
          <label>Provider
            <select name="provider">
              <option value="generic">generic</option>
              <option value="openai-compatible">openai-compatible</option>
            </select>
          </label>
          <label>Target URL<input name="target_url" autocomplete="off" placeholder="https://api.openai.com/v1"></label>
          <label>Allowed Paths<input name="allowed_paths" autocomplete="off" placeholder="/chat/completions"></label>
          <label>Allowed Methods<input name="allowed_methods" autocomplete="off" placeholder="POST"></label>
          <label>Project Binding
            <select name="project_binding">
              <option value="none">none</option>
            </select>
          </label>
          <button type="submit">Add Proxy Profile</button>
        </form>
      </section>
      <datalist id="credential-options"></datalist>
    </div>
    <div class="stack">
      <section>
        <h2>Credentials</h2>
        <div class="toolbar"><button id="refresh" class="secondary" type="button">Refresh</button></div>
        <table>
          <thead>
            <tr><th>Name</th></tr>
          </thead>
          <tbody id="credentials"></tbody>
        </table>
      </section>
      <section>
        <h2>Profiles</h2>
        <table>
          <thead>
            <tr><th>Name</th><th>Kind</th><th>Credential</th><th>Target</th></tr>
          </thead>
          <tbody id="profiles"></tbody>
        </table>
      </section>
    </div>
  </main>
  <script>
    const envvaultToken = new URLSearchParams(location.search).get("token") || sessionStorage.getItem("envvaultAdminToken") || "";
    if (envvaultToken) sessionStorage.setItem("envvaultAdminToken", envvaultToken);
    const statusNode = document.getElementById("status");
    const credentialsNode = document.getElementById("credentials");
    const credentialOptionsNode = document.getElementById("credential-options");
    const profilesNode = document.getElementById("profiles");
    const headers = () => ({
      "Content-Type": "application/json",
      "Authorization": "Bearer " + envvaultToken
    });
    const splitList = (value) => value.split(",").map((item) => item.trim()).filter(Boolean);
    const setStatus = (message) => { statusNode.textContent = message; };
    const request = async (path, options) => {
      const response = await fetch(path, {...options, headers: headers()});
      if (!response.ok) {
        const body = await response.text();
        throw new Error(body || response.statusText);
      }
      return response.json();
    };
    const refreshCredentials = async () => {
      const data = await request("/api/credentials", {method: "GET"});
      credentialsNode.replaceChildren(...data.credentials.map((credential) => {
        const row = document.createElement("tr");
        const cell = document.createElement("td");
        cell.textContent = credential;
        row.appendChild(cell);
        return row;
      }));
      credentialOptionsNode.replaceChildren(...data.credentials.map((credential) => {
        const option = document.createElement("option");
        option.value = credential;
        return option;
      }));
    };
    const refreshProfiles = async () => {
      const data = await request("/api/profiles", {method: "GET"});
      profilesNode.replaceChildren(...data.profiles.map((profile) => {
        const row = document.createElement("tr");
        [profile.name, profile.kind, profile.credential || "", profile.target_url || ""].forEach((value) => {
          const cell = document.createElement("td");
          cell.textContent = value;
          row.appendChild(cell);
        });
        return row;
      }));
    };
    const refreshAll = async () => {
      await Promise.all([refreshCredentials(), refreshProfiles()]);
    };
    const bindForm = (id, path, payload) => {
      document.getElementById(id).addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
          await request(path, {method: "POST", body: JSON.stringify(payload(new FormData(event.currentTarget)))});
          event.currentTarget.reset();
          await refreshAll();
          setStatus("Saved");
        } catch (error) {
          setStatus("Error");
        }
      });
    };
    bindForm("credential-form", "/api/credentials", (form) => ({
      name: form.get("name"),
      value: form.get("value")
    }));
    bindForm("inject-profile-form", "/api/inject-profiles", (form) => ({
      name: form.get("name"),
      credential: form.get("credential"),
      project_binding: form.get("project_binding")
    }));
    bindForm("proxy-profile-form", "/api/proxy-profiles", (form) => ({
      name: form.get("name"),
      credential: form.get("credential"),
      provider: form.get("provider"),
      target_url: form.get("target_url"),
      allowed_paths: splitList(form.get("allowed_paths") || ""),
      allowed_methods: splitList(form.get("allowed_methods") || "POST"),
      project_binding: form.get("project_binding")
    }));
    document.getElementById("refresh").addEventListener("click", () => refreshAll().catch(() => setStatus("Error")));
    refreshAll().catch(() => setStatus("Locked"));
  </script>
</body>
</html>`))
