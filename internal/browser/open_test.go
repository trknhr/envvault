package browser_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/audit"
	"github.com/trknhr/envvault/internal/browser"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/issuer"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/projectbinding"
)

func TestOpenPostsBootstrapJWTInAuthorizationHeaderAndOpensLaunchURL(t *testing.T) {
	var gotAuth string
	var gotCacheControl string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if strings.Contains(r.URL.String(), "bootstrap-jwt") {
			t.Fatalf("jwt leaked into request URL: %s", r.URL.String())
		}
		gotAuth = r.Header.Get("Authorization")
		gotCacheControl = r.Header.Get("Cache-Control")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"launch_url":"` + serverBaseURL(r) + `/auth/envvault/complete?code=opaque","expires_at":"2026-06-22T12:00:30Z"}`))
	}))
	defer server.Close()

	p := browserProfile(server.URL)
	issuer := &fakeIssuer{}
	opener := &fakeOpener{}
	client := browser.Client{HTTP: server.Client(), Issuer: issuer, Opener: opener}
	projectIdentity := projectbinding.Identity{Root: "/tmp/envvault-test-project"}
	wantProjectID, err := projectbinding.PathHash(projectIdentity.Root)
	if err != nil {
		t.Fatalf("PathHash() error = %v", err)
	}

	result, err := client.Open(context.Background(), browser.OpenRequest{
		Profile:         p,
		Browser:         "chrome",
		ProjectIdentity: projectIdentity,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if gotAuth != "Bearer bootstrap-jwt" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotCacheControl != "no-store" {
		t.Fatalf("Cache-Control = %q", gotCacheControl)
	}
	if gotBody["client"] != "envvault-cli" {
		t.Fatalf("client = %v", gotBody["client"])
	}
	if gotBody["requested_session_ttl_seconds"] != float64(1800) {
		t.Fatalf("requested_session_ttl_seconds = %v", gotBody["requested_session_ttl_seconds"])
	}
	if opener.browser != "chrome" {
		t.Fatalf("browser = %q", opener.browser)
	}
	if !strings.Contains(opener.rawURL, "/auth/envvault/complete?code=opaque") {
		t.Fatalf("opened URL = %q", opener.rawURL)
	}
	if strings.Contains(opener.rawURL, "bootstrap-jwt") {
		t.Fatalf("jwt leaked into launch URL: %q", opener.rawURL)
	}
	if result.LaunchURL != opener.rawURL {
		t.Fatalf("LaunchURL = %q, opener URL = %q", result.LaunchURL, opener.rawURL)
	}
	if len(issuer.grants) != 1 {
		t.Fatalf("issuer grants = %d, want 1", len(issuer.grants))
	}
	grant := issuer.grants[0]
	if grant.Profile != "admin-web/dev" {
		t.Fatalf("grant profile = %q", grant.Profile)
	}
	if grant.TTL != 60*time.Second {
		t.Fatalf("grant ttl = %s", grant.TTL)
	}
	if grant.Claims["envvault_purpose"] != "browser-bootstrap" {
		t.Fatalf("grant claims = %#v", grant.Claims)
	}
	if grant.Claims["envvault_session_id"] == "" {
		t.Fatalf("grant claims missing session id: %#v", grant.Claims)
	}
	if grant.Claims["envvault_project_id"] != wantProjectID {
		t.Fatalf("envvault_project_id = %#v, want %q", grant.Claims["envvault_project_id"], wantProjectID)
	}
	if grant.Claims["envvault_project_id"] == projectIdentity.Root {
		t.Fatalf("envvault_project_id leaked raw project root: %#v", grant.Claims["envvault_project_id"])
	}
}

func TestOpenPrintURLDoesNotOpenBrowser(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"launch_url":"` + serverBaseURL(r) + `/auth/envvault/complete?code=opaque","expires_at":"2026-06-22T12:00:30Z"}`))
	}))
	defer server.Close()

	opener := &fakeOpener{}
	client := browser.Client{HTTP: server.Client(), Issuer: &fakeIssuer{}, Opener: opener}
	result, err := client.Open(context.Background(), browser.OpenRequest{
		Profile:  browserProfile(server.URL),
		PrintURL: true,
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if opener.rawURL != "" {
		t.Fatalf("browser opened URL %q, want none", opener.rawURL)
	}
	if result.LaunchURL == "" {
		t.Fatal("LaunchURL is empty")
	}
}

func TestOpenRejectsBackendLaunchURLOutsideProfilePolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"launch_url":"https://evil.example/auth/envvault/complete?code=opaque","expires_at":"2026-06-22T12:00:30Z"}`))
	}))
	defer server.Close()

	opener := &fakeOpener{}
	client := browser.Client{HTTP: server.Client(), Issuer: &fakeIssuer{}, Opener: opener}
	_, err := client.Open(context.Background(), browser.OpenRequest{Profile: browserProfile(server.URL)})
	if err == nil {
		t.Fatal("Open() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.BrowserURLRejected {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.BrowserURLRejected)
	}
	if opener.rawURL != "" {
		t.Fatalf("browser opened URL %q, want none", opener.rawURL)
	}
}

func TestOpenRejectsExchangeResponseWithoutNoStore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"launch_url":"` + serverBaseURL(r) + `/auth/envvault/complete?code=opaque","expires_at":"2026-06-22T12:00:30Z"}`))
	}))
	defer server.Close()

	client := browser.Client{HTTP: server.Client(), Issuer: &fakeIssuer{}, Opener: &fakeOpener{}}
	_, err := client.Open(context.Background(), browser.OpenRequest{Profile: browserProfile(server.URL)})
	if err == nil {
		t.Fatal("Open() error = nil, want error")
	}
	if code, _ := clerr.CodeOf(err); code != clerr.BrowserExchangeFailed {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.BrowserExchangeFailed)
	}
}

func TestOpenRedactsExchangeErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bootstrap-jwt leaked body", http.StatusInternalServerError)
	}))
	defer server.Close()

	client := browser.Client{HTTP: server.Client(), Issuer: &fakeIssuer{}, Opener: &fakeOpener{}}
	_, err := client.Open(context.Background(), browser.OpenRequest{Profile: browserProfile(server.URL)})
	if err == nil {
		t.Fatal("Open() error = nil, want error")
	}
	if strings.Contains(err.Error(), "bootstrap-jwt") || strings.Contains(err.Error(), "leaked body") {
		t.Fatalf("error leaked response body: %q", err.Error())
	}
	if code, _ := clerr.CodeOf(err); code != clerr.BrowserExchangeFailed {
		t.Fatalf("CodeOf(error) = %q, want %q", code, clerr.BrowserExchangeFailed)
	}
}

func TestOpenRecordsSuccessfulBrowserSessionRequestAuditWithoutSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"launch_url":"` + serverBaseURL(r) + `/auth/envvault/complete?code=opaque","expires_at":"2026-06-22T12:00:30Z"}`))
	}))
	defer server.Close()

	issuer := &fakeIssuer{}
	recorder := &recordingAudit{}
	client := browser.Client{
		HTTP:   server.Client(),
		Issuer: issuer,
		Opener: &fakeOpener{},
		Audit:  recorder,
	}

	_, err := client.Open(context.Background(), browser.OpenRequest{Profile: browserProfile(server.URL)})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if len(recorder.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(recorder.events))
	}
	got := recorder.events[0]
	if got.Event != audit.EventBrowserSessionRequested {
		t.Fatalf("event = %q", got.Event)
	}
	if got.Profile != "admin-web/dev" {
		t.Fatalf("profile = %q", got.Profile)
	}
	if got.SessionID == "" {
		t.Fatal("session_id is empty")
	}
	if got.SessionID != issuer.grants[0].Claims["envvault_session_id"] {
		t.Fatalf("session_id = %q, grant claim = %q", got.SessionID, issuer.grants[0].Claims["envvault_session_id"])
	}
	if got.Result != audit.ResultSuccess {
		t.Fatalf("result = %q", got.Result)
	}
	assertAuditEventHasNoBrowserSecrets(t, got)
}

func TestOpenRecordsFailedBrowserSessionRequestAuditWithoutSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bootstrap-jwt leaked body", http.StatusInternalServerError)
	}))
	defer server.Close()

	issuer := &fakeIssuer{}
	recorder := &recordingAudit{}
	client := browser.Client{
		HTTP:   server.Client(),
		Issuer: issuer,
		Opener: &fakeOpener{},
		Audit:  recorder,
	}

	_, err := client.Open(context.Background(), browser.OpenRequest{Profile: browserProfile(server.URL)})
	if err == nil {
		t.Fatal("Open() error = nil, want error")
	}

	if len(recorder.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(recorder.events))
	}
	got := recorder.events[0]
	if got.Event != audit.EventBrowserSessionRequested {
		t.Fatalf("event = %q", got.Event)
	}
	if got.Result != audit.ResultFailure {
		t.Fatalf("result = %q", got.Result)
	}
	if got.ErrorCode != clerr.BrowserExchangeFailed {
		t.Fatalf("error_code = %q", got.ErrorCode)
	}
	if got.SessionID == "" {
		t.Fatal("session_id is empty")
	}
	assertAuditEventHasNoBrowserSecrets(t, got)
}

type fakeIssuer struct {
	grants []issuer.Grant
}

func (f *fakeIssuer) Issue(_ context.Context, grant issuer.Grant) (issuer.Credential, error) {
	f.grants = append(f.grants, grant)
	return issuer.Credential{
		AccessToken: "bootstrap-jwt",
		TokenType:   "Bearer",
		ExpiresAt:   time.Now().Add(grant.TTL),
		Scopes:      append([]string(nil), grant.Scopes...),
	}, nil
}

type fakeOpener struct {
	rawURL  string
	browser string
}

func (f *fakeOpener) Open(_ context.Context, rawURL string, browser string) error {
	f.rawURL = rawURL
	f.browser = browser
	return nil
}

type recordingAudit struct {
	events []audit.Event
}

func (r *recordingAudit) Record(_ context.Context, event audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func assertAuditEventHasNoBrowserSecrets(t *testing.T, event audit.Event) {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	for _, secret := range []string{"bootstrap-jwt", "opaque", "complete?code="} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit event contains %q: %s", secret, raw)
		}
	}
}

func browserProfile(baseURL string) profile.Profile {
	return profile.Profile{
		Name:              "admin-web/dev",
		Kind:              profile.KindBrowserSession,
		Resource:          baseURL,
		Scopes:            []string{"browser:session:create"},
		BootstrapTokenTTL: 60 * time.Second,
		LoginCodeTTL:      30 * time.Second,
		WebSessionTTL:     30 * time.Minute,
		ExchangeURL:       baseURL + "/auth/envvault/browser-sessions",
		CompleteURL:       baseURL + "/auth/envvault/complete",
		PostLoginURL:      baseURL + "/",
		AllowedHosts:      []string{strings.TrimPrefix(baseURL, "http://")},
	}
}

func serverBaseURL(r *http.Request) string {
	return "http://" + r.Host
}
