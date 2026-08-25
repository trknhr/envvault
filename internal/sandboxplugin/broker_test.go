package sandboxplugin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/profile"
	"github.com/trknhr/envvault/internal/sandboxplugin"
)

func TestBrokerOpensSandboxBoundDeliveryAndRevokesIt(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	const upstreamSecret = "ENVVAULT_PLUGIN_UPSTREAM_SECRET_CANARY"
	var providerMu sync.Mutex
	var providerAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		providerMu.Lock()
		providerAuth = r.Header.Get("Authorization")
		providerMu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "created")
	}))
	defer target.Close()

	profiles := profileMap{"openai/codex": providerProfile(target.URL + "/v1")}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("openai/key"), []byte(upstreamSecret)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	broker := &sandboxplugin.Broker{
		Profiles: profiles,
		Secrets:  secrets,
		HTTP:     target.Client(),
		Now:      func() time.Time { return now },
		IDSource: func() (string, error) { return "plugin-lease-1", nil },
	}
	request := sandboxplugin.OpenRequest{
		SandboxID: "openshell-sbx-1",
		Bindings: []sandboxplugin.Binding{{
			Profile: "openai/codex",
			Outputs: []sandboxplugin.Output{
				{Environment: "OPENAI_BASE_URL", Part: sandboxplugin.OutputBaseURL},
				{Environment: "OPENAI_API_KEY", Part: sandboxplugin.OutputToken},
				{Environment: "CODEX_API_KEY", Part: sandboxplugin.OutputToken},
			},
		}},
	}

	delivery, err := broker.Open(ctx, request)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if delivery.LeaseID != "plugin-lease-1" || delivery.SandboxID != request.SandboxID {
		t.Fatalf("delivery identity = %#v", delivery)
	}
	if delivery.SecurityLevel != connection.SecurityBrokered {
		t.Fatalf("security level = %q, want brokered", delivery.SecurityLevel)
	}
	if delivery.ExpiresAt != now.Add(time.Minute) {
		t.Fatalf("expires = %s, want %s", delivery.ExpiresAt, now.Add(time.Minute))
	}
	baseURL := delivery.Environment["OPENAI_BASE_URL"]
	token := delivery.Environment["OPENAI_API_KEY"]
	if !strings.HasPrefix(baseURL, "http://127.0.0.1:") || !strings.HasPrefix(token, "envvault-local-") {
		t.Fatal("delivery did not contain an EnvVault gateway and short-lived capability")
	}
	if delivery.Environment["CODEX_API_KEY"] != token {
		t.Fatal("token alias did not reuse the same sandbox capability")
	}
	if len(delivery.Egress) != 1 || delivery.Egress[0].Network != "tcp" {
		t.Fatalf("egress = %#v", delivery.Egress)
	}
	if delivery.Connections[0].Gateway != delivery.Egress[0] {
		t.Fatalf("connection gateway = %#v, egress = %#v", delivery.Connections[0].Gateway, delivery.Egress[0])
	}
	serialized, err := json.Marshal(delivery)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(serialized), upstreamSecret) {
		t.Fatal("serialized sandbox delivery leaked the upstream credential")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", delivery, delivery), token) {
		t.Fatal("formatted sandbox delivery leaked its short-lived capability")
	}

	proxyRequest, err := http.NewRequest(http.MethodPost, baseURL+"/responses", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	proxyRequest.Header.Set("Authorization", "Bearer "+token)
	response, err := target.Client().Do(proxyRequest)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", response.StatusCode)
	}
	providerMu.Lock()
	authOK := providerAuth == "Bearer "+upstreamSecret
	providerMu.Unlock()
	if !authOK {
		t.Fatal("provider did not receive the upstream credential")
	}

	if _, err := broker.Open(ctx, request); errorCode(err) != clerr.ConfigInvalid {
		t.Fatalf("duplicate Open() error = %v", err)
	}
	endpoint := delivery.Egress[0].Address
	if err := broker.Close(ctx, delivery.LeaseID); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := broker.Close(ctx, delivery.LeaseID); err != nil {
		t.Fatalf("idempotent Close() error = %v", err)
	}
	connection, err := net.DialTimeout("tcp", endpoint, 50*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		t.Fatal("gateway still accepted connections after lease close")
	}
}

func TestBrokerDescribesProfileWithoutCredentialReference(t *testing.T) {
	broker := &sandboxplugin.Broker{
		Profiles: profileMap{
			"openai/codex": providerProfile("https://api.example.test/v1"),
		},
	}
	descriptions, err := broker.Describe(context.Background(), sandboxplugin.DescribeRequest{
		Profiles: []string{"openai/codex"},
	})
	if err != nil {
		t.Fatalf("Describe() error = %v", err)
	}
	if len(descriptions) != 1 {
		t.Fatalf("descriptions = %#v", descriptions)
	}
	description := descriptions[0]
	if description.Profile != "openai/codex" || description.Protocol != "http" {
		t.Fatalf("description identity = %#v", description)
	}
	if description.Destination.Host != "api.example.test" || description.Destination.Port != 443 {
		t.Fatalf("destination = %#v", description.Destination)
	}
	if description.HTTP.BasePath != "/v1" || description.HTTP.Authentication != "bearer" {
		t.Fatalf("http description = %#v", description.HTTP)
	}
	if description.SessionTTLSeconds != 60 || fmt.Sprint(description.Outputs) != "[base-url token]" {
		t.Fatalf("ttl/outputs = %d/%v", description.SessionTTLSeconds, description.Outputs)
	}
	serialized, err := json.Marshal(descriptions)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(serialized), "openai/key") || strings.Contains(string(serialized), "credential") {
		t.Fatal("profile description exposed credential metadata")
	}
}

func TestBrokerCloseAllRevokesLeasesAndPreventsNewOnes(t *testing.T) {
	ctx := context.Background()
	broker := testBroker(t)
	delivery, err := broker.Open(ctx, validRequest("sandbox-one"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := broker.CloseAll(ctx); err != nil {
		t.Fatalf("CloseAll() error = %v", err)
	}
	if _, err := net.DialTimeout("tcp", delivery.Egress[0].Address, 50*time.Millisecond); err == nil {
		t.Fatal("gateway still accepted connections after CloseAll")
	}
	if _, err := broker.Open(ctx, validRequest("sandbox-two")); errorCode(err) != clerr.RuntimeUnavailable {
		t.Fatalf("Open(after CloseAll) error = %v", err)
	}
}

func TestBrokerAutomaticallyClosesExpiredLease(t *testing.T) {
	ctx := context.Background()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer target.Close()
	p := providerProfile(target.URL)
	p.LocalTokenTTL = 40 * time.Millisecond
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("openai/key"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	broker := &sandboxplugin.Broker{
		Profiles: profileMap{"openai/codex": p},
		Secrets:  secrets,
	}
	delivery, err := broker.Open(ctx, validRequest("sandbox-expiring"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		connection, dialErr := net.DialTimeout("tcp", delivery.Egress[0].Address, 20*time.Millisecond)
		if dialErr != nil {
			break
		}
		_ = connection.Close()
		if time.Now().After(deadline) {
			t.Fatal("expired gateway remained reachable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := broker.Open(ctx, validRequest("sandbox-expiring")); err != nil {
		t.Fatalf("Open(after expiry) error = %v", err)
	}
	if err := broker.CloseAll(ctx); err != nil {
		t.Fatalf("CloseAll() error = %v", err)
	}
}

func TestBrokerClosesPartialOpenAndReleasesSandboxReservation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	adapter := &recordingAdapter{now: now}
	profiles := profileMap{
		"openai/codex": providerProfile("https://api.example.test/v1"),
	}
	broker := &sandboxplugin.Broker{
		Profiles: profiles,
		Secrets:  keyring.NewMemoryStore(),
		Adapter:  adapter,
		Now:      func() time.Time { return now },
	}
	request := validRequest("sandbox-partial")
	request.Bindings = append(request.Bindings, sandboxplugin.Binding{
		Profile: "missing/profile",
		Outputs: []sandboxplugin.Output{
			{Environment: "SECOND_BASE_URL", Part: sandboxplugin.OutputBaseURL},
			{Environment: "SECOND_TOKEN", Part: sandboxplugin.OutputToken},
		},
	})

	if _, err := broker.Open(ctx, request); errorCode(err) != clerr.ProfileNotFound {
		t.Fatalf("Open(partial) error = %v", err)
	}
	if len(adapter.leases) != 1 || !adapter.leases[0].closed {
		t.Fatal("partially opened gateway was not closed")
	}
	if _, err := broker.Open(ctx, validRequest("sandbox-partial")); err != nil {
		t.Fatalf("Open(after partial failure) error = %v", err)
	}
	if err := broker.CloseAll(ctx); err != nil {
		t.Fatalf("CloseAll() error = %v", err)
	}
}

func TestBrokerValidatesGatewayPlacement(t *testing.T) {
	tests := []struct {
		name      string
		listen    string
		advertise string
		wantCode  clerr.Code
	}{
		{name: "loopback default"},
		{name: "container host route", listen: "0.0.0.0:0", advertise: "host.docker.internal"},
		{name: "fixed port", listen: "127.0.0.1:43123", wantCode: clerr.ConfigInvalid},
		{name: "public listener", listen: "8.8.8.8:0", advertise: "gateway.example.com", wantCode: clerr.ConfigInvalid},
		{name: "missing advertised host", listen: "0.0.0.0:0", wantCode: clerr.ConfigInvalid},
		{name: "invalid advertised host", listen: "0.0.0.0:0", advertise: "bad:host", wantCode: clerr.ConfigInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broker := testBroker(t)
			broker.ListenAddress = tt.listen
			broker.AdvertiseHost = tt.advertise
			err := broker.Validate()
			if got := errorCode(err); got != tt.wantCode {
				t.Fatalf("Validate() error/code = %v/%q, want %q", err, got, tt.wantCode)
			}
		})
	}
}

func TestOpenRequestValidationRejectsAmbiguousDelivery(t *testing.T) {
	tests := []struct {
		name    string
		request sandboxplugin.OpenRequest
	}{
		{name: "missing sandbox", request: validRequest("")},
		{name: "invalid sandbox", request: validRequest("sandbox/id")},
		{name: "missing bindings", request: sandboxplugin.OpenRequest{SandboxID: "sandbox-one"}},
		{name: "profile traversal", request: requestWithBinding("sandbox-one", "openai/../prod", validOutputs())},
		{name: "profile whitespace", request: requestWithBinding("sandbox-one", " openai/dev", validOutputs())},
		{name: "missing token", request: requestWithBinding("sandbox-one", "openai/dev", []sandboxplugin.Output{
			{Environment: "OPENAI_BASE_URL", Part: sandboxplugin.OutputBaseURL},
			{Environment: "OTHER_BASE_URL", Part: sandboxplugin.OutputBaseURL},
		})},
		{name: "direct credential part", request: requestWithBinding("sandbox-one", "openai/dev", []sandboxplugin.Output{
			{Environment: "OPENAI_BASE_URL", Part: sandboxplugin.OutputBaseURL},
			{Environment: "OPENAI_API_KEY", Part: "value"},
		})},
		{name: "duplicate environment", request: requestWithBinding("sandbox-one", "openai/dev", []sandboxplugin.Output{
			{Environment: "OPENAI_CONFIG", Part: sandboxplugin.OutputBaseURL},
			{Environment: "OPENAI_CONFIG", Part: sandboxplugin.OutputToken},
		})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.request.Validate(); errorCode(err) != clerr.ConfigInvalid {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

type profileMap map[string]profile.Profile

func (p profileMap) Profile(name string) (profile.Profile, error) {
	value, ok := p[name]
	if !ok {
		return profile.Profile{}, clerr.New(clerr.ProfileNotFound, name)
	}
	return value, nil
}

type recordingAdapter struct {
	now    time.Time
	leases []*recordingLease
}

func (*recordingAdapter) Protocol() connection.ProtocolType { return connection.ProtocolHTTP }

func (*recordingAdapter) Validate(connection.Policy) error { return nil }

func (a *recordingAdapter) Start(_ context.Context, _ connection.AdapterStartRequest) (connection.AdapterLease, error) {
	lease := &recordingLease{expiresAt: a.now.Add(time.Minute)}
	a.leases = append(a.leases, lease)
	return lease, nil
}

type recordingLease struct {
	expiresAt time.Time
	closed    bool
}

func (*recordingLease) Endpoint() connection.Endpoint {
	return connection.Endpoint{Network: "tcp", Address: "127.0.0.1:43123"}
}

func (l *recordingLease) ExpiresAt() time.Time { return l.expiresAt }

func (*recordingLease) BaseURL() string { return "http://127.0.0.1:43123/openai/codex" }

func (*recordingLease) Token() string { return "temporary-capability" }

func (l *recordingLease) Close(context.Context) error {
	l.closed = true
	return nil
}

func providerProfile(target string) profile.Profile {
	return profile.Profile{
		Name:           "openai/codex",
		Kind:           profile.KindProviderProxy,
		CredentialName: "openai/key",
		AuthMode:       "bearer",
		Provider:       "openai-compatible",
		TargetURL:      target,
		AllowedPaths:   []string{"/responses"},
		AllowedMethods: []string{http.MethodPost},
		LocalTokenTTL:  time.Minute,
		ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
}

func testBroker(t *testing.T) *sandboxplugin.Broker {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(ctx, keyring.CredentialValue("openai/key"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	return &sandboxplugin.Broker{
		Profiles: profileMap{"openai/codex": providerProfile(target.URL)},
		Secrets:  secrets,
		HTTP:     target.Client(),
		Now:      func() time.Time { return now },
	}
}

func validRequest(sandboxID string) sandboxplugin.OpenRequest {
	return requestWithBinding(sandboxID, "openai/codex", validOutputs())
}

func requestWithBinding(sandboxID, profileName string, outputs []sandboxplugin.Output) sandboxplugin.OpenRequest {
	return sandboxplugin.OpenRequest{
		SandboxID: sandboxID,
		Bindings: []sandboxplugin.Binding{{
			Profile: profileName,
			Outputs: outputs,
		}},
	}
}

func validOutputs() []sandboxplugin.Output {
	return []sandboxplugin.Output{
		{Environment: "OPENAI_BASE_URL", Part: sandboxplugin.OutputBaseURL},
		{Environment: "OPENAI_API_KEY", Part: sandboxplugin.OutputToken},
	}
}

func errorCode(err error) clerr.Code {
	code, _ := clerr.CodeOf(err)
	return code
}
