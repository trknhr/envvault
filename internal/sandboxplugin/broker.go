// Package sandboxplugin exposes a runtime-neutral lease contract for trusted
// agent-sandbox control planes. It returns only gateway connection metadata
// and short-lived capabilities; upstream credentials remain in EnvVault's
// credential provider and protocol adapter.
package sandboxplugin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/connection/compatprofile"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/keyring"
	"github.com/trknhr/envvault/internal/projectbinding"
	"github.com/trknhr/envvault/internal/providerproxy"
)

const maxBindings = 32

type OutputPart string

const (
	OutputBaseURL OutputPart = "base-url"
	OutputToken   OutputPart = "token"
)

// Output maps one provider-proxy output to an environment variable expected
// by the agent. Repeating a part with different environment names creates
// aliases without opening another gateway.
type Output struct {
	Environment string     `json:"environment"`
	Part        OutputPart `json:"part"`
}

type Binding struct {
	Profile string   `json:"profile"`
	Outputs []Output `json:"outputs"`
}

type ProjectIdentity struct {
	Root      string `json:"root,omitempty"`
	GitRemote string `json:"git_remote,omitempty"`
}

type OpenRequest struct {
	SandboxID string          `json:"sandbox_id"`
	Project   ProjectIdentity `json:"project,omitempty"`
	Bindings  []Binding       `json:"bindings"`
}

type DescribeRequest struct {
	Project  ProjectIdentity `json:"project,omitempty"`
	Profiles []string        `json:"profiles"`
}

type ProfileDescription struct {
	Profile           string          `json:"profile"`
	Protocol          string          `json:"protocol"`
	Destination       Destination     `json:"destination"`
	HTTP              HTTPDescription `json:"http"`
	SessionTTLSeconds int64           `json:"session_ttl_seconds"`
	Outputs           []OutputPart    `json:"outputs"`
}

type Destination struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

type HTTPDescription struct {
	Scheme           string   `json:"scheme"`
	BasePath         string   `json:"base_path"`
	ProviderStrategy string   `json:"provider_strategy"`
	Authentication   string   `json:"authentication"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedPaths     []string `json:"allowed_paths"`
}

// Endpoint is the data-plane address that an external sandbox must make
// reachable. It is not the upstream provider destination.
type Endpoint struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

type Connection struct {
	Profile   string    `json:"profile"`
	Gateway   Endpoint  `json:"gateway"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Delivery is safe to deliver to an untrusted sandbox, but its Environment
// map contains short-lived capabilities and must not be logged. It never
// contains an upstream credential.
type Delivery struct {
	LeaseID       string                   `json:"lease_id"`
	SandboxID     string                   `json:"sandbox_id"`
	SecurityLevel connection.SecurityLevel `json:"security_level"`
	ExpiresAt     time.Time                `json:"expires_at"`
	Environment   map[string]string        `json:"environment"`
	Egress        []Endpoint               `json:"egress"`
	Connections   []Connection             `json:"connections"`
}

func (Delivery) String() string {
	return "sandbox plugin delivery [REDACTED]"
}

func (Delivery) GoString() string {
	return "sandbox plugin delivery [REDACTED]"
}

type Broker struct {
	Profiles      providerproxy.ProfileResolver
	Secrets       keyring.Store
	Credentials   connection.CredentialProvider
	Adapter       connection.ProtocolAdapter
	HTTP          *http.Client
	Now           func() time.Time
	ListenAddress string
	AdvertiseHost string
	IDSource      func() (string, error)

	mu        sync.Mutex
	leases    map[string]*managedLease
	bySandbox map[string]string
	closed    bool
}

type managedLease struct {
	sandboxID    string
	resolver     *providerproxy.EnvResolver
	cancelExpiry context.CancelFunc
}

// Describe returns repository-safe provider metadata for a trusted sandbox
// control plane. Credential references and credential values are deliberately
// omitted.
func (b *Broker) Describe(ctx context.Context, request DescribeRequest) ([]ProfileDescription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if b.Profiles == nil {
		return nil, clerr.New(clerr.ProfileNotFound, "sandbox plugin profile resolver unavailable")
	}

	descriptions := make([]ProfileDescription, 0, len(request.Profiles))
	for _, name := range request.Profiles {
		stored, err := b.Profiles.Profile(name)
		if err != nil {
			return nil, err
		}
		if err := projectbinding.Check(stored.ProjectBinding, request.Project.identity()); err != nil {
			return nil, err
		}
		policy, err := compatprofile.FromProviderProxyProfile(stored)
		if err != nil {
			return nil, err
		}
		if policy.Protocol.Type != connection.ProtocolHTTP || policy.Protocol.HTTP == nil {
			return nil, clerr.New(clerr.RuntimeIncompatible, "sandbox plugin supports only http provider-proxy profiles")
		}
		httpPolicy := policy.Protocol.HTTP
		descriptions = append(descriptions, ProfileDescription{
			Profile:  name,
			Protocol: string(policy.Protocol.Type),
			Destination: Destination{
				Host: policy.Destination.Host,
				Port: policy.Destination.Port,
			},
			HTTP: HTTPDescription{
				Scheme:           string(httpPolicy.Scheme),
				BasePath:         httpPolicy.BasePath,
				ProviderStrategy: string(httpPolicy.ProviderStrategy),
				Authentication:   string(httpPolicy.Auth.Type),
				AllowedMethods:   append([]string(nil), httpPolicy.AllowedMethods...),
				AllowedPaths:     append([]string(nil), httpPolicy.AllowedPaths...),
			},
			SessionTTLSeconds: int64(policy.Limits.SessionTTL / time.Second),
			Outputs:           []OutputPart{OutputBaseURL, OutputToken},
		})
	}
	return descriptions, nil
}

func (b *Broker) Open(ctx context.Context, request OpenRequest) (delivery Delivery, openErr error) {
	if err := ctx.Err(); err != nil {
		return Delivery{}, err
	}
	if err := request.Validate(); err != nil {
		return Delivery{}, err
	}
	if err := b.Validate(); err != nil {
		return Delivery{}, err
	}
	if err := b.reserve(request.SandboxID); err != nil {
		return Delivery{}, err
	}
	reserved := true
	defer func() {
		if openErr != nil && reserved {
			b.releaseReservation(request.SandboxID)
		}
	}()

	resolver := &providerproxy.EnvResolver{
		Profiles:      b.Profiles,
		Secrets:       b.Secrets,
		Credentials:   b.Credentials,
		Adapter:       b.Adapter,
		HTTP:          b.HTTP,
		Now:           b.Now,
		SubjectID:     request.SandboxID,
		ListenAddress: defaultListenAddress(b.ListenAddress),
		AdvertiseHost: strings.TrimSpace(b.AdvertiseHost),
	}
	cleanupResolver := true
	defer func() {
		if cleanupResolver {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			openErr = errors.Join(openErr, resolver.Close(cleanupCtx))
		}
	}()

	environment := make(map[string]string)
	connections := make([]Connection, 0, len(request.Bindings))
	egress := make([]Endpoint, 0, len(request.Bindings))
	var expiresAt time.Time
	seenEndpoints := map[Endpoint]struct{}{}
	for _, binding := range request.Bindings {
		lease, err := resolver.ResolveProxy(ctx, binding.Profile, request.Project.identity())
		if err != nil {
			return Delivery{}, err
		}
		gateway, err := endpointFromBaseURL(lease.BaseURL)
		if err != nil {
			return Delivery{}, err
		}
		if lease.ExpiresAt.IsZero() {
			return Delivery{}, clerr.New(clerr.RuntimeIncompatible, "provider proxy lease has no expiry")
		}
		if expiresAt.IsZero() || lease.ExpiresAt.Before(expiresAt) {
			expiresAt = lease.ExpiresAt
		}
		for _, output := range binding.Outputs {
			switch output.Part {
			case OutputBaseURL:
				environment[output.Environment] = lease.BaseURL
			case OutputToken:
				environment[output.Environment] = lease.Token
			}
		}
		connections = append(connections, Connection{
			Profile:   binding.Profile,
			Gateway:   gateway,
			ExpiresAt: lease.ExpiresAt,
		})
		if _, exists := seenEndpoints[gateway]; !exists {
			seenEndpoints[gateway] = struct{}{}
			egress = append(egress, gateway)
		}
	}

	leaseID, err := b.newLeaseID()
	if err != nil {
		return Delivery{}, err
	}
	delivery = Delivery{
		LeaseID:       leaseID,
		SandboxID:     request.SandboxID,
		SecurityLevel: connection.SecurityBrokered,
		ExpiresAt:     expiresAt,
		Environment:   environment,
		Egress:        egress,
		Connections:   connections,
	}
	if err := b.commit(request.SandboxID, leaseID, &managedLease{sandboxID: request.SandboxID, resolver: resolver}); err != nil {
		return Delivery{}, err
	}
	b.scheduleExpiry(leaseID, expiresAt)
	reserved = false
	cleanupResolver = false
	return delivery, nil
}

// Close revokes a lease and closes all of its data-plane gateways. It is
// idempotent so sandbox teardown can be retried safely.
func (b *Broker) Close(ctx context.Context, leaseID string) error {
	lease := b.take(strings.TrimSpace(leaseID))
	if lease == nil {
		return nil
	}
	if lease.cancelExpiry != nil {
		lease.cancelExpiry()
	}
	return lease.resolver.Close(ctx)
}

// CloseAll prevents new leases and revokes every active sandbox lease.
func (b *Broker) CloseAll(ctx context.Context) error {
	b.mu.Lock()
	b.closed = true
	leases := make([]*managedLease, 0, len(b.leases))
	for _, lease := range b.leases {
		leases = append(leases, lease)
	}
	b.leases = nil
	b.bySandbox = nil
	b.mu.Unlock()

	var errs []error
	for i := len(leases) - 1; i >= 0; i-- {
		if leases[i].cancelExpiry != nil {
			leases[i].cancelExpiry()
		}
		if err := leases[i].resolver.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (b *Broker) Validate() error {
	if b.Profiles == nil {
		return clerr.New(clerr.ProfileNotFound, "sandbox plugin profile resolver unavailable")
	}
	if b.Credentials == nil && b.Secrets == nil {
		return clerr.New(clerr.KeyringUnavailable, "sandbox plugin credential provider unavailable")
	}
	address := defaultListenAddress(b.ListenAddress)
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "0" {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin gateway listen address must use port 0")
	}
	if !safeListenHost(host) {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin gateway listen host must be loopback, private, or unspecified")
	}
	advertise := strings.TrimSpace(b.AdvertiseHost)
	if unspecifiedHost(host) && advertise == "" {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin gateway advertise host is required for an unspecified listener")
	}
	if advertise != "" && !validAdvertiseHost(advertise) {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin gateway advertise host is invalid")
	}
	return nil
}

func (r OpenRequest) Validate() error {
	if !validSandboxID(r.SandboxID) {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin sandbox id is invalid")
	}
	if len(r.Bindings) == 0 || len(r.Bindings) > maxBindings {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin bindings must contain between 1 and 32 entries")
	}
	profiles := map[string]struct{}{}
	environment := map[string]struct{}{}
	for _, binding := range r.Bindings {
		if err := validateProfileName(binding.Profile); err != nil {
			return err
		}
		if _, exists := profiles[binding.Profile]; exists {
			return clerr.New(clerr.ConfigInvalid, "sandbox plugin profile bindings must be unique")
		}
		profiles[binding.Profile] = struct{}{}
		if len(binding.Outputs) < 2 || len(binding.Outputs) > maxBindings {
			return clerr.New(clerr.ConfigInvalid, "sandbox plugin binding outputs must contain between 2 and 32 entries")
		}
		var baseURLs, tokens int
		for _, output := range binding.Outputs {
			if !validEnvironmentName(output.Environment) {
				return clerr.New(clerr.ConfigInvalid, "sandbox plugin output environment name is invalid")
			}
			if _, exists := environment[output.Environment]; exists {
				return clerr.New(clerr.ConfigInvalid, "sandbox plugin output environment names must be unique")
			}
			environment[output.Environment] = struct{}{}
			switch output.Part {
			case OutputBaseURL:
				baseURLs++
			case OutputToken:
				tokens++
			default:
				return clerr.New(clerr.ConfigInvalid, "sandbox plugin output part must be base-url or token")
			}
		}
		if baseURLs == 0 || tokens == 0 {
			return clerr.New(clerr.ConfigInvalid, "sandbox plugin binding requires base-url and token outputs")
		}
	}
	return nil
}

func (r DescribeRequest) Validate() error {
	if len(r.Profiles) == 0 || len(r.Profiles) > maxBindings {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin describe profiles must contain between 1 and 32 entries")
	}
	seen := map[string]struct{}{}
	for _, name := range r.Profiles {
		if err := validateProfileName(name); err != nil {
			return err
		}
		if _, exists := seen[name]; exists {
			return clerr.New(clerr.ConfigInvalid, "sandbox plugin describe profiles must be unique")
		}
		seen[name] = struct{}{}
	}
	return nil
}

func (b *Broker) reserve(sandboxID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return clerr.New(clerr.RuntimeUnavailable, "sandbox plugin broker is closed")
	}
	if b.bySandbox == nil {
		b.bySandbox = map[string]string{}
	}
	if _, exists := b.bySandbox[sandboxID]; exists {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin already has a lease for this sandbox")
	}
	b.bySandbox[sandboxID] = ""
	return nil
}

func (b *Broker) releaseReservation(sandboxID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bySandbox[sandboxID] == "" {
		delete(b.bySandbox, sandboxID)
	}
}

func (b *Broker) commit(sandboxID, leaseID string, lease *managedLease) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		delete(b.bySandbox, sandboxID)
		return clerr.New(clerr.RuntimeUnavailable, "sandbox plugin broker closed while opening a lease")
	}
	if b.bySandbox[sandboxID] != "" {
		return clerr.New(clerr.RuntimeUnavailable, "sandbox plugin lease reservation was lost")
	}
	if b.leases == nil {
		b.leases = map[string]*managedLease{}
	}
	if _, exists := b.leases[leaseID]; exists {
		return clerr.New(clerr.IssueFailed, "sandbox plugin generated a duplicate lease id")
	}
	b.leases[leaseID] = lease
	b.bySandbox[sandboxID] = leaseID
	return nil
}

func (b *Broker) take(leaseID string) *managedLease {
	if leaseID == "" {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	lease := b.leases[leaseID]
	if lease == nil {
		return nil
	}
	delete(b.leases, leaseID)
	delete(b.bySandbox, lease.sandboxID)
	return lease
}

func (b *Broker) scheduleExpiry(leaseID string, expiresAt time.Time) {
	expiryCtx, cancel := context.WithCancel(context.Background())
	b.mu.Lock()
	lease := b.leases[leaseID]
	if lease == nil || b.closed {
		b.mu.Unlock()
		cancel()
		return
	}
	lease.cancelExpiry = cancel
	b.mu.Unlock()

	duration := expiresAt.Sub(b.now())
	go func() {
		if duration > 0 {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-expiryCtx.Done():
				return
			}
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = b.Close(cleanupCtx, leaseID)
	}()
}

func (b *Broker) newLeaseID() (string, error) {
	if b.IDSource != nil {
		return b.IDSource()
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", clerr.Wrap(clerr.IssueFailed, "generate sandbox plugin lease id", err)
	}
	return "plugin_" + hex.EncodeToString(raw[:]), nil
}

func (b *Broker) now() time.Time {
	if b.Now != nil {
		return b.Now()
	}
	return time.Now()
}

func endpointFromBaseURL(raw string) (Endpoint, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil {
		return Endpoint{}, clerr.New(clerr.RuntimeIncompatible, "provider proxy returned an invalid gateway url")
	}
	if _, _, err := net.SplitHostPort(parsed.Host); err != nil {
		return Endpoint{}, clerr.New(clerr.RuntimeIncompatible, "provider proxy returned a gateway without an explicit port")
	}
	return Endpoint{Network: "tcp", Address: parsed.Host}, nil
}

func validateProfileName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || trimmed != name {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin profile name is invalid")
	}
	ref, recognized, err := envref.ParseValue(envref.Format(name, envref.PartBaseURL))
	if err != nil || !recognized || ref.Profile != name || ref.Part != envref.PartBaseURL {
		return clerr.New(clerr.ConfigInvalid, "sandbox plugin profile name is invalid")
	}
	return nil
}

func validAdvertiseHost(host string) bool {
	if len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') ||
				(character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

var sandboxIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func validSandboxID(id string) bool {
	return sandboxIDPattern.MatchString(id)
}

func validEnvironmentName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func defaultListenAddress(address string) string {
	if strings.TrimSpace(address) == "" {
		return "127.0.0.1:0"
	}
	return strings.TrimSpace(address)
}

func safeListenHost(host string) bool {
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
}

func unspecifiedHost(host string) bool {
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

func (p ProjectIdentity) identity() projectbinding.Identity {
	return projectbinding.Identity{Root: p.Root, GitRemote: p.GitRemote}
}
