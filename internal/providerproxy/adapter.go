package providerproxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/connection"
	"github.com/trknhr/envvault/internal/profile"
)

// HTTPAdapter preserves the current provider-proxy behavior behind the typed
// connection adapter boundary.
type HTTPAdapter struct {
	HTTP          *http.Client
	Now           func() time.Time
	ListenAddress string
}

func (HTTPAdapter) Protocol() connection.ProtocolType {
	return connection.ProtocolHTTP
}

func (HTTPAdapter) Validate(policy connection.Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	if policy.Protocol.Type != connection.ProtocolHTTP || policy.Protocol.HTTP == nil {
		return clerr.New(clerr.ConfigInvalid, "http adapter requires an http connection policy")
	}
	if policy.Authentication.Delivery != connection.DeliveryProxy {
		return clerr.New(clerr.ConfigInvalid, "http adapter requires proxy credential delivery")
	}
	return nil
}

func (a HTTPAdapter) Start(ctx context.Context, request connection.AdapterStartRequest) (connection.AdapterLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := a.Validate(request.Policy); err != nil {
		return nil, err
	}
	if err := request.Grant.Validate(); err != nil {
		return nil, err
	}
	if request.Grant.PolicyName != request.Policy.Name ||
		request.Grant.Protocol != request.Policy.Protocol.Type ||
		request.Grant.Destination != request.Policy.Destination {
		return nil, clerr.New(clerr.ConfigInvalid, "connection grant does not match http policy")
	}
	if request.Credentials == nil {
		return nil, clerr.New(clerr.KeyringUnavailable, "connection credential provider unavailable")
	}
	now := a.now()
	if !now.Before(request.Grant.ExpiresAt) {
		return nil, clerr.New(clerr.IssueFailed, "connection grant expired")
	}

	credential, err := request.Credentials.Acquire(ctx, connection.CredentialRequest{
		SessionID: request.Grant.SessionID,
		SubjectID: request.Grant.SubjectID,
		Spec:      request.Policy.Authentication.Credential,
		TTL:       request.Grant.ExpiresAt.Sub(now),
	})
	if err != nil {
		return nil, err
	}
	revoke := true
	defer func() {
		if revoke {
			_ = request.Credentials.Revoke(context.Background(), credential)
		}
	}()

	token, err := newLocalToken()
	if err != nil {
		return nil, err
	}
	legacyProfile := profileFromPolicy(request.Policy)
	var server *Server
	err = credential.WithValue(ctx, func(value []byte) error {
		var startErr error
		server, startErr = Start(ctx, ServerOptions{
			Profile:       legacyProfile,
			APIKeyBytes:   value,
			Token:         token,
			Expires:       request.Grant.ExpiresAt,
			HTTP:          a.HTTP,
			Now:           a.Now,
			ListenAddress: a.ListenAddress,
		})
		return startErr
	})
	if err != nil {
		return nil, err
	}

	revoke = false
	return &HTTPAdapterLease{
		server:      server,
		credentials: request.Credentials,
		credential:  credential,
		token:       []byte(token),
		expiresAt:   request.Grant.ExpiresAt,
	}, nil
}

func (a HTTPAdapter) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// HTTPAdapterLease exposes only the short-lived client capability and local
// endpoint. It never exposes the upstream credential.
type HTTPAdapterLease struct {
	mu          sync.Mutex
	server      *Server
	credentials connection.CredentialProvider
	credential  connection.CredentialLease
	token       []byte
	expiresAt   time.Time
	closed      bool
}

func (l *HTTPAdapterLease) Endpoint() connection.Endpoint {
	if l.server == nil {
		return connection.Endpoint{}
	}
	return connection.Endpoint{Network: "tcp", Address: l.server.addr}
}

func (l *HTTPAdapterLease) ExpiresAt() time.Time {
	return l.expiresAt
}

func (l *HTTPAdapterLease) BaseURL() string {
	if l.server == nil {
		return ""
	}
	return l.server.BaseURL()
}

func (l *HTTPAdapterLease) Token() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(l.token)
}

func (l *HTTPAdapterLease) String() string {
	return "http adapter lease [REDACTED]"
}

func (l *HTTPAdapterLease) GoString() string {
	return "http adapter lease [REDACTED]"
}

func (l *HTTPAdapterLease) Close(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true

	var errs []error
	// Revoke first so a server shutdown that consumes its cleanup deadline
	// cannot leave the provider-owned credential buffer live.
	if l.credentials != nil && l.credential != nil {
		revokeCtx := ctx
		if revokeCtx == nil {
			revokeCtx = context.Background()
		}
		if err := l.credentials.Revoke(revokeCtx, l.credential); err != nil {
			errs = append(errs, err)
		}
	}
	if l.server != nil {
		if err := l.server.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	zero(l.token)
	l.token = nil
	return errors.Join(errs...)
}

func profileFromPolicy(policy connection.Policy) profile.Profile {
	httpPolicy := policy.Protocol.HTTP
	target := url.URL{
		Scheme: string(httpPolicy.Scheme),
		Host:   net.JoinHostPort(policy.Destination.Host, strconv.Itoa(int(policy.Destination.Port))),
		Path:   httpPolicy.BasePath,
	}
	return profile.Profile{
		Name:           policy.Name,
		Kind:           profile.KindProviderProxy,
		CredentialName: policy.Authentication.Credential.Ref,
		AuthMode:       string(httpPolicy.Auth.Type),
		Provider:       string(httpPolicy.ProviderStrategy),
		TargetURL:      target.String(),
		AllowedPaths:   append([]string(nil), httpPolicy.AllowedPaths...),
		AllowedMethods: append([]string(nil), httpPolicy.AllowedMethods...),
		LocalTokenTTL:  policy.Limits.SessionTTL,
		ProjectBinding: profile.ProjectBinding{Mode: profile.ProjectBindingNone},
	}
}
