package talosruntime

import (
	"context"
	"net/http"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/issuer"
	"github.com/trknhr/credlease/internal/issuer/talos"
	runtimetalos "github.com/trknhr/credlease/internal/runtime/talos"
)

type Runtime interface {
	Start(ctx context.Context) (runtimetalos.Endpoint, error)
	Stop(ctx context.Context) error
}

type Client struct {
	Runtime Runtime
	HTTP    *http.Client
}

func (c Client) IssueParentKey(ctx context.Context, request talos.ParentKeyRequest) (talos.ParentKey, error) {
	client, stop, err := c.start(ctx)
	if err != nil {
		return talos.ParentKey{}, err
	}
	parent, err := client.IssueParentKey(ctx, request)
	stopErr := stop(ctx)
	if err != nil {
		return talos.ParentKey{}, err
	}
	if stopErr != nil {
		return talos.ParentKey{}, stopErr
	}
	return parent, nil
}

func (c Client) DeriveJWT(ctx context.Context, parentKey string, grant issuer.Grant) (issuer.Credential, error) {
	client, stop, err := c.start(ctx)
	if err != nil {
		return issuer.Credential{}, err
	}
	credential, err := client.DeriveJWT(ctx, parentKey, grant)
	stopErr := stop(ctx)
	if err != nil {
		return issuer.Credential{}, err
	}
	if stopErr != nil {
		return issuer.Credential{}, stopErr
	}
	return credential, nil
}

func (c Client) JWKS(ctx context.Context) ([]byte, error) {
	client, stop, err := c.start(ctx)
	if err != nil {
		return nil, err
	}
	jwks, err := client.JWKS(ctx)
	stopErr := stop(ctx)
	if err != nil {
		return nil, err
	}
	if stopErr != nil {
		return nil, stopErr
	}
	return jwks, nil
}

func (c Client) start(ctx context.Context) (*talos.Client, func(context.Context) error, error) {
	if c.Runtime == nil {
		return nil, nil, clerr.New(clerr.RuntimeUnavailable, "talos runtime is required")
	}
	endpoint, err := c.Runtime.Start(ctx)
	if err != nil {
		return nil, nil, err
	}
	return talos.NewClient(endpoint.URL, c.HTTP), c.Runtime.Stop, nil
}
