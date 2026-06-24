package verifier

import (
	"context"
	"errors"

	"github.com/trknhr/credlease/pkg/browsersession"
)

type BrowserBootstrapVerifier struct {
	Verifier *Verifier
	Scopes   []string
}

func (v BrowserBootstrapVerifier) VerifyBootstrap(ctx context.Context, token string) (browsersession.BrowserGrant, error) {
	if v.Verifier == nil {
		return browsersession.BrowserGrant{}, errors.New("credlease verifier: verifier is required")
	}
	claims, err := v.Verifier.Verify(ctx, token, Requirements{
		Scopes:  v.Scopes,
		Purpose: "browser-bootstrap",
	})
	if err != nil {
		return browsersession.BrowserGrant{}, err
	}
	return browsersession.BrowserGrant{
		Profile:   claims.Profile,
		Resource:  claims.Resource,
		Scopes:    append([]string(nil), claims.Scopes...),
		SessionID: claims.SessionID,
		Purpose:   claims.Purpose,
		ExpiresAt: claims.ExpiresAt,
	}, nil
}
