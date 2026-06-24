package token

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/issuer"
)

type Format string

const (
	FormatRaw  Format = "raw"
	FormatJSON Format = "json"
)

type Output struct {
	Format     Format
	Credential issuer.Credential
	Profile    string
	Resource   string
	Now        time.Time
}

func Write(writer io.Writer, output Output) error {
	switch output.Format {
	case "", FormatRaw:
		_, err := fmt.Fprintln(writer, output.Credential.AccessToken)
		return err
	case FormatJSON:
		return writeJSON(writer, output)
	default:
		return clerr.New(clerr.ConfigInvalid, "unknown token output format")
	}
}

func writeJSON(writer io.Writer, output Output) error {
	now := output.Now
	if now.IsZero() {
		now = time.Now()
	}
	expiresIn := int64(output.Credential.ExpiresAt.Sub(now).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}
	body := struct {
		AccessToken string   `json:"access_token"`
		TokenType   string   `json:"token_type"`
		ExpiresAt   string   `json:"expires_at"`
		ExpiresIn   int64    `json:"expires_in"`
		Profile     string   `json:"profile"`
		Resource    string   `json:"resource"`
		Scope       []string `json:"scope"`
	}{
		AccessToken: output.Credential.AccessToken,
		TokenType:   output.Credential.TokenType,
		ExpiresAt:   output.Credential.ExpiresAt.UTC().Format(time.RFC3339),
		ExpiresIn:   expiresIn,
		Profile:     output.Profile,
		Resource:    output.Resource,
		Scope:       append([]string(nil), output.Credential.Scopes...),
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(body)
}
