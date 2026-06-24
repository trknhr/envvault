package process

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/trknhr/credlease/internal/clerr"
	"github.com/trknhr/credlease/internal/envref"
	"github.com/trknhr/credlease/internal/issuer"
	"github.com/trknhr/credlease/internal/profile"
	"github.com/trknhr/credlease/internal/projectbinding"
)

type ProfileResolver interface {
	Profile(name string) (profile.Profile, error)
}

type EnvInput struct {
	Parent          []string
	EnvFiles        []string
	InlineEnv       []string
	ProjectIdentity projectbinding.Identity
}

func BuildEnv(ctx context.Context, input EnvInput, profiles ProfileResolver, tokenIssuer issuer.Issuer) (map[string]string, error) {
	env := environToMap(input.Parent)

	for _, path := range input.EnvFiles {
		values, err := readDotenvFile(path)
		if err != nil {
			return nil, err
		}
		for key, value := range values {
			env[key] = value
		}
	}

	for _, assignment := range input.InlineEnv {
		key, value, err := parseAssignment(assignment)
		if err != nil {
			return nil, err
		}
		env[key] = value
	}

	cache := map[string]string{}
	for key, value := range env {
		ref, ok, err := envref.ParseValue(value)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		token, ok := cache[ref.Profile]
		if !ok {
			token, err = issueProfileToken(ctx, profiles, tokenIssuer, ref.Profile, input.ProjectIdentity)
			if err != nil {
				return nil, err
			}
			cache[ref.Profile] = token
		}
		env[key] = token
	}
	removeAuthorityEnv(env)

	return env, nil
}

func readDotenvFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "read env file", err)
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, err := parseAssignment(line)
		if err != nil {
			return nil, clerr.Wrap(clerr.ConfigInvalid, fmt.Sprintf("parse env file line %d", lineNumber), err)
		}
		values[key] = stripOptionalQuotes(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "scan env file", err)
	}
	return values, nil
}

func issueProfileToken(ctx context.Context, profiles ProfileResolver, tokenIssuer issuer.Issuer, name string, identity projectbinding.Identity) (string, error) {
	p, err := profiles.Profile(name)
	if err != nil {
		return "", err
	}
	if p.Kind != profile.KindProcess {
		return "", clerr.New(clerr.ProfileKindMismatch, name)
	}
	if err := projectbinding.Check(p.ProjectBinding, identity); err != nil {
		return "", err
	}
	claims, err := ProcessClaims(p, identity)
	if err != nil {
		return "", err
	}

	credential, err := tokenIssuer.Issue(ctx, issuer.Grant{
		Profile:  p.Name,
		Resource: p.Resource,
		Scopes:   append([]string(nil), p.Scopes...),
		TTL:      p.TokenTTL,
		Claims:   claims,
	})
	if err != nil {
		return "", err
	}
	return credential.AccessToken, nil
}

func environToMap(environ []string) map[string]string {
	env := make(map[string]string, len(environ))
	for _, item := range environ {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			continue
		}
		env[key] = value
	}
	return env
}

func removeAuthorityEnv(env map[string]string) {
	for _, key := range authorityEnvKeys {
		delete(env, key)
	}
}

var authorityEnvKeys = []string{
	"CREDLEASE_TALOS_HMAC_SECRET",
	"CREDLEASE_TALOS_SIGNING_KEY",
	"CREDLEASE_PROFILE_PARENT_KEY",
}

func parseAssignment(raw string) (string, string, error) {
	key, value, ok := strings.Cut(raw, "=")
	if !ok || strings.TrimSpace(key) == "" {
		return "", "", clerr.New(clerr.ConfigInvalid, "environment assignment must be KEY=VALUE")
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), nil
}

func stripOptionalQuotes(value string) string {
	if len(value) < 2 {
		return value
	}
	if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
		return value[1 : len(value)-1]
	}
	return value
}

func ProcessClaims(p profile.Profile, identity projectbinding.Identity) (map[string]any, error) {
	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}
	projectID, err := projectbinding.PathHash(identity.Root)
	if err != nil {
		return nil, err
	}
	claims := map[string]any{
		"credlease_session_id": sessionID,
		"credlease_project_id": projectID,
	}
	for key, value := range p.Claims {
		claims[key] = value
	}
	claims["credlease_profile"] = p.Name
	claims["credlease_resource"] = p.Resource
	claims["credlease_purpose"] = "process"
	return claims, nil
}

func newSessionID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", clerr.Wrap(clerr.IssueFailed, "generate session id", err)
	}
	return "hex:" + hex.EncodeToString(bytes[:]), nil
}
