package envref

import (
	"net/url"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
)

const schemePrefix = "envvault://"

type Reference struct {
	Raw     string
	Profile string
	Part    Part
}

type Part string

const (
	PartDefault Part = ""
	PartBaseURL Part = "base-url"
	PartToken   Part = "token"
)

func ParseValue(value string) (Reference, bool, error) {
	if !strings.HasPrefix(value, schemePrefix) {
		return Reference{}, false, nil
	}

	profile, part, err := parseProfile(value[len(schemePrefix):])
	if err != nil {
		return Reference{}, true, err
	}

	return Reference{Raw: value, Profile: profile, Part: part}, true, nil
}

func Format(profile string, part Part) string {
	if part == PartDefault {
		return schemePrefix + profile
	}
	return schemePrefix + profile + "/" + string(part)
}

func ProxyDotenv(profile string) string {
	return "ENVVAULT_PROXY_URL=" + Format(profile, PartBaseURL) + "\n" +
		"ENVVAULT_PROXY_TOKEN=" + Format(profile, PartToken) + "\n"
}

func parseProfile(raw string) (string, Part, error) {
	if raw == "" {
		return "", "", invalid("profile is required")
	}
	if strings.ContainsAny(raw, "?#\\") {
		return "", "", invalid("query, fragment, and backslash are not allowed")
	}

	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", "", invalid("percent-encoded separators are not allowed")
	}

	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", "", invalid("invalid percent encoding")
	}
	if decoded == "" {
		return "", "", invalid("profile is required")
	}

	segments := strings.Split(decoded, "/")
	for _, segment := range segments {
		if segment == "" {
			return "", "", invalid("empty profile segment is not allowed")
		}
		if segment == "." || segment == ".." {
			return "", "", invalid("profile traversal segment is not allowed")
		}
	}

	part := PartDefault
	last := segments[len(segments)-1]
	switch Part(last) {
	case PartBaseURL, PartToken:
		if len(segments) == 1 {
			return "", "", invalid("profile is required")
		}
		part = Part(last)
		segments = segments[:len(segments)-1]
	case "value":
		if len(segments) > 1 {
			return "", "", invalid("/value references are no longer supported; use envvault://<credential>")
		}
	}

	return strings.Join(segments, "/"), part, nil
}

func invalid(message string) error {
	return clerr.New(clerr.ReferenceInvalid, message)
}
