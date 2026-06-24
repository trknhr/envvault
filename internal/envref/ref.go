package envref

import (
	"net/url"
	"strings"

	"github.com/trknhr/credlease/internal/clerr"
)

const schemePrefix = "credlease://"

type Reference struct {
	Raw     string
	Profile string
}

func ParseValue(value string) (Reference, bool, error) {
	if !strings.HasPrefix(value, schemePrefix) {
		return Reference{}, false, nil
	}

	profile, err := parseProfile(value[len(schemePrefix):])
	if err != nil {
		return Reference{}, true, err
	}

	return Reference{Raw: value, Profile: profile}, true, nil
}

func parseProfile(raw string) (string, error) {
	if raw == "" {
		return "", invalid("profile is required")
	}
	if strings.ContainsAny(raw, "?#\\") {
		return "", invalid("query, fragment, and backslash are not allowed")
	}

	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
		return "", invalid("percent-encoded separators are not allowed")
	}

	decoded, err := url.PathUnescape(raw)
	if err != nil {
		return "", invalid("invalid percent encoding")
	}
	if decoded == "" {
		return "", invalid("profile is required")
	}

	segments := strings.Split(decoded, "/")
	for _, segment := range segments {
		if segment == "" {
			return "", invalid("empty profile segment is not allowed")
		}
		if segment == "." || segment == ".." {
			return "", invalid("profile traversal segment is not allowed")
		}
	}

	return strings.Join(segments, "/"), nil
}

func invalid(message string) error {
	return clerr.New(clerr.ReferenceInvalid, message)
}
