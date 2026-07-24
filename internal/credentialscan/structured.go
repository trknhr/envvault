package credentialscan

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

var (
	envAssignmentPattern = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*([^\r\n]*)`)
	yamlFieldPattern     = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*:[ \t]*([^\r\n]*)`)
	jsonFieldPattern     = regexp.MustCompile(`(?m)^[ \t]*"([^"\r\n]+)"[ \t]*:[ \t]*([^\r\n]*)`)
)

var secretFieldNames = map[string]struct{}{
	"access_token":        {},
	"accesstoken":         {},
	"api_key":             {},
	"apikey":              {},
	"api_secret":          {},
	"apisecret":           {},
	"auth_token":          {},
	"authtoken":           {},
	"client_secret":       {},
	"clientsecret":        {},
	"database_password":   {},
	"db_password":         {},
	"password":            {},
	"passwd":              {},
	"pwd":                 {},
	"private_key":         {},
	"privatekey":          {},
	"refresh_token":       {},
	"refreshtoken":        {},
	"secret":              {},
	"secret_access_key":   {},
	"secret_key":          {},
	"secretaccesskey":     {},
	"secretkey":           {},
	"service_account_key": {},
	"serviceaccountkey":   {},
	"token":               {},
}

var placeholderValues = map[string]struct{}{
	"<redacted>":    {},
	"changeme":      {},
	"default":       {},
	"dummy":         {},
	"example":       {},
	"none":          {},
	"null":          {},
	"password":      {},
	"redacted":      {},
	"replace_me":    {},
	"replace-me":    {},
	"sample":        {},
	"secret":        {},
	"test":          {},
	"todo":          {},
	"your_api_key":  {},
	"your_password": {},
	"your_secret":   {},
	"your_token":    {},
}

func detectStructured(path string, body []byte) []Finding {
	pattern := structuredPattern(path)
	if pattern == nil {
		return nil
	}

	base := strings.ToLower(filepath.Base(path))
	matches := pattern.FindAllSubmatchIndex(body, -1)
	findings := make([]Finding, 0, len(matches))
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}
		key := string(body[match[2]:match[3]])
		value := body[match[4]:match[5]]
		normalizedKey := normalizeFieldName(key)

		confidence := ConfidenceMedium
		ruleID := "envvault/secret-field"
		description := "Potential credential stored in a secret-named field"
		if base == "kaggle.json" && normalizedKey == "key" {
			confidence = ConfidenceHigh
			ruleID = "envvault/kaggle-api-key"
			description = "Potential Kaggle API key stored in kaggle.json"
		} else if !isSecretField(normalizedKey) {
			continue
		}
		if !plausibleRawCredential(value) {
			continue
		}

		line, column := lineColumn(body, match[2])
		findings = append(findings, Finding{
			Path:        path,
			Line:        line,
			Column:      column,
			Location:    key,
			RuleID:      ruleID,
			Description: description,
			Confidence:  confidence,
			Engine:      "envvault",
		})
	}
	return findings
}

func structuredPattern(path string) *regexp.Regexp {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(base))
	switch {
	case base == ".env", strings.HasPrefix(base, ".env."), ext == ".toml":
		return envAssignmentPattern
	case ext == ".yaml", ext == ".yml":
		return yamlFieldPattern
	case ext == ".json":
		return jsonFieldPattern
	default:
		return nil
	}
}

func normalizeFieldName(key string) string {
	key = strings.TrimSpace(strings.ToLower(key))
	var normalized strings.Builder
	normalized.Grow(len(key))
	previousUnderscore := false
	for _, r := range key {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			normalized.WriteRune(r)
			previousUnderscore = false
			continue
		}
		if !previousUnderscore {
			normalized.WriteByte('_')
			previousUnderscore = true
		}
	}
	return strings.Trim(normalized.String(), "_")
}

func isSecretField(key string) bool {
	for _, suffix := range []string{
		"_expiry", "_expires", "_file", "_id", "_name", "_path", "_ref",
		"_reference", "_ttl", "_type", "_uri", "_url",
	} {
		if strings.HasSuffix(key, suffix) {
			return false
		}
	}
	if _, ok := secretFieldNames[key]; ok {
		return true
	}
	for _, suffix := range []string{
		"_api_key", "_password", "_private_key", "_secret", "_secret_access_key",
		"_secret_key", "_token",
	} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

func plausibleRawCredential(raw []byte) bool {
	value := strings.TrimSpace(string(raw))
	value = strings.TrimSuffix(value, ",")
	value = strings.TrimSpace(value)
	if len(value) >= 2 {
		switch {
		case value[0] == '"' && value[len(value)-1] == '"',
			value[0] == '\'' && value[len(value)-1] == '\'':
			value = value[1 : len(value)-1]
		}
	}
	value = strings.TrimSpace(value)
	if len(value) < 4 {
		return false
	}

	lower := strings.ToLower(value)
	if _, ok := placeholderValues[lower]; ok {
		return false
	}
	if lower == "true" || lower == "false" || lower == "{}" || lower == "[]" {
		return false
	}
	for _, prefix := range []string{
		"$", "<", "{", "[", "envvault://", "file://", "os.getenv", "process.env.",
		"arn:aws:secretsmanager:", "projects/",
	} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}
	for _, prefix := range []string{"dummy_", "example_", "sample_", "test_", "your_"} {
		if strings.HasPrefix(lower, prefix) {
			return false
		}
	}

	trimmedMarkers := strings.Trim(value, "xX*.-_ ")
	return trimmedMarkers != ""
}

func lineColumn(body []byte, offset int) (int, int) {
	line := bytes.Count(body[:offset], []byte{'\n'}) + 1
	lineStart := bytes.LastIndexByte(body[:offset], '\n') + 1
	return line, offset - lineStart + 1
}
