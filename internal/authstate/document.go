// Package authstate stores structured authentication state on the host.
package authstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/trknhr/envvault/internal/envref"
	"gopkg.in/yaml.v3"
)

const MaxDocumentBytes = 1 << 20

// Metadata contains no tokens or other secret values.
type Metadata struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Provider     string   `json:"provider"`
	Format       string   `json:"format"`
	TokenField   string   `json:"token_field"`
	ExpiresField string   `json:"expires_field,omitempty"`
	RefreshField string   `json:"refresh_field,omitempty"`
	ClientID     string   `json:"client_id,omitempty"`
	Account      string   `json:"account,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

func ValidName(name string) bool {
	ref, ok, err := envref.ParseValue(envref.Format(name, envref.PartDefault))
	return err == nil && ok && ref.Part == envref.PartDefault && ref.Profile == name && name != "" &&
		strings.TrimSpace(name) == name && !strings.ContainsAny(name, "\r\n\x00")
}

func (m Metadata) Validate() error {
	if !ValidName(m.Name) || m.ID != "" && !validID(m.ID) {
		return errors.New("invalid authentication profile identity")
	}
	if m.Provider != "generic" && m.Provider != "github" {
		return errors.New("unsupported authentication provider")
	}
	if m.Format != "json" && m.Format != "yaml" {
		return errors.New("authentication format must be json or yaml")
	}
	for _, pointer := range []string{m.TokenField, m.ExpiresField, m.RefreshField} {
		if pointer == "" && pointer != m.TokenField {
			continue
		}
		if _, err := pointerParts(pointer); err != nil {
			return err
		}
	}
	if strings.ContainsAny(m.Account+m.ClientID+strings.Join(m.Scopes, ""), "\r\n\x00") {
		return errors.New("invalid authentication metadata")
	}
	return nil
}

// Parse canonicalizes a bounded document, rejecting ambiguous JSON/YAML.
// Parser diagnostics are deliberately not returned: they can contain secrets.
func Parse(body []byte, format string) ([]byte, error) {
	if len(body) == 0 || len(body) > MaxDocumentBytes {
		return nil, errors.New("authentication document size is invalid")
	}
	var value any
	var err error
	switch format {
	case "json":
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		value, err = jsonValue(decoder, 0)
		if err == nil {
			if _, tail := decoder.Token(); tail != io.EOF {
				err = errors.New("trailing document")
			}
		}
	case "yaml":
		var node yaml.Node
		decoder := yaml.NewDecoder(bytes.NewReader(body))
		err = decoder.Decode(&node)
		if err == nil {
			err = validateYAML(&node, 0)
		}
		if err == nil {
			err = node.Decode(&value)
		}
		if err == nil {
			var tail yaml.Node
			if decoder.Decode(&tail) != io.EOF {
				err = errors.New("trailing document")
			}
		}
	default:
		return nil, errors.New("authentication format must be json or yaml")
	}
	if err != nil {
		return nil, errors.New("invalid or ambiguous authentication document")
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, errors.New("authentication document must be an object")
	}
	canonical, err := json.Marshal(value)
	if err != nil || len(canonical) > MaxDocumentBytes {
		return nil, errors.New("authentication document cannot be encoded")
	}
	return canonical, nil
}

func jsonValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, errors.New("nesting limit")
	}
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("invalid key")
			}
			if _, exists := object[key]; exists {
				return nil, errors.New("duplicate key")
			}
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid object")
		}
		return object, nil
	case '[':
		array := []any{}
		for d.More() {
			value, err := jsonValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid array")
		}
		return array, nil
	}
	return nil, errors.New("invalid document")
}

func validateYAML(node *yaml.Node, depth int) error {
	if depth > 64 || node.Kind == yaml.AliasNode || node.Anchor != "" || node.Tag == "!!merge" {
		return errors.New("unsupported YAML")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || seen[key.Value] {
				return errors.New("invalid YAML key")
			}
			seen[key.Value] = true
		}
	}
	for _, child := range node.Content {
		if err := validateYAML(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func pointerParts(pointer string) ([]string, error) {
	if !strings.HasPrefix(pointer, "/") || len(pointer) > 1024 {
		return nil, errors.New("token selectors must be JSON pointers")
	}
	parts := strings.Split(pointer[1:], "/")
	for i, part := range parts {
		for j := 0; j < len(part); j++ {
			if part[j] == '~' {
				if j+1 == len(part) || part[j+1] != '0' && part[j+1] != '1' {
					return nil, errors.New("invalid JSON pointer")
				}
				j++
			}
		}
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
	}
	return parts, nil
}

func Field(document []byte, pointer string) (any, error) {
	parts, err := pointerParts(pointer)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(document))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil {
		return nil, errors.New("invalid authentication state")
	}
	for _, part := range parts {
		switch node := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = node[part]
			if !ok {
				return nil, errors.New("authentication field missing")
			}
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) || strconv.Itoa(index) != part {
				return nil, errors.New("authentication field missing")
			}
			value = node[index]
		default:
			return nil, errors.New("authentication field missing")
		}
	}
	return value, nil
}

func Token(document []byte, pointer string) ([]byte, error) {
	value, err := Field(document, pointer)
	if err != nil {
		return nil, err
	}
	token, ok := value.(string)
	if !ok || token == "" || len(token) > 16<<10 || strings.TrimSpace(token) != token || strings.Contains(token, "envvault://") || strings.ContainsFunc(token, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return nil, errors.New("authentication token is not a valid header value")
	}
	return []byte(token), nil
}

func Expiry(document []byte, pointer string) (time.Time, error) {
	if pointer == "" {
		return time.Time{}, nil
	}
	value, err := Field(document, pointer)
	if err != nil {
		return time.Time{}, err
	}
	switch v := value.(type) {
	case string:
		t, err := time.Parse(time.RFC3339, v)
		if err == nil {
			return t, nil
		}
	case json.Number:
		n, err := v.Int64()
		if err == nil && n > 0 {
			return time.Unix(n, 0), nil
		}
	}
	return time.Time{}, errors.New("authentication expiry must be RFC3339 or Unix seconds")
}
