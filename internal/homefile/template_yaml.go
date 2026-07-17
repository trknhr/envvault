package homefile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
	"gopkg.in/yaml.v3"
)

func (r *contentResolver) renderYAML(ctx context.Context, body []byte) ([]byte, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, clerr.New(clerr.ConfigInvalid, "home file YAML template is empty")
		}
		return nil, clerr.Wrap(clerr.ConfigInvalid, "parse home file YAML template", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, clerr.New(clerr.ConfigInvalid, "multiple YAML documents are not allowed")
		}
		return nil, clerr.Wrap(clerr.ConfigInvalid, "parse home file YAML template", err)
	}
	if err := r.resolveYAMLNode(ctx, &document, 0); err != nil {
		return nil, err
	}

	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "render home file YAML template", err)
	}
	if err := encoder.Close(); err != nil {
		zero(output.Bytes())
		return nil, clerr.Wrap(clerr.CleanupFailed, "close home file YAML encoder", err)
	}
	return copyWithTrailingNewline(output.Bytes()), nil
}

func (r *contentResolver) resolveYAMLNode(ctx context.Context, node *yaml.Node, depth int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth > maxTemplateDepth {
		return clerr.New(clerr.ConfigInvalid, "home file YAML template nesting exceeds 128 levels")
	}
	if node == nil {
		return clerr.New(clerr.ConfigInvalid, "home file YAML template contains an invalid node")
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return clerr.New(clerr.ConfigInvalid, "YAML anchors and aliases are not supported in home file templates")
	}

	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return clerr.New(clerr.ConfigInvalid, "home file YAML template must contain one document value")
		}
		return r.resolveYAMLNode(ctx, node.Content[0], depth)
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return clerr.New(clerr.ConfigInvalid, "home file YAML template contains an invalid mapping")
		}
		seen := make(map[string]struct{}, len(node.Content)/2)
		for index := 0; index < len(node.Content); index += 2 {
			key := node.Content[index]
			if key == nil || key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				return clerr.New(clerr.ConfigInvalid, "home file YAML template mapping keys must be strings")
			}
			if key.Anchor != "" || key.Value == "<<" || key.ShortTag() == "!!merge" {
				return clerr.New(clerr.ConfigInvalid, "YAML anchors, aliases, and merge keys are not supported in home file templates")
			}
			if _, duplicate := seen[key.Value]; duplicate {
				return clerr.New(clerr.ConfigInvalid, "duplicate YAML mapping key is not allowed")
			}
			seen[key.Value] = struct{}{}
			if err := r.resolveYAMLNode(ctx, node.Content[index+1], depth+1); err != nil {
				return err
			}
		}
		return nil
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := r.resolveYAMLNode(ctx, child, depth+1); err != nil {
				return err
			}
		}
		return nil
	case yaml.ScalarNode:
		if node.ShortTag() != "!!str" {
			if strings.Contains(node.Value, "envvault://") {
				return clerr.New(clerr.ConfigInvalid, "EnvVault reference must be a YAML string value")
			}
			return nil
		}
		resolved, err := r.resolveString(ctx, node.Value)
		if err != nil {
			return err
		}
		if resolved != node.Value {
			node.SetString(resolved)
		}
		return nil
	default:
		return clerr.New(clerr.ConfigInvalid, "home file YAML template contains an unsupported node")
	}
}
