package homefile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/trknhr/envvault/internal/clerr"
)

func (r *contentResolver) renderJSON(ctx context.Context, body []byte) ([]byte, error) {
	document, err := decodeJSONDocument(body)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "parse home file JSON template", err)
	}
	document, err = r.Resolve(ctx, document)
	if err != nil {
		return nil, err
	}
	rendered, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "render home file JSON template", err)
	}
	return copyWithTrailingNewline(rendered), nil
}

func decodeJSONDocument(body []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	document, err := decodeJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("multiple JSON values are not allowed")
		}
		return nil, err
	}
	return document, nil
}

func decodeJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxTemplateDepth {
		return nil, errors.New("JSON template nesting exceeds 128 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key must be a string")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, errors.New("duplicate JSON object key is not allowed")
			}
			value, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("invalid JSON object terminator")
		}
		return object, nil
	case '[':
		array := []any{}
		for decoder.More() {
			value, err := decodeJSONValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("invalid JSON array terminator")
		}
		return array, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}
