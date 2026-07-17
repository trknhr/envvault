package homefile

import (
	"context"

	"github.com/pelletier/go-toml/v2"
	"github.com/trknhr/envvault/internal/clerr"
)

func (r *contentResolver) renderTOML(ctx context.Context, body []byte) ([]byte, error) {
	document := map[string]any{}
	if err := toml.Unmarshal(body, &document); err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "parse home file TOML template", err)
	}
	resolved, err := r.Resolve(ctx, document)
	if err != nil {
		return nil, err
	}
	rendered, err := toml.Marshal(resolved)
	if err != nil {
		return nil, clerr.Wrap(clerr.ConfigInvalid, "render home file TOML template", err)
	}
	return copyWithTrailingNewline(rendered), nil
}
