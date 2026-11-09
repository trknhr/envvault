package transfer

import (
	"context"
	"sort"

	"github.com/trknhr/envvault/internal/authstate"
	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
)

// Result reports which names were written, replaced, or left untouched.
// It never includes secret values.
type Result struct {
	ImportedCredentials  []string
	ReplacedCredentials  []string
	SkippedCredentials   []string
	ImportedProfiles     []string
	ReplacedProfiles     []string
	SkippedProfiles      []string
	ImportedAuthProfiles []string
	ReplacedAuthProfiles []string
	SkippedAuthProfiles  []string
}

// Seal encrypts the bundle with passphrase.
func Seal(bundle Bundle, passphrase []byte, params KDFParams) ([]byte, error) {
	plaintext, err := bundle.marshal()
	if err != nil {
		return nil, err
	}
	defer keyring.Zero(plaintext)
	return Encrypt(passphrase, plaintext, params)
}

// Open decrypts a file into a bundle. The caller must Zero the bundle.
func Open(passphrase, file []byte) (Bundle, error) {
	plaintext, err := Decrypt(passphrase, file)
	if err != nil {
		return Bundle{}, err
	}
	defer keyring.Zero(plaintext)
	return unmarshalBundle(plaintext)
}

// Apply stores bundle secrets into the OS credential store and merges profiles
// into cfg. Existing secrets and profiles are skipped unless overwrite is set.
// save is called only after the credential store updates succeed. A failed save
// restores the previous credential values.
func Apply(ctx context.Context, secrets keyring.Store, cfg config.File, bundle Bundle, overwrite bool, save func(config.File) error) (Result, error) {
	if len(bundle.AuthProfiles) > 0 {
		return Result{}, clerr.New(clerr.ConfigInvalid, "authentication import requires a host authentication store")
	}
	if secrets == nil {
		return Result{}, clerr.New(clerr.KeyringUnavailable, "OS credential store unavailable")
	}
	if save == nil {
		return Result{}, clerr.New(clerr.ConfigInvalid, "config save is unavailable")
	}
	if err := validateBundle(bundle); err != nil {
		return Result{}, err
	}
	var result Result
	changes := make([]secretChange, 0, len(bundle.Credentials))
	rollback := func() {
		restoreCtx := context.WithoutCancel(ctx)
		for i := len(changes) - 1; i >= 0; i-- {
			changes[i].restore(restoreCtx, secrets)
		}
	}
	for _, credential := range bundle.Credentials {
		change, action, err := planCredential(ctx, secrets, credential, overwrite)
		if err != nil {
			rollback()
			return Result{}, err
		}
		switch action {
		case actionSkip:
			result.SkippedCredentials = append(result.SkippedCredentials, credential.Name)
			continue
		case actionImport:
			result.ImportedCredentials = append(result.ImportedCredentials, credential.Name)
		case actionReplace:
			result.ReplacedCredentials = append(result.ReplacedCredentials, credential.Name)
		}
		if err := change.apply(ctx, secrets, credential.Value); err != nil {
			rollback()
			return Result{}, err
		}
		changes = append(changes, change)
		cfg.AddCredential(credential.Name)
	}
	for _, name := range sortedProfileNames(bundle.Profiles) {
		stored := bundle.Profiles[name]
		if _, exists := cfg.Profiles[name]; exists && !overwrite {
			result.SkippedProfiles = append(result.SkippedProfiles, name)
			continue
		}
		if cfg.Profiles == nil {
			cfg.Profiles = map[string]config.Profile{}
		}
		if _, exists := cfg.Profiles[name]; exists {
			result.ReplacedProfiles = append(result.ReplacedProfiles, name)
		} else {
			result.ImportedProfiles = append(result.ImportedProfiles, name)
		}
		cfg.Profiles[name] = stored
	}
	if err := save(cfg); err != nil {
		rollback()
		return Result{}, err
	}
	for i := range changes {
		keyring.Zero(changes[i].previous)
	}
	return result, nil
}

type applyAction int

const (
	actionImport applyAction = iota
	actionReplace
	actionSkip
)

type secretChange struct {
	key      keyring.Key
	created  bool
	previous []byte
}

func (c secretChange) apply(ctx context.Context, secrets keyring.Store, value []byte) error {
	if err := secrets.Put(ctx, c.key, value); err != nil {
		return err
	}
	return nil
}

func (c secretChange) restore(ctx context.Context, secrets keyring.Store) {
	if c.created {
		_ = secrets.Delete(ctx, c.key)
		return
	}
	_ = secrets.Put(ctx, c.key, c.previous)
	keyring.Zero(c.previous)
}

func planCredential(ctx context.Context, secrets keyring.Store, credential Credential, overwrite bool) (secretChange, applyAction, error) {
	key := keyring.CredentialValue(credential.Name)
	current, err := secrets.Get(ctx, key)
	if err != nil {
		if clerrIsNotFound(err) {
			return secretChange{key: key, created: true}, actionImport, nil
		}
		return secretChange{}, 0, err
	}
	if !overwrite {
		keyring.Zero(current)
		return secretChange{}, actionSkip, nil
	}
	return secretChange{key: key, previous: current}, actionReplace, nil
}

func validateBundle(bundle Bundle) error {
	if len(bundle.Credentials) == 0 && len(bundle.Profiles) == 0 && len(bundle.AuthProfiles) == 0 {
		return clerr.New(clerr.ConfigInvalid, "nothing to import")
	}
	seen := map[string]struct{}{}
	for _, credential := range bundle.Credentials {
		if !validName(credential.Name) || len(credential.Value) == 0 {
			return clerr.New(clerr.ConfigInvalid, "export payload is invalid")
		}
		if _, ok := seen[credential.Name]; ok {
			return clerr.New(clerr.ConfigInvalid, "export payload is invalid")
		}
		seen[credential.Name] = struct{}{}
	}
	for name := range bundle.Profiles {
		if !validName(name) {
			return clerr.New(clerr.ConfigInvalid, "export profiles are invalid")
		}
	}
	for _, auth := range bundle.AuthProfiles {
		if auth.Metadata.Validate() != nil || len(auth.Document) == 0 || len(auth.Document) > authstate.MaxDocumentBytes {
			return clerr.New(clerr.ConfigInvalid, "authentication export is invalid")
		}
		if _, exists := seen[auth.Metadata.Name]; exists {
			return clerr.New(clerr.ConfigInvalid, "authentication export has duplicate credential names")
		}
		seen[auth.Metadata.Name] = struct{}{}
	}
	return nil
}

func sortedProfileNames(profiles map[string]config.Profile) []string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ApplyWithAuth reencrypts imported profiles with local keys and rolls them
// back together with opaque credentials if configuration cannot commit.
func ApplyWithAuth(ctx context.Context, secrets keyring.Store, cfg config.File, bundle Bundle, store authstate.Store, overwrite bool, save func(config.File) error) (Result, error) {
	if err := validateBundle(bundle); err != nil {
		return Result{}, err
	}
	if save == nil {
		return Result{}, clerr.New(clerr.ConfigInvalid, "configuration save unavailable")
	}
	type change struct {
		metadata authstate.Metadata
		previous authstate.Record
	}
	var changes []change
	defer func() {
		for i := range changes {
			changes[i].previous.Zero()
		}
	}()
	rollback := func() {
		for i := len(changes) - 1; i >= 0; i-- {
			c := &changes[i]
			if c.previous.Metadata.ID == "" {
				_ = store.Delete(context.WithoutCancel(ctx), c.metadata.ID)
			} else {
				_, _ = store.Put(context.WithoutCancel(ctx), c.previous.Metadata, c.previous.Document)
			}
		}
	}
	updated := make(map[string]string, len(cfg.AuthProfiles))
	for name, id := range cfg.AuthProfiles {
		updated[name] = id
	}
	cfg.AuthProfiles = updated
	var authResult Result
	for _, incoming := range bundle.AuthProfiles {
		metadata := incoming.Metadata
		metadata.ID = ""
		for _, name := range cfg.CredentialNames() {
			if name == metadata.Name {
				rollback()
				return Result{}, clerr.New(clerr.ConfigInvalid, "authentication name collides with an opaque credential")
			}
		}
		var previous authstate.Record
		if id, exists := cfg.AuthProfiles[metadata.Name]; exists {
			if !overwrite {
				authResult.SkippedAuthProfiles = append(authResult.SkippedAuthProfiles, metadata.Name)
				continue
			}
			var err error
			previous, err = store.Read(ctx, id)
			if err != nil {
				rollback()
				return Result{}, err
			}
			metadata.ID = id
		}
		stored, err := store.Put(ctx, metadata, incoming.Document)
		if err != nil {
			previous.Zero()
			rollback()
			return Result{}, err
		}
		changes = append(changes, change{metadata: stored, previous: previous})
		cfg.AuthProfiles[metadata.Name] = stored.ID
		cfg.Version = 2
		if previous.Metadata.ID == "" {
			authResult.ImportedAuthProfiles = append(authResult.ImportedAuthProfiles, metadata.Name)
		} else {
			authResult.ReplacedAuthProfiles = append(authResult.ReplacedAuthProfiles, metadata.Name)
		}
	}
	raw := bundle
	raw.AuthProfiles = nil
	for _, value := range raw.Credentials {
		if _, exists := cfg.AuthProfiles[value.Name]; exists {
			rollback()
			return Result{}, clerr.New(clerr.ConfigInvalid, "opaque credential collides with an authentication profile")
		}
	}
	var result Result
	var err error
	if len(raw.Credentials) == 0 && len(raw.Profiles) == 0 {
		err = save(cfg)
	} else {
		result, err = Apply(ctx, secrets, cfg, raw, overwrite, save)
	}
	if err != nil {
		rollback()
		return Result{}, err
	}
	result.ImportedAuthProfiles, result.ReplacedAuthProfiles, result.SkippedAuthProfiles = authResult.ImportedAuthProfiles, authResult.ReplacedAuthProfiles, authResult.SkippedAuthProfiles
	return result, nil
}
