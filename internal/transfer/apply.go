package transfer

import (
	"context"
	"sort"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/config"
	"github.com/trknhr/envvault/internal/keyring"
)

// Result reports which names were written, replaced, or left untouched.
// It never includes secret values.
type Result struct {
	ImportedCredentials []string
	ReplacedCredentials []string
	SkippedCredentials  []string
	ImportedProfiles    []string
	ReplacedProfiles    []string
	SkippedProfiles     []string
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
	if len(bundle.Credentials) == 0 && len(bundle.Profiles) == 0 {
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
