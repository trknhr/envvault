package config

import (
	"sort"

	"github.com/trknhr/envvault/internal/profile"
)

type ProfileStore struct {
	Path string
}

func (s ProfileStore) Profile(name string) (profile.Profile, error) {
	cfg, err := Load(s.Path)
	if err != nil {
		return profile.Profile{}, err
	}
	return cfg.Profile(name)
}

// ListProfiles reloads the config and returns validated profiles in stable
// name order. Callers use this for fail-closed discovery; credential values are
// never part of the returned metadata.
func (s ProfileStore) ListProfiles() ([]profile.Profile, error) {
	cfg, err := Load(s.Path)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)

	profiles := make([]profile.Profile, 0, len(names))
	for _, name := range names {
		resolved, err := cfg.Profile(name)
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, resolved)
	}
	return profiles, nil
}
