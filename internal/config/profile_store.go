package config

import "github.com/trknhr/credlease/internal/profile"

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
