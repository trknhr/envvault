package talos

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"

	"github.com/trknhr/credlease/internal/clerr"
	"gopkg.in/yaml.v3"
)

type LocalConfig struct {
	HTTPAddress  string
	MetricsAddr  string
	DatabaseDSN  string
	Issuer       string
	HMACSecret   []byte
	SigningSeed  []byte
	SigningKeyID string
}

func WriteLocalConfig(path string, config LocalConfig) error {
	rendered, err := renderLocalConfig(config)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "create talos config directory", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".talos-config-*")
	if err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "create temporary talos config", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.RuntimeUnavailable, "set talos config permissions", err)
	}
	if _, err := tmp.Write(rendered); err != nil {
		_ = tmp.Close()
		return clerr.Wrap(clerr.RuntimeUnavailable, "write talos config", err)
	}
	if err := tmp.Close(); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "close talos config", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "install talos config", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return clerr.Wrap(clerr.RuntimeUnavailable, "set final talos config permissions", err)
	}
	return nil
}

func renderLocalConfig(config LocalConfig) ([]byte, error) {
	httpHost, httpPort, err := parseLoopbackAddress(config.HTTPAddress, "talos http address")
	if err != nil {
		return nil, err
	}
	metricsHost, metricsPort, err := parseLoopbackAddress(config.MetricsAddr, "talos metrics address")
	if err != nil {
		return nil, err
	}
	if config.DatabaseDSN == "" {
		return nil, clerr.New(clerr.RuntimeUnavailable, "talos database dsn is required")
	}
	if config.Issuer == "" {
		return nil, clerr.New(clerr.RuntimeUnavailable, "talos issuer is required")
	}
	if len(config.HMACSecret) < 32 {
		return nil, clerr.New(clerr.RuntimeUnavailable, "talos hmac secret must be at least 32 bytes")
	}
	if len(config.SigningSeed) != ed25519.SeedSize {
		return nil, clerr.New(clerr.RuntimeUnavailable, "talos signing seed must be 32 bytes")
	}
	kid := config.SigningKeyID
	if kid == "" {
		kid = "current"
	}
	jwks, err := signingJWKS(kid, config.SigningSeed)
	if err != nil {
		return nil, err
	}

	return yaml.Marshal(localConfigYAML{
		Serve: serveConfigYAML{
			HTTP:    addressConfigYAML{Host: httpHost, Port: httpPort},
			Metrics: addressConfigYAML{Host: metricsHost, Port: metricsPort},
		},
		Credentials: credentialsConfigYAML{
			Issuer: config.Issuer,
			APIKeys: apiKeysConfigYAML{
				DefaultTTL: "720h",
				MaxTTL:     "8760h",
				Prefix: prefixConfigYAML{
					Current: "talos",
					Retired: []string{},
				},
			},
			DerivedTokens: derivedTokensConfigYAML{
				DefaultTTL: "1h",
				JWT: jwtConfigYAML{
					SigningKeys: signingKeysConfigYAML{
						URLs: []string{"base64://" + base64.RawURLEncoding.EncodeToString(jwks)},
					},
				},
				Macaroon: macaroonConfigYAML{
					Prefix: prefixConfigYAML{
						Current: "mc",
						Retired: []string{},
					},
				},
			},
		},
		DB: dbConfigYAML{DSN: config.DatabaseDSN},
		Log: logConfigYAML{
			Level:  "warn",
			Format: "json",
		},
		Secrets: secretsConfigYAML{
			HMAC: hmacConfigYAML{
				Current: base64.RawURLEncoding.EncodeToString(config.HMACSecret),
				Retired: []string{},
			},
		},
		Tracing: tracingConfigYAML{Enabled: false},
		Cache: cacheConfigYAML{
			Type: "noop",
			TTL:  "5m",
		},
		Multitenancy: multitenancyConfigYAML{Enabled: false},
	})
}

func parseLoopbackAddress(address, label string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, clerr.Wrap(clerr.RuntimeUnavailable, "parse "+label, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", 0, clerr.New(clerr.RuntimeUnavailable, label+" must bind to loopback")
	}
	portNumber, err := net.LookupPort("tcp", port)
	if err != nil || portNumber <= 0 {
		return "", 0, clerr.New(clerr.RuntimeUnavailable, label+" port is invalid")
	}
	return host, portNumber, nil
}

func signingJWKS(kid string, seed []byte) ([]byte, error) {
	key := ed25519.NewKeyFromSeed(seed)
	public := key.Public().(ed25519.PublicKey)
	body := map[string]any{
		"keys": []map[string]string{{
			"alg": "EdDSA",
			"crv": "Ed25519",
			"d":   base64.RawURLEncoding.EncodeToString(seed),
			"kid": kid,
			"kty": "OKP",
			"use": "sig",
			"x":   base64.RawURLEncoding.EncodeToString(public),
		}},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, clerr.Wrap(clerr.RuntimeUnavailable, "marshal talos jwks", err)
	}
	return raw, nil
}

type localConfigYAML struct {
	Serve        serveConfigYAML        `yaml:"serve"`
	Credentials  credentialsConfigYAML  `yaml:"credentials"`
	DB           dbConfigYAML           `yaml:"db"`
	Log          logConfigYAML          `yaml:"log"`
	Secrets      secretsConfigYAML      `yaml:"secrets"`
	Tracing      tracingConfigYAML      `yaml:"tracing"`
	Cache        cacheConfigYAML        `yaml:"cache"`
	Multitenancy multitenancyConfigYAML `yaml:"multitenancy"`
}

type serveConfigYAML struct {
	HTTP    addressConfigYAML `yaml:"http"`
	Metrics addressConfigYAML `yaml:"metrics"`
}

type addressConfigYAML struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type credentialsConfigYAML struct {
	Issuer        string                  `yaml:"issuer"`
	APIKeys       apiKeysConfigYAML       `yaml:"api_keys"`
	DerivedTokens derivedTokensConfigYAML `yaml:"derived_tokens"`
}

type apiKeysConfigYAML struct {
	DefaultTTL string           `yaml:"default_ttl"`
	MaxTTL     string           `yaml:"max_ttl"`
	Prefix     prefixConfigYAML `yaml:"prefix"`
}

type prefixConfigYAML struct {
	Current string   `yaml:"current"`
	Retired []string `yaml:"retired"`
}

type derivedTokensConfigYAML struct {
	DefaultTTL string             `yaml:"default_ttl"`
	JWT        jwtConfigYAML      `yaml:"jwt"`
	Macaroon   macaroonConfigYAML `yaml:"macaroon"`
}

type jwtConfigYAML struct {
	SigningKeys signingKeysConfigYAML `yaml:"signing_keys"`
}

type signingKeysConfigYAML struct {
	URLs []string `yaml:"urls"`
}

type macaroonConfigYAML struct {
	Prefix prefixConfigYAML `yaml:"prefix"`
}

type dbConfigYAML struct {
	DSN string `yaml:"dsn"`
}

type logConfigYAML struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type secretsConfigYAML struct {
	HMAC hmacConfigYAML `yaml:"hmac"`
}

type hmacConfigYAML struct {
	Current string   `yaml:"current"`
	Retired []string `yaml:"retired"`
}

type tracingConfigYAML struct {
	Enabled bool `yaml:"enabled"`
}

type cacheConfigYAML struct {
	Type string `yaml:"type"`
	TTL  string `yaml:"ttl"`
}

type multitenancyConfigYAML struct {
	Enabled bool `yaml:"enabled"`
}
