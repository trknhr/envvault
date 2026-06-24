package talos_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	runtimetalos "github.com/trknhr/credlease/internal/runtime/talos"
	"gopkg.in/yaml.v3"
)

func TestWriteLocalConfigCreatesPrivateTalosConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime", "talos.yaml")
	signingSeed := []byte("0123456789abcdef0123456789abcdef")
	hmacSecret := []byte("secret-canary-hmac-32-byte-value!")

	err := runtimetalos.WriteLocalConfig(path, runtimetalos.LocalConfig{
		HTTPAddress:  "127.0.0.1:49152",
		MetricsAddr:  "127.0.0.1:49153",
		DatabaseDSN:  "sqlite3:///tmp/credlease/talos.db?_journal_mode=WAL",
		Issuer:       "credlease-local:01JTESTINSTALL",
		HMACSecret:   hmacSecret,
		SigningSeed:  signingSeed,
		SigningKeyID: "current",
	})
	if err != nil {
		t.Fatalf("WriteLocalConfig() error = %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v, want 0600", info.Mode().Perm())
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(raw) == "" {
		t.Fatal("config is empty")
	}
	if bytes.Contains(raw, signingSeed) || bytes.Contains(raw, hmacSecret) {
		t.Fatalf("config contains raw secret bytes")
	}

	var cfg talosConfigYAML
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("Unmarshal() error = %v\n%s", err, raw)
	}
	if cfg.Serve.HTTP.Host != "127.0.0.1" || cfg.Serve.HTTP.Port != 49152 {
		t.Fatalf("HTTP bind = %s:%d, want 127.0.0.1:49152", cfg.Serve.HTTP.Host, cfg.Serve.HTTP.Port)
	}
	if cfg.Serve.Metrics.Host != "127.0.0.1" || cfg.Serve.Metrics.Port != 49153 {
		t.Fatalf("metrics bind = %s:%d, want 127.0.0.1:49153", cfg.Serve.Metrics.Host, cfg.Serve.Metrics.Port)
	}
	if cfg.Credentials.Issuer != "credlease-local:01JTESTINSTALL" {
		t.Fatalf("issuer = %q", cfg.Credentials.Issuer)
	}
	if cfg.DB.DSN != "sqlite3:///tmp/credlease/talos.db?_journal_mode=WAL" {
		t.Fatalf("db dsn = %q", cfg.DB.DSN)
	}
	if cfg.Secrets.HMAC.Current == "" {
		t.Fatal("hmac secret is empty")
	}

	jwksURL := cfg.Credentials.DerivedTokens.JWT.SigningKeys.URLs[0]
	if len(cfg.Credentials.DerivedTokens.JWT.SigningKeys.URLs) != 1 || len(jwksURL) <= len("base64://") {
		t.Fatalf("signing key URLs = %#v", cfg.Credentials.DerivedTokens.JWT.SigningKeys.URLs)
	}
	rawJWKS, err := base64.RawURLEncoding.DecodeString(jwksURL[len("base64://"):])
	if err != nil {
		t.Fatalf("DecodeString(JWKS URL) error = %v", err)
	}

	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := yaml.Unmarshal(rawJWKS, &jwks); err != nil {
		t.Fatalf("Unmarshal(JWKS) error = %v\n%s", err, rawJWKS)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("JWK keys = %d, want 1", len(jwks.Keys))
	}
	jwk := jwks.Keys[0]
	if jwk["kid"] != "current" || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || jwk["alg"] != "EdDSA" || jwk["use"] != "sig" {
		t.Fatalf("JWK metadata = %#v", jwk)
	}
	if jwk["d"] != base64.RawURLEncoding.EncodeToString(signingSeed) {
		t.Fatalf("JWK d = %q, want seed", jwk["d"])
	}
	public := ed25519.NewKeyFromSeed(signingSeed).Public().(ed25519.PublicKey)
	if jwk["x"] != base64.RawURLEncoding.EncodeToString(public) {
		t.Fatalf("JWK x = %q, want derived public key", jwk["x"])
	}
}

func TestWriteLocalConfigRejectsNonLoopbackHTTPAddress(t *testing.T) {
	err := runtimetalos.WriteLocalConfig(filepath.Join(t.TempDir(), "talos.yaml"), runtimetalos.LocalConfig{
		HTTPAddress:  "0.0.0.0:4420",
		MetricsAddr:  "127.0.0.1:4422",
		DatabaseDSN:  "sqlite3:///tmp/talos.db",
		Issuer:       "credlease-local:test",
		HMACSecret:   []byte("0123456789abcdef0123456789abcdef"),
		SigningSeed:  []byte("0123456789abcdef0123456789abcdef"),
		SigningKeyID: "current",
	})
	if err == nil {
		t.Fatal("WriteLocalConfig() error = nil, want loopback rejection")
	}
}

type talosConfigYAML struct {
	Serve struct {
		HTTP struct {
			Host string `yaml:"host"`
			Port int    `yaml:"port"`
		} `yaml:"http"`
		Metrics struct {
			Host string `yaml:"host"`
			Port int    `yaml:"port"`
		} `yaml:"metrics"`
	} `yaml:"serve"`
	Credentials struct {
		Issuer        string `yaml:"issuer"`
		DerivedTokens struct {
			JWT struct {
				SigningKeys struct {
					URLs []string `yaml:"urls"`
				} `yaml:"signing_keys"`
			} `yaml:"jwt"`
		} `yaml:"derived_tokens"`
	} `yaml:"credentials"`
	DB struct {
		DSN string `yaml:"dsn"`
	} `yaml:"db"`
	Secrets struct {
		HMAC struct {
			Current string `yaml:"current"`
		} `yaml:"hmac"`
	} `yaml:"secrets"`
}
