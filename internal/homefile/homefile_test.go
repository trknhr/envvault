package homefile_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/homefile"
	"github.com/trknhr/envvault/internal/keyring"
	"gopkg.in/yaml.v3"
)

func TestParseAcceptsRelativeHomeFileReference(t *testing.T) {
	const destination = ".config/app/auth.json"
	spec, err := homefile.Parse(destination + "=envvault://app/config")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if spec.Path != destination {
		t.Fatalf("Path = %q", spec.Path)
	}
	if spec.Reference.Profile != "app/config" || spec.Reference.Part != envref.PartDefault {
		t.Fatalf("Reference = %#v", spec.Reference)
	}
	if spec.Kind != homefile.KindCredential || spec.Source != "" || spec.Format != homefile.FormatJSON {
		t.Fatalf("Spec = %#v", spec)
	}
}

func TestParseAllPreservesPercentEncodedRawCredentialReference(t *testing.T) {
	specs, err := homefile.ParseAll([]string{".credential=envvault://foo%25x"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	if len(specs) != 1 || specs[0].Reference.Raw != "envvault://foo%25x" || specs[0].Reference.Profile != "foo%x" {
		t.Fatalf("Specs = %#v", specs)
	}
	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir: t.TempDir(),
		Specs:    specs,
		Secrets:  memoryStore(t, map[string]string{"foo%x": "encoded-profile-secret"}),
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	output, err := os.ReadFile(filepath.Join(workspace.HomeDir(), ".credential"))
	if err != nil {
		t.Fatalf("ReadFile(raw credential) error = %v", err)
	}
	if string(output) != "encoded-profile-secret" {
		t.Fatalf("raw credential = %q", output)
	}
}

func TestParseAcceptsBareDotfileAsCurrentDirectoryJSONTemplate(t *testing.T) {
	spec, err := homefile.Parse(".hogehoge")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if spec.Path != ".hogehoge" || spec.Source != ".hogehoge" || spec.Kind != homefile.KindTemplate || spec.Format != homefile.FormatJSON {
		t.Fatalf("Spec = %#v", spec)
	}
	if spec.Reference.Profile != "" {
		t.Fatalf("Reference = %#v, want empty", spec.Reference)
	}
}

func TestParseInfersTemplateFormatFromMappedSource(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		path   string
		source string
		format homefile.Format
	}{
		{name: "JSON", value: ".config/app/config=templates/config.json", path: ".config/app/config", source: filepath.Clean("templates/config.json"), format: homefile.FormatJSON},
		{name: "YAML", value: ".config/app/config=templates/config.yaml", path: ".config/app/config", source: filepath.Clean("templates/config.yaml"), format: homefile.FormatYAML},
		{name: "YML case insensitive", value: ".config/app/config=templates/config.YML", path: ".config/app/config", source: filepath.Clean("templates/config.YML"), format: homefile.FormatYAML},
		{name: "TOML", value: ".config/app/config=templates/config.toml", path: ".config/app/config", source: filepath.Clean("templates/config.toml"), format: homefile.FormatTOML},
		{name: "extensionless JSON", value: ".config/app/config=templates/config", path: ".config/app/config", source: filepath.Clean("templates/config"), format: homefile.FormatJSON},
		{name: "parent source", value: ".config/app/config=../shared/config.json", path: ".config/app/config", source: filepath.Clean("../shared/config.json"), format: homefile.FormatJSON},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := homefile.Parse(tt.value)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if spec.Path != tt.path || spec.Source != tt.source || spec.Kind != homefile.KindTemplate || spec.Format != tt.format {
				t.Fatalf("Spec = %#v", spec)
			}
		})
	}
}

func TestParseAcceptsAbsoluteTemplateSource(t *testing.T) {
	source := filepath.Join(t.TempDir(), "config.toml")
	spec, err := homefile.Parse(".config/app/config=" + source)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if spec.Source != filepath.Clean(source) || spec.Format != homefile.FormatTOML || spec.Kind != homefile.KindTemplate {
		t.Fatalf("Spec = %#v", spec)
	}
}

func TestParseRejectsUnknownTemplateExtension(t *testing.T) {
	if _, err := homefile.Parse(".config/app/config=templates/config.ini"); err == nil {
		t.Fatal("Parse() error = nil")
	}
}

func TestParseRejectsAmbiguousTemplateSources(t *testing.T) {
	for _, value := range []string{
		".hogehoge=~/config.json",
		`.hogehoge=~\config.json`,
		".hogehoge=Bearer envvault://app/config.json",
		".hogehoge=${envvault://app/config}.json",
	} {
		t.Run(value, func(t *testing.T) {
			if _, err := homefile.Parse(value); err == nil {
				t.Fatalf("Parse(%q) error = nil", value)
			}
		})
	}
}

func TestParseRejectsUnsafeOrAmbiguousValues(t *testing.T) {
	absolute := filepath.Join(string(os.PathSeparator), "tmp", "secret")
	tests := []string{
		"=envvault://app/config",
		"../template.json",
		"~/.hogehoge",
		".=envvault://app/config",
		"../secret=envvault://app/config",
		`..\secret=envvault://app/config`,
		"safe/../secret=envvault://app/config",
		"safe/./secret=envvault://app/config",
		"safe//secret=envvault://app/config",
		`C:\secret=envvault://app/config`,
		`\\server\share\secret=envvault://app/config`,
		filepath.Join("~", ".hogehoge") + "=envvault://app/config",
		absolute + "=envvault://app/config",
		".hogehoge=" + filepath.Join("~", ".hogehoge"),
		".hogehoge=envvault://app/config?ttl=1h",
		".hogehoge=envvault://app/config/base-url",
		".hogehoge=envvault://app/config/token",
	}
	for _, value := range tests {
		t.Run(strings.ReplaceAll(value, string(os.PathSeparator), "_"), func(t *testing.T) {
			_, err := homefile.Parse(value)
			if err == nil {
				t.Fatalf("Parse(%q) error = nil", value)
			}
		})
	}
}

func TestParseAllRejectsDuplicateDestinations(t *testing.T) {
	_, err := homefile.ParseAll([]string{
		".hogehoge=envvault://first",
		".hogehoge=envvault://second",
	})
	if err == nil {
		t.Fatal("ParseAll() error = nil")
	}
}

func TestParseAllRejectsAncestorDestinationCollision(t *testing.T) {
	_, err := homefile.ParseAll([]string{
		".config/app",
		".config/app/token=envvault://second",
	})
	if err == nil {
		t.Fatal("ParseAll() error = nil")
	}
}

func TestPrepareRendersMappedJSONTemplatesWithoutChangingSources(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	sourceDir := filepath.Join(t.TempDir(), "project")
	templatePath := filepath.Join(sourceDir, "templates", "config.json")
	if err := os.MkdirAll(filepath.Dir(templatePath), 0o700); err != nil {
		t.Fatalf("MkdirAll(template parent) error = %v", err)
	}
	template := []byte(`{
  "endpoint": "https://api.example.test",
  "token": "envvault://hogehoge/auth",
  "envvault://literal-key": "kept",
  "nested": {"password": "envvault://database/password"},
  "values": ["envvault://hogehoge/auth", true, null, 1.25]
}`)
	if err := os.WriteFile(templatePath, template, 0o600); err != nil {
		t.Fatalf("WriteFile(template) error = %v", err)
	}
	secondTemplatePath := filepath.Join(sourceDir, "templates", "second.json")
	secondTemplate := []byte(`{"token":"envvault://hogehoge/auth"}`)
	if err := os.WriteFile(secondTemplatePath, secondTemplate, 0o600); err != nil {
		t.Fatalf("WriteFile(second template) error = %v", err)
	}
	secrets := &countingStore{store: keyring.NewMemoryStore()}
	const token = "quote=\" backslash=\\ newline=\n"
	if err := secrets.Put(context.Background(), keyring.CredentialValue("hogehoge/auth"), []byte(token)); err != nil {
		t.Fatalf("Put(token) error = %v", err)
	}
	const jsonLookingSecret = `{"admin":true}`
	if err := secrets.Put(context.Background(), keyring.CredentialValue("database/password"), []byte(jsonLookingSecret)); err != nil {
		t.Fatalf("Put(password) error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{
		".config/hogehoge/config.json=templates/config.json",
		".config/hogehoge/second.json=templates/second.json",
	})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}

	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir:  cacheDir,
		SourceDir: sourceDir,
		Specs:     specs,
		Secrets:   secrets,
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	output, err := os.ReadFile(filepath.Join(workspace.HomeDir(), ".config", "hogehoge", "config.json"))
	if err != nil {
		t.Fatalf("ReadFile(output) error = %v", err)
	}
	if !bytes.HasSuffix(output, []byte("\n")) {
		t.Fatalf("output does not end in newline: %q", output)
	}
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.UseNumber()
	var rendered map[string]any
	if err := decoder.Decode(&rendered); err != nil {
		t.Fatalf("Decode(output) error = %v", err)
	}
	if rendered["endpoint"] != "https://api.example.test" || rendered["token"] != token {
		t.Fatalf("rendered top-level values = %#v", rendered)
	}
	if rendered["envvault://literal-key"] != "kept" {
		t.Fatalf("JSON object key was changed: %#v", rendered)
	}
	nested, ok := rendered["nested"].(map[string]any)
	if !ok || nested["password"] != jsonLookingSecret {
		t.Fatalf("rendered nested values = %#v", rendered["nested"])
	}
	values, ok := rendered["values"].([]any)
	if !ok || len(values) != 4 || values[0] != token || values[1] != true || values[2] != nil || values[3] != json.Number("1.25") {
		t.Fatalf("rendered array = %#v", rendered["values"])
	}
	if secrets.gets["hogehoge/auth"] != 1 {
		t.Fatalf("token keyring reads = %d, want 1", secrets.gets["hogehoge/auth"])
	}
	after, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("ReadFile(original template) error = %v", err)
	}
	if !bytes.Equal(after, template) {
		t.Fatalf("original template changed:\n%s", after)
	}
	if bytes.Contains(after, []byte(token)) || bytes.Contains(after, []byte(jsonLookingSecret)) {
		t.Fatal("original template contains resolved secrets")
	}
	if runtime.GOOS != "windows" {
		assertMode(t, filepath.Join(workspace.HomeDir(), ".config", "hogehoge", "config.json"), 0o600)
	}
	secondOutput, err := os.ReadFile(filepath.Join(workspace.HomeDir(), ".config", "hogehoge", "second.json"))
	if err != nil {
		t.Fatalf("ReadFile(second output) error = %v", err)
	}
	if !bytes.Contains(secondOutput, []byte(`"token": "quote=\" backslash=\\ newline=\n"`)) {
		t.Fatalf("second output did not safely render token: %q", secondOutput)
	}
	secondAfter, err := os.ReadFile(secondTemplatePath)
	if err != nil {
		t.Fatalf("ReadFile(second template) error = %v", err)
	}
	if !bytes.Equal(secondAfter, secondTemplate) {
		t.Fatal("second original template changed")
	}
}

func TestPrepareAllowsJSONTemplateWithoutReferences(t *testing.T) {
	sourceDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(sourceDir, ".hogehoge"), []byte(`{"enabled":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile(template) error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{".hogehoge"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir:  t.TempDir(),
		SourceDir: sourceDir,
		Specs:     specs,
		Secrets:   keyring.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	output, err := os.ReadFile(filepath.Join(workspace.HomeDir(), ".hogehoge"))
	if err != nil {
		t.Fatalf("ReadFile(output) error = %v", err)
	}
	if string(output) != "{\n  \"enabled\": true\n}\n" {
		t.Fatalf("output = %q", output)
	}
}

func TestPrepareRendersYAMLTemplateAndKeepsResolvedScalarsAsStrings(t *testing.T) {
	sourceDir := t.TempDir()
	templatePath := filepath.Join(sourceDir, "templates", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(templatePath), 0o700); err != nil {
		t.Fatalf("MkdirAll(template parent) error = %v", err)
	}
	template := []byte(`endpoint: https://api.example.test
enabled: true
token: envvault://app/auth
boolean-looking: envvault://value/boolean
date-looking: envvault://value/date
nested:
  - envvault://app/auth
"envvault://literal-key": kept
`)
	if err := os.WriteFile(templatePath, template, 0o600); err != nil {
		t.Fatalf("WriteFile(template) error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{".config/app/config.yaml=templates/config.yaml"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir:  t.TempDir(),
		SourceDir: sourceDir,
		Specs:     specs,
		Secrets: memoryStore(t, map[string]string{
			"app/auth":      "token-secret",
			"value/boolean": "false",
			"value/date":    "2026-07-10",
		}),
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	output, err := os.ReadFile(filepath.Join(workspace.HomeDir(), ".config", "app", "config.yaml"))
	if err != nil {
		t.Fatalf("ReadFile(output) error = %v", err)
	}
	if !bytes.HasSuffix(output, []byte("\n")) {
		t.Fatalf("output does not end in newline: %q", output)
	}
	var rendered map[string]any
	if err := yaml.Unmarshal(output, &rendered); err != nil {
		t.Fatalf("Unmarshal(output) error = %v", err)
	}
	if rendered["endpoint"] != "https://api.example.test" || rendered["enabled"] != true || rendered["token"] != "token-secret" {
		t.Fatalf("rendered values = %#v", rendered)
	}
	if value, ok := rendered["boolean-looking"].(string); !ok || value != "false" {
		t.Fatalf("boolean-looking = %#v (%T), want string", rendered["boolean-looking"], rendered["boolean-looking"])
	}
	if value, ok := rendered["date-looking"].(string); !ok || value != "2026-07-10" {
		t.Fatalf("date-looking = %#v (%T), want string", rendered["date-looking"], rendered["date-looking"])
	}
	values, ok := rendered["nested"].([]any)
	if !ok || len(values) != 1 || values[0] != "token-secret" {
		t.Fatalf("nested = %#v", rendered["nested"])
	}
	if rendered["envvault://literal-key"] != "kept" {
		t.Fatalf("YAML mapping key was changed: %#v", rendered)
	}
	after, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("ReadFile(template) error = %v", err)
	}
	if !bytes.Equal(after, template) {
		t.Fatal("YAML template source changed")
	}
}

func TestPrepareRendersTOMLTemplateAndKeepsResolvedScalarsAsStrings(t *testing.T) {
	sourceDir := t.TempDir()
	templatePath := filepath.Join(sourceDir, "templates", "config.toml")
	if err := os.MkdirAll(filepath.Dir(templatePath), 0o700); err != nil {
		t.Fatalf("MkdirAll(template parent) error = %v", err)
	}
	template := []byte(`endpoint = "https://api.example.test"
enabled = true
token = "envvault://app/auth"
boolean-looking = "envvault://value/boolean"
date-looking = "envvault://value/date"
native-date = 2026-07-10
"envvault://literal-key" = "kept"
tokens = ["envvault://app/auth", "kept"]

[nested]
password = "envvault://app/password"

[[servers]]
name = "primary"
token = "envvault://app/auth"

[[servers]]
name = "secondary"
token = "envvault://app/password"
`)
	if err := os.WriteFile(templatePath, template, 0o600); err != nil {
		t.Fatalf("WriteFile(template) error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{".config/app/config.toml=templates/config.toml"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir:  t.TempDir(),
		SourceDir: sourceDir,
		Specs:     specs,
		Secrets: memoryStore(t, map[string]string{
			"app/auth":      "token-secret",
			"app/password":  `quote=" and slash=\`,
			"value/boolean": "false",
			"value/date":    "2026-07-10",
		}),
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	output, err := os.ReadFile(filepath.Join(workspace.HomeDir(), ".config", "app", "config.toml"))
	if err != nil {
		t.Fatalf("ReadFile(output) error = %v", err)
	}
	if !bytes.HasSuffix(output, []byte("\n")) {
		t.Fatalf("output does not end in newline: %q", output)
	}
	var rendered map[string]any
	if err := toml.Unmarshal(output, &rendered); err != nil {
		t.Fatalf("Unmarshal(output) error = %v", err)
	}
	if rendered["endpoint"] != "https://api.example.test" || rendered["enabled"] != true || rendered["token"] != "token-secret" {
		t.Fatalf("rendered values = %#v", rendered)
	}
	if value, ok := rendered["boolean-looking"].(string); !ok || value != "false" {
		t.Fatalf("boolean-looking = %#v (%T), want string", rendered["boolean-looking"], rendered["boolean-looking"])
	}
	if value, ok := rendered["date-looking"].(string); !ok || value != "2026-07-10" {
		t.Fatalf("date-looking = %#v (%T), want string", rendered["date-looking"], rendered["date-looking"])
	}
	if value, ok := rendered["native-date"].(toml.LocalDate); !ok || value.String() != "2026-07-10" {
		t.Fatalf("native-date = %#v (%T), want TOML local date", rendered["native-date"], rendered["native-date"])
	}
	if rendered["envvault://literal-key"] != "kept" {
		t.Fatalf("TOML key was changed: %#v", rendered)
	}
	tokens, ok := rendered["tokens"].([]any)
	if !ok || len(tokens) != 2 || tokens[0] != "token-secret" || tokens[1] != "kept" {
		t.Fatalf("tokens = %#v", rendered["tokens"])
	}
	nested, ok := rendered["nested"].(map[string]any)
	if !ok || nested["password"] != `quote=" and slash=\` {
		t.Fatalf("nested = %#v", rendered["nested"])
	}
	servers, ok := rendered["servers"].([]any)
	if !ok || len(servers) != 2 {
		t.Fatalf("servers = %#v", rendered["servers"])
	}
	primary, primaryOK := servers[0].(map[string]any)
	secondary, secondaryOK := servers[1].(map[string]any)
	if !primaryOK || !secondaryOK ||
		primary["name"] != "primary" || primary["token"] != "token-secret" ||
		secondary["name"] != "secondary" || secondary["token"] != `quote=" and slash=\` {
		t.Fatalf("servers = %#v", servers)
	}
	after, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("ReadFile(template) error = %v", err)
	}
	if !bytes.Equal(after, template) {
		t.Fatal("TOML template source changed")
	}
}

func TestPrepareRejectsUnsafeJSONTemplatesAndCleansWorkspace(t *testing.T) {
	deep := strings.Repeat("[", 130) + `"envvault://good"` + strings.Repeat("]", 130)
	tests := []struct {
		name        string
		body        []byte
		credentials map[string][]byte
	}{
		{name: "invalid JSON", body: []byte(`{"token":`)},
		{name: "duplicate key", body: []byte(`{"token":"envvault://good","token":"other"}`)},
		{name: "trailing document", body: []byte(`{"token":"envvault://good"} {}`), credentials: map[string][]byte{"good": []byte("secret-canary")}},
		{name: "embedded reference", body: []byte(`{"a":"envvault://good","z":"Bearer envvault://good"}`), credentials: map[string][]byte{"good": []byte("secret-canary")}},
		{name: "malformed reference", body: []byte(`{"token":"envvault://good?scope=admin"}`)},
		{name: "proxy part", body: []byte(`{"token":"envvault://proxy/token"}`)},
		{name: "missing credential", body: []byte(`{"token":"envvault://missing"}`)},
		{name: "invalid UTF-8 JSON", body: []byte{'{', '"', 'v', '"', ':', '"', 0xff, '"', '}'}},
		{name: "invalid UTF-8 credential", body: []byte(`{"token":"envvault://binary"}`), credentials: map[string][]byte{"binary": []byte{0xff, 0xfe}}},
		{name: "excessive depth", body: []byte(deep), credentials: map[string][]byte{"good": []byte("secret-canary")}},
		{name: "oversized", body: bytes.Repeat([]byte(" "), (4<<20)+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourceDir := t.TempDir()
			templatePath := filepath.Join(sourceDir, ".hogehoge")
			if err := os.WriteFile(templatePath, tt.body, 0o600); err != nil {
				t.Fatalf("WriteFile(template) error = %v", err)
			}
			store := keyring.NewMemoryStore()
			for name, value := range tt.credentials {
				if err := store.Put(context.Background(), keyring.CredentialValue(name), value); err != nil {
					t.Fatalf("Put(%s) error = %v", name, err)
				}
			}
			specs, err := homefile.ParseAll([]string{".hogehoge"})
			if err != nil {
				t.Fatalf("ParseAll() error = %v", err)
			}
			cacheDir := filepath.Join(t.TempDir(), "cache")
			_, err = homefile.Prepare(context.Background(), homefile.Options{
				CacheDir:  cacheDir,
				SourceDir: sourceDir,
				Specs:     specs,
				Secrets:   store,
			})
			if err == nil {
				t.Fatal("Prepare() error = nil")
			}
			if strings.Contains(err.Error(), "secret-canary") || strings.Contains(err.Error(), "scope=admin") {
				t.Fatalf("error leaked template or credential content: %v", err)
			}
			entries, readErr := os.ReadDir(filepath.Join(cacheDir, "tmp"))
			if readErr != nil {
				t.Fatalf("ReadDir(tmp) error = %v", readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("partial workspace remains: %#v", entries)
			}
			after, readErr := os.ReadFile(templatePath)
			if readErr != nil {
				t.Fatalf("ReadFile(template) error = %v", readErr)
			}
			if !bytes.Equal(after, tt.body) {
				t.Fatal("original template changed after failure")
			}
		})
	}
}

func TestPrepareRejectsUnsafeYAMLTemplates(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed", body: "token: [\n"},
		{name: "duplicate key", body: "token: envvault://good\ntoken: other\n"},
		{name: "multiple documents", body: "token: envvault://good\n---\ntoken: other\n"},
		{name: "anchor and alias", body: "shared: &shared envvault://good\ncopy: *shared\n"},
		{name: "merge key", body: "merged:\n  <<: {token: envvault://good}\n"},
		{name: "non-string mapping key", body: "true: value\n"},
		{name: "embedded reference", body: "token: Bearer envvault://good\n"},
		{name: "proxy part", body: "token: envvault://proxy/token\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertTemplateRejected(t, ".yaml", []byte(tt.body), map[string]string{"good": "secret-canary"})
		})
	}
}

func TestPrepareRejectsExcessivelyDeepYAMLTemplate(t *testing.T) {
	body := strings.Repeat("[", 130) + "envvault://good" + strings.Repeat("]", 130) + "\n"
	err := assertTemplateRejected(t, ".yaml", []byte(body), map[string]string{"good": "secret-canary"})
	if !strings.Contains(err.Error(), "nesting exceeds 128 levels") {
		t.Fatalf("Prepare() error = %v, want YAML nesting limit", err)
	}
}

func TestPrepareRejectsUnsafeTOMLTemplates(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed", body: "token =\n"},
		{name: "duplicate key", body: "token = \"envvault://good\"\ntoken = \"other\"\n"},
		{name: "embedded reference", body: "token = \"Bearer envvault://good\"\n"},
		{name: "proxy part", body: "token = \"envvault://proxy/token\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertTemplateRejected(t, ".toml", []byte(tt.body), map[string]string{"good": "secret-canary"})
		})
	}
}

func TestPrepareResolvesParentRelativeAndAbsoluteTemplateSources(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "project", "subdirectory")
	if err := os.MkdirAll(sourceDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(source directory) error = %v", err)
	}
	parentSource := filepath.Join(root, "project", "shared", "config.json")
	if err := os.MkdirAll(filepath.Dir(parentSource), 0o700); err != nil {
		t.Fatalf("MkdirAll(parent source) error = %v", err)
	}
	if err := os.WriteFile(parentSource, []byte(`{"source":"parent"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(parent source) error = %v", err)
	}
	absoluteSource := filepath.Join(root, "absolute.json")
	if err := os.WriteFile(absoluteSource, []byte(`{"source":"absolute"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(absolute source) error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{
		"parent.json=../shared/config.json",
		"absolute.json=" + absoluteSource,
	})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir:  t.TempDir(),
		SourceDir: sourceDir,
		Specs:     specs,
		Secrets:   keyring.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	for name, want := range map[string]string{"parent.json": "parent", "absolute.json": "absolute"} {
		output, err := os.ReadFile(filepath.Join(workspace.HomeDir(), name))
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", name, err)
		}
		var rendered map[string]string
		if err := json.Unmarshal(output, &rendered); err != nil {
			t.Fatalf("Unmarshal(%s) error = %v", name, err)
		}
		if rendered["source"] != want {
			t.Fatalf("%s source = %q, want %q", name, rendered["source"], want)
		}
	}
}

func TestPrepareAbsoluteTemplateSourceDoesNotRequireSourceDir(t *testing.T) {
	source := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(source, []byte(`{"enabled":true}`), 0o600); err != nil {
		t.Fatalf("WriteFile(source) error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{".hogehoge=" + source})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir: t.TempDir(),
		Specs:    specs,
		Secrets:  keyring.NewMemoryStore(),
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	if _, err := os.Stat(filepath.Join(workspace.HomeDir(), ".hogehoge")); err != nil {
		t.Fatalf("Stat(output) error = %v", err)
	}
}

func TestPrepareRequiresAbsoluteSourceDirForRelativeTemplate(t *testing.T) {
	specs, err := homefile.ParseAll([]string{".hogehoge"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	for _, tt := range []struct {
		name      string
		sourceDir string
	}{
		{name: "empty"},
		{name: "relative", sourceDir: "relative"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := filepath.Join(t.TempDir(), "cache")
			_, err := homefile.Prepare(context.Background(), homefile.Options{
				CacheDir:  cacheDir,
				SourceDir: tt.sourceDir,
				Specs:     specs,
				Secrets:   keyring.NewMemoryStore(),
			})
			if err == nil {
				t.Fatal("Prepare() error = nil")
			}
			if _, statErr := os.Stat(filepath.Join(cacheDir, "tmp")); !os.IsNotExist(statErr) {
				t.Fatalf("Prepare created workspace before validating SourceDir: %v", statErr)
			}
		})
	}
}

func TestPrepareRejectsMissingOrNonRegularTemplateSource(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{name: "missing", setup: func(*testing.T, string) {}},
		{name: "directory", setup: func(t *testing.T, sourceDir string) {
			if err := os.Mkdir(filepath.Join(sourceDir, ".hogehoge"), 0o700); err != nil {
				t.Fatalf("Mkdir(template) error = %v", err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourceDir := t.TempDir()
			tt.setup(t, sourceDir)
			specs, err := homefile.ParseAll([]string{".hogehoge"})
			if err != nil {
				t.Fatalf("ParseAll() error = %v", err)
			}
			_, err = homefile.Prepare(context.Background(), homefile.Options{
				CacheDir:  t.TempDir(),
				SourceDir: sourceDir,
				Specs:     specs,
				Secrets:   keyring.NewMemoryStore(),
			})
			if err == nil {
				t.Fatal("Prepare() error = nil")
			}
		})
	}
}

func TestPrepareRejectsTemplateSourceSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks requires additional privileges on some Windows hosts")
	}
	sourceDir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{"token":"envvault://good"}`), 0o600); err != nil {
		t.Fatalf("WriteFile(outside) error = %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(sourceDir, ".hogehoge")); err != nil {
		t.Fatalf("Symlink(template) error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{".hogehoge"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	_, err = homefile.Prepare(context.Background(), homefile.Options{
		CacheDir:  t.TempDir(),
		SourceDir: sourceDir,
		Specs:     specs,
		Secrets:   memoryStore(t, map[string]string{"good": "secret-canary"}),
	})
	if err == nil {
		t.Fatal("Prepare() error = nil")
	}
	if strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("error leaked secret: %v", err)
	}
}

func TestPrepareRejectsSocketTemplateSourceWithoutLeavingWorkspace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-domain socket fixture is unavailable on Windows")
	}
	sourceDir, err := os.MkdirTemp("", "evhf-")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sourceDir) })
	source := filepath.Join(sourceDir, ".hogehoge")
	listener, err := net.Listen("unix", source)
	if err != nil {
		t.Fatalf("Listen(unix) error = %v", err)
	}
	defer listener.Close()
	specs, err := homefile.ParseAll([]string{".hogehoge"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	cacheDir := filepath.Join(t.TempDir(), "cache")
	_, err = homefile.Prepare(context.Background(), homefile.Options{
		CacheDir:  cacheDir,
		SourceDir: sourceDir,
		Specs:     specs,
		Secrets:   keyring.NewMemoryStore(),
	})
	if err == nil {
		t.Fatal("Prepare() error = nil")
	}
	entries, readErr := os.ReadDir(filepath.Join(cacheDir, "tmp"))
	if readErr != nil {
		t.Fatalf("ReadDir(tmp) error = %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("partial workspace remains: %#v", entries)
	}
}

func TestPrepareCreatesPrivateIsolatedHomeAndCleansIt(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	originalHome := filepath.Join(t.TempDir(), "real-home")
	if err := os.MkdirAll(originalHome, 0o700); err != nil {
		t.Fatalf("MkdirAll(original home) error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{".hogehoge=envvault://app/config"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("app/config"), []byte(`{"token":"secret-canary"}`)); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir: cacheDir,
		Specs:    specs,
		Secrets:  secrets,
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	home := workspace.HomeDir()
	env := map[string]string{"HOME": originalHome}
	workspace.ApplyEnvironment(env)
	if env["HOME"] != home {
		t.Fatalf("HOME = %q, want %q", env["HOME"], home)
	}
	if env["XDG_CONFIG_HOME"] != filepath.Join(home, ".config") {
		t.Fatalf("XDG_CONFIG_HOME = %q", env["XDG_CONFIG_HOME"])
	}
	if env["XDG_STATE_HOME"] != filepath.Join(home, ".local", "state") {
		t.Fatalf("XDG_STATE_HOME = %q", env["XDG_STATE_HOME"])
	}
	body, err := os.ReadFile(filepath.Join(home, ".hogehoge"))
	if err != nil {
		t.Fatalf("ReadFile(home file) error = %v", err)
	}
	if string(body) != `{"token":"secret-canary"}` {
		t.Fatalf("home file = %q", body)
	}
	if _, err := os.Stat(filepath.Join(originalHome, ".hogehoge")); !os.IsNotExist(err) {
		t.Fatalf("original home was modified: %v", err)
	}
	active, err := homefile.IsActive(filepath.Dir(home))
	if err != nil {
		t.Fatalf("IsActive() error = %v", err)
	}
	if !active {
		t.Fatal("IsActive() = false, want true")
	}
	if runtime.GOOS != "windows" {
		assertMode(t, home, 0o700)
		assertMode(t, filepath.Join(home, ".hogehoge"), 0o600)
	}
	if err := workspace.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := workspace.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatalf("isolated home still exists: %v", err)
	}
}

func TestPrepareWritesRawCredentialBytesExactly(t *testing.T) {
	raw := []byte{0x00, 0xff, 't', 'o', 'k', 'e', 'n', 0x00, 0xfe, '\n'}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("app/binary"), raw); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{".credential=envvault://app/binary"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir: t.TempDir(),
		Specs:    specs,
		Secrets:  secrets,
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	output, err := os.ReadFile(filepath.Join(workspace.HomeDir(), ".credential"))
	if err != nil {
		t.Fatalf("ReadFile(raw credential) error = %v", err)
	}
	if !bytes.Equal(output, raw) {
		t.Fatalf("raw credential = %v, want %v", output, raw)
	}
}

func TestPrepareRemovesPartialWorkspaceWhenResolutionFails(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	specs, err := homefile.ParseAll([]string{
		"first=envvault://first",
		"second=envvault://second",
	})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	secrets := keyring.NewMemoryStore()
	if err := secrets.Put(context.Background(), keyring.CredentialValue("first"), []byte("secret-canary")); err != nil {
		t.Fatalf("Put() error = %v", err)
	}

	_, err = homefile.Prepare(context.Background(), homefile.Options{
		CacheDir: cacheDir,
		Specs:    specs,
		Secrets:  secrets,
	})
	if err == nil {
		t.Fatal("Prepare() error = nil")
	}
	if strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("error leaked secret: %v", err)
	}
	entries, readErr := os.ReadDir(filepath.Join(cacheDir, "tmp"))
	if readErr != nil {
		t.Fatalf("ReadDir(tmp) error = %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("partial workspaces remain: %#v", entries)
	}
}

func TestPrepareRevalidatesProgrammaticSpecsBeforeCreatingWorkspace(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	_, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir: cacheDir,
		Specs: []homefile.Spec{{
			Path:      "../../outside",
			Reference: envref.Reference{Profile: "app/config"},
		}},
		Secrets: memoryStore(t, map[string]string{"app/config": "secret-canary"}),
	})
	if err == nil {
		t.Fatal("Prepare() error = nil")
	}
	if _, statErr := os.Stat(filepath.Join(cacheDir, "tmp")); !os.IsNotExist(statErr) {
		t.Fatalf("Prepare created workspace before validating specs: %v", statErr)
	}
}

func TestApplyEnvironmentSetsWindowsHomeVariables(t *testing.T) {
	specs, err := homefile.ParseAll([]string{"credential=envvault://app/config"})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	workspace, err := homefile.Prepare(context.Background(), homefile.Options{
		CacheDir: t.TempDir(),
		Specs:    specs,
		Secrets:  memoryStore(t, map[string]string{"app/config": "secret"}),
		GOOS:     "windows",
	})
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	defer workspace.Close()
	env := map[string]string{
		"home":              "real-home",
		"UserProfile":       "real-profile",
		"appdata":           "real-appdata",
		"localappdata":      "real-localappdata",
		"xdg_config_home":   "real-config",
		"Xdg_Data_Home":     "real-data",
		"xdg_cache_home":    "real-cache",
		"xdg_state_home":    "real-state",
		"homedrive":         "Z:",
		"homepath":          `\Users\real`,
		"UNRELATED_SETTING": "preserved",
	}
	workspace.ApplyEnvironment(env)
	if env["HOME"] != workspace.HomeDir() {
		t.Fatalf("HOME = %q", env["HOME"])
	}
	if env["USERPROFILE"] != workspace.HomeDir() {
		t.Fatalf("USERPROFILE = %q", env["USERPROFILE"])
	}
	if env["APPDATA"] == "" || env["LOCALAPPDATA"] == "" {
		t.Fatalf("windows home env = %#v", env)
	}
	for _, key := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME"} {
		if got := countKeyFold(env, key); got != 1 {
			t.Fatalf("case-insensitive key count for %s = %d; env=%#v", key, got, env)
		}
	}
	if _, exists := env["homedrive"]; exists {
		t.Fatalf("lowercase inherited HOMEDRIVE remains: %#v", env)
	}
	if env["UNRELATED_SETTING"] != "preserved" {
		t.Fatalf("unrelated environment changed: %#v", env)
	}
}

func assertTemplateRejected(t *testing.T, extension string, body []byte, credentials map[string]string) error {
	t.Helper()
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "template"+extension)
	if err := os.WriteFile(source, body, 0o600); err != nil {
		t.Fatalf("WriteFile(template) error = %v", err)
	}
	specs, err := homefile.ParseAll([]string{".config/app/config=template" + extension})
	if err != nil {
		t.Fatalf("ParseAll() error = %v", err)
	}
	cacheDir := filepath.Join(t.TempDir(), "cache")
	_, err = homefile.Prepare(context.Background(), homefile.Options{
		CacheDir:  cacheDir,
		SourceDir: sourceDir,
		Specs:     specs,
		Secrets:   memoryStore(t, credentials),
	})
	if err == nil {
		t.Fatal("Prepare() error = nil")
	}
	if strings.Contains(err.Error(), "secret-canary") {
		t.Fatalf("error leaked credential content: %v", err)
	}
	after, readErr := os.ReadFile(source)
	if readErr != nil {
		t.Fatalf("ReadFile(template) error = %v", readErr)
	}
	if !bytes.Equal(after, body) {
		t.Fatal("template source changed after failure")
	}
	entries, readErr := os.ReadDir(filepath.Join(cacheDir, "tmp"))
	if readErr != nil {
		t.Fatalf("ReadDir(tmp) error = %v", readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("partial workspace remains: %#v", entries)
	}
	return err
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("mode(%s) = %o, want %o", path, got, want)
	}
}

func memoryStore(t *testing.T, values map[string]string) keyring.Store {
	t.Helper()
	store := keyring.NewMemoryStore()
	for name, value := range values {
		if err := store.Put(context.Background(), keyring.CredentialValue(name), []byte(value)); err != nil {
			t.Fatalf("Put(%s) error = %v", name, err)
		}
	}
	return store
}

func countKeyFold(env map[string]string, want string) int {
	count := 0
	for key := range env {
		if strings.EqualFold(key, want) {
			count++
		}
	}
	return count
}

type countingStore struct {
	store *keyring.MemoryStore
	gets  map[string]int
}

func (s *countingStore) Get(ctx context.Context, key keyring.Key) ([]byte, error) {
	if s.gets == nil {
		s.gets = map[string]int{}
	}
	name := string(key)
	const prefix = "envvault/credential/"
	const suffix = "/value"
	name = strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	s.gets[name]++
	return s.store.Get(ctx, key)
}

func (s *countingStore) Put(ctx context.Context, key keyring.Key, value []byte) error {
	return s.store.Put(ctx, key, value)
}

func (s *countingStore) Delete(ctx context.Context, key keyring.Key) error {
	return s.store.Delete(ctx, key)
}
