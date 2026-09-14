package sandboxsession

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/envref"
	"github.com/trknhr/envvault/internal/process"
	"github.com/trknhr/envvault/internal/sandboxplugin"
)

var applicationName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
var reservedName = regexp.MustCompile(`^(?:PATH|HOME|USER|LOGNAME|SHELL|ENV|BASH_ENV|BASHOPTS|SHELLOPTS|IFS|CDPATH|TMPDIR|TMP|TEMP|TERM|TERMINFO|TERMINFO_DIRS|COLORTERM|LANG|LANGUAGE|CODEX_HOME|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|SSL_CERT_FILE|SSL_CERT_DIR|NODE_EXTRA_CA_CERTS|NODE_OPTIONS|NODE_PATH|DOCKER.*|BUILDKIT.*|BUILDX.*|LD_.*|DYLD_.*|LC_.*|GIT_.*|SSH_.*|NPM_.*|PYTHON.*|AI_.*|AGENT_INFRA_.*|ENVVAULT_TALOS_.*|ENVVAULT_PROFILE_PARENT_KEY)$`)

// ValidateEnvironment prevents selected values from controlling the trusted
// host runtime process. Values are never included in diagnostics.
func ValidateEnvironment(environment map[string]string) error {
	if len(environment) == 0 || len(environment) > 64 {
		return clerr.New(clerr.ConfigInvalid, "sandbox exec requires 1–64 application environment variables")
	}
	for name, value := range environment {
		if !applicationName.MatchString(name) || reservedName.MatchString(name) {
			return clerr.New(clerr.ConfigInvalid, "sandbox exec environment names must be uppercase application variables, not runtime controls")
		}
		if value == "" || len(value) > 16384 || strings.ContainsRune(value, 0) {
			return clerr.New(clerr.ConfigInvalid, "sandbox exec environment value is empty or invalid")
		}
	}
	return nil
}

// ReadBindings uses the usual dotenv precedence without resolving credentials.
// Files are overlaid in order, then --env overrides the selected file values.
func ReadBindings(ctx context.Context, files, assignments []string) ([]sandboxplugin.Binding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	environment, err := process.ReadEnv(process.EnvInput{EnvFiles: files, InlineEnv: assignments})
	if err != nil {
		return nil, err
	}
	if err := ValidateEnvironment(environment); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(environment))
	for name := range environment {
		names = append(names, name)
	}
	sort.Strings(names)
	bindings := []sandboxplugin.Binding{}
	index := map[string]int{}
	for _, name := range names {
		ref, recognized, err := envref.ParseValue(environment[name])
		if err != nil || !recognized || (ref.Part != envref.PartBaseURL && ref.Part != envref.PartToken) {
			return nil, clerr.New(clerr.ConfigInvalid, "sandbox exec accepts only envvault://profile/base-url and /token references; no raw values or direct credentials")
		}
		i, exists := index[ref.Profile]
		if !exists {
			i = len(bindings)
			index[ref.Profile] = i
			bindings = append(bindings, sandboxplugin.Binding{Profile: ref.Profile})
		}
		bindings[i].Outputs = append(bindings[i].Outputs, sandboxplugin.Output{
			Environment: name, Part: sandboxplugin.OutputPart(ref.Part),
		})
	}
	if err := (sandboxplugin.OpenRequest{SandboxID: "validate-bindings", Bindings: bindings}).Validate(); err != nil {
		return nil, err
	}
	return bindings, nil
}
