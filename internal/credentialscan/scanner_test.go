package credentialscan_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/trknhr/envvault/internal/credentialscan"
)

func TestInspectDetectsGitleaksFindingWithoutExposingValue(t *testing.T) {
	root := t.TempDir()
	secret := syntheticGitHubToken()
	writeFile(t, filepath.Join(root, ".env"), []byte("GITHUB_TOKEN="+secret+"\n"))

	scanner := newScanner(t)
	result, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !hasFinding(result.Findings, func(finding credentialscan.Finding) bool {
		return finding.Engine == "gitleaks" && finding.Confidence == credentialscan.ConfidenceHigh
	}) {
		t.Fatalf("Inspect() findings = %#v, want high-confidence Gitleaks finding", result.Findings)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("serialized result exposed credential value")
	}
}

func TestInspectTreatsGenericGitleaksFindingAsMediumConfidence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "settings.txt"), []byte(
		"database_password = \"8ae31b4b3b3f4a6d85b6d06eac3f5f72\"\n",
	))

	scanner := newScanner(t)
	defaultResult, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{})
	if err != nil {
		t.Fatalf("Inspect(default) error = %v", err)
	}
	if hasFinding(defaultResult.Findings, isGenericGitleaksFinding) {
		t.Fatalf("Inspect(default) findings = %#v, did not want generic finding", defaultResult.Findings)
	}

	mediumResult, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{
		IncludeMedium: true,
	})
	if err != nil {
		t.Fatalf("Inspect(include medium) error = %v", err)
	}
	if !hasFinding(mediumResult.Findings, func(finding credentialscan.Finding) bool {
		return isGenericGitleaksFinding(finding) &&
			finding.Confidence == credentialscan.ConfidenceMedium
	}) {
		t.Fatalf("Inspect(include medium) findings = %#v, want medium generic finding", mediumResult.Findings)
	}
}

func TestInspectTreatsCDKS3AssetObjectKeyAsMediumConfidence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "tree.json"), []byte(`{
  "code": {
    "s3Bucket": "cdk-hnb659fds-assets-324732725304-ap-northeast-1",
    "s3Key": "e7b7ed053fe32e6acaeb18faf7a29da553ae56a45e2129f1bf99b9d9c90806b9.zip"
  },
  "environmentVariables": {
    "SLACK_SIGNING_SECRET_SECRET_ID": "/example/serverless-agent/slack-signing-secret",
    "AGENTCORE_RUNTIME_ARN": {
      "Fn::GetAtt": ["AgentCoreApplicationAgentSlackAgentRuntimeD0DDE7C4", "AgentRuntimeArn"]
    }
  }
}
`))

	scanner := newScanner(t)
	defaultResult, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{})
	if err != nil {
		t.Fatalf("Inspect(default) error = %v", err)
	}
	if hasFinding(defaultResult.Findings, isGenericGitleaksFinding) {
		t.Fatalf("Inspect(default) findings = %#v, did not want generic finding", defaultResult.Findings)
	}

	mediumResult, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{
		IncludeMedium: true,
	})
	if err != nil {
		t.Fatalf("Inspect(include medium) error = %v", err)
	}
	if !hasFinding(mediumResult.Findings, func(finding credentialscan.Finding) bool {
		return isGenericGitleaksFinding(finding) &&
			finding.Confidence == credentialscan.ConfidenceMedium
	}) {
		t.Fatalf("Inspect(include medium) findings = %#v, want medium generic finding", mediumResult.Findings)
	}
}

func TestInspectStillReportsPotentialRawS3Key(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "settings.txt"), []byte(
		"s3Key: 8ae31b4b3b3f4a6d85b6d06eac3f5f72\n",
	))

	scanner := newScanner(t)
	result, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{
		IncludeMedium: true,
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !hasFinding(result.Findings, isGenericGitleaksFinding) {
		t.Fatalf("Inspect() findings = %#v, want potential raw S3 key finding", result.Findings)
	}
}

func TestInspectFindsKnownCredentialFile(t *testing.T) {
	root := t.TempDir()
	secret := "a1b2c3d4e5f6g7h8i9j0"
	writeFile(t, filepath.Join(root, "kaggle.json"), []byte(
		"{\n  \"username\": \"example-user\",\n  \"key\": \""+secret+"\"\n}\n",
	))

	scanner := newScanner(t)
	result, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !hasFinding(result.Findings, func(finding credentialscan.Finding) bool {
		return finding.RuleID == "envvault/kaggle-api-key" &&
			finding.Confidence == credentialscan.ConfidenceHigh &&
			finding.Location == "key"
	}) {
		t.Fatalf("Inspect() findings = %#v, want Kaggle API key finding", result.Findings)
	}
}

func TestInspectDetectsPathOnlyGitleaksFinding(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "client.p12")
	writeFile(t, path, []byte{0, 1, 2})

	scanner := newScanner(t)
	result, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !hasFinding(result.Findings, func(finding credentialscan.Finding) bool {
		return finding.RuleID == "pkcs12-file" &&
			finding.Confidence == credentialscan.ConfidenceHigh &&
			finding.Path == filepath.ToSlash(path) &&
			finding.Line == 0
	}) {
		t.Fatalf("Inspect() findings = %#v, want path-only PKCS#12 finding", result.Findings)
	}
	if !slices.ContainsFunc(result.Skipped, func(skipped credentialscan.Skipped) bool {
		return skipped.Path == filepath.ToSlash(path) && skipped.Reason == "binary"
	}) {
		t.Fatalf("Inspect() skipped = %#v, want binary content skip", result.Skipped)
	}
}

func TestInspectIncludesSemanticFindingsOnlyWhenRequested(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "settings.yaml"), []byte("password: blue-horse-blue-horse\n"))

	scanner := newScanner(t)
	defaultResult, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{})
	if err != nil {
		t.Fatalf("Inspect(default) error = %v", err)
	}
	if hasFinding(defaultResult.Findings, isEnvVaultSecretField) {
		t.Fatalf("Inspect(default) findings = %#v, did not want medium finding", defaultResult.Findings)
	}

	mediumResult, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{IncludeMedium: true})
	if err != nil {
		t.Fatalf("Inspect(include medium) error = %v", err)
	}
	if !hasFinding(mediumResult.Findings, isEnvVaultSecretField) {
		t.Fatalf("Inspect(include medium) findings = %#v, want semantic finding", mediumResult.Findings)
	}
}

func TestInspectIgnoresReferencesAndPlaceholders(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".env"), []byte(strings.Join([]string{
		"API_KEY=envvault://openai/dev",
		"PASSWORD=${DATABASE_PASSWORD}",
		"TOKEN=YOUR_TOKEN",
		"CLIENT_SECRET=changeme",
		"TOKEN_URL=https://auth.example.test/token",
		"API_KEY_REF=secret-manager/key-name",
		"CREDENTIAL_PATH=/home/user/credentials.json",
		"ENVIRONMENT=development",
	}, "\n")+"\n"))

	scanner := newScanner(t)
	result, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{IncludeMedium: true})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if hasFinding(result.Findings, func(finding credentialscan.Finding) bool {
		return finding.Engine == "envvault"
	}) {
		t.Fatalf("Inspect() findings = %#v, did not want reference or placeholder findings", result.Findings)
	}
}

func TestInspectScansIgnoredAndUntrackedFiles(t *testing.T) {
	root := t.TempDir()
	secret := syntheticGitHubToken()
	writeFile(t, filepath.Join(root, ".gitignore"), []byte(".env\n"))
	writeFile(t, filepath.Join(root, ".env"), []byte("GITHUB_TOKEN="+secret+"\n"))

	scanner := newScanner(t)
	result, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !hasFinding(result.Findings, func(finding credentialscan.Finding) bool {
		return strings.HasSuffix(finding.Path, "/.env")
	}) {
		t.Fatalf("Inspect() findings = %#v, want ignored .env finding", result.Findings)
	}
}

func TestInspectDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := syntheticGitHubToken()
	target := filepath.Join(outside, "credential.env")
	writeFile(t, target, []byte("GITHUB_TOKEN="+secret+"\n"))
	link := filepath.Join(root, "credential.env")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("Symlink() unavailable: %v", err)
	}

	scanner := newScanner(t)
	result, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("Inspect() findings = %#v, want none", result.Findings)
	}
	if !slices.ContainsFunc(result.Skipped, func(skipped credentialscan.Skipped) bool {
		return strings.HasSuffix(skipped.Path, "credential.env") && skipped.Reason == "symlink"
	}) {
		t.Fatalf("Inspect() skipped = %#v, want symlink", result.Skipped)
	}
}

func TestInspectReturnsDeterministicFindingOrder(t *testing.T) {
	root := t.TempDir()
	secret := syntheticGitHubToken()
	writeFile(t, filepath.Join(root, "z.env"), []byte("GITHUB_TOKEN="+secret+"\n"))
	writeFile(t, filepath.Join(root, "a.env"), []byte("GITHUB_TOKEN="+secret+"\n"))

	scanner := newScanner(t)
	result, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if len(result.Findings) < 2 {
		t.Fatalf("Inspect() findings = %#v, want at least two", result.Findings)
	}
	for i := 1; i < len(result.Findings); i++ {
		previous := result.Findings[i-1]
		current := result.Findings[i]
		if previous.Path > current.Path {
			t.Fatalf("Inspect() findings are not sorted: %#v", result.Findings)
		}
	}
}

func TestInspectLimitsNestedDirectoryDepth(t *testing.T) {
	root := t.TempDir()
	oneLevel := filepath.Join(root, "one")
	twoLevels := filepath.Join(oneLevel, "two")
	if err := os.MkdirAll(twoLevels, 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	secret := syntheticGitHubToken()
	writeFile(t, filepath.Join(root, "root.env"), []byte("GITHUB_TOKEN="+secret+"\n"))
	writeFile(t, filepath.Join(oneLevel, "one.env"), []byte("GITHUB_TOKEN="+secret+"\n"))
	writeFile(t, filepath.Join(twoLevels, "two.env"), []byte("GITHUB_TOKEN="+secret+"\n"))

	scanner := newScanner(t)
	result, err := scanner.Inspect(context.Background(), []string{root}, credentialscan.Options{
		Depth:   1,
		Workers: 2,
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if !hasFinding(result.Findings, func(finding credentialscan.Finding) bool {
		return strings.HasSuffix(finding.Path, "/root.env")
	}) {
		t.Fatalf("Inspect() findings = %#v, want root file", result.Findings)
	}
	if !hasFinding(result.Findings, func(finding credentialscan.Finding) bool {
		return strings.HasSuffix(finding.Path, "/one/one.env")
	}) {
		t.Fatalf("Inspect() findings = %#v, want one-level file", result.Findings)
	}
	if hasFinding(result.Findings, func(finding credentialscan.Finding) bool {
		return strings.HasSuffix(finding.Path, "/two/two.env")
	}) {
		t.Fatalf("Inspect() findings = %#v, did not want two-level file", result.Findings)
	}
	if !slices.ContainsFunc(result.Skipped, func(skipped credentialscan.Skipped) bool {
		return strings.HasSuffix(skipped.Path, "/one/two") && skipped.Reason == "depth"
	}) {
		t.Fatalf("Inspect() skipped = %#v, want depth skip", result.Skipped)
	}
}

func TestInspectRejectsInvalidParallelismOptions(t *testing.T) {
	scanner := newScanner(t)
	for _, options := range []credentialscan.Options{
		{Depth: -1},
		{Workers: -1},
		{Workers: credentialscan.MaxWorkers + 1},
	} {
		if _, err := scanner.Inspect(context.Background(), []string{t.TempDir()}, options); err == nil {
			t.Fatalf("Inspect(%+v) error = nil, want error", options)
		}
	}
}

func newScanner(t *testing.T) *credentialscan.Scanner {
	t.Helper()
	scanner, err := credentialscan.New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return scanner
}

func writeFile(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}

func syntheticGitHubToken() string {
	return "ghp_" + "A1b2C3d4E5f6G7h8" + "I9j0K1l2M3n4O5p6Q7r8"
}

func hasFinding(findings []credentialscan.Finding, match func(credentialscan.Finding) bool) bool {
	return slices.ContainsFunc(findings, match)
}

func isEnvVaultSecretField(finding credentialscan.Finding) bool {
	return finding.RuleID == "envvault/secret-field" &&
		finding.Confidence == credentialscan.ConfidenceMedium
}

func isGenericGitleaksFinding(finding credentialscan.Finding) bool {
	return finding.Engine == "gitleaks" && finding.RuleID == "generic-api-key"
}
