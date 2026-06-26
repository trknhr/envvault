package talos_test

import (
	"regexp"
	"strings"
	"testing"

	runtimetalos "github.com/trknhr/envvault/internal/runtime/talos"
)

func TestDefaultReleaseManifestPinsTalosArtifacts(t *testing.T) {
	manifest, err := runtimetalos.DefaultReleaseManifest()
	if err != nil {
		t.Fatalf("DefaultReleaseManifest() error = %v", err)
	}

	if manifest.Version != "v26.2.0" {
		t.Fatalf("Version = %q, want v26.2.0", manifest.Version)
	}
	if manifest.SourceURL != "https://github.com/ory/talos/releases/tag/v26.2.0" {
		t.Fatalf("SourceURL = %q", manifest.SourceURL)
	}
	assertChecksumSource(t, manifest.Checksums)

	want := map[runtimetalos.Platform]struct {
		url    string
		sha256 string
	}{
		{OS: "darwin", Arch: "amd64"}: {
			url:    "https://github.com/ory/talos/releases/download/v26.2.0/talos_26.2.0-macOS_sqlite_64bit.tar.gz",
			sha256: "36813381052d18661eb5996ac872a6fae2eb6146e9213143aa10036ed094fc7d",
		},
		{OS: "darwin", Arch: "arm64"}: {
			url:    "https://github.com/ory/talos/releases/download/v26.2.0/talos_26.2.0-macOS_sqlite_arm64.tar.gz",
			sha256: "fb7318daee3c7a0e00496e57569991b4f5023029b2b4b2ba7f90212f1f460c9e",
		},
		{OS: "linux", Arch: "amd64"}: {
			url:    "https://github.com/ory/talos/releases/download/v26.2.0/talos_26.2.0-linux_sqlite_64bit.tar.gz",
			sha256: "9a659029d0ffd060119288bdac3576977d560feb9c6199851b3c5d863ccd1895",
		},
		{OS: "linux", Arch: "arm64"}: {
			url:    "https://github.com/ory/talos/releases/download/v26.2.0/talos_26.2.0-linux_sqlite_arm64.tar.gz",
			sha256: "e906f418cf5641686324b080e8c6f8388de1507e103a0d1bf4091883c465cbde",
		},
		{OS: "windows", Arch: "amd64"}: {
			url:    "https://github.com/ory/talos/releases/download/v26.2.0/talos_26.2.0-windows_sqlite_64bit.zip",
			sha256: "6d63a5cddf21729e797dfbe2bb88b5e8c2437f6f68d7286fe754c18269c5c717",
		},
	}

	for platform, expected := range want {
		artifact, ok := findArtifact(manifest, platform)
		if !ok {
			t.Fatalf("manifest missing artifact for %#v", platform)
		}
		if artifact.URL != expected.url {
			t.Fatalf("%s/%s URL = %q", platform.OS, platform.Arch, artifact.URL)
		}
		if artifact.SHA256 != expected.sha256 {
			t.Fatalf("%s/%s SHA256 = %q", platform.OS, platform.Arch, artifact.SHA256)
		}
	}
}

func assertChecksumSource(t *testing.T, checksums runtimetalos.ChecksumSource) {
	t.Helper()
	if checksums.URL != "https://github.com/ory/talos/releases/download/v26.2.0/checksums.txt" {
		t.Fatalf("checksums URL = %q", checksums.URL)
	}
	if checksums.SHA256 != "90a006698489c0b1862aa4f345d7de2adcecae3249d0fdcc4ee2ed07014cbd88" {
		t.Fatalf("checksums SHA256 = %q", checksums.SHA256)
	}
	assertSHA256Hex(t, checksums.SHA256)
}

func findArtifact(manifest runtimetalos.Manifest, platform runtimetalos.Platform) (runtimetalos.Artifact, bool) {
	for _, artifact := range manifest.Artifacts {
		if artifact.OS == platform.OS && artifact.Arch == platform.Arch {
			return artifact, true
		}
	}
	return runtimetalos.Artifact{}, false
}

func assertSHA256Hex(t *testing.T, value string) {
	t.Helper()
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(value) {
		t.Fatalf("SHA256 %q is not 64 lowercase hex characters", value)
	}
	if strings.HasPrefix(value, "sha256:") {
		t.Fatalf("SHA256 %q must not include the sha256: prefix", value)
	}
}
