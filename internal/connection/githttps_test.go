package connection_test

import (
	"net/http"
	"testing"

	"github.com/trknhr/envvault/internal/connection"
)

func TestGitHTTPSReadWriteAndReferenceBoundaries(t *testing.T) {
	readPaths, _ := connection.GitHTTPSPaths("owner/repo.git", false)
	writePaths, _ := connection.GitHTTPSPaths("owner/repo", true)
	for _, test := range []struct {
		method, path, contentType string
		read, write               bool
	}{
		{"GET", "/owner/repo.git/info/refs?service=git-upload-pack", "", true, true},
		{"GET", "/owner/repo/info/refs?service=git-receive-pack", "", false, true},
		{"POST", "/owner/repo.git/git-upload-pack", "application/x-git-upload-pack-request", true, true},
		{"POST", "/owner/repo/git-receive-pack", "application/x-git-receive-pack-request", false, true},
		{"GET", "/owner/other/info/refs?service=git-upload-pack", "", false, false},
		{"GET", "/owner/repo/info/refs?service=git-upload-pack&service=git-receive-pack", "", false, false},
		{"GET", "/owner/repo/info/refs?service=git-upload-pack&bad;query", "", false, false},
		{"GET", "/owner/repo/info/refs", "", false, false},
		{"GET", "/owner/%72epo/info/refs?service=git-upload-pack", "", false, false},
		{"GET", "/owner/../owner/repo/info/refs?service=git-upload-pack", "", false, false},
		{"POST", "/owner/repo/git-upload-pack?service=git-upload-pack", "application/x-git-upload-pack-request", false, false},
		{"POST", "/owner/repo/git-upload-pack", "application/json", false, false},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			r, err := http.NewRequest(test.method, "https://github.com"+test.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Content-Type", test.contentType)
			r.SetBasicAuth("x-access-token", "envvault://github/work")
			for _, scope := range []struct {
				paths []string
				want  bool
			}{{readPaths, test.read}, {writePaths, test.write}} {
				if got := connection.GitHTTPSReference(r, "github.com", "envvault://github/work", []string{"GET", "POST"}, scope.paths); got != scope.want {
					t.Fatalf("repository/service boundary: got %t, want %t", got, scope.want)
				}
			}
			if !connection.HasCredentialReference(r) {
				t.Fatal("Basic reference was not recognized")
			}
			r.SetBasicAuth("x-access-token", "raw-canary")
			if connection.GitHTTPSReference(r, "github.com", "envvault://github/work", []string{"GET", "POST"}, writePaths) {
				t.Fatal("accepted raw token")
			}
		})
	}
	for _, repository := range []string{"owner/.git", "owner/..", "owner/repo/extra", "owner/repo?x", "/repo", "owner/%72epo"} {
		if _, ok := connection.GitHTTPSPaths(repository, false); ok {
			t.Fatalf("accepted invalid repository %q", repository)
		}
	}
}
