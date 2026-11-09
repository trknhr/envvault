package connection

import (
	"net/http"
	"net/url"
	"path"
	"strings"
)

// GitHTTPSPaths builds exact smart-HTTP endpoints for one GitHub repository.
func GitHTTPSPaths(repository string, write bool) ([]string, bool) {
	repository = strings.TrimSuffix(repository, ".git")
	parts := strings.Split(repository, "/")
	if len(parts) != 2 {
		return nil, false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return nil, false
			}
		}
	}
	var paths []string
	for _, suffix := range []string{"", ".git"} {
		base := "/" + repository + suffix
		paths = append(paths, base+"/info/refs", base+"/git-upload-pack")
		if write {
			paths = append(paths, base+"/git-receive-pack")
		}
	}
	return paths, true
}

func IsGitHTTPSRequest(request *http.Request, host string) bool {
	if host != "github.com" || request.URL.RawPath != "" || path.Clean(request.URL.Path) != request.URL.Path {
		return false
	}
	for _, suffix := range []string{"/info/refs", "/git-upload-pack", "/git-receive-pack"} {
		if strings.HasSuffix(request.URL.Path, suffix) {
			return true
		}
	}
	return false
}

// GitHTTPSAllowed checks both transport endpoints and the advertised service.
// A read-only profile cannot advertise or invoke receive-pack.
func GitHTTPSAllowed(request *http.Request, host string, methods, paths []string) bool {
	if !IsGitHTTPSRequest(request, host) {
		return false
	}
	methodAllowed, pathAllowed := false, false
	for _, method := range methods {
		methodAllowed = methodAllowed || method == request.Method
	}
	for _, allowed := range paths {
		pathAllowed = pathAllowed || allowed == request.URL.Path
	}
	if !methodAllowed || !pathAllowed {
		return false
	}
	if strings.HasSuffix(request.URL.Path, "/info/refs") {
		query, err := url.ParseQuery(request.URL.RawQuery)
		values := query["service"]
		if err != nil || request.Method != "GET" || len(query) != 1 || len(values) != 1 {
			return false
		}
		switch values[0] {
		case "git-upload-pack":
			return true
		case "git-receive-pack":
			writePath := strings.TrimSuffix(request.URL.Path, "/info/refs") + "/git-receive-pack"
			for _, allowed := range paths {
				if allowed == writePath {
					return true
				}
			}
		}
		return false
	}
	if request.Method != "POST" || request.URL.RawQuery != "" {
		return false
	}
	service := path.Base(request.URL.Path)
	return strings.Split(request.Header.Get("Content-Type"), ";")[0] == "application/x-"+service+"-request"
}

func GitHTTPSReference(request *http.Request, host, expected string, methods, paths []string) bool {
	_, password, ok := request.BasicAuth()
	return ok && len(request.Header.Values("Authorization")) == 1 && password == expected && GitHTTPSAllowed(request, host, methods, paths)
}

func HasCredentialReference(request *http.Request) bool {
	for _, values := range request.Header {
		for _, value := range values {
			if strings.Contains(value, "envvault://") {
				return true
			}
		}
	}
	_, password, ok := request.BasicAuth()
	return ok && strings.Contains(password, "envvault://")
}
