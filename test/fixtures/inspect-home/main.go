package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type snapshot struct {
	Home  string                `json:"home"`
	Files map[string]fileStatus `json:"files"`
}

type fileStatus struct {
	SHA256 string      `json:"sha256"`
	Mode   os.FileMode `json:"mode"`
	Size   int64       `json:"size"`
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "locate home")
		os.Exit(1)
	}
	result, err := inspect(home, os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode inspection")
		os.Exit(1)
	}
}

func inspect(home string, paths []string) (snapshot, error) {
	result := snapshot{Home: home, Files: make(map[string]fileStatus, len(paths))}
	for _, relativePath := range paths {
		if !filepath.IsLocal(relativePath) {
			return snapshot{}, fmt.Errorf("inspect path must be relative")
		}
		path := filepath.Join(home, relativePath)
		body, err := os.ReadFile(path)
		if err != nil {
			return snapshot{}, fmt.Errorf("read inspected home file")
		}
		info, err := os.Stat(path)
		if err != nil {
			return snapshot{}, fmt.Errorf("inspect home file")
		}
		digest := sha256.Sum256(body)
		result.Files[relativePath] = fileStatus{
			SHA256: hex.EncodeToString(digest[:]),
			Mode:   info.Mode().Perm(),
			Size:   info.Size(),
		}
	}
	return result, nil
}
