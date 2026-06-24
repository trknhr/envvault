package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const secretScanUsage = "usage: credlease-ci secret-scan [root]"

var secretMarkers = [][]byte{
	[]byte("secret-canary"),
	[]byte("parent-secret"),
	[]byte("0123456789abcdef0123456789abcdef"),
	[]byte("abcdef0123456789abcdef0123456789"),
	[]byte("Authorization: Bearer"),
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "secret-scan" || len(args) > 2 {
		fmt.Fprintln(stderr, secretScanUsage)
		return 2
	}
	root := "."
	if len(args) == 2 {
		root = args[1]
	}
	matches, err := scanSecrets(root)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if len(matches) > 0 {
		fmt.Fprintf(stderr, "secret marker found in %d file%s\n", len(matches), pluralS(len(matches)))
		for _, path := range matches {
			fmt.Fprintln(stderr, path)
		}
		return 1
	}
	return 0
}

func scanSecrets(root string) ([]string, error) {
	var matches []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if shouldSkipDir(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if shouldSkipFile(path) {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, marker := range secretMarkers {
			if bytes.Contains(body, marker) {
				matches = append(matches, path)
				return nil
			}
		}
		return nil
	})
	return matches, err
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", ".idea", ".vscode":
		return true
	default:
		return false
	}
}

func shouldSkipFile(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "go.sum":
		return true
	}
	ext := strings.ToLower(filepath.Ext(base))
	switch ext {
	case ".go", ".md":
		return true
	default:
		return false
	}
}

func pluralS(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
