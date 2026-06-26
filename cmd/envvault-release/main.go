package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	releasepkg "github.com/trknhr/envvault/internal/releasepkg"
)

const packageUsage = "usage: envvault-release package --version <version> --platform <os/arch> --binary <path> [--repo-root <path>] [--dist <path>]"
const packageManifestsUsage = "usage: envvault-release package-manifests --version <version> --base-url <release-url> [--dist <path>]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, packageUsage)
		fmt.Fprintln(stderr, packageManifestsUsage)
		return 2
	}

	switch args[0] {
	case "package":
		return runPackage(args[1:], stdout, stderr)
	case "package-manifests":
		return runPackageManifests(args[1:], stdout, stderr)
	default:
		fmt.Fprintln(stderr, packageUsage)
		fmt.Fprintln(stderr, packageManifestsUsage)
		return 2
	}
}

func runPackage(args []string, stdout, stderr io.Writer) int {
	options, err := parsePackageArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr, packageUsage)
		return 2
	}
	artifact, err := releasepkg.Package(options)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := releasepkg.UpdateChecksums(options.DistDir, []releasepkg.Artifact{artifact}); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s  %s\n", artifact.SHA256, artifact.Name)
	return 0
}

func runPackageManifests(args []string, stdout, stderr io.Writer) int {
	options, err := parsePackageManifestsArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		fmt.Fprintln(stderr, packageManifestsUsage)
		return 2
	}
	artifacts, err := releasepkg.ReadChecksums(filepath.Join(options.DistDir, "SHA256SUMS"))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	options.Artifacts = artifacts
	paths, err := releasepkg.WritePackageManagerManifests(options)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintln(stdout, relativeManifestPath(options.DistDir, paths.HomebrewFormula))
	fmt.Fprintln(stdout, relativeManifestPath(options.DistDir, paths.ScoopManifest))
	return 0
}

func parsePackageArgs(args []string) (releasepkg.PackageOptions, error) {
	flags := flag.NewFlagSet("package", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	version := flags.String("version", "", "release version")
	platformRaw := flags.String("platform", "", "target platform as os/arch")
	binaryPath := flags.String("binary", "", "path to built envvault binary")
	repoRoot := flags.String("repo-root", ".", "repository root")
	distDir := flags.String("dist", "dist", "distribution output directory")
	if err := flags.Parse(args); err != nil {
		return releasepkg.PackageOptions{}, err
	}
	if flags.NArg() != 0 {
		return releasepkg.PackageOptions{}, fmt.Errorf("unexpected package argument")
	}
	if *version == "" || *platformRaw == "" || *binaryPath == "" {
		return releasepkg.PackageOptions{}, fmt.Errorf("version, platform, and binary are required")
	}
	platform, err := parsePlatform(*platformRaw)
	if err != nil {
		return releasepkg.PackageOptions{}, err
	}
	return releasepkg.PackageOptions{
		RepoRoot:   *repoRoot,
		DistDir:    *distDir,
		Version:    *version,
		Platform:   platform,
		BinaryPath: *binaryPath,
	}, nil
}

func parsePlatform(value string) (releasepkg.Platform, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return releasepkg.Platform{}, fmt.Errorf("platform must be formatted as os/arch")
	}
	return releasepkg.Platform{OS: parts[0], Arch: parts[1]}, nil
}

func parsePackageManifestsArgs(args []string) (releasepkg.PackageManagerManifestOptions, error) {
	flags := flag.NewFlagSet("package-manifests", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	version := flags.String("version", "", "release version")
	baseURL := flags.String("base-url", "", "release download base URL")
	distDir := flags.String("dist", "dist", "distribution output directory")
	if err := flags.Parse(args); err != nil {
		return releasepkg.PackageManagerManifestOptions{}, err
	}
	if flags.NArg() != 0 {
		return releasepkg.PackageManagerManifestOptions{}, fmt.Errorf("unexpected package-manifests argument")
	}
	if *version == "" || *baseURL == "" {
		return releasepkg.PackageManagerManifestOptions{}, fmt.Errorf("version and base-url are required")
	}
	return releasepkg.PackageManagerManifestOptions{
		DistDir: *distDir,
		Version: *version,
		BaseURL: *baseURL,
	}, nil
}

func relativeManifestPath(distDir, path string) string {
	rel, err := filepath.Rel(distDir, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(rel)
}
