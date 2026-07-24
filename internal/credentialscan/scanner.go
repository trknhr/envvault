package credentialscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/detect"
)

const (
	defaultMaxFileSize = 10 * 1024 * 1024
	maxDefaultWorkers  = 8
	MaxWorkers         = 32
)

type Scanner struct {
	maxFileSize int64
}

func New() (*Scanner, error) {
	if err := loadGitleaksConfig(); err != nil {
		return nil, fmt.Errorf("initialize credential detector: %w", err)
	}
	return &Scanner{
		maxFileSize: defaultMaxFileSize,
	}, nil
}

func (s *Scanner) Inspect(ctx context.Context, paths []string, options Options) (Result, error) {
	workerCount, err := inspectWorkerCount(options.Workers)
	if err != nil {
		return Result{}, err
	}
	if options.Depth < 0 {
		return Result{}, errors.New("inspect depth cannot be negative")
	}

	result := Result{
		Findings: make([]Finding, 0),
		Skipped:  make([]Skipped, 0),
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}

	jobs := make(chan scanJob)
	outputs := make(chan scanOutput)
	var workerGroup sync.WaitGroup
	for range workerCount {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			s.scanWorker(ctx, jobs, outputs, options)
		}()
	}

	walkError := make(chan error, 1)
	go func() {
		walkError <- walkInspectPaths(ctx, paths, options.Depth, jobs, outputs)
		close(jobs)
	}()
	go func() {
		workerGroup.Wait()
		close(outputs)
	}()

	var firstScanError error
	for output := range outputs {
		if output.err != nil {
			if firstScanError == nil {
				firstScanError = output.err
			}
			continue
		}
		if output.skipped != nil {
			result.Skipped = append(result.Skipped, *output.skipped)
		}
		if output.scanned {
			result.FilesScanned++
		}
		result.Findings = append(result.Findings, output.findings...)
	}
	if err := <-walkError; err != nil {
		return Result{}, err
	}
	if firstScanError != nil {
		return Result{}, firstScanError
	}

	slices.SortFunc(result.Findings, compareFindings)
	slices.SortFunc(result.Skipped, func(a, b Skipped) int {
		if result := strings.Compare(a.Path, b.Path); result != 0 {
			return result
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	return result, nil
}

type scanJob struct {
	path    string
	display string
	info    fs.FileInfo
}

type scanOutput struct {
	findings []Finding
	skipped  *Skipped
	scanned  bool
	err      error
}

func (s *Scanner) scanWorker(
	ctx context.Context,
	jobs <-chan scanJob,
	outputs chan<- scanOutput,
	options Options,
) {
	var detector *detect.Detector
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-jobs:
			if !ok {
				return
			}
			if detector == nil {
				detector = newGitleaksDetector()
			}
			output := s.scanFile(ctx, detector, job, options)
			select {
			case outputs <- output:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *Scanner) scanFile(
	ctx context.Context,
	detector *detect.Detector,
	job scanJob,
	options Options,
) scanOutput {
	body, reason, err := readRegularFile(job.path, job.info, s.maxFileSize)
	if err != nil {
		return scanOutput{err: fmt.Errorf("inspect %s: %w", job.display, err)}
	}
	if reason != "" {
		return scanOutput{
			findings: detectWithGitleaks(ctx, detector, job.display, nil),
			skipped:  &Skipped{Path: job.display, Reason: reason},
		}
	}
	defer zeroBytes(body)

	findings := detectWithGitleaks(ctx, detector, job.display, body)
	findings = append(findings, detectStructured(job.display, body)...)
	if !options.IncludeMedium {
		findings = slices.DeleteFunc(findings, func(finding Finding) bool {
			return finding.Confidence != ConfidenceHigh
		})
	}
	return scanOutput{findings: findings, scanned: true}
}

func walkInspectPaths(
	ctx context.Context,
	paths []string,
	depth int,
	jobs chan<- scanJob,
	outputs chan<- scanOutput,
) error {
	seen := make(map[string]struct{})
	for _, requestedPath := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		if strings.TrimSpace(requestedPath) == "" {
			return errors.New("inspect path cannot be empty")
		}
		root := filepath.Clean(requestedPath)
		if _, err := os.Lstat(root); err != nil {
			return fmt.Errorf("inspect %s: %w", displayPath(root), err)
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return fmt.Errorf("inspect %s: %w", displayPath(path), walkErr)
			}
			if err := ctx.Err(); err != nil {
				return err
			}

			display := displayPath(path)
			if entry.Type()&os.ModeSymlink != 0 {
				return sendScanOutput(ctx, outputs, scanOutput{
					skipped: &Skipped{Path: display, Reason: "symlink"},
				})
			}
			if entry.IsDir() {
				if path != root && shouldSkipDirectory(entry.Name()) {
					if err := sendScanOutput(ctx, outputs, scanOutput{
						skipped: &Skipped{Path: display, Reason: "excluded_directory"},
					}); err != nil {
						return err
					}
					return filepath.SkipDir
				}
				if path != root && exceedsDepth(root, path, depth) {
					if err := sendScanOutput(ctx, outputs, scanOutput{
						skipped: &Skipped{Path: display, Reason: "depth"},
					}); err != nil {
						return err
					}
					return filepath.SkipDir
				}
				return nil
			}

			info, err := entry.Info()
			if err != nil {
				return fmt.Errorf("inspect %s: %w", display, err)
			}
			if !info.Mode().IsRegular() {
				return sendScanOutput(ctx, outputs, scanOutput{
					skipped: &Skipped{Path: display, Reason: "not_regular"},
				})
			}

			identity, err := filepath.Abs(path)
			if err != nil {
				return fmt.Errorf("inspect %s: %w", display, err)
			}
			identity = filepath.Clean(identity)
			if _, ok := seen[identity]; ok {
				return nil
			}
			seen[identity] = struct{}{}

			select {
			case jobs <- scanJob{path: path, display: display, info: info}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func sendScanOutput(ctx context.Context, outputs chan<- scanOutput, output scanOutput) error {
	select {
	case outputs <- output:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func exceedsDepth(root, path string, depth int) bool {
	if depth == 0 {
		return false
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return true
	}
	relative = filepath.Clean(relative)
	if relative == "." {
		return false
	}
	return len(strings.Split(relative, string(os.PathSeparator))) > depth
}

func inspectWorkerCount(requested int) (int, error) {
	if requested < 0 || requested > MaxWorkers {
		return 0, fmt.Errorf("inspect workers must be between 0 and %d", MaxWorkers)
	}
	if requested > 0 {
		return requested, nil
	}
	return min(max(runtime.GOMAXPROCS(0), 1), maxDefaultWorkers), nil
}

func readRegularFile(path string, expected fs.FileInfo, maxFileSize int64) ([]byte, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()

	actual, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !actual.Mode().IsRegular() {
		return nil, "not_regular", nil
	}
	if !os.SameFile(expected, actual) {
		return nil, "changed_during_scan", nil
	}
	if actual.Size() > maxFileSize {
		return nil, "too_large", nil
	}

	body, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil {
		zeroBytes(body)
		return nil, "", err
	}
	if int64(len(body)) > maxFileSize {
		zeroBytes(body)
		return nil, "too_large", nil
	}
	if bytes.IndexByte(body, 0) >= 0 {
		zeroBytes(body)
		return nil, "binary", nil
	}
	return body, "", nil
}

func shouldSkipDirectory(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", ".next", "build", "coverage", "dist", "node_modules", "target", "vendor":
		return true
	default:
		return false
	}
}

func displayPath(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

func zeroBytes(body []byte) {
	for i := range body {
		body[i] = 0
	}
}

func compareFindings(a, b Finding) int {
	if result := strings.Compare(a.Path, b.Path); result != 0 {
		return result
	}
	if a.Line != b.Line {
		return a.Line - b.Line
	}
	if a.Column != b.Column {
		return a.Column - b.Column
	}
	return strings.Compare(a.RuleID, b.RuleID)
}
