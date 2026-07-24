package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/trknhr/envvault/internal/clerr"
	"github.com/trknhr/envvault/internal/credentialscan"
)

type inspectArgs struct {
	paths          []string
	format         string
	includeMedium  bool
	failOnFindings bool
	depth          int
	workers        int
	verbose        bool
}

type inspectJSONResult struct {
	Findings     []credentialscan.Finding `json:"findings"`
	FilesScanned int                      `json:"files_scanned"`
	PathsSkipped int                      `json:"paths_skipped"`
	Skipped      []credentialscan.Skipped `json:"skipped,omitempty"`
}

func (a App) runInspect(ctx context.Context, parsed inspectArgs, stdout, stderr io.Writer) int {
	if parsed.format != "text" && parsed.format != "json" {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "inspect output format must be text or json"))
		return 2
	}
	if parsed.depth < 0 {
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, "inspect depth cannot be negative"))
		return 2
	}
	if parsed.workers < 0 || parsed.workers > credentialscan.MaxWorkers {
		message := fmt.Sprintf(
			"inspect workers must be between 0 and %d",
			credentialscan.MaxWorkers,
		)
		fmt.Fprintln(stderr, clerr.New(clerr.ConfigInvalid, message))
		return 2
	}

	scanner, err := credentialscan.New()
	if err != nil {
		fmt.Fprintf(stderr, "envvault: inspect: %v\n", err)
		return 1
	}
	result, err := scanner.Inspect(ctx, parsed.paths, credentialscan.Options{
		IncludeMedium: parsed.includeMedium,
		Depth:         parsed.depth,
		Workers:       parsed.workers,
	})
	if err != nil {
		fmt.Fprintf(stderr, "envvault: inspect: %v\n", err)
		return 1
	}

	if parsed.format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		jsonResult := inspectJSONResult{
			Findings:     result.Findings,
			FilesScanned: result.FilesScanned,
			PathsSkipped: len(result.Skipped),
		}
		if parsed.verbose {
			jsonResult.Skipped = result.Skipped
		}
		if err := encoder.Encode(jsonResult); err != nil {
			fmt.Fprintf(stderr, "envvault: inspect: write output: %v\n", err)
			return 1
		}
	} else if err := writeInspectText(stdout, result, parsed.verbose); err != nil {
		fmt.Fprintf(stderr, "envvault: inspect: write output: %v\n", err)
		return 1
	}

	if parsed.failOnFindings && len(result.Findings) > 0 {
		return 1
	}
	return 0
}

func writeInspectText(writer io.Writer, result credentialscan.Result, verbose bool) error {
	if len(result.Findings) == 0 {
		if _, err := fmt.Fprintln(writer, "No potential raw credentials detected."); err != nil {
			return err
		}
	} else {
		rows := make([][]string, 0, len(result.Findings))
		for _, finding := range result.Findings {
			rows = append(rows, []string{
				finding.Path,
				inspectLocation(finding),
				string(finding.Confidence),
				finding.RuleID,
				finding.Description,
			})
		}
		if err := writeTable(writer, []string{"PATH", "LOCATION", "CONFIDENCE", "RULE", "DESCRIPTION"}, rows); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(
		writer,
		"Scanned %d file%s; skipped %d path%s.\n",
		result.FilesScanned,
		pluralSuffix(result.FilesScanned),
		len(result.Skipped),
		pluralSuffix(len(result.Skipped)),
	); err != nil {
		return err
	}
	if !verbose || len(result.Skipped) == 0 {
		return nil
	}

	rows := make([][]string, 0, len(result.Skipped))
	for _, skipped := range result.Skipped {
		rows = append(rows, []string{skipped.Path, skipped.Reason})
	}
	return writeTable(writer, []string{"SKIPPED", "REASON"}, rows)
}

func inspectLocation(finding credentialscan.Finding) string {
	location := finding.Location
	if finding.Line <= 0 {
		if location == "" {
			return "-"
		}
		return location
	}

	position := strconv.Itoa(finding.Line)
	if finding.Column > 0 {
		position += ":" + strconv.Itoa(finding.Column)
	}
	if location != "" {
		position += " (" + location + ")"
	}
	return position
}

func pluralSuffix(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
