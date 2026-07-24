package credentialscan

import (
	"context"
	"strings"
	"sync"

	"github.com/spf13/viper"
	gitleaksconfig "github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

const genericAPIKeyRuleID = "generic-api-key"

var (
	defaultConfigOnce sync.Once
	defaultConfig     gitleaksconfig.Config
	defaultConfigErr  error
)

func loadGitleaksConfig() error {
	defaultConfigOnce.Do(func() {
		parser := viper.New()
		parser.SetConfigType("toml")
		if err := parser.ReadConfig(strings.NewReader(gitleaksconfig.DefaultConfig)); err != nil {
			defaultConfigErr = err
			return
		}
		var parsed gitleaksconfig.ViperConfig
		if err := parser.Unmarshal(&parsed); err != nil {
			defaultConfigErr = err
			return
		}
		defaultConfig, defaultConfigErr = parsed.Translate()
	})
	if defaultConfigErr != nil {
		return defaultConfigErr
	}
	return nil
}

func newGitleaksDetector() *detect.Detector {
	detector := detect.NewDetector(defaultConfig)
	detector.Redact = 100
	// A local raw-credential inventory should not be suppressible by a source
	// comment intended for repository secret scanning.
	detector.IgnoreGitleaksAllow = true
	return detector
}

func detectWithGitleaks(ctx context.Context, detector *detect.Detector, path string, body []byte) []Finding {
	rawFindings := detector.DetectContext(ctx, detect.Fragment{
		Raw:      string(body),
		FilePath: path,
	})
	findings := make([]Finding, 0, len(rawFindings))
	for i := range rawFindings {
		raw := &rawFindings[i]
		confidence := ConfidenceHigh
		if raw.RuleID == genericAPIKeyRuleID {
			confidence = ConfidenceMedium
		}
		findings = append(findings, Finding{
			Path:        path,
			Line:        raw.StartLine,
			Column:      raw.StartColumn,
			RuleID:      raw.RuleID,
			Description: raw.Description,
			Confidence:  confidence,
			Engine:      "gitleaks",
		})

		// Gitleaks already redacts these fields because detector.Redact is 100.
		// Clear them anyway so the upstream object cannot accidentally be
		// serialized or logged if this adapter changes later.
		raw.Line = ""
		raw.Match = ""
		raw.Secret = ""
		raw.Fragment = nil
	}
	return findings
}
