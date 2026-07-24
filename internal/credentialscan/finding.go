package credentialscan

// Confidence describes how strongly a finding resembles a raw credential.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
)

// Finding deliberately contains no credential value, match text, hash, or
// fingerprint. Keep this type safe to serialize and log.
type Finding struct {
	Path        string     `json:"path"`
	Line        int        `json:"line,omitempty"`
	Column      int        `json:"column,omitempty"`
	Location    string     `json:"location,omitempty"`
	RuleID      string     `json:"rule_id"`
	Description string     `json:"description"`
	Confidence  Confidence `json:"confidence"`
	Engine      string     `json:"engine"`
}

type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type Result struct {
	Findings     []Finding `json:"findings"`
	FilesScanned int       `json:"files_scanned"`
	Skipped      []Skipped `json:"skipped"`
}

type Options struct {
	IncludeMedium bool
	// Depth is the maximum number of nested directories to scan below each
	// requested directory. Zero means unlimited.
	Depth int
	// Workers is the number of files scanned concurrently. Zero selects an
	// automatic bounded value.
	Workers int
}
