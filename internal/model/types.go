package model

type SourceTrust string

const (
	SourceTrusted   SourceTrust = "trusted"
	SourceUntrusted SourceTrust = "untrusted"
	SourceUnknown   SourceTrust = "unknown"
)

type RiskSignal struct {
	Name    string `json:"name"`
	Weight  int    `json:"weight"`
	Matched string `json:"matched,omitempty"`
}

type PromptAssessment struct {
	Score    int          `json:"score"`
	Severity string       `json:"severity"`
	Signals  []RiskSignal `json:"signals"`
}

type GateRequest struct {
	Source string         `json:"source"`
	Text   string         `json:"text"`
	Tool   string         `json:"tool"`
	Args   map[string]any `json:"args"`
}

type GateDecision struct {
	Allowed          bool             `json:"allowed"`
	RequiresApproval bool             `json:"requires_approval"`
	Reason           string           `json:"reason"`
	SourceTrust      SourceTrust      `json:"source_trust"`
	Assessment       PromptAssessment `json:"assessment"`
	Violations       []string         `json:"violations"`
}
