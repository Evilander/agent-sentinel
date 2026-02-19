package policy

import (
	"encoding/json"
	"os"
)

type Config struct {
	MaxRiskScore             int      `json:"max_risk_score"`
	ApprovalRiskThreshold    int      `json:"approval_risk_threshold"`
	HighRiskRequiresApproval bool     `json:"high_risk_requires_approval"`
	BlockedTools             []string `json:"blocked_tools"`
	SensitiveTools           []string `json:"sensitive_tools"`
	BlockedArgPatterns       []string `json:"blocked_arg_patterns"`
	TrustedSources           []string `json:"trusted_sources"`
}

func DefaultConfig() Config {
	return Config{
		MaxRiskScore:             75,
		ApprovalRiskThreshold:    35,
		HighRiskRequiresApproval: true,
		BlockedTools: []string{
			"shell.exec",
			"filesystem.read_secret",
			"credentials.export",
		},
		SensitiveTools: []string{
			"shell.exec",
			"http.request",
			"filesystem.write",
			"filesystem.read",
			"database.query",
		},
		BlockedArgPatterns: []string{
			`(?i)api[_-]?key`,
			`(?i)\btoken\b`,
			`(?i)\bpassword\b`,
			`(?i)\bsecret\b`,
			`(?i)\.env`,
			`(?i)id_rsa`,
		},
		TrustedSources: []string{
			"system",
			"developer",
			"policy-engine",
		},
	}
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := DefaultConfig()
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
