package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"agent-sentinel/internal/model"
	"agent-sentinel/internal/risk"
)

type Engine struct {
	cfg          Config
	scorer       *risk.Scorer
	argBlocklist []*regexp.Regexp
}

func NewEngine(cfg Config) (*Engine, error) {
	engine := &Engine{
		cfg:          cfg,
		scorer:       risk.NewScorer(),
		argBlocklist: make([]*regexp.Regexp, 0, len(cfg.BlockedArgPatterns)),
	}
	for _, pattern := range cfg.BlockedArgPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid blocked arg pattern %q: %w", pattern, err)
		}
		engine.argBlocklist = append(engine.argBlocklist, re)
	}
	return engine, nil
}

func (e *Engine) Evaluate(req model.GateRequest) model.GateDecision {
	trust := e.sourceTrust(req.Source)
	assessment := e.scorer.Assess(req.Text, trust)

	decision := model.GateDecision{
		Allowed:          true,
		RequiresApproval: false,
		Reason:           "allowed",
		SourceTrust:      trust,
		Assessment:       assessment,
		Violations:       make([]string, 0),
	}

	tool := strings.TrimSpace(req.Tool)
	if tool == "" {
		decision.Allowed = false
		decision.Reason = "missing tool"
		decision.Violations = append(decision.Violations, "tool_not_provided")
		return decision
	}

	if slices.Contains(e.cfg.BlockedTools, tool) {
		decision.Allowed = false
		decision.Reason = "tool is explicitly blocked"
		decision.Violations = append(decision.Violations, "blocked_tool")
	}

	if trust == model.SourceUntrusted && slices.Contains(e.cfg.SensitiveTools, tool) {
		decision.Violations = append(decision.Violations, "untrusted_sensitive_tool")
	}

	if e.argsContainSensitivePattern(req.Args) {
		decision.Allowed = false
		decision.Reason = "tool args match blocked sensitive patterns"
		decision.Violations = append(decision.Violations, "blocked_arg_pattern")
	}

	if assessment.Score >= e.cfg.MaxRiskScore {
		decision.Allowed = false
		decision.Reason = "risk score exceeds policy maximum"
		decision.Violations = append(decision.Violations, "risk_exceeds_max")
	}

	if e.cfg.HighRiskRequiresApproval && assessment.Score >= e.cfg.ApprovalRiskThreshold {
		decision.RequiresApproval = true
		if decision.Allowed {
			decision.Allowed = false
			decision.Reason = "human approval required for high-risk request"
		}
		decision.Violations = append(decision.Violations, "approval_required")
	}

	if decision.Allowed && trust == model.SourceUntrusted && slices.Contains(e.cfg.SensitiveTools, tool) {
		decision.Allowed = false
		decision.RequiresApproval = true
		decision.Reason = "sensitive tool from untrusted source requires approval"
		decision.Violations = append(decision.Violations, "sensitive_tool_needs_approval")
	}

	return decision
}

func (e *Engine) sourceTrust(source string) model.SourceTrust {
	source = strings.TrimSpace(strings.ToLower(source))
	if source == "" {
		return model.SourceUnknown
	}
	for _, trusted := range e.cfg.TrustedSources {
		if source == strings.ToLower(trusted) {
			return model.SourceTrusted
		}
	}
	return model.SourceUntrusted
}

func (e *Engine) argsContainSensitivePattern(args map[string]any) bool {
	if len(args) == 0 {
		return false
	}
	b, err := json.Marshal(args)
	if err != nil {
		return true
	}
	body := string(b)
	for _, re := range e.argBlocklist {
		if re.MatchString(body) {
			return true
		}
	}
	return false
}
