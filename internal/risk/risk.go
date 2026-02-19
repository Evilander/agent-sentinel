package risk

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"agent-sentinel/internal/model"
)

type Rule struct {
	Name    string
	Weight  int
	Pattern *regexp.Regexp
}

type Scorer struct {
	rules []Rule
}

func NewScorer() *Scorer {
	return &Scorer{
		rules: []Rule{
			{
				Name:    "ignore_instructions",
				Weight:  20,
				Pattern: regexp.MustCompile(`(?i)ignore\s+(all|any|previous|prior)\s+(instructions|prompts?)`),
			},
			{
				Name:    "reveal_system_prompt",
				Weight:  25,
				Pattern: regexp.MustCompile(`(?i)(reveal|print|show)\s+.*(system prompt|hidden prompt|policy)`),
			},
			{
				Name:    "secret_exfiltration",
				Weight:  30,
				Pattern: regexp.MustCompile(`(?i)(send|upload|exfiltrat|post)\s+.*(api[\s_-]?key|token|password|secret|credential)`),
			},
			{
				Name:    "dangerous_exec",
				Weight:  20,
				Pattern: regexp.MustCompile(`(?i)(run|execute|invoke)\s+.*(bash|powershell|cmd|terminal|shell)`),
			},
			{
				Name:    "network_callback",
				Weight:  15,
				Pattern: regexp.MustCompile(`(?i)(curl|wget|http://|https://|webhook)`),
			},
			{
				Name:    "role_confusion",
				Weight:  12,
				Pattern: regexp.MustCompile(`(?i)(you are now|new instructions|developer override|tool override)`),
			},
			{
				Name:    "hidden_content",
				Weight:  18,
				Pattern: regexp.MustCompile(`(?i)(<!--|<script|display:\s*none|hidden text)`),
			},
			{
				Name:    "obfuscation_hint",
				Weight:  10,
				Pattern: regexp.MustCompile(`(?i)(base64|rot13|hex encoded|unicode escapes?)`),
			},
		},
	}
}

func (s *Scorer) Assess(text string, trust model.SourceTrust) model.PromptAssessment {
	assessment := model.PromptAssessment{
		Score:    0,
		Severity: "low",
		Signals:  make([]model.RiskSignal, 0),
	}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return assessment
	}

	for _, rule := range s.rules {
		match := rule.Pattern.FindString(trimmed)
		if match == "" {
			continue
		}
		assessment.Score += rule.Weight
		assessment.Signals = append(assessment.Signals, model.RiskSignal{
			Name:    rule.Name,
			Weight:  rule.Weight,
			Matched: match,
		})
	}

	if trust == model.SourceUntrusted {
		imperative := regexp.MustCompile(`(?i)\b(do|run|execute|send|open|read|download|install)\b`)
		if imperative.MatchString(trimmed) {
			assessment.Score += 12
			assessment.Signals = append(assessment.Signals, model.RiskSignal{
				Name:   "untrusted_imperative_bonus",
				Weight: 12,
			})
		}
	}

	nonASCII := nonASCIIRatio(trimmed)
	if nonASCII > 0.15 {
		assessment.Score += 8
		assessment.Signals = append(assessment.Signals, model.RiskSignal{
			Name:   "unicode_obfuscation",
			Weight: 8,
		})
	}

	if assessment.Score > 100 {
		assessment.Score = 100
	}
	assessment.Severity = severityFromScore(assessment.Score)
	return assessment
}

func severityFromScore(score int) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 40:
		return "high"
	case score >= 20:
		return "medium"
	default:
		return "low"
	}
}

func nonASCIIRatio(s string) float64 {
	if s == "" {
		return 0
	}
	total := utf8.RuneCountInString(s)
	if total == 0 {
		return 0
	}
	non := 0
	for _, r := range s {
		if r > 127 {
			non++
		}
	}
	return float64(non) / float64(total)
}
