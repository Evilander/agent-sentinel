package policy

import (
	"testing"

	"agent-sentinel/internal/model"
)

func TestEvaluate_BlocksBlockedTool(t *testing.T) {
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision := engine.Evaluate(model.GateRequest{
		Source: "system",
		Text:   "Run maintenance.",
		Tool:   "shell.exec",
		Args: map[string]any{
			"cmd": "echo ok",
		},
	})

	if decision.Allowed {
		t.Fatalf("expected blocked tool to be denied")
	}
}

func TestEvaluate_BlocksSensitiveArgs(t *testing.T) {
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision := engine.Evaluate(model.GateRequest{
		Source: "system",
		Text:   "post this",
		Tool:   "http.request",
		Args: map[string]any{
			"body": "token=abc",
		},
	})

	if decision.Allowed {
		t.Fatalf("expected sensitive args to be denied")
	}
}

func TestEvaluate_AllowsBenignRequest(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SensitiveTools = []string{"shell.exec"}
	engine, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	decision := engine.Evaluate(model.GateRequest{
		Source: "system",
		Text:   "Summarize changes.",
		Tool:   "llm.summarize",
		Args: map[string]any{
			"max_tokens": 100,
		},
	})

	if !decision.Allowed {
		t.Fatalf("expected benign request to be allowed, reason: %s", decision.Reason)
	}
}
