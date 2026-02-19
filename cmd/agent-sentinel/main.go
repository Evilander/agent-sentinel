package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"agent-sentinel/internal/model"
	"agent-sentinel/internal/policy"
	"agent-sentinel/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	case "gate":
		exitCode, err := runGate(os.Args[2:])
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(exitCode)
	case "serve":
		if err := runServe(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("agent-sentinel: deterministic policy gateway for AI agents")
	fmt.Println()
	fmt.Println("usage:")
	fmt.Println("  agent-sentinel scan -source web -text \"...\"")
	fmt.Println("  agent-sentinel gate -source web -text \"...\" -tool shell.exec -args '{\"cmd\":\"whoami\"}' [-policy policy.json]")
	fmt.Println("  agent-sentinel serve -addr :8080 [-policy policy.json]")
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	source := fs.String("source", "", "source label (e.g. web,email,system)")
	text := fs.String("text", "", "prompt text to score")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := policy.DefaultConfig()
	engine, err := policy.NewEngine(cfg)
	if err != nil {
		return err
	}

	assessment := engine.Evaluate(model.GateRequest{
		Source: *source,
		Text:   *text,
		Tool:   "noop",
		Args:   map[string]any{},
	}).Assessment
	return printJSON(assessment)
}

func runGate(args []string) (int, error) {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	source := fs.String("source", "", "source label (e.g. web,email,system)")
	text := fs.String("text", "", "prompt text associated with the action")
	tool := fs.String("tool", "", "tool name to evaluate")
	argsJSON := fs.String("args", "{}", "JSON object for tool args")
	policyPath := fs.String("policy", "", "path to policy JSON")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}

	if *tool == "" {
		return 2, errors.New("missing required -tool")
	}

	cfg, err := policy.LoadConfig(*policyPath)
	if err != nil {
		return 2, fmt.Errorf("load policy: %w", err)
	}

	engine, err := policy.NewEngine(cfg)
	if err != nil {
		return 2, fmt.Errorf("build engine: %w", err)
	}

	parsedArgs := map[string]any{}
	if err := json.Unmarshal([]byte(*argsJSON), &parsedArgs); err != nil {
		return 2, fmt.Errorf("parse -args JSON: %w", err)
	}

	decision := engine.Evaluate(model.GateRequest{
		Source: *source,
		Text:   *text,
		Tool:   *tool,
		Args:   parsedArgs,
	})
	if err := printJSON(decision); err != nil {
		return 2, err
	}
	if decision.Allowed {
		return 0, nil
	}
	return 3, nil
}

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "listen address")
	policyPath := fs.String("policy", "", "path to policy JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := policy.LoadConfig(*policyPath)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}

	engine, err := policy.NewEngine(cfg)
	if err != nil {
		return fmt.Errorf("build engine: %w", err)
	}

	srv := server.New(engine)
	log.Printf("agent-sentinel listening on %s", *addr)
	return http.ListenAndServe(*addr, srv.Handler())
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
