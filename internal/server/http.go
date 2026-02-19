package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"agent-sentinel/internal/model"
	"agent-sentinel/internal/policy"
	"agent-sentinel/internal/risk"
)

type scanRequest struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}

type Server struct {
	engine *policy.Engine
}

func New(engine *policy.Engine) *Server {
	return &Server{engine: engine}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/v1/scan", s.handleScan)
	mux.HandleFunc("/v1/gate", s.handleGate)
	return mux
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}

	trust := model.SourceUnknown
	switch req.Source {
	case "system", "developer", "policy-engine":
		trust = model.SourceTrusted
	case "":
		trust = model.SourceUnknown
	default:
		trust = model.SourceUntrusted
	}
	scorer := risk.NewScorer()
	assessment := scorer.Assess(req.Text, trust)
	writeJSON(w, http.StatusOK, assessment)
}

func (s *Server) handleGate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}

	var req model.GateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	decision := s.engine.Evaluate(req)
	writeJSON(w, http.StatusOK, decision)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
