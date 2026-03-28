// K-Veritas attestation server.
//
// The server holds the RSA private key and is the only entity that can issue
// valid signatures. It receives a data_hash from the client — never the raw
// experiment data — and signs the payload data_hash:nonce:signed_at.
//
// Endpoints:
//
//	POST /api/v1/init        Register a session; returns an opaque token.
//	POST /api/v1/seal        Validate token and sign data hash; returns attestation.
//	POST /api/v1/record-run  Record a run invocation in the ledger.
//	GET  /api/v1/run-history Return all run invocations for a session.
//	GET  /api/v1/public-key  Return the server's public key in PEM format.
//
// Key storage: keys/private.pem and keys/public.pem. Generated on first run.
package main

import (
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mamadouk/kveritas/internal/crypto"
)

type serverSession struct {
	Token     string    `json:"token"`
	MachineID string    `json:"machine_id"`
	InitAt    time.Time `json:"init_at"`
	Sealed    bool      `json:"sealed"`
}

type runInvocation struct {
	RunIndex    int     `json:"run_index"`
	StartedAt   string  `json:"started_at"`
	DurationSec float64 `json:"duration_sec"`
	DurationFmt string  `json:"duration_fmt"`
	ExitCode    int     `json:"exit_code"`
	MetricHash  string  `json:"metric_hash"`
	StdoutLines int     `json:"stdout_lines"`
}

type srv struct {
	privKey      *rsa.PrivateKey
	pubKeyPEM    string
	mu           sync.RWMutex
	sessions     map[string]*serverSession     // session_id -> session
	tokens       map[string]string              // token -> session_id
	runHistory   map[string][]runInvocation     // session_id -> runs
}

func main() {
	addr := flag.String("addr", ":7433", "listen address")
	keysDir := flag.String("keys", "keys", "directory for RSA key pair")
	flag.Parse()

	s, err := newServer(*keysDir)
	if err != nil {
		log.Fatalf("server init: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/public-key", s.handlePublicKey)
	mux.HandleFunc("POST /api/v1/init", s.handleInit)
	mux.HandleFunc("POST /api/v1/seal", s.handleSeal)
	mux.HandleFunc("POST /api/v1/record-run", s.handleRecordRun)
	mux.HandleFunc("GET /api/v1/run-history", s.handleRunHistory)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"service": "K-Veritas Attestation Server",
			"version": "1.1",
			"status":  "operational",
		})
	})

	log.Printf("K-Veritas attestation server listening on %s", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}

func newServer(keysDir string) (*srv, error) {
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, err
	}

	privPath := filepath.Join(keysDir, "private.pem")
	pubPath := filepath.Join(keysDir, "public.pem")

	var privKey *rsa.PrivateKey

	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		log.Println("Generating 4096-bit RSA key pair (one-time operation)...")
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("key generation: %w", err)
		}
		privKey = key

		privPEM, err := crypto.MarshalPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pubPEM, err := crypto.MarshalPublicKey(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
			return nil, err
		}
		log.Printf("Keys written to %s and %s", privPath, pubPath)
	} else {
		privPEM, err := os.ReadFile(privPath)
		if err != nil {
			return nil, err
		}
		privKey, err = crypto.LoadPrivateKey(privPEM)
		if err != nil {
			return nil, fmt.Errorf("loading private key: %w", err)
		}
		log.Printf("Loaded existing key from %s", privPath)
	}

	pubPEM, err := crypto.MarshalPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &srv{
		privKey:    privKey,
		pubKeyPEM:  string(pubPEM),
		sessions:   make(map[string]*serverSession),
		tokens:     make(map[string]string),
		runHistory: make(map[string][]runInvocation),
	}, nil
}

// POST /api/v1/init
func (s *srv) handleInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		MachineID string `json:"machine_id"`
		InitAt    string `json:"init_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.SessionID == "" || req.MachineID == "" {
		writeError(w, http.StatusBadRequest, "session_id and machine_id are required")
		return
	}

	nonce, err := crypto.RandomNonce()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "nonce generation failed")
		return
	}
	token := nonce // token is a single-use random value

	initAt := time.Now().UTC()
	if req.InitAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, req.InitAt); err == nil {
			initAt = t
		}
	}

	s.mu.Lock()
	s.sessions[req.SessionID] = &serverSession{
		Token:     token,
		MachineID: req.MachineID,
		InitAt:    initAt,
	}
	s.tokens[token] = req.SessionID
	s.mu.Unlock()

	log.Printf("Session registered: %s machine=%s", req.SessionID, req.MachineID)
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// POST /api/v1/record-run
func (s *srv) handleRecordRun(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string  `json:"token"`
		SessionID   string  `json:"session_id"`
		MachineID   string  `json:"machine_id"`
		RunIndex    int     `json:"run_index"`
		StartedAt   string  `json:"started_at"`
		DurationSec float64 `json:"duration_sec"`
		DurationFmt string  `json:"duration_fmt"`
		ExitCode    int     `json:"exit_code"`
		MetricHash  string  `json:"metric_hash"`
		StdoutLines int     `json:"stdout_lines"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	s.mu.Lock()
	sess, ok := s.sessions[req.SessionID]
	if !ok || sess.Token != req.Token {
		s.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "invalid session or token")
		return
	}
	s.runHistory[req.SessionID] = append(s.runHistory[req.SessionID], runInvocation{
		RunIndex:    req.RunIndex,
		StartedAt:   req.StartedAt,
		DurationSec: req.DurationSec,
		DurationFmt: req.DurationFmt,
		ExitCode:    req.ExitCode,
		MetricHash:  req.MetricHash,
		StdoutLines: req.StdoutLines,
	})
	s.mu.Unlock()

	log.Printf("Run recorded: session=%s run=%d exit=%d", req.SessionID, req.RunIndex, req.ExitCode)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /api/v1/run-history?session_id=<id>&token=<token>
func (s *srv) handleRunHistory(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")
	token := r.URL.Query().Get("token")

	s.mu.RLock()
	sess, ok := s.sessions[sessionID]
	if !ok || sess.Token != token {
		s.mu.RUnlock()
		writeError(w, http.StatusUnauthorized, "invalid session or token")
		return
	}
	runs := s.runHistory[sessionID]
	s.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"runs":       runs,
		"total_runs": len(runs),
	})
}

// POST /api/v1/seal
func (s *srv) handleSeal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token     string `json:"token"`
		SessionID string `json:"session_id"`
		MachineID string `json:"machine_id"`
		DataHash  string `json:"data_hash"`
		RunCount  int    `json:"run_count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	s.mu.Lock()
	sess, ok := s.sessions[req.SessionID]
	if !ok {
		s.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "unknown session; run 'kveritas init' first")
		return
	}
	if sess.Sealed {
		s.mu.Unlock()
		writeError(w, http.StatusConflict, "session already sealed")
		return
	}
	if sess.Token != req.Token {
		s.mu.Unlock()
		writeError(w, http.StatusUnauthorized, "invalid session token")
		return
	}
	if sess.MachineID != req.MachineID {
		s.mu.Unlock()
		writeError(w, http.StatusUnauthorized,
			"machine ID mismatch: seal must come from the same machine as init")
		return
	}
	if len(req.DataHash) != 64 {
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, "data_hash must be 64 hex characters (SHA-256)")
		return
	}
	if req.RunCount < 1 {
		s.mu.Unlock()
		writeError(w, http.StatusBadRequest, "cannot seal a session with no runs")
		return
	}
	sess.Sealed = true
	s.mu.Unlock()

	nonce, err := crypto.RandomNonce()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "nonce generation failed")
		return
	}

	signedAt := time.Now().UTC().Format(time.RFC3339Nano)
	payload := crypto.Payload(req.DataHash, nonce, signedAt)

	sig, err := crypto.SignPSS(s.privKey, payload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "signing failed")
		return
	}

	msgHash := crypto.HashBytes([]byte(payload))

	log.Printf("Sealed session %s (%d runs, data_hash=%s...)", req.SessionID, req.RunCount, req.DataHash[:8])

	writeJSON(w, http.StatusOK, map[string]string{
		"nonce":               nonce,
		"signed_at":           signedAt,
		"signature":           sig,
		"signed_message_hash": msgHash,
		"public_key_pem":      s.pubKeyPEM,
	})
}

// GET /api/v1/public-key
func (s *srv) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"public_key": s.pubKeyPEM})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
