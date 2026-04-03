package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	DirName     = ".kveritas"
	SessionFile = "session.json"
	RunsDir     = "runs"
	SealFile    = "seal.json"
)

type Session struct {
	ID         string    `json:"id"`
	InitAt     time.Time `json:"init_at"`
	ProjectDir string    `json:"project_dir"`
	MachineID  string    `json:"machine_id"`
	Token      string    `json:"token"`
	ServerURL  string    `json:"server_url"`
	OrgToken   string    `json:"org_token,omitempty"`
	UserEmail  string    `json:"user_email,omitempty"`
	Runs       []string  `json:"runs"`
	Sealed     bool      `json:"sealed"`
}

type RunRecord struct {
	ID          string            `json:"id"`
	SessionID   string            `json:"session_id"`
	Index       int               `json:"index"`
	Command     []string          `json:"command"`
	StartAt     time.Time         `json:"start_at"`
	EndAt       time.Time         `json:"end_at"`
	DurationSec float64           `json:"duration_sec"`
	DurationFmt string            `json:"duration_fmt,omitempty"`
	ExitCode    int               `json:"exit_code"`
	PreHashes   map[string]string `json:"pre_hashes"`
	PostHashes  map[string]string `json:"post_hashes"`
	Modified    []string          `json:"modified_files"`
	StdoutHash  string            `json:"stdout_hash"`
	StderrHash  string            `json:"stderr_hash"`
	StdoutLines int               `json:"stdout_lines"`
	Metrics     []Metric          `json:"metrics"`
	Phases      []Phase           `json:"phases,omitempty"`
	Claims      []Claim           `json:"claims,omitempty"`
	Seeds       []Seed            `json:"seeds,omitempty"`
	Hardware    HardwareInfo      `json:"hardware"`
	EnvDigest   string            `json:"env_digest"`
}

type Metric struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Step   string  `json:"step,omitempty"`
	Line   int     `json:"line"`
	Source string  `json:"source"`
}

type Phase struct {
	Name      string            `json:"name"`
	Line      int               `json:"line"`
	Timestamp string            `json:"timestamp,omitempty"`
	Counters  map[string]float64 `json:"counters,omitempty"`
}

type Claim struct {
	Metric    string  `json:"metric"`
	Operator  string  `json:"operator"`
	Value     float64 `json:"value"`
	Line      int     `json:"line"`
	Timestamp string  `json:"timestamp,omitempty"`
}

type Seed struct {
	Source    string `json:"source"`
	Value    string `json:"value"`
	Line     int    `json:"line"`
	Timestamp string `json:"timestamp,omitempty"`
}

type HardwareInfo struct {
	Hostname string  `json:"hostname"`
	OS       string  `json:"os"`
	Arch     string  `json:"arch"`
	CPUCores int     `json:"cpu_cores"`
	MemGB    float64 `json:"mem_gb"`
	GPUInfo  string  `json:"gpu_info,omitempty"`
}

type SealRecord struct {
	SessionID        string    `json:"session_id"`
	SealedAt         time.Time `json:"sealed_at"`
	DataHash         string    `json:"data_hash"`
	Nonce            string    `json:"nonce"`
	SignedAt         string    `json:"signed_at"`
	Signature        string    `json:"signature"`
	SignedMessageHash string   `json:"signed_message_hash"`
	PublicKeyPEM     string    `json:"public_key_pem"`
	ServerURL        string    `json:"server_url"`
}

// Find walks up from the working directory to find a .kveritas directory.
func Find() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(dir, DirName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("no %s directory found; run 'kveritas init' first", DirName)
}

func Load(kvDir string) (*Session, error) {
	data, err := os.ReadFile(filepath.Join(kvDir, SessionFile))
	if err != nil {
		return nil, err
	}
	var s Session
	return &s, json.Unmarshal(data, &s)
}

func (s *Session) Save(kvDir string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(kvDir, SessionFile), data, 0600)
}

func (s *Session) SaveRun(kvDir string, r *RunRecord) error {
	runsDir := filepath.Join(kvDir, RunsDir)
	if err := os.MkdirAll(runsDir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(runsDir, r.ID+".json"), data, 0600)
}

func LoadRun(kvDir, runID string) (*RunRecord, error) {
	data, err := os.ReadFile(filepath.Join(kvDir, RunsDir, runID+".json"))
	if err != nil {
		return nil, err
	}
	var r RunRecord
	return &r, json.Unmarshal(data, &r)
}

func SaveSeal(kvDir string, seal *SealRecord) error {
	data, err := json.MarshalIndent(seal, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(kvDir, SealFile), data, 0600)
}

func LoadSeal(kvDir string) (*SealRecord, error) {
	data, err := os.ReadFile(filepath.Join(kvDir, SealFile))
	if err != nil {
		return nil, err
	}
	var seal SealRecord
	return &seal, json.Unmarshal(data, &seal)
}
