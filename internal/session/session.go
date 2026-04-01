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
	Runs         []string          `json:"runs"`
	Sealed       bool              `json:"sealed"`
	SourceHashes map[string]string `json:"source_hashes,omitempty"`
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
	Hardware    HardwareInfo      `json:"hardware"`
	EnvDigest   string            `json:"env_digest"`

	// Per-phase hardware snapshots (Addition 1)
	Phases     []PhaseEvent   `json:"phases,omitempty"`
	// Inline claims committed in stdout (Addition 2)
	Claims     []InlineClaim  `json:"claims,omitempty"`
	// Seed commitments declared in stdout (Addition 4)
	Seeds      []SeedCommitment `json:"seeds,omitempty"`
	// Hash of only the metric lines for ledger (Addition 3)
	MetricHash string          `json:"metric_hash,omitempty"`
	// Background hardware samples taken during the run
	HardwareSamples []HardwareSample `json:"hardware_samples,omitempty"`
	// Aggregate hash of all tracked source files
	SourceCodeHash string `json:"source_code_hash,omitempty"`
}

type Metric struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Step   string  `json:"step,omitempty"`
	Line   int     `json:"line"`
	Source string  `json:"source"`
}

type HardwareInfo struct {
	Hostname string  `json:"hostname"`
	OS       string  `json:"os"`
	Arch     string  `json:"arch"`
	CPUCores int     `json:"cpu_cores"`
	CPUModel string  `json:"cpu_model,omitempty"`
	MemGB    float64 `json:"mem_gb"`
	GPUInfo  string  `json:"gpu_info,omitempty"`
	GPUCount int     `json:"gpu_count,omitempty"`
	GPUNames []string `json:"gpu_names,omitempty"`
}

// HardwareCounters captures detailed hardware state at a point in time.
// Values are best-effort; zero means the counter was unavailable.
type HardwareCounters struct {
	CPUTimeSec   float64 `json:"cpu_time_sec"`
	MemUsedGB    float64 `json:"mem_used_gb"`
	GPUUtilPct   float64 `json:"gpu_util_pct,omitempty"`
	GPUMemUsedMB float64 `json:"gpu_mem_used_mb,omitempty"`
	GPUTempC     float64 `json:"gpu_temp_c,omitempty"`
	GPUPowerW    float64 `json:"gpu_power_w,omitempty"`
	CPUTempC     float64 `json:"cpu_temp_c,omitempty"`
	DiskReadMB   float64 `json:"disk_read_mb"`
	DiskWriteMB  float64 `json:"disk_write_mb"`
}

// PhaseEvent records a KVERITAS_PHASE boundary with hardware state.
type PhaseEvent struct {
	Name      string           `json:"name"`
	Line      int              `json:"line"`
	Timestamp time.Time        `json:"timestamp"`
	Counters  HardwareCounters `json:"counters"`
}

// InlineClaim records a KVERITAS_CLAIM committed inside stdout.
type InlineClaim struct {
	Metric string  `json:"metric"`
	Value  float64 `json:"value"`
	Phase  string  `json:"phase,omitempty"`
	Line   int     `json:"line"`
}

// SeedCommitment records a KVERITAS_INPUT seed declaration.
type SeedCommitment struct {
	Source    string    `json:"source"`
	Value    string    `json:"value"`
	Line     int       `json:"line"`
	Timestamp time.Time `json:"timestamp"`
}

// HardwareSample is a timestamped hardware reading taken during a run.
type HardwareSample struct {
	Timestamp time.Time        `json:"timestamp"`
	Counters  HardwareCounters `json:"counters"`
}

// HMCAResult is the output of the Hardware-Metric Consistency Analyzer.
type HMCAResult struct {
	Score   float64  `json:"hmca_score"`
	Flags   []string `json:"hmca_flags,omitempty"`
	Verdict string   `json:"hmca_verdict"`
}

// LedgerRunEntry is a run record from the server ledger (no actual metric values).
type LedgerRunEntry struct {
	RunIndex    int     `json:"run_index"`
	StartedAt   string  `json:"started_at"`
	DurationSec float64 `json:"duration_sec"`
	DurationFmt string  `json:"duration_fmt"`
	ExitCode    int     `json:"exit_code"`
	MetricHash  string  `json:"metric_hash"`
	StdoutLines int     `json:"stdout_lines"`
}

type SealRecord struct {
	SessionID        string    `json:"session_id"`
	SealedAt         time.Time `json:"sealed_at"`
	DataHash         string    `json:"data_hash"`
	Nonce            string    `json:"nonce"`
	SignedAt         string    `json:"signed_at"`
	Signature        string    `json:"signature"`
	SignedMessageHash string `json:"signed_message_hash"`
	PublicKeyPEM      string `json:"public_key_pem"`
	ServerURL         string `json:"server_url"`
	SourceBundleHash  string `json:"source_bundle_hash,omitempty"`
	// CanonicalJSON is the exact bytes that were hashed to produce DataHash.
	// Verifiers re-hash this directly instead of reconstructing the signing
	// data structure, making verification immune to future field additions.
	CanonicalJSON    string `json:"canonical_json,omitempty"`
	// Run history from server ledger, embedded at seal time (Addition 3)
	RunHistory       []LedgerRunEntry `json:"run_history,omitempty"`
	TotalRunCount    int              `json:"total_run_count,omitempty"`
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

// FormatDuration formats seconds into a human-readable string.
func FormatDuration(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%.1f seconds", seconds)
	}
	d := time.Duration(seconds * float64(time.Second))
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%d minutes %d seconds", m, s)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		return fmt.Sprintf("%d hours %d minutes", h, m)
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	if days < 30 {
		return fmt.Sprintf("%d days %d hours", days, h)
	}
	months := days / 30
	remainDays := days % 30
	return fmt.Sprintf("%d months %d days", months, remainDays)
}
