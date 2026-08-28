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
	ID           string            `json:"id"`
	InitAt       time.Time         `json:"init_at"`
	ProjectDir   string            `json:"project_dir"`
	MachineID    string            `json:"machine_id"`
	Token        string            `json:"token"`
	ServerURL    string            `json:"server_url"`
	Type         string            `json:"type,omitempty"`
	Runs         []string          `json:"runs"`
	Sealed       bool              `json:"sealed"`
	SourceHashes map[string]string `json:"source_hashes,omitempty"`
	// Disclosure level for provenance: redacted (default), names, or open.
	Disclosure string `json:"disclosure,omitempty"`
	// Per-session salt for provenance leaf hashes. Kept local, never published.
	ProvSalt string `json:"prov_salt,omitempty"`
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
	EnvPackages string            `json:"env_packages,omitempty"`

	// Per-phase hardware snapshots
	Phases []PhaseEvent `json:"phases,omitempty"`
	// Inline claims committed in stdout
	Claims []InlineClaim `json:"claims,omitempty"`
	// Seed commitments declared in stdout
	Seeds []SeedCommitment `json:"seeds,omitempty"`
	// Hash of only the metric lines for ledger
	MetricHash string `json:"metric_hash,omitempty"`
	// Background hardware samples taken during the run
	HardwareSamples []HardwareSample `json:"hardware_samples,omitempty"`
	// Aggregate hash of all tracked source files
	SourceCodeHash string `json:"source_code_hash,omitempty"`
	// Author-declared model card (KVERITAS_MODEL / KVERITAS_WORKLOAD)
	Declared *DeclaredModel `json:"declared,omitempty"`
	// File and subprocess activity observed during the run (Linux only for now)
	Trace *RunTrace `json:"trace,omitempty"`
	// Content-addressed state history of the run (Merkle snapshots at boundaries)
	Provenance *Provenance `json:"provenance,omitempty"`
	// SHA-256 of the checkout bundle (open disclosure only), binding it to the report
	ProvBundleHash string `json:"prov_bundle_hash,omitempty"`
	// Attested benchmark artifacts declared via KVERITAS_ARTIFACT
	Artifacts []Artifact `json:"artifacts,omitempty"`
}

// Artifact is a model or dataset the run declared for attestation. A public
// artifact carries its plain content hash so a verifier can match it against an
// independently published reference; a private one carries a salted commitment
// that reveals nothing.
type Artifact struct {
	Role       string `json:"role"`
	Name       string `json:"name,omitempty"`
	Hash       string `json:"hash"`
	Visibility string `json:"visibility"`
	SizeBucket string `json:"size_bucket,omitempty"`
}

// Provenance is the signed state history of a run: a hash-chained series of
// content-addressed snapshots taken at run boundaries. At the default disclosure
// level file names are redacted, so the timeline proves what changed and when
// without revealing code, data, or filenames.
type Provenance struct {
	Disclosure string         `json:"disclosure"`
	Root       string         `json:"root"`
	Head       string         `json:"head"`
	FileCount  int            `json:"file_count"`
	Commits    []ProvCommit   `json:"commits"`
	Withheld   []WithheldFile `json:"withheld,omitempty"`
	Truncated  bool           `json:"truncated,omitempty"`
}

// ProvEvent is what triggered a snapshot: run_start, phase, or run_end.
type ProvEvent struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
}

// ProvChange is one file that changed between two snapshots. Path is a stable
// pseudonym unless the author disclosed real names.
type ProvChange struct {
	Op   string `json:"op"`
	Path string `json:"path"`
}

// ProvCommit is one state transition: the Merkle root of the tracked files at
// this moment, the event that produced it, and a link that binds it to the prior
// commit so the order and content cannot be altered.
type ProvCommit struct {
	Index     int          `json:"index"`
	Timestamp time.Time    `json:"timestamp"`
	PrevRoot  string       `json:"prev_root"`
	Root      string       `json:"root"`
	Event     ProvEvent    `json:"event"`
	Changed   []ProvChange `json:"changed,omitempty"`
	PrevLink  string       `json:"prev_link"`
	Link      string       `json:"link"`
}

// WithheldFile is a file the author kept out of any bundle via .kveritasignore.
// Its hash is still committed, so it is disclosed here (redacted) rather than
// silently dropped.
type WithheldFile struct {
	Path       string `json:"path"`
	Hash       string `json:"hash"`
	SizeBucket string `json:"size_bucket"`
}

// FileEvent is one file the run touched, as seen by the activity tracer. Op is
// "read" for a file that was opened but not written, or "write" for a file the
// run created or modified. Reads are coalesced to the first open of each path;
// writes carry the final content hash.
type FileEvent struct {
	Op        string    `json:"op"`
	Path      string    `json:"path"`
	Hash      string    `json:"hash,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ProcEvent is one subprocess the run spawned, as seen by the activity tracer.
type ProcEvent struct {
	PID     int       `json:"pid"`
	PPID    int       `json:"ppid"`
	Command string    `json:"command"`
	StartAt time.Time `json:"start_at"`
}

// RunTrace is the file and subprocess activity captured during a single run.
// It is reconstructed into an event tree and timeline at seal time so a reviewer
// can see what the run read, produced, and spawned, and when. Truncated is set
// when the number of distinct files exceeded the capture cap.
type RunTrace struct {
	Files     []FileEvent `json:"files,omitempty"`
	Procs     []ProcEvent `json:"procs,omitempty"`
	Truncated bool        `json:"truncated,omitempty"`
}

type Metric struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Step   string  `json:"step,omitempty"`
	Line   int     `json:"line"`
	Source string  `json:"source"`
}

type HardwareInfo struct {
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Arch     string   `json:"arch"`
	CPUCores int      `json:"cpu_cores"`
	CPUModel string   `json:"cpu_model,omitempty"`
	MemGB    float64  `json:"mem_gb"`
	GPUInfo  string   `json:"gpu_info,omitempty"`
	GPUCount int      `json:"gpu_count,omitempty"`
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
	// Extra CPU-side channels for coherence analysis (per-process, cumulative).
	CtxSwitches float64 `json:"ctx_switches,omitempty"`
	MinorFaults float64 `json:"minor_faults,omitempty"`
	Threads     float64 `json:"threads,omitempty"`
	CPUFreqMHz  float64 `json:"cpu_freq_mhz,omitempty"`
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
	Value     string    `json:"value"`
	Line      int       `json:"line"`
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

// DeclaredModel is the author-committed model card for a run, declared via the
// KVERITAS_MODEL and KVERITAS_WORKLOAD stdout directives. It is the WRITTEN claim
// that the compute-cost certificate checks against the hardware evidence.
type DeclaredModel struct {
	Params      int64   `json:"params,omitempty"`
	Arch        string  `json:"arch,omitempty"`
	Precision   string  `json:"precision,omitempty"`
	DatasetSize int64   `json:"dataset_size,omitempty"`
	Epochs      float64 `json:"epochs,omitempty"`
	BatchSize   int64   `json:"batch_size,omitempty"`
	SeqLen      int64   `json:"seq_len,omitempty"`
}

// ComputeCert is the per-run compute-cost attestation certificate: a non-deniable
// check that the declared work was physically performed on the reported hardware.
// It is derived from the declared model card and the hardware samples, and is
// recomputed at verify time so any sample or claim tampering breaks the signature.
type ComputeCert struct {
	FDeclaredFLOPs float64  `json:"f_declared_flops,omitempty"`
	GPUActiveSec   float64  `json:"gpu_active_sec,omitempty"`
	EnergyJoules   float64  `json:"energy_joules,omitempty"`
	PeakGPUMemMB   float64  `json:"peak_gpu_mem_mb,omitempty"`
	FPeakGenerous  float64  `json:"f_peak_generous,omitempty"`
	MinPJPerFLOP   float64  `json:"min_pj_per_flop,omitempty"`
	ImpliedMFU     float64  `json:"implied_mfu,omitempty"`
	TimeBoundOK    bool     `json:"time_bound_ok"`
	EnergyBoundOK  bool     `json:"energy_bound_ok"`
	MemoryBoundOK  bool     `json:"memory_bound_ok"`
	Verdict        string   `json:"verdict"`
	Notes          []string `json:"notes,omitempty"`
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
	SessionID         string    `json:"session_id"`
	SealedAt          time.Time `json:"sealed_at"`
	DataHash          string    `json:"data_hash"`
	Nonce             string    `json:"nonce"`
	SignedAt          string    `json:"signed_at"`
	Signature         string    `json:"signature"`
	SignedMessageHash string    `json:"signed_message_hash"`
	PublicKeyPEM      string    `json:"public_key_pem"`
	ServerURL         string    `json:"server_url"`
	SourceBundleHash  string    `json:"source_bundle_hash,omitempty"`
	// CanonicalJSON is the exact bytes that were hashed to produce DataHash.
	// Verifiers re-hash this directly instead of reconstructing the signing
	// data structure, making verification immune to future field additions.
	CanonicalJSON string `json:"canonical_json,omitempty"`
	VisualPDFHash string `json:"visual_pdf_hash,omitempty"`
	SealBlockHash string `json:"seal_block_hash,omitempty"`
	// SHA-256 of the combined multi-run checkout bundle, bound into the signature.
	CheckoutBundleHash string `json:"checkout_bundle_hash,omitempty"`
	// Run history from server ledger, embedded at seal time
	RunHistory    []LedgerRunEntry `json:"run_history,omitempty"`
	TotalRunCount int              `json:"total_run_count,omitempty"`
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
