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
	Disclosure   string            `json:"disclosure,omitempty"`
	// Per-session salt for provenance leaf hashes. Kept local, never published.
	ProvSalt    string      `json:"prov_salt,omitempty"`
	Results     string      `json:"results,omitempty"`
	Invocations int         `json:"invocations,omitempty"`
	ChainHead   string      `json:"chain_head,omitempty"`
	Branch      string      `json:"branch,omitempty"`
	Steps       []Step      `json:"steps,omitempty"`
	Failed      []FailedRun `json:"failed,omitempty"`
}

type Step struct {
	Kind       string    `json:"kind"`
	ID         string    `json:"id"`
	At         time.Time `json:"at"`
	Branch     string    `json:"branch"`
	Message    string    `json:"message,omitempty"`
	Target     string    `json:"target,omitempty"`
	Root       string    `json:"root,omitempty"`
	Files      int       `json:"files,omitempty"`
	Invocation int       `json:"invocation"`
	Digest     string    `json:"digest"`
}

type FailedRun struct {
	Invocation int       `json:"invocation"`
	Command    []string  `json:"command"`
	ExitCode   int       `json:"exit_code"`
	At         time.Time `json:"at"`
	Branch     string    `json:"branch,omitempty"`
}

func (s *Session) CurrentBranch() string {
	if s.Branch == "" {
		return "main"
	}
	return s.Branch
}

func (s *Session) SetAside() map[string]string {
	out := map[string]string{}
	for _, st := range s.Steps {
		switch st.Kind {
		case "set-aside":
			out[st.Target] = st.Message
		case "bring-back":
			delete(out, st.Target)
		}
	}
	return out
}

func RunBranch(r *RunRecord) string {
	if r.Branch == "" {
		return "main"
	}
	return r.Branch
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

	Phases          []PhaseEvent     `json:"phases,omitempty"`
	Claims          []InlineClaim    `json:"claims,omitempty"`
	Seeds           []SeedCommitment `json:"seeds,omitempty"`
	MetricHash      string           `json:"metric_hash,omitempty"`
	HardwareSamples []HardwareSample `json:"hardware_samples,omitempty"`
	SourceCodeHash  string           `json:"source_code_hash,omitempty"`
	Declared        *DeclaredModel   `json:"declared,omitempty"`
	Trace           *RunTrace        `json:"trace,omitempty"`
	Provenance      *Provenance      `json:"provenance,omitempty"`
	ProvBundleHash  string           `json:"prov_bundle_hash,omitempty"`
	Artifacts       []Artifact       `json:"artifacts,omitempty"`
	Invocation      int              `json:"invocation,omitempty"`
	RunDigest       string           `json:"run_digest,omitempty"`
	Launch          string           `json:"launch,omitempty"`
	OutputCaptured  bool             `json:"output_captured,omitempty"`
	ChannelHash     string           `json:"channel_hash,omitempty"`
	ChannelMessages int              `json:"channel_messages,omitempty"`
	ChannelGaps     int              `json:"channel_gaps,omitempty"`
	Distributed     *Distributed     `json:"distributed,omitempty"`
	Cells           []NotebookCell   `json:"cells,omitempty"`
	Nodes           []NodeRecord     `json:"nodes,omitempty"`
	NodesExpected   int              `json:"nodes_expected,omitempty"`
	Branch          string           `json:"branch,omitempty"`
}

type SealClaim struct {
	Run    int     `json:"run"`
	Metric string  `json:"metric"`
	Value  float64 `json:"value"`
	Source string  `json:"source"`
}

type NodeRecord struct {
	Node            int              `json:"node"`
	MachineID       string           `json:"machine_id"`
	StartAt         time.Time        `json:"start_at"`
	EndAt           time.Time        `json:"end_at"`
	DurationSec     float64          `json:"duration_sec"`
	ExitCode        int              `json:"exit_code"`
	Hardware        HardwareInfo     `json:"hardware"`
	StdoutHash      string           `json:"stdout_hash"`
	StderrHash      string           `json:"stderr_hash"`
	StdoutLines     int              `json:"stdout_lines"`
	EnvDigest       string           `json:"env_digest,omitempty"`
	HardwareSamples []HardwareSample `json:"hardware_samples,omitempty"`
}

type Distributed struct {
	WorldSize      int    `json:"world_size,omitempty"`
	LocalWorldSize int    `json:"local_world_size,omitempty"`
	Nodes          int    `json:"nodes,omitempty"`
	Launcher       string `json:"launcher,omitempty"`
}

type NotebookCell struct {
	ExecCount int       `json:"exec_count"`
	Hash      string    `json:"hash"`
	Seq       int       `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
}

type Artifact struct {
	Role       string `json:"role"`
	Name       string `json:"name,omitempty"`
	Hash       string `json:"hash"`
	Visibility string `json:"visibility"`
	SizeBucket string `json:"size_bucket,omitempty"`
}

type Provenance struct {
	Disclosure string         `json:"disclosure"`
	Root       string         `json:"root"`
	Head       string         `json:"head"`
	FileCount  int            `json:"file_count"`
	Commits    []ProvCommit   `json:"commits"`
	Withheld   []WithheldFile `json:"withheld,omitempty"`
	Truncated  bool           `json:"truncated,omitempty"`
}

type ProvEvent struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
}

type ProvChange struct {
	Op   string `json:"op"`
	Path string `json:"path"`
}

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

type WithheldFile struct {
	Path       string `json:"path"`
	Hash       string `json:"hash"`
	SizeBucket string `json:"size_bucket"`
}

type FileEvent struct {
	Op        string    `json:"op"`
	Path      string    `json:"path"`
	Hash      string    `json:"hash,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

type ProcEvent struct {
	PID     int       `json:"pid"`
	PPID    int       `json:"ppid"`
	Command string    `json:"command"`
	StartAt time.Time `json:"start_at"`
}

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
	Seq    int     `json:"seq,omitempty"`
}

type HardwareInfo struct {
	Hostname  string   `json:"hostname,omitempty"`
	MachineID string   `json:"machine_id,omitempty"`
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	CPUCores  int      `json:"cpu_cores"`
	CPUModel  string   `json:"cpu_model,omitempty"`
	MemGB     float64  `json:"mem_gb"`
	GPUInfo   string   `json:"gpu_info,omitempty"`
	GPUCount  int      `json:"gpu_count,omitempty"`
	GPUNames  []string `json:"gpu_names,omitempty"`
}

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
	CtxSwitches  float64 `json:"ctx_switches,omitempty"`
	MinorFaults  float64 `json:"minor_faults,omitempty"`
	Threads      float64 `json:"threads,omitempty"`
	CPUFreqMHz   float64 `json:"cpu_freq_mhz,omitempty"`
}

type PhaseEvent struct {
	Name      string           `json:"name"`
	Line      int              `json:"line"`
	Timestamp time.Time        `json:"timestamp"`
	Counters  HardwareCounters `json:"counters"`
	Seq       int              `json:"seq,omitempty"`
}

type InlineClaim struct {
	Metric string  `json:"metric"`
	Value  float64 `json:"value"`
	Phase  string  `json:"phase,omitempty"`
	Line   int     `json:"line"`
	Seq    int     `json:"seq,omitempty"`
}

type SeedCommitment struct {
	Source    string    `json:"source"`
	Value     string    `json:"value"`
	Line      int       `json:"line"`
	Timestamp time.Time `json:"timestamp"`
	Seq       int       `json:"seq,omitempty"`
}

type HardwareSample struct {
	Timestamp time.Time        `json:"timestamp"`
	Counters  HardwareCounters `json:"counters"`
}

type HMCAResult struct {
	Score   float64         `json:"hmca_score"`
	Flags   []string        `json:"hmca_flags,omitempty"`
	Verdict string          `json:"hmca_verdict"`
	Nodes   []NodeCoherence `json:"hmca_nodes,omitempty"`
}

type NodeCoherence struct {
	Run     int     `json:"run"`
	Node    int     `json:"node"`
	Score   float64 `json:"score"`
	Verdict string  `json:"verdict"`
	Samples int     `json:"samples"`
}

type DeclaredModel struct {
	Params      int64   `json:"params,omitempty"`
	Arch        string  `json:"arch,omitempty"`
	Precision   string  `json:"precision,omitempty"`
	DatasetSize int64   `json:"dataset_size,omitempty"`
	Epochs      float64 `json:"epochs,omitempty"`
	BatchSize   int64   `json:"batch_size,omitempty"`
	SeqLen      int64   `json:"seq_len,omitempty"`
}

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

type LedgerRunEntry struct {
	RunIndex    int     `json:"run_index"`
	StartedAt   string  `json:"started_at"`
	DurationSec float64 `json:"duration_sec"`
	DurationFmt string  `json:"duration_fmt"`
	ExitCode    int     `json:"exit_code"`
	MetricHash  string  `json:"metric_hash"`
	StdoutLines int     `json:"stdout_lines"`
	Invocation  *int    `json:"invocation,omitempty"`
	RunDigest   string  `json:"run_digest,omitempty"`
	EndedAt     string  `json:"ended_at,omitempty"`
	ReceivedAt  string  `json:"received_at,omitempty"`
}

func (e LedgerRunEntry) AnchorDelay() (time.Duration, bool) {
	end, err1 := time.Parse(time.RFC3339Nano, e.EndedAt)
	got, err2 := time.Parse(time.RFC3339Nano, e.ReceivedAt)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	if d := got.Sub(end); d > 0 {
		return d, true
	}
	return 0, true
}

func DescribeAnchorDelay(d time.Duration) string {
	if d < time.Minute {
		return "at run end"
	}
	return FormatDuration(d.Seconds()) + " after run end (unwitnessed gap)"
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
	// The exact signed bytes: verifiers re-hash them, so new fields never break old reports.
	CanonicalJSON      string            `json:"canonical_json,omitempty"`
	VisualPDFHash      string            `json:"visual_pdf_hash,omitempty"`
	SealBlockHash      string            `json:"seal_block_hash,omitempty"`
	CheckoutBundleHash string            `json:"checkout_bundle_hash,omitempty"`
	RunHistory         []LedgerRunEntry  `json:"run_history,omitempty"`
	TotalRunCount      int               `json:"total_run_count,omitempty"`
	LedgerCheckpoint   *LedgerCheckpoint `json:"ledger_checkpoint,omitempty"`
}

type LedgerCheckpoint struct {
	Seq       int64  `json:"seq"`
	EntryHash string `json:"entry_hash"`
	At        string `json:"at"`
	Signature string `json:"signature"`
}

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

type ArchiveRecord struct {
	ID          string          `json:"id"`
	Version     int             `json:"version"`
	Title       string          `json:"title"`
	Authors     []RecordAuthor  `json:"authors"`
	SubmittedBy RecordAuthor    `json:"submitted_by"`
	Abstract    string          `json:"abstract"`
	Tags        []string        `json:"tags,omitempty"`
	License     string          `json:"license,omitempty"`
	Published   string          `json:"published"`
	Purpose     string          `json:"purpose,omitempty"`
	WorkType    string          `json:"type,omitempty"`
	Field       string          `json:"field,omitempty"`
	Paper       string          `json:"paper,omitempty"`
	Code        string          `json:"code,omitempty"`
	Original    string          `json:"original_code,omitempty"`
	Reports     []ArchiveReport `json:"reports"`
}

type RecordAuthor struct {
	Name        string `json:"name" yaml:"name"`
	Affiliation string `json:"affiliation,omitempty" yaml:"affiliation,omitempty"`
}

type ArchiveReport struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	SessionID    string `json:"session_id"`
	DataHash     string `json:"data_hash"`
	SealedAt     string `json:"sealed_at"`
	ReportSHA256 string `json:"report_sha256"`
	ReportSize   int64  `json:"report_size"`
	BundleSHA256 string `json:"bundle_sha256,omitempty"`
	BundleSize   int64  `json:"bundle_size,omitempty"`
}
