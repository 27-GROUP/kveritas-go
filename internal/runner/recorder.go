package runner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/bundle"
	"github.com/Mamadou2727/kveritas-go/internal/compute"
	"github.com/Mamadou2727/kveritas-go/internal/hardware"
	"github.com/Mamadou2727/kveritas-go/internal/metrics"
	"github.com/Mamadou2727/kveritas-go/internal/provenance"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/Mamadou2727/kveritas-go/internal/tracer"
	"github.com/google/uuid"
)

type Options struct {
	Autolog  bool
	FindAuto bool
	Launch   string
	Nodes    bool
	Log      io.Writer
}

type Result struct {
	Record   *session.RunRecord
	Declared bool
	Auto     []session.Metric
}

type Recorder struct {
	sess      *session.Session
	command   []string
	fileHints []string
	opts      Options
	log       io.Writer
	rec       *session.RunRecord
	kvDir     string
	expected  int
	endNodes  func()
	sampler   *hardware.Sampler
	obs       *tracer.Observer
	prov      *provenance.Recorder
	provLevel provenance.Level
	salt      []byte
	pid       int
	srcHashes map[string]string

	parser    *metrics.Parser
	auto      *metrics.Auto
	declared  *session.DeclaredModel
	declSeen  bool
	nearMiss  bool
	lineNum   int
	stdoutBuf bytes.Buffer
	stderrBuf bytes.Buffer
	metricBuf bytes.Buffer
	mu        sync.Mutex

	explicit  []session.Metric
	autoLines []session.Metric
	phases    []session.PhaseEvent
	claims    []session.InlineClaim
	seeds     []session.SeedCommitment
	artifacts []session.Artifact
}

func NewRecorder(sess *session.Session, command, fileHints []string, opts Options) (*Recorder, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("no command specified")
	}
	r := &Recorder{sess: sess, command: command, fileHints: fileHints, opts: opts, log: opts.Log,
		parser: &metrics.Parser{}, auto: &metrics.Auto{}, declared: &session.DeclaredModel{}}
	if r.log == nil {
		r.log = os.Stderr
	}

	var preHashes map[string]string
	var preErr error
	var hw session.HardwareInfo
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); preHashes, preErr = hashFiles(fileHints) }()
	go func() { defer wg.Done(); hw = hardware.Snapshot() }()
	// Each run hashes its own source, so seal compares against the latest run.
	go func() {
		defer wg.Done()
		if files, err := bundle.CollectSourceFiles(sess.ProjectDir); err == nil && len(files) > 0 {
			r.srcHashes = provenance.HashFilesCached(sess.ProjectDir, filepath.Join(sess.ProjectDir, session.DirName), files)
		}
	}()
	wg.Wait()
	if preErr != nil {
		return nil, fmt.Errorf("pre-run file hashing: %w", preErr)
	}

	r.sampler = hardware.NewSampler(100 * time.Millisecond)
	r.sampler.Start()
	r.rec = &session.RunRecord{
		ID:        uuid.New().String()[:8],
		SessionID: sess.ID,
		Index:     len(sess.Runs),
		Command:   command,
		StartAt:   time.Now().UTC(),
		PreHashes: preHashes,
		Hardware:  hw,
		Modified:  []string{},
		Metrics:   []session.Metric{},
		Phases:    []session.PhaseEvent{},
		Claims:    []session.InlineClaim{},
		Seeds:     []session.SeedCommitment{},
		Launch:    opts.Launch,
	}
	fmt.Fprintf(r.log, "[kveritas] Monitoring: %v\n", command)
	r.kvDir = filepath.Join(sess.ProjectDir, session.DirName)
	r.endNodes = func() {}
	if opts.Nodes {
		r.expected = expectedNodes(command)
		r.endNodes = announceRun(r.kvDir, r.rec.ID, r.rec.StartAt, r.expected)
	}
	// Watch the tree before the child starts so early file opens (interpreter, imports) are caught.
	r.obs = tracer.New(sess.ProjectDir)
	r.obs.Start()
	return r, nil
}

func (r *Recorder) Attach(pid int) {
	r.pid = pid
	r.obs.SetPID(pid)
	r.sampler.SetPID(pid)
	r.provLevel = provenance.ParseLevel(r.sess.Disclosure)
	r.salt = decodeSalt(r.sess.ProvSalt)
	r.prov = provenance.New(r.sess.ProjectDir, r.sess.Disclosure, r.sess.ID, r.salt)
	r.prov.Snapshot("run_start", "")
	// The command can name a private script or dataset, so redacted keeps only the interpreter.
	r.rec.Command = redactCommand(r.command, r.provLevel)
}

func (r *Recorder) Abandon() {
	r.obs.Stop()
	r.sampler.Stop()
	r.endNodes()
}

func (r *Recorder) Stderr() io.Writer { return &r.stderrBuf }

func (r *Recorder) Line(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lineNum++
	r.stdoutBuf.WriteString(line)
	r.stdoutBuf.WriteByte('\n')
	lines, ok, near := metrics.TranslateKV(line)
	if ok {
		for _, l := range lines {
			r.handle(l)
		}
		return
	}
	// Usually ordinary output (an LLM's "KV cache"), so noted once.
	if near && !r.nearMiss {
		r.nearMiss = true
		fmt.Fprintf(r.log, "[kveritas] Note: output line %d starts with KV but is not a result line; ignored\n", r.lineNum)
	}
	if !r.handle(line) && (r.opts.Autolog || r.opts.FindAuto) {
		r.autoLines = append(r.autoLines, r.auto.Line(line, r.lineNum)...)
	}
}

func (r *Recorder) handle(line string) bool {
	n := r.lineNum
	where := fmt.Sprintf("line %d", n)
	if name, ok := r.parser.ParsePhase(line); ok {
		r.phases = append(r.phases, hardware.CapturePhaseEvent(name, n, r.pid))
		r.prov.Snapshot("phase", name)
		fmt.Fprintf(r.log, "[kveritas] Phase: %s (%s, hardware snapshot captured)\n", name, where)
		return true
	}
	if c, ok := r.parser.ParseClaim(line, n); ok {
		r.claims = append(r.claims, *c)
		fmt.Fprintln(&r.metricBuf, line)
		fmt.Fprintf(r.log, "[kveritas] Claim: %s=%.6g (%s)\n", c.Metric, c.Value, where)
		return true
	}
	if r.parser.ParseDeclared(line, r.declared) {
		r.declSeen = true
		fmt.Fprintf(r.log, "[kveritas] Declared model card updated (%s)\n", where)
		return true
	}
	if v, ok := r.parser.ParseSeed(line); ok {
		r.seeds = append(r.seeds, session.SeedCommitment{Source: "seed:" + v, Value: v, Line: n, Timestamp: time.Now().UTC()})
		fmt.Fprintf(r.log, "[kveritas] Seed committed: %s (%s)\n", v, where)
		return true
	}
	if d, ok := r.parser.ParseArtifact(line); ok {
		if art := buildArtifact(d, r.sess.ProjectDir, r.salt, r.provLevel); art != nil {
			r.artifacts = append(r.artifacts, *art)
			fmt.Fprintf(r.log, "[kveritas] Artifact attested: %s (%s, %s)\n", d.Role, art.Visibility, where)
		} else {
			fmt.Fprintf(r.log, "[kveritas] Warning: artifact %q not attested, cannot read %s (%s)\n", d.Role, d.Path, where)
		}
		return true
	}
	if m, ok := r.parser.Parse(line, n); ok {
		r.explicit = append(r.explicit, *m)
		fmt.Fprintln(&r.metricBuf, line)
		return true
	}
	return false
}

func (r *Recorder) Finish(exitCode int) (*Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer r.endNodes()
	rec := r.rec

	// A low cap would make the stored rate depend on duration.
	samples := hardware.Decimate(r.sampler.Stop(), sampleCap())
	if len(samples) > 0 {
		fmt.Fprintf(r.log, "[kveritas] Hardware sampler: %d samples collected\n", len(samples))
	}

	r.prov.Snapshot("run_end", "")
	rec.Provenance = r.prov.Result()
	if len(r.artifacts) > 0 {
		rec.Artifacts = r.artifacts
	}
	if rec.Provenance != nil {
		fmt.Fprintf(r.log, "[kveritas] Provenance: %d snapshots, %d files, %d withheld (%s)\n",
			len(rec.Provenance.Commits), rec.Provenance.FileCount, len(rec.Provenance.Withheld), rec.Provenance.Disclosure)
		if err := r.prov.Keystore().Save(filepath.Join(r.kvDir, "keystore-"+rec.ID+".json")); err != nil {
			fmt.Fprintf(r.log, "[kveritas] Warning: could not write proof keystore: %v\n", err)
		}
		if r.provLevel >= provenance.Open {
			path := filepath.Join(r.kvDir, "bundle-"+rec.ID+".zip")
			if h, err := r.prov.WriteBundle(path); err == nil && h != "" {
				rec.ProvBundleHash = h
				fmt.Fprintf(r.log, "[kveritas] Checkout bundle written (%s)\n", path)
			}
		}
	}

	// The activity map exposes real file names, so it ships only once names are disclosed.
	trace := r.obs.Stop()
	if r.provLevel >= provenance.Names {
		rec.Trace = trace
		if trace != nil {
			fmt.Fprintf(r.log, "[kveritas] Activity trace: %d files, %d subprocesses\n", len(trace.Files), len(trace.Procs))
		}
	}

	rec.EndAt = time.Now().UTC()
	rec.DurationSec = rec.EndAt.Sub(rec.StartAt).Seconds()
	rec.DurationFmt = session.FormatDuration(rec.DurationSec)
	rec.ExitCode = exitCode
	if r.opts.Nodes {
		if nodes := collectNodes(r.kvDir, rec.ID, r.expected); len(nodes) > 0 || r.expected > 1 {
			rec.Nodes = nodes
			rec.NodesExpected = r.expected
			rec.Hardware.MachineID = hardware.MachineID()
		}
	}
	rec.StdoutLines = r.lineNum
	rec.StdoutHash = digestBuf(r.stdoutBuf.Bytes())
	rec.StderrHash = digestBuf(r.stderrBuf.Bytes())
	rec.Phases = r.phases
	rec.Claims = r.claims
	rec.Seeds = r.seeds
	rec.MetricHash = digestBuf(r.metricBuf.Bytes())
	rec.HardwareSamples = samples
	if r.declSeen {
		rec.Declared = r.declared
	}

	var auto []session.Metric
	if r.opts.Autolog || r.opts.FindAuto {
		auto = mergeAuto(r.explicit, r.autoLines, metrics.AutoFiles(r.sess.ProjectDir, rec.StartAt))
	}
	rec.Metrics = append([]session.Metric{}, r.explicit...)
	if r.opts.Autolog {
		rec.Metrics = append(rec.Metrics, auto...)
	}
	rec.Metrics = append(rec.Metrics, measured(rec)...)

	var postHashes map[string]string
	var postErr error
	var envDig, envPackages string
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); postHashes, postErr = hashFiles(r.fileHints) }()
	go func() { defer wg.Done(); envDig, envPackages, _ = envDigest(r.command) }()
	wg.Wait()
	if postErr != nil {
		return nil, fmt.Errorf("post-run file hashing: %w", postErr)
	}
	rec.PostHashes = postHashes
	rec.EnvDigest = envDig
	rec.EnvPackages = envPackages
	if len(r.srcHashes) > 0 {
		if len(r.sess.SourceHashes) == 0 {
			fmt.Fprintf(r.log, "[kveritas] Indexed %d source files for integrity tracking\n", len(r.srcHashes))
		}
		r.sess.SourceHashes = r.srcHashes
		rec.SourceCodeHash = computeAggregateSourceHash(r.srcHashes)
	}
	for path, pre := range rec.PreHashes {
		if post, ok := postHashes[path]; ok && post != pre {
			rec.Modified = append(rec.Modified, path)
		}
	}
	if len(rec.Modified) > 0 {
		fmt.Fprintf(r.log, "[kveritas] Warning: files modified during run: %v\n", rec.Modified)
	}
	if r.provLevel < provenance.Names {
		rec.PreHashes = nil
		rec.PostHashes = nil
		rec.Modified = nil
		// The package list can name internal packages; redacted keeps only its digest, still signed.
		rec.EnvPackages = ""
	}

	kept := 0
	if r.opts.Autolog {
		kept = len(auto)
	}
	r.parser.Summary(r.log, kept)
	fmt.Fprintf(r.log, "[kveritas] Run complete (%s, exit %d)\n", rec.DurationFmt, rec.ExitCode)
	return &Result{Record: rec, Declared: r.parser.Declared(), Auto: auto}, nil
}

// Declared names win, and a metric file beats the console line that echoed it.
func mergeAuto(explicit, lines, files []session.Metric) []session.Metric {
	have := map[string]bool{}
	for _, m := range explicit {
		have[m.Name] = true
	}
	fromFiles := map[string]bool{}
	for _, m := range files {
		fromFiles[m.Name] = true
	}
	var out []session.Metric
	for _, m := range files {
		if !have[m.Name] {
			out = append(out, m)
		}
	}
	for _, m := range lines {
		if !have[m.Name] && !fromFiles[m.Name] {
			out = append(out, m)
		}
	}
	return out
}

func measured(rec *session.RunRecord) []session.Metric {
	var out []session.Metric
	add := func(name string, v float64) {
		if v > 0 {
			r, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'g', 6, 64), 64)
			out = append(out, session.Metric{Name: name, Value: r, Source: "measured"})
		}
	}
	add("wall_time_s", rec.DurationSec)
	var cpu, mem, gpu, energy, gpuMem float64
	for _, s := range append([][]session.HardwareSample{rec.HardwareSamples}, nodeSamples(rec)...) {
		if len(s) > 1 {
			cpu += s[len(s)-1].Counters.CPUTimeSec - s[0].Counters.CPUTimeSec
		}
		for _, x := range s {
			mem = max(mem, x.Counters.MemUsedGB)
		}
		g, e, gm, _ := compute.Usage(s)
		gpu, energy, gpuMem = gpu+g, energy+e, gpuMem+gm
	}
	add("cpu_time_s", cpu)
	add("peak_memory_gb", mem)
	add("gpu_time_s", gpu)
	add("gpu_energy_j", energy)
	add("peak_gpu_memory_mb", gpuMem)
	return out
}

func nodeSamples(rec *session.RunRecord) [][]session.HardwareSample {
	var out [][]session.HardwareSample
	for _, n := range rec.Nodes {
		out = append(out, n.HardwareSamples)
	}
	return out
}
