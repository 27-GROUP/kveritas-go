package runner

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"

	"sync"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/bundle"
	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/hardware"
	"github.com/Mamadou2727/kveritas-go/internal/metrics"
	"github.com/Mamadou2727/kveritas-go/internal/provenance"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/Mamadou2727/kveritas-go/internal/tracer"
	"github.com/google/uuid"
)

// Run executes command as a monitored subprocess.
//
// It tees stdout and stderr to the terminal while simultaneously hashing them,
// parsing metrics, capturing phase boundaries with hardware snapshots, recording
// inline claims, and tracking seed commitments.
func Run(sess *session.Session, command []string, fileHints []string) (*session.RunRecord, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("no command specified")
	}

	// Pre-hash files and snapshot hardware concurrently.
	var preHashes map[string]string
	var preHashErr error
	var hwInfo session.HardwareInfo
	var setupWg sync.WaitGroup

	setupWg.Add(2)
	go func() {
		defer setupWg.Done()
		preHashes, preHashErr = hashFiles(fileHints)
	}()
	go func() {
		defer setupWg.Done()
		hwInfo = hardware.Snapshot()
	}()
	setupWg.Wait()

	if preHashErr != nil {
		return nil, fmt.Errorf("pre-run file hashing: %w", preHashErr)
	}

	// Start background hardware sampler. A short interval gives enough resolution
	// to integrate GPU energy and active time for the compute-cost certificate.
	sampler := hardware.NewSampler(2 * time.Second)
	sampler.Start()

	rec := &session.RunRecord{
		ID:        uuid.New().String()[:8],
		SessionID: sess.ID,
		Index:     len(sess.Runs),
		Command:   command,
		StartAt:   time.Now().UTC(),
		PreHashes: preHashes,
		Hardware:  hwInfo,
		Modified:  []string{},
		Metrics:   []session.Metric{},
		Phases:    []session.PhaseEvent{},
		Claims:    []session.InlineClaim{},
		Seeds:     []session.SeedCommitment{},
	}

	fmt.Fprintf(os.Stderr, "[kveritas] Monitoring: %v\n", command)

	var (
		stdoutBuf    bytes.Buffer
		stderrBuf    bytes.Buffer
		metricLines  bytes.Buffer // only metric/claim lines for hashing
		stdoutLines  int
		allMetrics   []session.Metric
		allPhases    []session.PhaseEvent
		allClaims    []session.InlineClaim
		allSeeds     []session.SeedCommitment
		declared     = &session.DeclaredModel{}
		declaredSeen bool
		mu           sync.Mutex
	)

	parser := &metrics.Parser{}
	cmd := exec.Command(command[0], command[1:]...)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	// Start watching the project tree before the child runs so early file opens
	// (the interpreter loading the script and its imports) are captured.
	obs := tracer.New(sess.ProjectDir)
	obs.Start()

	if err := cmd.Start(); err != nil {
		obs.Stop()
		return nil, fmt.Errorf("failed to start %q: %w", command[0], err)
	}
	obs.SetPID(cmd.Process.Pid)

	// Provenance records a content-addressed snapshot at the start, at each phase,
	// and at the end, so the run becomes a tamper-evident state timeline.
	provLevel := provenance.ParseLevel(sess.Disclosure)
	salt := decodeSalt(sess.ProvSalt)
	prov := provenance.New(sess.ProjectDir, sess.Disclosure, salt)
	prov.Snapshot("run_start", "")

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		// Increase scanner buffer for long lines
		scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			fmt.Fprintln(os.Stdout, line)
			fmt.Fprintln(&stdoutBuf, line)

			if phaseName, ok := parser.ParsePhase(line); ok {
				pe := hardware.CapturePhaseEvent(phaseName, lineNum)
				mu.Lock()
				allPhases = append(allPhases, pe)
				mu.Unlock()
				prov.Snapshot("phase", phaseName)
				fmt.Fprintf(os.Stderr, "[kveritas] Phase: %s (line %d, hardware snapshot captured)\n", phaseName, lineNum)
				continue
			}

			if claim, ok := parser.ParseClaim(line, lineNum); ok {
				mu.Lock()
				allClaims = append(allClaims, *claim)
				mu.Unlock()
				fmt.Fprintln(&metricLines, line)
				fmt.Fprintf(os.Stderr, "[kveritas] Claim: %s=%.6g (line %d)\n", claim.Metric, claim.Value, lineNum)
				continue
			}

			if parser.ParseDeclared(line, declared) {
				declaredSeen = true
				fmt.Fprintf(os.Stderr, "[kveritas] Declared model card updated (line %d)\n", lineNum)
				continue
			}

			if seedVal, ok := parser.ParseSeed(line); ok {
				sc := session.SeedCommitment{
					Source:    "seed:" + seedVal,
					Value:     seedVal,
					Line:      lineNum,
					Timestamp: time.Now().UTC(),
				}
				mu.Lock()
				allSeeds = append(allSeeds, sc)
				mu.Unlock()
				fmt.Fprintf(os.Stderr, "[kveritas] Seed committed: %s (line %d)\n", seedVal, lineNum)
				continue
			}

			if m, ok := parser.Parse(line, lineNum); ok {
				mu.Lock()
				allMetrics = append(allMetrics, *m)
				mu.Unlock()
				fmt.Fprintln(&metricLines, line)
			} else {
				heuristics := parser.ParseHeuristic(line, lineNum)
				if len(heuristics) > 0 {
					mu.Lock()
					allMetrics = append(allMetrics, heuristics...)
					mu.Unlock()
				}
			}
		}
		stdoutLines = lineNum
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		tee := io.TeeReader(stderrPipe, os.Stderr)
		io.Copy(&stderrBuf, tee) //nolint:errcheck
	}()

	wg.Wait()

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			exitCode = exit.ExitCode()
		}
	}

	hwSamples := sampler.Stop()
	if len(hwSamples) > 0 {
		fmt.Fprintf(os.Stderr, "[kveritas] Hardware sampler: %d samples collected\n", len(hwSamples))
	}

	prov.Snapshot("run_end", "")
	rec.Provenance = prov.Result()
	if rec.Provenance != nil {
		fmt.Fprintf(os.Stderr, "[kveritas] Provenance: %d snapshots, %d files, %d withheld (%s)\n",
			len(rec.Provenance.Commits), rec.Provenance.FileCount,
			len(rec.Provenance.Withheld), rec.Provenance.Disclosure)
	}

	// The cleartext activity map exposes real file names, so it only ships once the
	// author has chosen to disclose names.
	trace := obs.Stop()
	if provLevel >= provenance.Names {
		rec.Trace = trace
		if trace != nil {
			fmt.Fprintf(os.Stderr, "[kveritas] Activity trace: %d files, %d subprocesses\n",
				len(trace.Files), len(trace.Procs))
		}
	}

	rec.EndAt = time.Now().UTC()
	rec.DurationSec = rec.EndAt.Sub(rec.StartAt).Seconds()
	rec.DurationFmt = session.FormatDuration(rec.DurationSec)
	rec.ExitCode = exitCode
	rec.StdoutLines = stdoutLines
	rec.StdoutHash = digestBuf(stdoutBuf.Bytes())
	rec.StderrHash = digestBuf(stderrBuf.Bytes())
	rec.Metrics = allMetrics
	rec.Phases = allPhases
	rec.Claims = allClaims
	rec.Seeds = allSeeds
	rec.MetricHash = digestBuf(metricLines.Bytes())
	rec.HardwareSamples = hwSamples
	if declaredSeen {
		rec.Declared = declared
	}

	// Post-run: hash files, env digest, and source indexing concurrently.
	var postHashes map[string]string
	var postHashErr error
	var envDig string

	var postWg sync.WaitGroup
	postWg.Add(2)
	go func() {
		defer postWg.Done()
		postHashes, postHashErr = hashFiles(fileHints)
	}()
	go func() {
		defer postWg.Done()
		envDig, _ = envDigest()
	}()

	if len(sess.SourceHashes) == 0 {
		postWg.Add(1)
		go func() {
			defer postWg.Done()
			files, err := bundle.CollectSourceFiles(sess.ProjectDir)
			if err == nil && len(files) > 0 {
				hashes, err := bundle.HashSourceFiles(sess.ProjectDir, files)
				if err == nil {
					sess.SourceHashes = hashes
					fmt.Fprintf(os.Stderr, "[kveritas] Indexed %d source files for integrity tracking\n", len(hashes))
				}
			}
		}()
	}

	postWg.Wait()

	if postHashErr != nil {
		return nil, fmt.Errorf("post-run file hashing: %w", postHashErr)
	}
	rec.PostHashes = postHashes
	rec.EnvDigest = envDig

	if len(sess.SourceHashes) > 0 {
		rec.SourceCodeHash = computeAggregateSourceHash(sess.SourceHashes)
	}

	for path, pre := range preHashes {
		if post, ok := postHashes[path]; ok && post != pre {
			rec.Modified = append(rec.Modified, path)
		}
	}
	if len(rec.Modified) > 0 {
		fmt.Fprintf(os.Stderr, "[kveritas] Warning: files modified during run: %v\n", rec.Modified)
	}

	parser.WarnIfEmpty()
	fmt.Fprintf(os.Stderr, "[kveritas] Run complete (%s, exit %d)\n",
		rec.DurationFmt, rec.ExitCode)

	return rec, nil
}

func hashFiles(paths []string) (map[string]string, error) {
	result := make(map[string]string, len(paths))
	for _, p := range paths {
		h, err := crypto.HashFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		result[p] = h
	}
	return result, nil
}

func digestBuf(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func decodeSalt(s string) []byte {
	if b, err := hex.DecodeString(s); err == nil && len(b) > 0 {
		return b
	}
	return []byte(s)
}

func envDigest() (string, error) {
	// Python: pip freeze
	for _, pip := range []string{"pip", "pip3"} {
		out, err := exec.Command(pip, "freeze").Output()
		if err == nil {
			return digestBuf(out), nil
		}
	}
	// R: installed.packages()
	out, err := exec.Command("Rscript", "-e", "cat(paste(installed.packages()[,'Package'], installed.packages()[,'Version'], sep='==', collapse='\n'))").Output()
	if err == nil && len(out) > 0 {
		return digestBuf(out), nil
	}
	// Julia: Pkg.status()
	out, err = exec.Command("julia", "-e", "using Pkg; for (uuid, info) in Pkg.dependencies(); println(info.name, \"==\", info.version); end").Output()
	if err == nil && len(out) > 0 {
		return digestBuf(out), nil
	}
	return "", fmt.Errorf("no package manager available (tried pip, R, Julia)")
}

// MetricLinesDigest computes the hash of concatenated explicit metric and claim
// lines from the run's stdout, for ledger recording. The actual values stay
// private; only the hash is published.
func MetricLinesDigest(metricLines []string) string {
	h := sha256.New()
	for _, l := range metricLines {
		h.Write([]byte(l))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func computeAggregateSourceHash(hashes map[string]string) string {
	if len(hashes) == 0 {
		return ""
	}
	paths := make([]string, 0, len(hashes))
	for p := range hashes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write([]byte(":"))
		h.Write([]byte(hashes[p]))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
