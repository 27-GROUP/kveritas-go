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
	"path/filepath"
	"sort"
	"strings"

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

type Options struct {
	ShowResults bool
}

func Run(sess *session.Session, command []string, fileHints []string, opts Options) (*session.RunRecord, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("no command specified")
	}

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

	// Short interval gives enough resolution to integrate GPU energy for the compute cert.
	sampler := hardware.NewSampler(100 * time.Millisecond)
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
	kvDir := filepath.Join(sess.ProjectDir, session.DirName)
	expected := expectedNodes(command)
	endNodes := announceRun(kvDir, rec.ID, rec.StartAt, expected)
	defer endNodes()

	var (
		stdoutBuf    bytes.Buffer
		stderrBuf    bytes.Buffer
		metricLines  bytes.Buffer
		stdoutLines  int
		allMetrics   []session.Metric
		allPhases    []session.PhaseEvent
		allClaims    []session.InlineClaim
		allSeeds     []session.SeedCommitment
		allArtifacts []session.Artifact
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
	cmd.Stdin = os.Stdin
	cmd.Env = runEnv()
	out, err := openOut()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[kveritas] Warning: %s unavailable (%v); print result lines instead\n", OutEnv, err)
		cmd.Env = append(cmd.Env, OutEnv+"="+os.DevNull)
	} else {
		defer out.cleanup()
		cmd.Env = append(cmd.Env, OutEnv+"="+out.path)
	}

	// Watch the tree before the child starts so early file opens (interpreter, imports) are caught.
	obs := tracer.New(sess.ProjectDir)
	obs.Start()

	if err := cmd.Start(); err != nil {
		obs.Stop()
		return nil, fmt.Errorf("failed to start %q: %w", command[0], err)
	}
	pid := cmd.Process.Pid
	obs.SetPID(pid)
	sampler.SetPID(pid)

	// Snapshots at start, each phase, and end make the run a verifiable state timeline.
	provLevel := provenance.ParseLevel(sess.Disclosure)
	salt := decodeSalt(sess.ProvSalt)
	prov := provenance.New(sess.ProjectDir, sess.Disclosure, sess.ID, salt)
	prov.Snapshot("run_start", "")

	// The command can name a private script or dataset, so redacted keeps only the interpreter.
	rec.Command = redactCommand(command, provLevel)

	where := func(lineNum, seq int) string {
		if seq > 0 {
			return fmt.Sprintf("%s line %d", OutEnv, seq)
		}
		return fmt.Sprintf("line %d", lineNum)
	}

	// Printed lines and result-file lines share one path, serialized so phases snapshot in order.
	var lineMu sync.Mutex
	handle := func(line string, lineNum, seq int) {
		lineMu.Lock()
		defer lineMu.Unlock()

		if phaseName, ok := parser.ParsePhase(line); ok {
			pe := hardware.CapturePhaseEvent(phaseName, lineNum, pid)
			pe.Seq = seq
			mu.Lock()
			allPhases = append(allPhases, pe)
			mu.Unlock()
			prov.Snapshot("phase", phaseName)
			fmt.Fprintf(os.Stderr, "[kveritas] Phase: %s (%s, hardware snapshot captured)\n", phaseName, where(lineNum, seq))
			return
		}

		if claim, ok := parser.ParseClaim(line, lineNum); ok {
			claim.Seq = seq
			mu.Lock()
			allClaims = append(allClaims, *claim)
			mu.Unlock()
			fmt.Fprintln(&metricLines, line)
			fmt.Fprintf(os.Stderr, "[kveritas] Claim: %s=%.6g (%s)\n", claim.Metric, claim.Value, where(lineNum, seq))
			return
		}

		if parser.ParseDeclared(line, declared) {
			declaredSeen = true
			fmt.Fprintf(os.Stderr, "[kveritas] Declared model card updated (%s)\n", where(lineNum, seq))
			return
		}

		if seedVal, ok := parser.ParseSeed(line); ok {
			sc := session.SeedCommitment{
				Source:    "seed:" + seedVal,
				Value:     seedVal,
				Line:      lineNum,
				Timestamp: time.Now().UTC(),
				Seq:       seq,
			}
			mu.Lock()
			allSeeds = append(allSeeds, sc)
			mu.Unlock()
			fmt.Fprintf(os.Stderr, "[kveritas] Seed committed: %s (%s)\n", seedVal, where(lineNum, seq))
			return
		}

		if decl, ok := parser.ParseArtifact(line); ok {
			if art := buildArtifact(decl, sess.ProjectDir, salt, provLevel); art != nil {
				mu.Lock()
				allArtifacts = append(allArtifacts, *art)
				mu.Unlock()
				fmt.Fprintf(os.Stderr, "[kveritas] Artifact attested: %s (%s, %s)\n", decl.Role, art.Visibility, where(lineNum, seq))
			} else {
				// Silence here would let a mistyped path look attested to its author.
				fmt.Fprintf(os.Stderr, "[kveritas] Warning: artifact %q not attested, cannot read %s (%s)\n",
					decl.Role, decl.Path, where(lineNum, seq))
			}
			return
		}

		if m, ok := parser.Parse(line, lineNum); ok {
			m.Seq = seq
			mu.Lock()
			allMetrics = append(allMetrics, *m)
			mu.Unlock()
			fmt.Fprintln(&metricLines, line)
		} else if seq == 0 {
			heuristics := parser.ParseHeuristic(line, lineNum)
			if len(heuristics) > 0 {
				mu.Lock()
				allMetrics = append(allMetrics, heuristics...)
				mu.Unlock()
			}
		} else {
			fmt.Fprintf(os.Stderr, "[kveritas] Warning: result line %d on %s rejected: %s\n", seq, OutEnv, line)
		}
	}

	// A malformed KV line on stdout is usually ordinary output (an LLM's "KV cache"),
	// so it is noted once rather than per line.
	nearMissShown := false
	accept := func(line string, lineNum, seq int) {
		lines, ok, near := metrics.TranslateKV(line)
		switch {
		case ok:
			for _, l := range lines {
				handle(l, lineNum, seq)
			}
		case near && seq > 0:
			fmt.Fprintf(os.Stderr, "[kveritas] Warning: %s line %d is not a valid KV line: %s\n", OutEnv, seq, line)
		case near:
			if !nearMissShown {
				nearMissShown = true
				fmt.Fprintf(os.Stderr, "[kveritas] Note: output line %d starts with KV but is not a result line; ignored\n", lineNum)
			}
			handle(line, lineNum, seq)
		default:
			handle(line, lineNum, seq)
		}
		if opts.ShowResults && seq > 0 && (ok || strings.HasPrefix(line, "KVERITAS_")) {
			fmt.Fprintf(os.Stderr, "[kveritas] %s\n", line)
		}
	}

	var (
		outBuf   bytes.Buffer
		outLines int
		outDone  = make(chan struct{})
	)
	if out != nil {
		go func() {
			defer close(outDone)
			sc := bufio.NewScanner(out.reader)
			sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				outBuf.WriteString(line)
				outBuf.WriteByte('\n')
				outLines++
				accept(line, 0, outLines)
			}
		}()
	} else {
		close(outDone)
	}

	var outWG sync.WaitGroup
	outWG.Add(2)
	go func() {
		defer outWG.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			fmt.Fprintln(os.Stdout, line)
			fmt.Fprintln(&stdoutBuf, line)
			accept(line, lineNum, 0)
		}
		stdoutLines = lineNum
	}()
	go func() {
		defer outWG.Done()
		io.Copy(&stderrBuf, io.TeeReader(stderrPipe, os.Stderr)) //nolint:errcheck
	}()
	outWG.Wait()

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			exitCode = exit.ExitCode()
		}
	}
	if out != nil {
		// A descendant that outlives the run could hold the result file open forever.
		out.finish()
		select {
		case <-outDone:
		case <-time.After(3 * time.Second):
			out.close()
			<-outDone
		}
	}

	// A low cap would make the stored rate depend on duration, silently rescaling
	// anything later derived from how fast the counters move.
	hwSamples := hardware.Decimate(sampler.Stop(), sampleCap())
	if len(hwSamples) > 0 {
		fmt.Fprintf(os.Stderr, "[kveritas] Hardware sampler: %d samples collected\n", len(hwSamples))
	}

	prov.Snapshot("run_end", "")
	rec.Provenance = prov.Result()
	if len(allArtifacts) > 0 {
		rec.Artifacts = allArtifacts
	}
	if rec.Provenance != nil {
		fmt.Fprintf(os.Stderr, "[kveritas] Provenance: %d snapshots, %d files, %d withheld (%s)\n",
			len(rec.Provenance.Commits), rec.Provenance.FileCount,
			len(rec.Provenance.Withheld), rec.Provenance.Disclosure)
		if err := prov.Keystore().Save(filepath.Join(kvDir, "keystore-"+rec.ID+".json")); err != nil {
			fmt.Fprintf(os.Stderr, "[kveritas] Warning: could not write proof keystore: %v\n", err)
		}
		if provLevel >= provenance.Open {
			bundlePath := filepath.Join(kvDir, "bundle-"+rec.ID+".zip")
			if h, err := prov.WriteBundle(bundlePath); err == nil && h != "" {
				rec.ProvBundleHash = h
				fmt.Fprintf(os.Stderr, "[kveritas] Checkout bundle written (%s)\n", bundlePath)
			}
		}
	}

	// The cleartext activity map exposes real file names, so it ships only once names are disclosed.
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
	if nodes := collectNodes(kvDir, rec.ID, expected); len(nodes) > 0 || expected > 1 {
		rec.Nodes = nodes
		rec.NodesExpected = expected
		rec.Hardware.MachineID = hardware.MachineID()
	}
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
	if outLines > 0 {
		rec.ChannelHash = digestBuf(outBuf.Bytes())
		rec.ChannelMessages = outLines
	}

	var postHashes map[string]string
	var postHashErr error
	var envDig, envPackages string

	var postWg sync.WaitGroup
	postWg.Add(2)
	go func() {
		defer postWg.Done()
		postHashes, postHashErr = hashFiles(fileHints)
	}()
	go func() {
		defer postWg.Done()
		envDig, envPackages, _ = envDigest(command)
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
	rec.EnvPackages = envPackages

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

	// File-hint hashes are keyed by real paths and provenance already covers them,
	// so they are dropped at the redacted level.
	if provLevel < provenance.Names {
		rec.PreHashes = nil
		rec.PostHashes = nil
		rec.Modified = nil
		// The package list can name internal packages; redacted keeps only its digest, still signed.
		rec.EnvPackages = ""
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

func redactCommand(cmd []string, level provenance.Level) []string {
	if level >= provenance.Names || len(cmd) < 2 {
		return cmd
	}
	return []string{cmd[0], "<redacted>"}
}

// buildArtifact hashes a declared model or dataset. Public artifacts get a plain
// content hash so they can be matched to a published reference; private ones get a
// salted commitment, with the name kept only once names are disclosed.
func buildArtifact(d *metrics.ArtifactDecl, projectDir string, salt []byte, level provenance.Level) *session.Artifact {
	content, err := os.ReadFile(filepath.Join(projectDir, d.Path))
	if err != nil {
		return nil
	}
	art := &session.Artifact{Role: d.Role, Visibility: d.Visibility, SizeBucket: provenance.SizeBucket(int64(len(content)))}
	if d.Visibility == "public" {
		art.Hash = provenance.ContentHash(content)
		art.Name = d.Name
	} else {
		art.Visibility = "private"
		art.Hash = provenance.SaltedLeaf(salt, d.Path, content)
		if level >= provenance.Names {
			art.Name = d.Name
		}
	}
	return art
}

// envDigest captures the run's dependency environment. For Python it follows the
// exact interpreter that ran the code, not whatever pip is first on PATH. Returns
// the freeze content and its digest; the digest is always signed, the content is
// withheld at the redacted level.
func envDigest(command []string) (digest string, content string, err error) {
	if len(command) > 0 && strings.HasPrefix(strings.ToLower(filepath.Base(command[0])), "python") {
		interp := command[0]
		if !strings.ContainsRune(interp, filepath.Separator) {
			if resolved, e := exec.LookPath(interp); e == nil {
				interp = resolved
			}
		}
		if out, e := exec.Command(interp, "-m", "pip", "freeze").Output(); e == nil {
			return digestBuf(out), string(out), nil
		}
	}
	// Fallbacks: pip on PATH, then R, then Julia.
	for _, pip := range []string{"pip", "pip3"} {
		if out, e := exec.Command(pip, "freeze").Output(); e == nil {
			return digestBuf(out), string(out), nil
		}
	}
	if out, e := exec.Command("Rscript", "-e", "cat(paste(installed.packages()[,'Package'], installed.packages()[,'Version'], sep='==', collapse='\n'))").Output(); e == nil && len(out) > 0 {
		return digestBuf(out), string(out), nil
	}
	if out, e := exec.Command("julia", "-e", "using Pkg; for (uuid, info) in Pkg.dependencies(); println(info.name, \"==\", info.version); end").Output(); e == nil && len(out) > 0 {
		return digestBuf(out), string(out), nil
	}
	return "", "", fmt.Errorf("no package manager available (tried the run interpreter, pip, R, Julia)")
}

// MetricLinesDigest hashes the concatenated metric and claim lines for ledger
// recording; only the hash is published, not the values.
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
