package runner

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func Run(sess *session.Session, command []string, fileHints []string) (*session.RunRecord, error) {
	return execute(sess, command, fileHints, nil)
}

// Attachment describes an already running process the observer joins instead of
// launching one: the SDK's own interpreter, a notebook kernel.
type Attachment struct {
	PID     int
	Channel *os.File
	Live    io.Writer
	// Optional: the process's own stdout and stderr, redirected through these pipes by
	// the SDK, are recorded like a wrapped run's and passed on to Echo and EchoErr.
	Stdout  *os.File
	Stderr  *os.File
	Echo    io.Writer
	EchoErr io.Writer
	exe     string
}

// Attach observes pid from now until the SDK sends bye or closes the channel.
func Attach(sess *session.Session, att *Attachment) (*session.RunRecord, error) {
	command, exe := processCommand(att.PID)
	att.exe = exe
	return execute(sess, command, nil, att)
}

func execute(sess *session.Session, command []string, fileHints []string, att *Attachment) (*session.RunRecord, error) {
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
		metricLines  bytes.Buffer // only metric/claim lines for hashing
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
	var (
		cmd        *exec.Cmd
		stdoutPipe io.ReadCloser
		stderrPipe io.ReadCloser
		chanR      *os.File
		keepW      *os.File
		dropFIFO   = func() {}
		err        error
	)
	if att == nil {
		cmd = exec.Command(command[0], command[1:]...)
		if stdoutPipe, err = cmd.StdoutPipe(); err != nil {
			return nil, err
		}
		if stderrPipe, err = cmd.StderrPipe(); err != nil {
			return nil, err
		}
		// KVERITAS_RUN tells an SDK it is inside a run even where no channel exists
		// (Windows); it then prints protocol lines instead.
		cmd.Env = append(os.Environ(), "KVERITAS_RUN=1")
		if r, k, path, cleanup, ferr := openFIFO(); ferr == nil {
			chanR, keepW, dropFIFO = r, k, cleanup
			cmd.Env = append(cmd.Env, ChannelEnv+"=fifo:"+path)
		}
	} else {
		chanR = att.Channel
		rec.Launch = "attached"
		if att.Stdout != nil {
			stdoutPipe = att.Stdout
			rec.OutputCaptured = true
		}
		if att.Stderr != nil {
			stderrPipe = att.Stderr
		}
	}

	// Watch the tree before the child starts so early file opens (interpreter, imports) are caught.
	obs := tracer.New(sess.ProjectDir)
	obs.Start()

	pid := 0
	if att == nil {
		if err := cmd.Start(); err != nil {
			obs.Stop()
			if chanR != nil {
				chanR.Close()
				keepW.Close()
				dropFIFO()
			}
			return nil, fmt.Errorf("failed to start %q: %w", command[0], err)
		}
		pid = cmd.Process.Pid
	} else {
		pid = att.PID
		if !hardware.ProcessAlive(pid) {
			obs.Stop()
			return nil, fmt.Errorf("process %d is not running", pid)
		}
	}
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
			return fmt.Sprintf("message %d", seq)
		}
		return fmt.Sprintf("line %d", lineNum)
	}

	// Printed lines and channel messages share one path, serialized so phases snapshot in order.
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
			fmt.Fprintf(os.Stderr, "[kveritas] Warning: channel message %d rejected: %s\n", seq, line)
		}
	}

	var (
		chanBuf  bytes.Buffer
		chanMsgs int
		chanGaps int
		dist     *session.Distributed
		cells    []session.NotebookCell
		chanDone = make(chan struct{})
		sawBye   bool
		byeExit  int
	)
	if chanR != nil {
		go func() {
			defer close(chanDone)
			sc := bufio.NewScanner(chanR)
			sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
			// Each sending process numbers its own messages; the record uses arrival order.
			next := map[int]int{}
			for sc.Scan() {
				raw := sc.Bytes()
				chanBuf.Write(raw)
				chanBuf.WriteByte('\n')
				var msg channelMessage
				if err := json.Unmarshal(raw, &msg); err != nil {
					fmt.Fprintf(os.Stderr, "[kveritas] Warning: unreadable channel message ignored\n")
					continue
				}
				chanMsgs++
				want := next[msg.Proc]
				if want == 0 {
					want = 1
				}
				if msg.Seq != want {
					chanGaps++
					fmt.Fprintf(os.Stderr, "[kveritas] Warning: channel message %d arrived where %d was expected\n", msg.Seq, want)
				}
				next[msg.Proc] = msg.Seq + 1
				msg.Seq = chanMsgs
				switch msg.Kind {
				case "hello":
					dist = msg.distributed()
				case "bye":
					if att != nil {
						sawBye = true
						if msg.ExitCode != nil {
							byeExit = *msg.ExitCode
						}
						return
					}
				case "cell":
					c, err := msg.cell(sess.ProjectDir)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[kveritas] Warning: could not record notebook cell: %v\n", err)
					}
					lineMu.Lock()
					cells = append(cells, c)
					lineMu.Unlock()
				default:
					if l := msg.line(); l != "" {
						handle(l, 0, msg.Seq)
					} else {
						fmt.Fprintf(os.Stderr, "[kveritas] Warning: channel message %d (%s) ignored\n", msg.Seq, msg.Kind)
					}
				}
			}
		}()
	} else {
		close(chanDone)
	}

	if att != nil && att.Live != nil {
		go streamLive(sampler, att.Live, chanDone)
	}
	// An attached process that dies never sends bye; stop reading so the run closes as interrupted.
	if att != nil {
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-chanDone:
					return
				case <-t.C:
					if !hardware.ProcessAlive(pid) {
						chanR.Close()
						return
					}
				}
			}
		}()
	}

	echoOut, echoErr := io.Writer(os.Stdout), io.Writer(os.Stderr)
	if att != nil {
		echoOut, echoErr = att.Echo, att.EchoErr
	}
	var outWG sync.WaitGroup
	if stdoutPipe != nil {
		outWG.Add(1)
		go func() {
			defer outWG.Done()
			scanner := bufio.NewScanner(stdoutPipe)
			scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
			lineNum := 0
			for scanner.Scan() {
				lineNum++
				line := scanner.Text()
				if echoOut != nil {
					fmt.Fprintln(echoOut, line)
				}
				fmt.Fprintln(&stdoutBuf, line)
				handle(line, lineNum, 0)
			}
			stdoutLines = lineNum
		}()
	}
	if stderrPipe != nil {
		outWG.Add(1)
		go func() {
			defer outWG.Done()
			var src io.Reader = stderrPipe
			if echoErr != nil {
				src = io.TeeReader(stderrPipe, echoErr)
			}
			io.Copy(&stderrBuf, src) //nolint:errcheck
		}()
	}
	if att == nil {
		outWG.Wait()
	}

	exitCode := 0
	if att == nil {
		if err := cmd.Wait(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				exitCode = exit.ExitCode()
			}
		}
		// A descendant that outlives the run could hold the pipe open forever.
		if chanR != nil {
			keepW.Close()
			select {
			case <-chanDone:
			case <-time.After(3 * time.Second):
				chanR.Close()
				<-chanDone
			}
			chanR.Close()
			dropFIFO()
		}
	} else {
		<-chanDone
		chanR.Close()
		// The SDK restores its stdout and stderr before bye; a child still holding them
		// open must not stall the record.
		done := make(chan struct{})
		go func() { outWG.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			if att.Stdout != nil {
				att.Stdout.Close()
			}
			if att.Stderr != nil {
				att.Stderr.Close()
			}
			<-done
		}
		// The channel closing without bye means the observed process died mid-run.
		exitCode = -1
		if sawBye {
			exitCode = byeExit
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
	if chanMsgs > 0 {
		rec.ChannelHash = digestBuf(chanBuf.Bytes())
		rec.ChannelMessages = chanMsgs
		rec.ChannelGaps = chanGaps
		rec.Distributed = dist
		rec.Cells = cells
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
		envCmd := command
		if att != nil && att.exe != "" {
			envCmd = []string{att.exe}
		}
		envDig, envPackages, _ = envDigest(envCmd)
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
