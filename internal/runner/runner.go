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
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mamadouk/kveritas/internal/bundle"
	"github.com/mamadouk/kveritas/internal/crypto"
	"github.com/mamadouk/kveritas/internal/hardware"
	"github.com/mamadouk/kveritas/internal/metrics"
	"github.com/mamadouk/kveritas/internal/session"
)

// Run executes command as a monitored subprocess.
//
// It tees stdout and stderr to the terminal while simultaneously hashing them
// and parsing metrics. Files listed in fileHints are hashed before and after
// the run; any file whose hash changes is recorded in RunRecord.Modified.
func Run(sess *session.Session, command []string, fileHints []string) (*session.RunRecord, error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("no command specified")
	}

	preHashes, err := hashFiles(fileHints)
	if err != nil {
		return nil, fmt.Errorf("pre-run file hashing: %w", err)
	}

	rec := &session.RunRecord{
		ID:        uuid.New().String()[:8],
		SessionID: sess.ID,
		Index:     len(sess.Runs),
		Command:   command,
		StartAt:   time.Now().UTC(),
		PreHashes: preHashes,
		Hardware:  hardware.Snapshot(),
		Modified:  []string{},
		Metrics:   []session.Metric{},
	}

	fmt.Fprintf(os.Stderr, "[kveritas] Monitoring: %v\n", command)

	var (
		stdoutBuf   bytes.Buffer
		stderrBuf   bytes.Buffer
		stdoutLines int
		allMetrics  []session.Metric
		mu          sync.Mutex
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

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %q: %w", command[0], err)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			fmt.Fprintln(os.Stdout, line)
			fmt.Fprintln(&stdoutBuf, line)
			if m, ok := parser.Parse(line, lineNum); ok {
				mu.Lock()
				allMetrics = append(allMetrics, *m)
				mu.Unlock()
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

	rec.EndAt = time.Now().UTC()
	rec.DurationSec = rec.EndAt.Sub(rec.StartAt).Seconds()
	rec.ExitCode = exitCode
	rec.StdoutLines = stdoutLines
	rec.StdoutHash = digestBuf(stdoutBuf.Bytes())
	rec.StderrHash = digestBuf(stderrBuf.Bytes())
	rec.Metrics = allMetrics

	postHashes, err := hashFiles(fileHints)
	if err != nil {
		return nil, fmt.Errorf("post-run file hashing: %w", err)
	}
	rec.PostHashes = postHashes

	for path, pre := range preHashes {
		if post, ok := postHashes[path]; ok && post != pre {
			rec.Modified = append(rec.Modified, path)
		}
	}
	if len(rec.Modified) > 0 {
		fmt.Fprintf(os.Stderr, "[kveritas] Warning: files modified during run: %v\n", rec.Modified)
	}

	if digest, err := envDigest(); err == nil {
		rec.EnvDigest = digest
	}

	if len(sess.SourceHashes) == 0 {
		files, err := bundle.CollectSourceFiles(sess.ProjectDir)
		if err == nil && len(files) > 0 {
			hashes, err := bundle.HashSourceFiles(sess.ProjectDir, files)
			if err == nil {
				sess.SourceHashes = hashes
				fmt.Fprintf(os.Stderr, "[kveritas] Indexed %d source files for integrity tracking\n", len(hashes))
			}
		}
	}

	parser.WarnIfEmpty()
	fmt.Fprintf(os.Stderr, "[kveritas] Run complete (%.2fs, exit %d)\n",
		rec.DurationSec, rec.ExitCode)

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
