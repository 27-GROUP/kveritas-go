package runner

import (
	"bufio"
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

	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/metrics"
	"github.com/Mamadou2727/kveritas-go/internal/provenance"
	"github.com/Mamadou2727/kveritas-go/internal/session"
)

func Run(sess *session.Session, command []string, fileHints []string, opts Options) (*Result, error) {
	opts.Nodes = true
	r, err := NewRecorder(sess, command, fileHints, opts)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(command[0], command[1:]...)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		r.Abandon()
		return nil, err
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		r.Abandon()
		return nil, err
	}
	cmd.Stdin = os.Stdin
	cmd.Env = runEnv()
	if err := cmd.Start(); err != nil {
		r.Abandon()
		return nil, fmt.Errorf("failed to start %q: %w", command[0], err)
	}
	r.Attach(cmd.Process.Pid)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(stdoutPipe)
		sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			fmt.Fprintln(os.Stdout, line)
			r.Line(line)
		}
	}()
	go func() {
		defer wg.Done()
		io.Copy(r.Stderr(), io.TeeReader(stderrPipe, os.Stderr)) //nolint:errcheck
	}()
	wg.Wait()

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			exitCode = exit.ExitCode()
		}
	}
	return r.Finish(exitCode)
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
