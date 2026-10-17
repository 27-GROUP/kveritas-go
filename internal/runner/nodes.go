package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/hardware"
	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const (
	nodesDir     = "nodes"
	nodeRunFile  = "run.json"
	nodeBeat     = 5 * time.Second
	nodeLiveness = 30 * time.Second
	// A worker started this long before or after node 0 is not part of its run.
	nodeAdoptWindow = 10 * time.Minute
)

type nodeRun struct {
	RunID    string    `json:"run_id"`
	StartAt  time.Time `json:"start_at"`
	Expected int       `json:"expected,omitempty"`
}

type nodeStatus struct {
	State     string              `json:"state"`
	Node      int                 `json:"node"`
	MachineID string              `json:"machine_id"`
	RunID     string              `json:"run_id,omitempty"`
	Beat      int                 `json:"beat"`
	Record    *session.NodeRecord `json:"record,omitempty"`
}

// NodeRank is this machine's node in a multi-node run, 0 when it is the only or the
// first one. KVERITAS_NODE_RANK wins, then the launcher's own flags, then Slurm.
func NodeRank(command []string) int {
	if n, ok := envInt("KVERITAS_NODE_RANK"); ok {
		return n
	}
	if n, ok := flagInt(command, "node_rank", "node-rank", "machine_rank", "machine-rank"); ok {
		return n
	}
	for _, k := range []string{"SLURM_NODEID", "NODE_RANK", "GROUP_RANK"} {
		if n, ok := envInt(k); ok {
			return n
		}
	}
	return 0
}

// 0 means unknown: node 0 then waits only for nodes that announced themselves.
func expectedNodes(command []string) int {
	if n, ok := envInt("KVERITAS_NODES"); ok {
		return n
	}
	if n, ok := flagInt(command, "nnodes", "num_machines", "num-machines", "num_nodes", "num-nodes"); ok {
		return n
	}
	if n, ok := envInt("SLURM_STEP_NUM_NODES"); ok {
		return n
	}
	return 0
}

func envInt(key string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	return n, err == nil && n >= 0
}

// Reads --name=v and --name v; an elastic range such as 1:4 counts as its maximum.
func flagInt(args []string, names ...string) (int, bool) {
	for i, a := range args {
		for _, name := range names {
			flag := "--" + name
			var v string
			switch {
			case strings.HasPrefix(a, flag+"="):
				v = a[len(flag)+1:]
			case a == flag && i+1 < len(args):
				v = args[i+1]
			default:
				continue
			}
			if j := strings.LastIndex(v, ":"); j >= 0 {
				v = v[j+1:]
			}
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				return n, true
			}
		}
	}
	return 0, false
}

func writeJSONAtomic(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func announceRun(kvDir, runID string, start time.Time, expected int) func() {
	dir := filepath.Join(kvDir, nodesDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return func() {}
	}
	for _, st := range readNodeStatuses(dir) {
		if st.State == "done" {
			os.Remove(st.path)
		}
	}
	runPath := filepath.Join(dir, nodeRunFile)
	if err := writeJSONAtomic(runPath, nodeRun{RunID: runID, StartAt: start, Expected: expected}); err != nil {
		fmt.Fprintf(os.Stderr, "[kveritas] Warning: other nodes cannot join this run: %v\n", err)
	}
	return func() { os.Remove(runPath) }
}

type statusFile struct {
	nodeStatus
	path string
}

func readNodeStatuses(dir string) []statusFile {
	entries, _ := os.ReadDir(dir)
	var out []statusFile
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "node-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var st nodeStatus
		if json.Unmarshal(data, &st) == nil {
			out = append(out, statusFile{st, path})
		}
	}
	return out
}

func nodeWait() time.Duration {
	if v, ok := envInt("KVERITAS_NODE_WAIT"); ok {
		return time.Duration(v) * time.Second
	}
	return 5 * time.Minute
}

// collectNodes waits for every node that joined the run to finish and returns their
// records. Liveness is judged by node 0's clock watching heartbeats change, never by
// comparing clocks across machines.
func collectNodes(kvDir, runID string, expected int) []session.NodeRecord {
	dir := filepath.Join(kvDir, nodesDir)
	deadline := time.Now().Add(nodeWait())
	lastBeat := map[string]int{}
	lastChange := map[string]time.Time{}
	waited := false
	for {
		var done []statusFile
		pending := 0
		now := time.Now()
		for _, st := range readNodeStatuses(dir) {
			if st.RunID != runID && st.RunID != "" {
				continue
			}
			if st.State == "done" && st.Record != nil {
				if st.RunID == runID {
					done = append(done, st)
				}
				continue
			}
			if b, seen := lastBeat[st.path]; !seen || b != st.Beat {
				lastBeat[st.path], lastChange[st.path] = st.Beat, now
			}
			if now.Sub(lastChange[st.path]) < nodeLiveness {
				pending++
			}
		}
		if pending == 0 || now.After(deadline) {
			if pending > 0 {
				fmt.Fprintf(os.Stderr, "[kveritas] Warning: %d node(s) still running after %s; recorded without them\n", pending, nodeWait())
			}
			sort.Slice(done, func(i, j int) bool { return done[i].Node < done[j].Node })
			records := make([]session.NodeRecord, 0, len(done))
			for _, st := range done {
				records = append(records, *st.Record)
				os.Remove(st.path)
			}
			if len(records) > 0 || expected > 1 {
				fmt.Fprintf(os.Stderr, "[kveritas] Nodes: %d of %s measured\n", len(records)+1, expectedText(expected, len(records)+1))
			}
			return records
		}
		if !waited {
			fmt.Fprintf(os.Stderr, "[kveritas] Waiting for %d other node(s) to finish\n", pending)
			waited = true
		}
		time.Sleep(time.Second)
	}
}

func expectedText(expected, measured int) string {
	if expected < measured {
		return strconv.Itoa(measured)
	}
	return strconv.Itoa(expected)
}

func currentRun(dir string, workerStart time.Time) string {
	data, err := os.ReadFile(filepath.Join(dir, nodeRunFile))
	if err != nil {
		return ""
	}
	var r nodeRun
	if json.Unmarshal(data, &r) != nil {
		return ""
	}
	if d := r.StartAt.Sub(workerStart); d > nodeAdoptWindow || d < -nodeAdoptWindow {
		return ""
	}
	return r.RunID
}

type countingHash struct {
	h     hash.Hash
	lines int
	mu    sync.Mutex
}

func (c *countingHash) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines += strings.Count(string(p), "\n")
	return c.h.Write(p)
}

func (c *countingHash) sum() string { return hex.EncodeToString(c.h.Sum(nil)) }

// Measures this node the way node 0 measures its own run and hands the record to
// node 0 through the shared session folder. An empty kvDir still runs the command.
func RunNode(kvDir string, command []string, rank int) (int, error) {
	if len(command) == 0 {
		return 0, fmt.Errorf("no command specified")
	}
	machine := hardware.MachineID()
	dir := ""
	if kvDir != "" {
		dir = filepath.Join(kvDir, nodesDir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "[kveritas] Warning: node %d cannot reach the session (%v); running unmeasured\n", rank, err)
			dir = ""
		}
	}
	path := ""
	if dir != "" {
		path = filepath.Join(dir, fmt.Sprintf("node-%d-%s.json", rank, machine))
	}

	hw := hardware.Snapshot()
	hw.MachineID = machine
	start := time.Now().UTC()
	st := nodeStatus{State: "running", Node: rank, MachineID: machine}
	var stMu sync.Mutex
	write := func() {
		if path == "" {
			return
		}
		stMu.Lock()
		defer stMu.Unlock()
		if id := currentRun(dir, start); id != "" {
			st.RunID = id
		}
		st.Beat++
		if err := writeJSONAtomic(path, st); err != nil {
			fmt.Fprintf(os.Stderr, "[kveritas] Warning: node %d status not written: %v\n", rank, err)
		}
	}
	write()
	fmt.Fprintf(os.Stderr, "[kveritas] Node %d: measuring %v for the run on node 0\n", rank, command)

	sampler := hardware.NewSampler(100 * time.Millisecond)
	sampler.Start()
	stdoutH := &countingHash{h: sha256.New()}
	stderrH := &countingHash{h: sha256.New()}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.MultiWriter(os.Stdout, stdoutH)
	cmd.Stderr = io.MultiWriter(os.Stderr, stderrH)
	// A helper process that outlives the command must not hold the record back.
	cmd.WaitDelay = 3 * time.Second
	if err := cmd.Start(); err != nil {
		sampler.Stop()
		if path != "" {
			os.Remove(path)
		}
		return 0, fmt.Errorf("failed to start %q: %w", command[0], err)
	}
	sampler.SetPID(cmd.Process.Pid)

	stopBeat := make(chan struct{})
	go func() {
		t := time.NewTicker(nodeBeat)
		defer t.Stop()
		for {
			select {
			case <-stopBeat:
				return
			case <-t.C:
				write()
			}
		}
	}()

	exitCode := 0
	if err := cmd.Wait(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			exitCode = exit.ExitCode()
		} else if !errors.Is(err, exec.ErrWaitDelay) {
			exitCode = -1
		}
	}
	end := time.Now().UTC()
	close(stopBeat)
	samples := hardware.Decimate(sampler.Stop(), sampleCap())
	envDig, _, _ := envDigest(command)

	rec := &session.NodeRecord{
		Node:            rank,
		MachineID:       machine,
		StartAt:         start,
		EndAt:           end,
		DurationSec:     end.Sub(start).Seconds(),
		ExitCode:        exitCode,
		Hardware:        hw,
		StdoutHash:      stdoutH.sum(),
		StderrHash:      stderrH.sum(),
		StdoutLines:     stdoutH.lines,
		EnvDigest:       envDig,
		HardwareSamples: samples,
	}
	stMu.Lock()
	st.State, st.Record = "done", rec
	stMu.Unlock()
	write()
	switch {
	case path == "":
	case st.RunID == "":
		fmt.Fprintf(os.Stderr, "[kveritas] Warning: node %d found no run on node 0; its measurement was not joined to a run\n", rank)
	default:
		fmt.Fprintf(os.Stderr, "[kveritas] Node %d: %d samples delivered to node 0 (exit %d)\n", rank, len(samples), exitCode)
	}
	return exitCode, nil
}

func sampleCap() int {
	if v := os.Getenv("KVERITAS_SAMPLE_CAP"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 1 {
			return n
		}
	}
	return 7200
}
