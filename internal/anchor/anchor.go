package anchor

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/client"
	"github.com/Mamadou2727/kveritas-go/internal/crypto"
)

const (
	outboxFile   = "outbox.json"
	outboxLock   = "outbox.lock"
	inflightFile = "inflight.json"
	runLockFile  = "run.lock"
)

func Genesis(sessionID string) string {
	return crypto.HashBytes([]byte("kveritas-run-chain:" + sessionID))
}

func Next(prev, digest string) string {
	return crypto.HashBytes([]byte(prev + ":" + digest))
}

var mu sync.Mutex

func Pending(kvDir string) []client.RunAnchor {
	q, _ := load(kvDir)
	return q
}

func Enqueue(kvDir string, a client.RunAnchor) error {
	return withLock(kvDir, func() error {
		q, err := load(kvDir)
		if err != nil {
			return err
		}
		for _, e := range q {
			if e.Invocation == a.Invocation {
				return nil
			}
		}
		return save(kvDir, append(q, a))
	})
}

// Sends queued anchors oldest first and stops at the first failure, so the server
// never receives invocation k+1 before k.
func Flush(c *client.Client, kvDir string) (int, error) {
	q, err := load(kvDir)
	if err != nil || len(q) == 0 {
		return len(q), err
	}
	sent := map[int]bool{}
	var sendErr error
	for _, a := range q {
		if sendErr = c.SendRunAnchor(a); sendErr != nil {
			break
		}
		sent[a.Invocation] = true
	}
	var left int
	lockErr := withLock(kvDir, func() error {
		cur, err := load(kvDir)
		if err != nil {
			return err
		}
		keep := cur[:0]
		for _, a := range cur {
			if !sent[a.Invocation] {
				keep = append(keep, a)
			}
		}
		left = len(keep)
		return save(kvDir, keep)
	})
	if lockErr != nil {
		return left, lockErr
	}
	return left, sendErr
}

func Rejected(err error) bool {
	var se *client.ServerError
	return errors.As(err, &se) && se.Status >= 400 && se.Status < 500 && se.Status != 429
}

// Retries with backoff until the queue drains, the budget runs out, or the server
// rejects an anchor outright (retrying a rejection would never succeed).
func FlushWithin(c *client.Client, kvDir string, budget time.Duration) (int, error) {
	deadline := time.Now().Add(budget)
	wait := time.Second
	for {
		left, err := Flush(c, kvDir)
		if left == 0 || Rejected(err) || time.Now().Add(wait).After(deadline) {
			return left, err
		}
		time.Sleep(wait)
		if wait < 8*time.Second {
			wait *= 2
		}
	}
}

func Background(c *client.Client, kvDir string, every time.Duration) func() {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				touchInflight(kvDir)
				if len(Pending(kvDir)) > 0 {
					_, _ = Flush(c, kvDir)
				}
			}
		}
	}()
	return func() { close(done) }
}

func load(kvDir string) ([]client.RunAnchor, error) {
	data, err := os.ReadFile(filepath.Join(kvDir, outboxFile))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var q []client.RunAnchor
	if err := json.Unmarshal(data, &q); err != nil {
		return nil, fmt.Errorf("outbox unreadable: %w", err)
	}
	return q, nil
}

func save(kvDir string, q []client.RunAnchor) error {
	path := filepath.Join(kvDir, outboxFile)
	if len(q) == 0 {
		err := os.Remove(path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return writeAtomic(path, q)
}

func writeAtomic(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Guards read-modify-write of the outbox across processes: a run's background flush
// and a concurrent status or seal share the same file.
func withLock(kvDir string, fn func() error) error {
	mu.Lock()
	defer mu.Unlock()
	path := filepath.Join(kvDir, outboxLock)
	for i := 0; ; i++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			f.Close()
			break
		}
		if st, serr := os.Stat(path); serr == nil && time.Since(st.ModTime()) > 30*time.Second {
			os.Remove(path)
			continue
		}
		if i > 100 {
			return fmt.Errorf("outbox is locked by another kveritas process")
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer os.Remove(path)
	return fn()
}

type Inflight struct {
	Invocation int       `json:"invocation"`
	Index      int       `json:"index"`
	PID        int       `json:"pid"`
	Command    []string  `json:"command"`
	StartedAt  time.Time `json:"started_at"`
	LastSeen   time.Time `json:"last_seen"`
}

func BeginRun(kvDir string, inf Inflight) error {
	inf.PID = os.Getpid()
	inf.LastSeen = inf.StartedAt
	return writeAtomic(filepath.Join(kvDir, inflightFile), inf)
}

func EndRun(kvDir string) {
	os.Remove(filepath.Join(kvDir, inflightFile))
}

func LoadInflight(kvDir string) (*Inflight, bool) {
	data, err := os.ReadFile(filepath.Join(kvDir, inflightFile))
	if err != nil {
		return nil, false
	}
	var inf Inflight
	if json.Unmarshal(data, &inf) != nil {
		return nil, false
	}
	return &inf, true
}

// Keeps a last-seen time so a run killed with its terminal is recorded as ending
// roughly when it died, not when it started.
func touchInflight(kvDir string) {
	inf, ok := LoadInflight(kvDir)
	if !ok || inf.PID != os.Getpid() {
		return
	}
	inf.LastSeen = time.Now().UTC()
	_ = writeAtomic(filepath.Join(kvDir, inflightFile), inf)
}

func AcquireRun(kvDir string) (func(), error) {
	path := filepath.Join(kvDir, runLockFile)
	for i := 0; i < 2; i++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			fmt.Fprintf(f, "%d", os.Getpid())
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if pid, ok := RunLockHolder(kvDir); ok {
			return nil, fmt.Errorf("another run is in progress in this session (pid %d); wait for it to finish", pid)
		}
		os.Remove(path)
	}
	return nil, fmt.Errorf("could not take the session run lock")
}

func RunLockHolder(kvDir string) (int, bool) {
	data, err := os.ReadFile(filepath.Join(kvDir, runLockFile))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid == os.Getpid() {
		return 0, false
	}
	return pid, alive(pid)
}
