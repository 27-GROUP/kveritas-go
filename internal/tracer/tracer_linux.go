//go:build linux

// Package tracer records what a run reads, writes, and spawns, from the parent
// kveritas process out of the traced program's reach. It watches the OS, not the
// process, so it is language-agnostic: inotify for file activity under the project
// directory, /proc polling for subprocesses.
package tracer

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// maxFiles caps the number of distinct files kept so a run that touches an
// enormous tree cannot produce an unbounded trace.
const maxFiles = 10000

// skipDirs are never watched: noise, or feedback on ourselves. __pycache__ is kept
// on purpose, since a warm run reads cached bytecode instead of the .py; watching
// it and normalizing the .pyc back to source keeps the "main used helper.py" edge.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".venv": true,
	"venv": true, ".kveritas": true, "dist": true, ".mypy_cache": true,
	".pytest_cache": true, ".ipynb_checkpoints": true, ".tox": true,
}

// inotify masks. The stdlib exposes these on Linux.
const (
	watchMask = syscall.IN_OPEN | syscall.IN_CLOSE_WRITE | syscall.IN_CREATE |
		syscall.IN_MOVED_TO | syscall.IN_MOVED_FROM | syscall.IN_DELETE
	eventHeader = 16 // sizeof(struct inotify_event) without the name field
)

// Observer watches a project directory and the process tree of a run.
type Observer struct {
	root string

	fd  int
	wds map[int32]string

	mu      sync.Mutex
	opened  map[string]time.Time
	wrote   map[string]time.Time
	deleted map[string]time.Time
	trunc   bool

	pid   int32
	procs map[int]session.ProcEvent
	seen  map[int]bool

	stop    chan struct{}
	wg      sync.WaitGroup
	started bool
}

// New creates an observer scoped to root. It does not start watching yet.
func New(root string) *Observer {
	abs, err := filepath.Abs(root)
	if err == nil {
		root = abs
	}
	return &Observer{
		root:    root,
		wds:     make(map[int32]string),
		opened:  make(map[string]time.Time),
		wrote:   make(map[string]time.Time),
		deleted: make(map[string]time.Time),
		procs:   make(map[int]session.ProcEvent),
		seen:    make(map[int]bool),
		stop:    make(chan struct{}),
	}
}

// Start begins watching. It never fails the run: if inotify is unavailable the
// observer simply records nothing.
func (o *Observer) Start() {
	fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
	if err != nil {
		return
	}
	o.fd = fd
	o.addWatchTree(o.root)
	o.started = true
	o.wg.Add(1)
	go o.readLoop()
}

// SetPID tells the observer which process to follow for subprocess spawns. It is
// called after the child starts.
func (o *Observer) SetPID(pid int) {
	if !o.started {
		return
	}
	atomic.StoreInt32(&o.pid, int32(pid))
	o.wg.Add(1)
	go o.procLoop()
}

// Stop ends observation and returns the assembled trace.
func (o *Observer) Stop() *session.RunTrace {
	if !o.started {
		return nil
	}
	close(o.stop)
	o.wg.Wait()
	if o.fd != 0 {
		syscall.Close(o.fd)
	}
	return o.assemble()
}

func (o *Observer) addWatchTree(dir string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		if path != dir && skipDirs[info.Name()] {
			return filepath.SkipDir
		}
		wd, werr := syscall.InotifyAddWatch(o.fd, path, watchMask)
		if werr == nil {
			o.mu.Lock()
			o.wds[int32(wd)] = path
			o.mu.Unlock()
		}
		return nil
	})
}

func (o *Observer) readLoop() {
	defer o.wg.Done()
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-o.stop:
			return
		default:
		}
		n, err := syscall.Read(o.fd, buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			return
		}
		o.parse(buf[:n])
	}
}

func (o *Observer) parse(buf []byte) {
	for off := 0; off+eventHeader <= len(buf); {
		wd := int32(binary.LittleEndian.Uint32(buf[off:]))
		mask := binary.LittleEndian.Uint32(buf[off+4:])
		nameLen := int(binary.LittleEndian.Uint32(buf[off+12:]))
		nameStart := off + eventHeader
		if nameStart+nameLen > len(buf) {
			break
		}
		name := ""
		if nameLen > 0 {
			raw := buf[nameStart : nameStart+nameLen]
			if i := bytes.IndexByte(raw, 0); i >= 0 {
				raw = raw[:i]
			}
			name = string(raw)
		}
		off = nameStart + nameLen
		o.handle(wd, mask, name)
	}
}

func (o *Observer) handle(wd int32, mask uint32, name string) {
	o.mu.Lock()
	dir := o.wds[wd]
	o.mu.Unlock()
	if dir == "" {
		return
	}
	isDir := mask&syscall.IN_ISDIR != 0
	full := dir
	if name != "" {
		full = filepath.Join(dir, name)
	}

	// A new subdirectory appears: start watching it so nothing below is missed.
	if isDir && mask&(syscall.IN_CREATE|syscall.IN_MOVED_TO) != 0 {
		if !skipDirs[name] {
			o.addWatchTree(full)
		}
		return
	}
	if isDir {
		return
	}

	now := time.Now().UTC()
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case mask&(syscall.IN_CLOSE_WRITE|syscall.IN_MOVED_TO) != 0:
		if _, ok := o.wrote[full]; !ok {
			if o.atCap() {
				o.trunc = true
				return
			}
			o.wrote[full] = now
		} else {
			o.wrote[full] = now
		}
		delete(o.deleted, full)
	case mask&syscall.IN_OPEN != 0:
		if _, ok := o.opened[full]; !ok {
			if o.atCap() {
				o.trunc = true
				return
			}
			o.opened[full] = now
		}
	case mask&(syscall.IN_DELETE|syscall.IN_MOVED_FROM) != 0:
		o.deleted[full] = now
	}
}

func (o *Observer) atCap() bool {
	return len(o.opened)+len(o.wrote) >= maxFiles
}

// procLoop follows the run's process tree and records each subprocess the first
// time it is seen.
func (o *Observer) procLoop() {
	defer o.wg.Done()
	root := int(atomic.LoadInt32(&o.pid))
	// Poll frequently: real subprocesses outlive this and /proc is cheap. Very
	// short-lived helpers may be missed, but usually surface as a file read too.
	ticker := time.NewTicker(40 * time.Millisecond)
	defer ticker.Stop()
	for {
		o.scanProcs(root)
		select {
		case <-o.stop:
			o.scanProcs(root)
			return
		case <-ticker.C:
		}
	}
}

func (o *Observer) scanProcs(root int) {
	parent := readProcTable()
	if parent == nil {
		return
	}
	now := time.Now().UTC()
	for pid := range parent {
		if pid == root || !descends(pid, root, parent) {
			continue
		}
		o.mu.Lock()
		unseen := !o.seen[pid]
		if unseen {
			o.seen[pid] = true
		}
		o.mu.Unlock()
		if !unseen {
			continue
		}
		ev := session.ProcEvent{PID: pid, PPID: parent[pid], Command: readCmdline(strconv.Itoa(pid)), StartAt: now}
		o.mu.Lock()
		o.procs[pid] = ev
		o.mu.Unlock()
	}
}

// descends reports whether pid is a descendant of root by walking parent links.
func descends(pid, root int, parent map[int]int) bool {
	for depth := 0; depth < 64; depth++ {
		pp, ok := parent[pid]
		if !ok || pp == 0 {
			return false
		}
		if pp == root {
			return true
		}
		pid = pp
	}
	return false
}

// readProcTable reads /proc once, returning a pid->ppid map. Command lines are
// read lazily, only for the descendants actually recorded, to keep each poll cheap.
func readProcTable() map[int]int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	parent := make(map[int]int, len(entries))
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// Fields after the ")" that closes comm: state, ppid, ...
		close := bytes.LastIndexByte(stat, ')')
		if close < 0 || close+2 >= len(stat) {
			continue
		}
		fields := strings.Fields(string(stat[close+2:]))
		if len(fields) < 2 {
			continue
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		parent[pid] = ppid
	}
	return parent
}

func readCmdline(pid string) string {
	raw, err := os.ReadFile("/proc/" + pid + "/cmdline")
	if err != nil || len(raw) == 0 {
		return ""
	}
	parts := bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, string(p))
	}
	return strings.Join(out, " ")
}

// assemble turns the collected maps into a timeline-ordered trace. Reads are
// files that were opened but never written; writes carry their final content
// hash. Both are relative to the project directory when possible.
func (o *Observer) assemble() *session.RunTrace {
	o.mu.Lock()
	defer o.mu.Unlock()

	files := make([]session.FileEvent, 0, len(o.opened)+len(o.wrote))
	readSeen := make(map[string]bool)
	for path, ts := range o.opened {
		if _, written := o.wrote[path]; written {
			continue
		}
		disp := o.rel(normalizeSource(path))
		if readSeen[disp] {
			continue
		}
		readSeen[disp] = true
		files = append(files, session.FileEvent{Op: "read", Path: disp, Timestamp: ts})
	}
	for path, ts := range o.wrote {
		if isCacheArtifact(path) {
			continue
		}
		hash := ""
		if _, gone := o.deleted[path]; !gone {
			if h, err := crypto.HashFile(path); err == nil {
				hash = h
			}
		}
		files = append(files, session.FileEvent{Op: "write", Path: o.rel(path), Hash: hash, Timestamp: ts})
	}

	procs := make([]session.ProcEvent, 0, len(o.procs))
	for _, p := range o.procs {
		procs = append(procs, p)
	}

	sortFiles(files)
	sortProcs(procs)

	if len(files) == 0 && len(procs) == 0 {
		return nil
	}
	return &session.RunTrace{Files: files, Procs: procs, Truncated: o.trunc}
}

// isCacheArtifact reports whether a path is generated bytecode cache rather than
// an experiment output, so it can be left out of the write list.
func isCacheArtifact(path string) bool {
	return strings.Contains(path, "/__pycache__/")
}

// normalizeSource maps a compiled bytecode file back to the source it came from
// (e.g. pkg/__pycache__/helper.cpython-312.pyc -> pkg/helper.py) so a module the
// run loaded from cache still shows up as its source file in the tree.
func normalizeSource(path string) string {
	dir := filepath.Dir(path)
	if filepath.Base(dir) != "__pycache__" {
		return path
	}
	name := filepath.Base(path)
	if !strings.HasSuffix(name, ".pyc") {
		return path
	}
	stem := strings.TrimSuffix(name, ".pyc")
	if i := strings.IndexByte(stem, '.'); i >= 0 { // drop ".cpython-312"
		stem = stem[:i]
	}
	return filepath.Join(filepath.Dir(dir), stem+".py")
}

func (o *Observer) rel(path string) string {
	if r, err := filepath.Rel(o.root, path); err == nil && !strings.HasPrefix(r, "..") {
		return r
	}
	return path
}

func sortFiles(f []session.FileEvent) {
	for i := 1; i < len(f); i++ {
		for j := i; j > 0 && f[j].Timestamp.Before(f[j-1].Timestamp); j-- {
			f[j], f[j-1] = f[j-1], f[j]
		}
	}
}

func sortProcs(p []session.ProcEvent) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].StartAt.Before(p[j-1].StartAt); j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}
