//go:build !windows

package runner

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// A named pipe reaches every process of the job by path, so launchers that close
// inherited descriptors (torchrun, multiprocessing spawn) cannot cut it, and lines
// under the pipe buffer size arrive whole even when several ranks write at once. The
// held write end keeps the pipe from reading as EOF before the program opens it.
func openOut() (*outChannel, error) {
	dir, err := os.MkdirTemp("", "kveritas-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "out")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	r, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		r.Close()
		os.RemoveAll(dir)
		return nil, err
	}
	fr := &fifoReader{f: r, stop: make(chan struct{})}
	return &outChannel{
		path:    path,
		reader:  fr,
		finish:  func() { w.Close() },
		close:   fr.close,
		cleanup: func() { w.Close(); fr.close(); os.RemoveAll(dir) },
	}, nil
}

// macOS keeps a pipe out of Go's poller (kqueue misses the last writer closing, Go
// issue 24164), so a read there returns EAGAIN instead of waiting. Retrying keeps the
// pipe drained; stopping the retries is how a lingering writer is cut off.
type fifoReader struct {
	f    *os.File
	stop chan struct{}
	once sync.Once
}

func (r *fifoReader) Read(p []byte) (int, error) {
	for {
		n, err := r.f.Read(p)
		if n > 0 || err == nil || !errors.Is(err, syscall.EAGAIN) {
			return n, err
		}
		select {
		case <-r.stop:
			return 0, io.EOF
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (r *fifoReader) close() {
	r.once.Do(func() {
		close(r.stop)
		r.f.Close()
	})
}
