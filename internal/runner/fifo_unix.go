//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"syscall"
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
	return &outChannel{
		path:    path,
		reader:  r,
		finish:  func() { w.Close() },
		close:   func() { r.Close() },
		cleanup: func() { w.Close(); r.Close(); os.RemoveAll(dir) },
	}, nil
}
