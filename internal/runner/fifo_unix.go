//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"syscall"
)

// A named pipe reaches every process of the job by path, so launchers that close
// inherited descriptors (torchrun, multiprocessing spawn) cannot cut it. keep is the
// observer's own write end: closing it after the job exits makes the reader see EOF
// once everything written has been read.
func openFIFO() (reader, keep *os.File, path string, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "kveritas-")
	if err != nil {
		return nil, nil, "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }
	path = filepath.Join(dir, "channel")
	if err = syscall.Mkfifo(path, 0600); err != nil {
		cleanup()
		return nil, nil, "", nil, err
	}
	if reader, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err != nil {
		cleanup()
		return nil, nil, "", nil, err
	}
	if keep, err = os.OpenFile(path, os.O_WRONLY, 0); err != nil {
		reader.Close()
		cleanup()
		return nil, nil, "", nil, err
	}
	return reader, keep, path, cleanup, nil
}
