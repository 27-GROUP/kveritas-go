//go:build !windows

package runner

import (
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// A named pipe reaches every process of the job by path, so launchers that close
// inherited descriptors (torchrun, multiprocessing spawn) cannot cut it. keep is the
// observer's own write end: closing it after the job exits makes the reader see EOF
// once everything written has been read.
// Inherited pipes arrive blocking; non-blocking ones go through Go's poller, so Close
// can interrupt a read that a lingering writer (a multiprocessing helper) never ends.
func InheritedReader(fd int, name string) *os.File {
	_ = syscall.SetNonblock(fd, true)
	return os.NewFile(uintptr(fd), name)
}

// A pipe no writer has opened yet reads as EOF, which would end an attached run
// before the SDK connects. A write end is held until release, called once the
// SDK is connected so the SDK closing the pipe still reads as EOF. Safe to call twice.
func OpenFIFOReader(path string) (reader *os.File, release func(), err error) {
	if reader, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0); err != nil {
		return nil, nil, err
	}
	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		reader.Close()
		return nil, nil, err
	}
	var once sync.Once
	return reader, func() { once.Do(func() { w.Close() }) }, nil
}

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
