//go:build windows

package runner

import (
	"os"
	"path/filepath"
)

func openOut() (*outChannel, error) {
	dir, err := os.MkdirTemp("", "kveritas-")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	t := &tailReader{f: f, done: make(chan struct{})}
	return &outChannel{
		path:    path,
		reader:  t,
		finish:  func() { close(t.done) },
		close:   func() { f.Close() },
		cleanup: func() { f.Close(); os.RemoveAll(dir) },
	}, nil
}
