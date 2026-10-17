//go:build windows

package runner

import (
	"errors"
	"os"
)

func InheritedReader(fd int, name string) *os.File {
	return os.NewFile(uintptr(fd), name)
}

func OpenFIFOReader(path string) (*os.File, error) {
	return nil, errors.New("named pipes are not used on Windows")
}

func openFIFO() (reader, keep *os.File, path string, cleanup func(), err error) {
	return nil, nil, "", nil, errors.New("named pipes are not used on Windows")
}
