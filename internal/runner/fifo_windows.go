//go:build windows

package runner

import (
	"errors"
	"os"
)

func openFIFO() (reader, keep *os.File, path string, cleanup func(), err error) {
	return nil, nil, "", nil, errors.New("named pipes are not used on Windows")
}
