package runner

import (
	"io"
	"os"
	"strings"
	"time"
)

// OutEnv names the file a program writes its result lines to, in any language. Its
// lines are hashed into the signed record like stdout, but never reach the terminal.
const OutEnv = "KVERITAS_OUT"

type outChannel struct {
	path   string
	reader io.Reader
	// finish lets the reader end once every writer is gone; close ends it at once.
	finish  func()
	close   func()
	cleanup func()
}

func runEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	buffered := true
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, OutEnv+"=") {
			continue
		}
		if strings.HasPrefix(e, "PYTHONUNBUFFERED=") {
			buffered = false
		}
		env = append(env, e)
	}
	// Piped Python output is block-buffered, which would delay result lines and skew
	// the hardware snapshots taken at phase boundaries.
	if buffered {
		env = append(env, "PYTHONUNBUFFERED=1")
	}
	return env
}

// Follows a file that writers append to, until done is closed and it is fully read.
type tailReader struct {
	f    *os.File
	done chan struct{}
}

func (t *tailReader) Read(p []byte) (int, error) {
	for {
		n, err := t.f.Read(p)
		if n > 0 {
			return n, nil
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		select {
		case <-t.done:
			if n, _ := t.f.Read(p); n > 0 {
				return n, nil
			}
			return 0, io.EOF
		case <-time.After(100 * time.Millisecond):
		}
	}
}
