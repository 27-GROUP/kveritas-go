package runner

import (
	"os"
	"strings"
)

func runEnv() []string {
	env := os.Environ()
	for _, e := range env {
		if strings.HasPrefix(e, "PYTHONUNBUFFERED=") {
			return env
		}
	}
	// Piped Python output is block-buffered, which would delay result lines and skew
	// the hardware snapshots taken at phase boundaries.
	return append(env, "PYTHONUNBUFFERED=1")
}
