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
	// Block-buffered Python output would delay result lines and skew phase snapshots.
	return append(env, "PYTHONUNBUFFERED=1")
}
