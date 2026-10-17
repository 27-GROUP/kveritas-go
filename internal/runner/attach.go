package runner

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/hardware"
)

// The record keeps only the interpreter's name, since its full path can name a home
// folder; the full path is returned separately to read the package list.
func processCommand(pid int) (args []string, exe string) {
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); err == nil {
			args = strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
		}
		exe, _ = os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	}
	if len(args) == 0 || args[0] == "" {
		if out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output(); err == nil {
			args = strings.Fields(string(bytes.TrimSpace(out)))
		}
	}
	if len(args) == 0 {
		return []string{"pid:" + strconv.Itoa(pid)}, ""
	}
	if exe == "" {
		exe = args[0]
	}
	args[0] = filepath.Base(args[0])
	return args, exe
}

type liveSample struct {
	Kind      string  `json:"kind"`
	Timestamp string  `json:"timestamp"`
	CPUTime   float64 `json:"cpu_time_sec"`
	MemGB     float64 `json:"mem_used_gb"`
	GPUUtil   float64 `json:"gpu_util_pct"`
	GPUMemMB  float64 `json:"gpu_mem_used_mb"`
	GPUPowerW float64 `json:"gpu_power_w"`
}

// Display only: what the SDK shows while the run goes. It never feeds the record.
func streamLive(s *hardware.Sampler, w io.Writer, done <-chan struct{}) {
	enc := json.NewEncoder(w)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if smp, ok := s.Latest(); ok {
				c := smp.Counters
				_ = enc.Encode(liveSample{
					Kind: "sample", Timestamp: smp.Timestamp.Format(time.RFC3339Nano),
					CPUTime: c.CPUTimeSec, MemGB: c.MemUsedGB, GPUUtil: c.GPUUtilPct,
					GPUMemMB: c.GPUMemUsedMB, GPUPowerW: c.GPUPowerW,
				})
			}
		}
	}
}
