package hardware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/mamadouk/kveritas/internal/session"
)

func Snapshot() session.HardwareInfo {
	hostname, _ := os.Hostname()
	return session.HardwareInfo{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
		MemGB:    memGB(),
		GPUInfo:  gpuInfo(),
	}
}

// MachineID returns an 8-byte hex fingerprint of the host machine.
// It is not a secret — its purpose is replay-attack detection across machines.
func MachineID() string {
	hostname, _ := os.Hostname()
	raw := fmt.Sprintf("%s:%s:%s:%d", hostname, runtime.GOOS, runtime.GOARCH, runtime.NumCPU())
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:8])
}

func memGB() float64 {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/proc/meminfo")
		if err != nil {
			return 0
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				var kb float64
				fmt.Sscanf(strings.TrimPrefix(line, "MemTotal:"), "%f", &kb)
				return kb / 1048576
			}
		}
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
		if err == nil {
			var b float64
			fmt.Sscanf(strings.TrimSpace(string(out)), "%f", &b)
			return b / 1073741824
		}
	}
	return 0
}

func gpuInfo() string {
	out, err := exec.Command(
		"nvidia-smi",
		"--query-gpu=name,memory.total",
		"--format=csv,noheader",
	).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
