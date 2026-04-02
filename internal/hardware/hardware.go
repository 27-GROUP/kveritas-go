package hardware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/mamadouk/kveritas/internal/session"
)

func Snapshot() session.HardwareInfo {
	hostname, _ := os.Hostname()
	gpuNames := gpuNames()
	gpuSummary := gpuInfo()
	return session.HardwareInfo{
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
		CPUModel: cpuModel(),
		MemGB:    memGB(),
		GPUInfo:  gpuSummary,
		GPUCount: len(gpuNames),
		GPUNames: gpuNames,
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

// DetailedCounters captures a full hardware state snapshot for phase tracking.
// Best-effort: zeros mean the counter was unavailable on this platform.
func DetailedCounters() session.HardwareCounters {
	c := session.HardwareCounters{}
	switch runtime.GOOS {
	case "linux":
		c.CPUTimeSec = linuxCPUTime()
		c.MemUsedGB = linuxMemUsed()
		c.CPUTempC = linuxCPUTemp()
		c.DiskReadMB, c.DiskWriteMB = linuxDiskIO()
	case "darwin":
		c.CPUTimeSec = darwinCPUTime()
		c.MemUsedGB = darwinMemUsed()
	}
	// GPU counters (nvidia-smi works on Linux, Windows, and some macOS)
	g := gpuCounters()
	c.GPUUtilPct = g.GPUUtilPct
	c.GPUMemUsedMB = g.GPUMemUsedMB
	c.GPUTempC = g.GPUTempC
	c.GPUPowerW = g.GPUPowerW
	return c
}

// CapturePhaseEvent creates a PhaseEvent with current hardware counters.
func CapturePhaseEvent(name string, line int) session.PhaseEvent {
	return session.PhaseEvent{
		Name:      name,
		Line:      line,
		Timestamp: time.Now().UTC(),
		Counters:  DetailedCounters(),
	}
}

func cpuModel() string {
	switch runtime.GOOS {
	case "linux":
		data, err := os.ReadFile("/proc/cpuinfo")
		if err != nil {
			return ""
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "model name") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					return strings.TrimSpace(parts[1])
				}
			}
		}
	case "darwin":
		out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

func gpuNames() []string {
	out, err := exec.Command(
		"nvidia-smi",
		"--query-gpu=name",
		"--format=csv,noheader",
	).Output()
	if err == nil {
		var names []string
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			name := strings.TrimSpace(line)
			if name != "" {
				names = append(names, name)
			}
		}
		return names
	}
	out, err = exec.Command("rocm-smi", "--showproductname").Output()
	if err == nil {
		var names []string
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "=") && !strings.Contains(line, "GPU") {
				names = append(names, "AMD "+line)
			}
		}
		return names
	}
	return nil
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
	// NVIDIA
	out, err := exec.Command(
		"nvidia-smi",
		"--query-gpu=name,memory.total",
		"--format=csv,noheader",
	).Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}
	// AMD ROCm
	out, err = exec.Command("rocm-smi", "--showproductname").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "=") && !strings.Contains(line, "GPU") {
				return "AMD " + line
			}
		}
	}
	return ""
}

// --- Linux-specific counters ---

func linuxCPUTime() float64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				return 0
			}
			var total float64
			for _, f := range fields[1:] {
				v, _ := strconv.ParseFloat(f, 64)
				total += v
			}
			// Convert from jiffies (1/100 sec) to seconds
			return total / 100.0
		}
	}
	return 0
}

func linuxMemUsed() float64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	var total, avail float64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fmt.Sscanf(strings.TrimPrefix(line, "MemTotal:"), "%f", &total)
		}
		if strings.HasPrefix(line, "MemAvailable:") {
			fmt.Sscanf(strings.TrimPrefix(line, "MemAvailable:"), "%f", &avail)
		}
	}
	if total > 0 {
		return (total - avail) / 1048576 // KB to GB
	}
	return 0
}

func linuxCPUTemp() float64 {
	// Try thermal zones
	for i := 0; i < 10; i++ {
		path := fmt.Sprintf("/sys/class/thermal/thermal_zone%d/temp", i)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(string(data)), 64)
		if err == nil && v > 0 {
			return v / 1000.0 // millidegrees to degrees
		}
	}
	return 0
}

func linuxDiskIO() (readMB, writeMB float64) {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}
		// Field 2 is device name; aggregate all devices
		rSectors, _ := strconv.ParseFloat(fields[5], 64)
		wSectors, _ := strconv.ParseFloat(fields[9], 64)
		readMB += rSectors * 512 / (1024 * 1024)
		writeMB += wSectors * 512 / (1024 * 1024)
	}
	return readMB, writeMB
}

// --- macOS-specific counters ---

func darwinCPUTime() float64 {
	out, err := exec.Command("sysctl", "-n", "kern.cp_time").Output()
	if err != nil {
		return 0
	}
	var total float64
	for _, f := range strings.Fields(strings.TrimSpace(string(out))) {
		v, _ := strconv.ParseFloat(f, 64)
		total += v
	}
	return total / 100.0
}

func darwinMemUsed() float64 {
	out, err := exec.Command("vm_stat").Output()
	if err != nil {
		return 0
	}
	pageSize := 4096.0
	var active, wired, compressed float64
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "page size of") {
			fmt.Sscanf(line, "Mach Virtual Memory Statistics: (page size of %f bytes)", &pageSize)
		}
		if strings.HasPrefix(line, "Pages active:") {
			fmt.Sscanf(strings.TrimPrefix(line, "Pages active:"), "%f", &active)
		}
		if strings.HasPrefix(line, "Pages wired down:") {
			fmt.Sscanf(strings.TrimPrefix(line, "Pages wired down:"), "%f", &wired)
		}
		if strings.HasPrefix(line, "Pages occupied by compressor:") {
			fmt.Sscanf(strings.TrimPrefix(line, "Pages occupied by compressor:"), "%f", &compressed)
		}
	}
	return (active + wired + compressed) * pageSize / (1024 * 1024 * 1024)
}

// --- GPU counters (cross-platform via nvidia-smi / rocm-smi) ---

type gpuState struct {
	GPUUtilPct   float64
	GPUMemUsedMB float64
	GPUTempC     float64
	GPUPowerW    float64
}

func gpuCounters() gpuState {
	g := gpuState{}

	// NVIDIA
	out, err := exec.Command("nvidia-smi",
		"--query-gpu=utilization.gpu,memory.used,temperature.gpu,power.draw",
		"--format=csv,noheader,nounits",
	).Output()
	if err == nil {
		fields := strings.Split(strings.TrimSpace(string(out)), ",")
		if len(fields) >= 4 {
			g.GPUUtilPct, _ = strconv.ParseFloat(strings.TrimSpace(fields[0]), 64)
			g.GPUMemUsedMB, _ = strconv.ParseFloat(strings.TrimSpace(fields[1]), 64)
			g.GPUTempC, _ = strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
			g.GPUPowerW, _ = strconv.ParseFloat(strings.TrimSpace(fields[3]), 64)
		}
		return g
	}

	// AMD ROCm
	out, err = exec.Command("rocm-smi", "--showuse", "--showtemp", "--showmeminfo", "vram", "--csv").Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "GPU use") {
				parts := strings.Split(line, ",")
				if len(parts) >= 2 {
					g.GPUUtilPct, _ = strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(parts[1], "%")), 64)
				}
			}
			if strings.Contains(line, "Temperature") {
				parts := strings.Split(line, ",")
				if len(parts) >= 2 {
					g.GPUTempC, _ = strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
				}
			}
		}
	}

	return g
}
