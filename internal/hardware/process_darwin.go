//go:build darwin

package hardware

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// macOS has no /proc: one ps call gives every process's parent, CPU time and memory,
// which is enough to scope CPU and memory to the run's tree. Apple GPUs expose no
// per-process counters, so GPU readings stay machine-wide.
func ProcessCounters(rootPID int) session.HardwareCounters {
	c := ProcessCPUCounters(rootPID)
	g := ProcessGPUCounters(rootPID)
	c.GPUUtilPct, c.GPUMemUsedMB, c.GPUPowerW, c.GPUTempC = g.GPUUtilPct, g.GPUMemUsedMB, g.GPUPowerW, g.GPUTempC
	return c
}

func ProcessCPUCounters(rootPID int) session.HardwareCounters {
	c := session.HardwareCounters{}
	out, err := exec.Command("ps", "-A", "-o", "pid=,ppid=,time=,rss=").Output()
	if err != nil {
		return c
	}
	rows := parsePS(out)
	for pid := range treeOf(rows, rootPID, os.Getpid()) {
		r := rows[pid]
		c.CPUTimeSec += r.cpu
		c.MemUsedGB += r.rssKB / 1e6
	}
	return c
}

func ProcessGPUCounters(rootPID int) session.HardwareCounters {
	g := gpuCounters()
	return session.HardwareCounters{GPUUtilPct: g.GPUUtilPct, GPUMemUsedMB: g.GPUMemUsedMB, GPUPowerW: g.GPUPowerW, GPUTempC: g.GPUTempC}
}

func ProcessAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}
