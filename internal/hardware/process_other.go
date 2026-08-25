//go:build !linux

package hardware

import "github.com/Mamadou2727/kveritas-go/internal/session"

// ProcessCounters falls back to system-wide counters on platforms without /proc.
// Per-process attribution is Linux-only for now.
func ProcessCounters(rootPID int) session.HardwareCounters {
	return DetailedCounters()
}

// ProcessCPUCounters and ProcessGPUCounters mirror the Linux split; off Linux the
// sampler falls back to the combined system-wide reading each tick.
func ProcessCPUCounters(rootPID int) session.HardwareCounters {
	return DetailedCounters()
}

func ProcessGPUCounters(rootPID int) session.HardwareCounters {
	return session.HardwareCounters{}
}

// ProcessAlive is best-effort on platforms without /proc; sampling continues.
func ProcessAlive(pid int) bool { return true }
