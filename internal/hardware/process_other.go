//go:build !linux

package hardware

import "github.com/Mamadou2727/kveritas-go/internal/session"

// ProcessCounters falls back to system-wide counters on platforms without /proc.
// Per-process attribution is Linux-only for now.
func ProcessCounters(rootPID int) session.HardwareCounters {
	return DetailedCounters()
}

// ProcessAlive is best-effort on platforms without /proc; sampling continues.
func ProcessAlive(pid int) bool { return true }
