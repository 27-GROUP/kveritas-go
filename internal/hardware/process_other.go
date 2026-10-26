//go:build !linux && !darwin && !windows

package hardware

import "github.com/Mamadou2727/kveritas-go/internal/session"

func ProcessCounters(rootPID int) session.HardwareCounters {
	return DetailedCounters()
}

func ProcessCPUCounters(rootPID int) session.HardwareCounters {
	return DetailedCounters()
}

func ProcessGPUCounters(rootPID int) session.HardwareCounters {
	return session.HardwareCounters{}
}

func ProcessAlive(pid int) bool { return true }
