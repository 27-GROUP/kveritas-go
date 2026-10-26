//go:build windows

package hardware

import (
	"os"
	"syscall"
	"unsafe"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const processQueryLimitedInformation = 0x1000

var procGetProcessMemoryInfo = syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

func processParents() map[int]int {
	snap, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer syscall.CloseHandle(snap)
	parents := map[int]int{}
	var e syscall.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = syscall.Process32First(snap, &e); err == nil; err = syscall.Process32Next(snap, &e) {
		parents[int(e.ProcessID)] = int(e.ParentProcessID)
	}
	return parents
}

func windowsTree(rootPID int) map[int]bool {
	parents := processParents()
	delete(parents, os.Getpid())
	tree := map[int]bool{rootPID: true}
	for changed := true; changed; {
		changed = false
		for pid, ppid := range parents {
			if !tree[pid] && pid != ppid && tree[ppid] {
				tree[pid] = true
				changed = true
			}
		}
	}
	return tree
}

func processUsage(pid int) (cpuSec, memGB float64, pageFaults float64) {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return 0, 0, 0
	}
	defer syscall.CloseHandle(h)
	var created, exited, kernel, user syscall.Filetime
	if syscall.GetProcessTimes(h, &created, &exited, &kernel, &user) == nil {
		ticks := (uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)) +
			(uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime))
		cpuSec = float64(ticks) / 1e7
	}
	var m processMemoryCounters
	m.cb = uint32(unsafe.Sizeof(m))
	if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&m)), uintptr(m.cb)); r != 0 {
		memGB = float64(m.workingSetSize) / 1e9
		pageFaults = float64(m.pageFaultCount)
	}
	return cpuSec, memGB, pageFaults
}

func ProcessCounters(rootPID int) session.HardwareCounters {
	c := ProcessCPUCounters(rootPID)
	g := ProcessGPUCounters(rootPID)
	c.GPUUtilPct, c.GPUMemUsedMB, c.GPUPowerW, c.GPUTempC = g.GPUUtilPct, g.GPUMemUsedMB, g.GPUPowerW, g.GPUTempC
	return c
}

func ProcessCPUCounters(rootPID int) session.HardwareCounters {
	c := session.HardwareCounters{}
	for pid := range windowsTree(rootPID) {
		cpu, mem, pf := processUsage(pid)
		c.CPUTimeSec += cpu
		c.MemUsedGB += mem
		c.MinorFaults += pf
	}
	return c
}

func ProcessGPUCounters(rootPID int) session.HardwareCounters {
	g := gpuCounters()
	return session.HardwareCounters{GPUUtilPct: g.GPUUtilPct, GPUMemUsedMB: g.GPUMemUsedMB, GPUPowerW: g.GPUPowerW, GPUTempC: g.GPUTempC}
}

func ProcessAlive(pid int) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	return syscall.GetExitCodeProcess(h, &code) == nil && code == 259
}
