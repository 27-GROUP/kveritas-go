//go:build linux

package hardware

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// ProcessCounters measures hardware use for the tree rooted at rootPID, so other
// activity on the machine is not counted against the run. CPU and memory come from
// /proc; GPU memory and utilization from nvidia-smi filtered to the tree's PIDs;
// GPU power is device draw scaled by the tree's share of utilization.
func ProcessCounters(rootPID int) session.HardwareCounters {
	c := ProcessCPUCounters(rootPID)
	g := ProcessGPUCounters(rootPID)
	c.GPUTempC = g.GPUTempC
	c.GPUMemUsedMB = g.GPUMemUsedMB
	c.GPUUtilPct = g.GPUUtilPct
	c.GPUPowerW = g.GPUPowerW
	return c
}

// ProcessCPUCounters reads only the cheap /proc and sysfs counters for the tree.
// It makes no nvidia-smi calls, so it is fast enough to sample at a high rate.
func ProcessCPUCounters(rootPID int) session.HardwareCounters {
	pids := descendantPIDs(rootPID)
	c := session.HardwareCounters{}
	pageGB := float64(os.Getpagesize()) / 1e9
	for pid := range pids {
		c.CPUTimeSec += procCPUSeconds(pid)
		c.MemUsedGB += procRSSPages(pid) * pageGB
		mf, thr := procMinfltThreads(pid)
		c.MinorFaults += mf
		c.Threads += thr
		c.CtxSwitches += procCtxSwitches(pid)
		rb, wb := procIO(pid)
		c.DiskReadMB += rb
		c.DiskWriteMB += wb
	}
	c.CPUTempC = linuxCPUTemp()
	c.CPUFreqMHz = linuxCPUFreqMHz()
	return c
}

// ProcessGPUCounters reads the per-process GPU counters via nvidia-smi (slower),
// returning only the GPU fields. The sampler refreshes it at a lower rate.
func ProcessGPUCounters(rootPID int) session.HardwareCounters {
	pids := descendantPIDs(rootPID)
	c := session.HardwareCounters{}
	dev := gpuCounters()
	c.GPUTempC = dev.GPUTempC
	c.GPUMemUsedMB = gpuMemForPIDs(pids)
	ourUtil := gpuUtilForPIDs(pids)
	c.GPUUtilPct = ourUtil
	switch {
	case dev.GPUUtilPct > 0:
		share := ourUtil / dev.GPUUtilPct
		if share > 1 {
			share = 1
		}
		c.GPUPowerW = dev.GPUPowerW * share
	case ourUtil > 0:
		c.GPUPowerW = dev.GPUPowerW
	}
	return c
}

// ProcessAlive reports whether the process still exists.
func ProcessAlive(pid int) bool {
	_, err := os.Stat("/proc/" + strconv.Itoa(pid))
	return err == nil
}

// descendantPIDs returns rootPID and every process descended from it.
func descendantPIDs(rootPID int) map[int]bool {
	parent := map[int]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return map[int]bool{rootPID: true}
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if ppid, ok := readPPID(pid); ok {
			parent[pid] = ppid
		}
	}
	tree := map[int]bool{rootPID: true}
	changed := true
	for changed {
		changed = false
		for pid, ppid := range parent {
			if tree[pid] {
				continue
			}
			if tree[ppid] {
				tree[pid] = true
				changed = true
			}
		}
	}
	return tree
}

func readPPID(pid int) (int, bool) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	close := bytes.LastIndexByte(data, ')')
	if close < 0 || close+2 >= len(data) {
		return 0, false
	}
	fields := strings.Fields(string(data[close+2:]))
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	return ppid, err == nil
}

// procCPUSeconds returns cumulative user+system CPU seconds for a process.
func procCPUSeconds(pid int) float64 {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	close := bytes.LastIndexByte(data, ')')
	if close < 0 || close+2 >= len(data) {
		return 0
	}
	fields := strings.Fields(string(data[close+2:]))
	// After comm: state ppid pgrp ... utime(12th) stime(13th) in this slice.
	if len(fields) < 13 {
		return 0
	}
	utime, _ := strconv.ParseFloat(fields[11], 64)
	stime, _ := strconv.ParseFloat(fields[12], 64)
	return (utime + stime) / clockTicks
}

const clockTicks = 100.0

// procMinfltThreads returns a process's cumulative minor page faults and its
// current thread count, from /proc/<pid>/stat.
func procMinfltThreads(pid int) (minflt, threads float64) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0
	}
	close := bytes.LastIndexByte(data, ')')
	if close < 0 || close+2 >= len(data) {
		return 0, 0
	}
	fields := strings.Fields(string(data[close+2:]))
	if len(fields) < 18 {
		return 0, 0
	}
	minflt, _ = strconv.ParseFloat(fields[7], 64)   // minflt
	threads, _ = strconv.ParseFloat(fields[17], 64) // num_threads
	return minflt, threads
}

// procCtxSwitches returns a process's cumulative context switches (voluntary +
// nonvoluntary), from /proc/<pid>/status.
func procCtxSwitches(pid int) float64 {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return 0
	}
	var total float64
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "voluntary_ctxt_switches:") || strings.HasPrefix(line, "nonvoluntary_ctxt_switches:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				v, _ := strconv.ParseFloat(f[1], 64)
				total += v
			}
		}
	}
	return total
}

// procIO returns a process's cumulative read/write bytes as MB, from /proc/<pid>/io.
func procIO(pid int) (readMB, writeMB float64) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/io")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		switch f[0] {
		case "read_bytes:":
			readMB = v / 1e6
		case "write_bytes:":
			writeMB = v / 1e6
		}
	}
	return readMB, writeMB
}

// linuxCPUFreqMHz returns the mean current CPU frequency across cores (MHz).
func linuxCPUFreqMHz() float64 {
	matches, err := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq")
	if err != nil || len(matches) == 0 {
		return 0
	}
	var sum float64
	var n int
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
		if err == nil {
			sum += v / 1000.0 // kHz -> MHz
			n++
		}
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// procRSSPages returns a process's resident set size in memory pages.
func procRSSPages(pid int) float64 {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0
	}
	rss, _ := strconv.ParseFloat(fields[1], 64)
	return rss
}

// gpuMemForPIDs sums GPU memory (MB) used by the given processes.
func gpuMemForPIDs(pids map[int]bool) float64 {
	out, err := exec.Command("nvidia-smi",
		"--query-compute-apps=pid,used_gpu_memory",
		"--format=csv,noheader,nounits",
	).Output()
	if err != nil {
		return 0
	}
	total := 0.0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || !pids[pid] {
			continue
		}
		mem, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		total += mem
	}
	return total
}

// gpuUtilForPIDs sums the SM (compute) utilization of the given processes via
// nvidia-smi pmon.
func gpuUtilForPIDs(pids map[int]bool) float64 {
	out, err := exec.Command("nvidia-smi", "pmon", "-c", "1").Output()
	if err != nil {
		return 0
	}
	total := 0.0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, err := strconv.Atoi(fields[1])
		if err != nil || !pids[pid] {
			continue
		}
		if sm, err := strconv.ParseFloat(fields[3], 64); err == nil {
			total += sm
		}
	}
	return total
}
