//go:build linux

package hardware

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// ProcessCounters measures hardware use for the process tree rooted at rootPID,
// so activity from anything else on the machine (a browser, another job) is not
// counted against the run. CPU and memory come from /proc for the whole tree; GPU
// memory and utilization come from nvidia-smi filtered to the tree's PIDs; GPU
// power is the device draw scaled by the tree's share of GPU utilization.
func ProcessCounters(rootPID int) session.HardwareCounters {
	pids := descendantPIDs(rootPID)
	c := session.HardwareCounters{}

	pageGB := float64(os.Getpagesize()) / 1e9
	for pid := range pids {
		c.CPUTimeSec += procCPUSeconds(pid)
		c.MemUsedGB += procRSSPages(pid) * pageGB
	}
	c.CPUTempC = linuxCPUTemp()

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
