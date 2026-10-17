package hardware

import (
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type GPU struct {
	Index    int     `json:"index"`
	Name     string  `json:"name"`
	UUID     string  `json:"uuid"`
	MemoryMB float64 `json:"memory_mb"`
	Driver   string  `json:"driver"`
}

type Inventory struct {
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	CPUModel    string  `json:"cpu_model,omitempty"`
	CPUCores    int     `json:"cpu_cores"`
	MemGB       float64 `json:"mem_gb"`
	CUDAVersion string  `json:"cuda_version,omitempty"`
	GPUs        []GPU   `json:"gpus"`
}

var cudaRe = regexp.MustCompile(`CUDA Version:\s*([0-9.]+)`)

func Detect() Inventory {
	snap := Snapshot()
	inv := Inventory{
		OS:       snap.OS,
		Arch:     snap.Arch,
		CPUModel: snap.CPUModel,
		CPUCores: snap.CPUCores,
		MemGB:    snap.MemGB,
		GPUs:     []GPU{},
	}
	out, err := exec.Command("nvidia-smi",
		"--query-gpu=index,name,uuid,memory.total,driver_version",
		"--format=csv,noheader,nounits").Output()
	if err != nil {
		return inv
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Split(line, ",")
		if len(f) < 5 {
			continue
		}
		idx, _ := strconv.Atoi(strings.TrimSpace(f[0]))
		mem, _ := strconv.ParseFloat(strings.TrimSpace(f[3]), 64)
		inv.GPUs = append(inv.GPUs, GPU{
			Index:    idx,
			Name:     strings.TrimSpace(f[1]),
			UUID:     strings.TrimSpace(f[2]),
			MemoryMB: mem,
			Driver:   strings.TrimSpace(f[4]),
		})
	}
	if banner, err := exec.Command("nvidia-smi").Output(); err == nil {
		if m := cudaRe.FindSubmatch(banner); m != nil {
			inv.CUDAVersion = string(m[1])
		}
	}
	return inv
}
