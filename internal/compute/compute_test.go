package compute

import (
	"testing"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

func t0(sec int) time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second)
}

// gpuSamples builds an active GPU trace over durSec seconds.
func gpuSamples(durSec int, util, powerW, memMB, cpuPerSec float64) []session.HardwareSample {
	var s []session.HardwareSample
	cpu := 0.0
	for i := 0; i <= durSec; i++ {
		cpu += cpuPerSec
		s = append(s, session.HardwareSample{
			Timestamp: t0(i),
			Counters:  session.HardwareCounters{CPUTimeSec: cpu, GPUUtilPct: util, GPUPowerW: powerW, GPUMemUsedMB: memMB},
		})
	}
	return s
}

// cpuSamples builds a CPU-only trace (no GPU) accumulating cpuPerSec core-seconds/s.
func cpuSamples(durSec int, cpuPerSec float64) []session.HardwareSample {
	var s []session.HardwareSample
	cpu := 0.0
	for i := 0; i <= durSec; i++ {
		cpu += cpuPerSec
		s = append(s, session.HardwareSample{
			Timestamp: t0(i),
			Counters:  session.HardwareCounters{CPUTimeSec: cpu},
		})
	}
	return s
}

func gpuHW() session.HardwareInfo {
	return session.HardwareInfo{GPUNames: []string{"NVIDIA GeForce RTX 5060 Ti"}, GPUCount: 1}
}
func cpuHW() session.HardwareInfo { return session.HardwareInfo{CPUCores: 16} }

// The benchmark matrix: honest runs must not be accused; fabrications on GPU AND
// CPU must be caught; runs with no evidence or no card abstain.
func TestComputeBenchmark(t *testing.T) {
	cases := []struct {
		name   string
		rec    session.RunRecord
		expect string
	}{
		{
			name: "honest_gpu_train",
			rec: session.RunRecord{
				Hardware:        gpuHW(),
				Declared:        &session.DeclaredModel{Params: 25_000_000, DatasetSize: 60000, Epochs: 5},
				HardwareSamples: gpuSamples(300, 85, 160, 8000, 12),
			},
			expect: "PASS",
		},
		{
			name: "honest_cpu_train",
			rec: session.RunRecord{
				Hardware:        cpuHW(),
				Declared:        &session.DeclaredModel{Params: 5_000_000, DatasetSize: 60000, Epochs: 5},
				HardwareSamples: cpuSamples(60, 12), // ~720 core-seconds
			},
			expect: "PASS",
		},
		{
			name: "fraud_gpu_overclaim",
			rec: session.RunRecord{
				Hardware:        gpuHW(),
				Declared:        &session.DeclaredModel{Params: 175_000_000_000, DatasetSize: 300_000_000, Epochs: 1, SeqLen: 1000},
				HardwareSamples: gpuSamples(20, 90, 180, 12000, 4),
			},
			expect: "FABRICATION-IMPOSSIBLE",
		},
		{
			name: "fraud_cpu_overclaim_no_gpu",
			rec: session.RunRecord{
				Hardware:        cpuHW(),
				Declared:        &session.DeclaredModel{Params: 70_000_000_000, DatasetSize: 10_000_000, Epochs: 3, SeqLen: 2048},
				HardwareSamples: cpuSamples(6, 13), // ~80 core-seconds, no GPU
			},
			expect: "FABRICATION-IMPOSSIBLE",
		},
		{
			name: "no_declared_card",
			rec: session.RunRecord{
				Hardware:        cpuHW(),
				HardwareSamples: cpuSamples(30, 12),
			},
			expect: "N/A",
		},
		{
			name:   "no_telemetry",
			rec:    session.RunRecord{Hardware: cpuHW(), Declared: &session.DeclaredModel{Params: 70_000_000_000, DatasetSize: 10_000_000, Epochs: 3, SeqLen: 2048}},
			expect: "N/A",
		},
	}

	for _, c := range cases {
		got := Analyze(&c.rec).Verdict
		if got != c.expect {
			t.Errorf("%s: expected %s, got %s", c.name, c.expect, got)
		} else {
			t.Logf("%-28s -> %s", c.name, got)
		}
	}
}
