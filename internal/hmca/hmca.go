package hmca

import (
	"fmt"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// Analyze runs the Hardware-Metric Consistency Analyzer against a set of runs
// and their background hardware samples. The result is deterministic and
// included in the canonical hash at seal time.
func Analyze(runs []*session.RunRecord, samples []session.HardwareSample) session.HMCAResult {
	var flags []string
	score := 1.0

	for i, run := range runs {
		runFlags := analyzeRun(run, samples)
		for _, f := range runFlags {
			flags = append(flags, fmt.Sprintf("run_%d: %s", i+1, f))
		}
		score -= float64(len(runFlags)) * 0.1
	}

	if score < 0 {
		score = 0
	}

	verdict := "PASS"
	if score < 0.5 {
		verdict = "FAIL"
	} else if score < 0.8 {
		verdict = "WARN"
	}

	return session.HMCAResult{
		Score:   score,
		Flags:   flags,
		Verdict: verdict,
	}
}

func analyzeRun(run *session.RunRecord, samples []session.HardwareSample) []string {
	var flags []string

	// RULE: ZERO_COST_METRIC - metrics reported but duration is near-zero
	if len(run.Metrics) > 0 && run.DurationSec < 1.0 {
		flags = append(flags, "ZERO_COST_METRIC: metrics reported in <1s execution")
	}

	// RULE: LOW_ACTIVITY_HIGH_GAIN - high-value metrics with minimal hardware usage
	hasHighMetric := false
	for _, m := range run.Metrics {
		if m.Value > 0.9 && m.Source == "explicit" {
			hasHighMetric = true
			break
		}
	}

	runSamples := filterSamples(samples, run.StartAt, run.EndAt)

	if hasHighMetric && len(runSamples) > 0 {
		avgCPU := avgCPUActivity(runSamples)
		avgMem := avgMemActivity(runSamples)

		if avgCPU < 5.0 && run.DurationSec > 10.0 {
			flags = append(flags, "LOW_ACTIVITY_HIGH_GAIN: high metrics but <5% CPU activity")
		}

		if avgMem < 0.1 && run.DurationSec > 30.0 {
			flags = append(flags, "LOW_ACTIVITY_HIGH_GAIN: high metrics but near-zero memory change")
		}
	}

	// RULE: GPU_CLAIM_NO_GPU - claims GPU usage but no GPU detected
	hasGPUPhase := false
	for _, p := range run.Phases {
		if p.Counters.GPUUtilPct > 0 || p.Counters.GPUMemUsedMB > 0 {
			hasGPUPhase = true
			break
		}
	}
	gpuInHardware := run.Hardware.GPUInfo != ""
	if !gpuInHardware && hasGPUPhase {
		flags = append(flags, "GPU_CLAIM_NO_GPU: GPU counters reported but no GPU in hardware snapshot")
	}

	// RULE: IDLE_RUN - hardware idle for the entire run
	if len(runSamples) >= 3 && allIdle(runSamples) && run.DurationSec > 60 {
		flags = append(flags, "IDLE_RUN: hardware was idle for the entire run duration")
	}

	// RULE: PHASE_MISMATCH - eval phase should use less resources than train phase
	trainPhases, evalPhases := splitPhases(run.Phases)
	if len(trainPhases) > 0 && len(evalPhases) > 0 {
		trainCPU := phaseAvgCPU(trainPhases)
		evalCPU := phaseAvgCPU(evalPhases)
		if evalCPU > trainCPU*2.0 && trainCPU > 0 {
			flags = append(flags, "PHASE_MISMATCH: eval phase used more CPU than train phase")
		}
	}

	return flags
}

func filterSamples(samples []session.HardwareSample, start, end time.Time) []session.HardwareSample {
	var filtered []session.HardwareSample
	for _, s := range samples {
		if !s.Timestamp.Before(start) && !s.Timestamp.After(end) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

func avgCPUActivity(samples []session.HardwareSample) float64 {
	if len(samples) < 2 {
		return 100
	}
	first := samples[0].Counters.CPUTimeSec
	last := samples[len(samples)-1].Counters.CPUTimeSec
	elapsed := samples[len(samples)-1].Timestamp.Sub(samples[0].Timestamp).Seconds()
	if elapsed <= 0 {
		return 100
	}
	cpuDelta := last - first
	return (cpuDelta / elapsed) * 100
}

func avgMemActivity(samples []session.HardwareSample) float64 {
	if len(samples) < 2 {
		return 100
	}
	first := samples[0].Counters.MemUsedGB
	last := samples[len(samples)-1].Counters.MemUsedGB
	return last - first
}

func allIdle(samples []session.HardwareSample) bool {
	for i := 1; i < len(samples); i++ {
		cpuDelta := samples[i].Counters.CPUTimeSec - samples[i-1].Counters.CPUTimeSec
		elapsed := samples[i].Timestamp.Sub(samples[i-1].Timestamp).Seconds()
		if elapsed > 0 && (cpuDelta/elapsed)*100 > 5.0 {
			return false
		}
	}
	return true
}

func splitPhases(phases []session.PhaseEvent) (train, eval []session.PhaseEvent) {
	for _, p := range phases {
		lower := strings.ToLower(p.Name)
		if strings.Contains(lower, "train") {
			train = append(train, p)
		}
		if strings.Contains(lower, "eval") || strings.Contains(lower, "test") || strings.Contains(lower, "valid") {
			eval = append(eval, p)
		}
	}
	return
}

func phaseAvgCPU(phases []session.PhaseEvent) float64 {
	if len(phases) == 0 {
		return 0
	}
	total := 0.0
	for _, p := range phases {
		total += p.Counters.CPUTimeSec
	}
	return total / float64(len(phases))
}
