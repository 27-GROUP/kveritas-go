// Package compute attests that a run's declared FLOPs could physically have been
// performed on the reported hardware. Bounds are generous toward the author so an
// honest run never trips the accusatory verdict.
package compute

import (
	"fmt"
	"strings"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const (
	// GPU utilization percent above which an interval counts as active.
	utilActiveThreshold = 5.0
	// Energy floor below any real device efficiency (best measured ~3.1 pJ/FLOP),
	// set low so the bound never false-accuses a more efficient run.
	minJoulesPerFLOP = 0.5e-12
	// Below this declared work the certificate is not applicable.
	computeFloorFLOPs = 1e12
	fp16BytesPerParam = 2
	// Generous upper bound on one CPU core's FP32 throughput; peak x core-seconds
	// is the most FLOPs the CPU could have contributed.
	cpuPeakFLOPSPerCore = 1e12
	// Upper bound on any single machine's throughput, for the telemetry-independent
	// wall-clock floor: F FLOPs need >= F/absolutePeakFLOPS seconds on any hardware.
	absolutePeakFLOPS = 1e16
	// At or above this, a run with no compute evidence is flagged for review rather
	// than silently passed N/A.
	largeModelParams = 1e9
)

// Analyze produces the compute-cost certificate for a single run.
func Analyze(rec *session.RunRecord) session.ComputeCert {
	cert := session.ComputeCert{TimeBoundOK: true, EnergyBoundOK: true, MemoryBoundOK: true}

	active, energy, peakMem, cpuCoreSec := aggregate(rec.HardwareSamples)
	cert.GPUActiveSec = active
	cert.EnergyJoules = energy
	cert.PeakGPUMemMB = peakMem

	fDeclared := declaredFLOPs(rec.Declared)
	cert.FDeclaredFLOPs = fDeclared

	// No model card declared: nothing to attest.
	if rec.Declared == nil {
		cert.Verdict = "N/A"
		cert.Notes = append(cert.Notes, "no declared model card; compute certificate not applicable")
		return cert
	}

	// Total FLOP capacity: GPU peak over active time plus CPU peak over core-seconds.
	// Summed to stay generous and cover GPU-only, CPU-only, or mixed runs.
	gpuPeak := generousPeakFLOPs(rec.Hardware)
	cpuCapacity := cpuPeakFLOPSPerCore * cpuCoreSec
	availableFLOPs := gpuPeak*active + cpuCapacity
	cert.FPeakGenerous = gpuPeak
	cert.MinPJPerFLOP = minJoulesPerFLOP * 1e12

	haveTelemetry := active > 0 || energy > 0 || peakMem > 0 || cpuCoreSec > 0
	// Substantial: training FLOPs clear the floor, or the model itself is large.
	substantial := fDeclared >= computeFloorFLOPs || rec.Declared.Params >= largeModelParams

	// Telemetry-independent wall-clock floor: catches a print-and-exit fake that
	// finishes before it could deliver the declared FLOPs on any hardware.
	if fDeclared > 0 && rec.DurationSec > 0 {
		minWallSec := fDeclared / absolutePeakFLOPS
		if rec.DurationSec < minWallSec {
			cert.TimeBoundOK = false
			cert.Notes = append(cert.Notes, fmt.Sprintf(
				"time-impossible: %.3e declared FLOPs need >= %.1fs on any hardware, but the run lasted %.1fs",
				fDeclared, minWallSec, rec.DurationSec))
		}
	}

	switch {
	case haveTelemetry && fDeclared >= computeFloorFLOPs:
		// Time bound: declared FLOPs cannot exceed observed hardware capacity.
		if availableFLOPs > 0 {
			cert.ImpliedMFU = fDeclared / availableFLOPs
			if fDeclared > availableFLOPs {
				cert.TimeBoundOK = false
				cert.Notes = append(cert.Notes, fmt.Sprintf(
					"time-impossible: %.3e declared FLOPs exceed the %.3e the hardware could deliver (%.1fs GPU-active at %.2e FLOP/s + %.1f CPU core-seconds)",
					fDeclared, availableFLOPs, active, gpuPeak, cpuCoreSec))
			}
		} else {
			cert.TimeBoundOK = false
			cert.Notes = append(cert.Notes,
				"time-impossible: heavy declared work but no compute activity observed")
		}

		// Energy bound: declared FLOPs need at least fDeclared*minJoulesPerFLOP joules.
		if energy > 0 {
			minEnergy := fDeclared * minJoulesPerFLOP
			if energy < minEnergy {
				cert.EnergyBoundOK = false
				cert.Notes = append(cert.Notes, fmt.Sprintf(
					"energy-impossible: declared work needs >= %.1f J, but only %.1f J measured",
					minEnergy, energy))
			}
		}

		// Memory note (soft): fp16 weights alone should fit the observed footprint.
		if rec.Declared.Params > 0 && peakMem > 0 {
			weightsMB := float64(rec.Declared.Params*fp16BytesPerParam) / 1e6
			if weightsMB > peakMem*1.1 {
				cert.Notes = append(cert.Notes, fmt.Sprintf(
					"memory-review: declared params need ~%.0f MB of weights, but peak GPU memory was %.0f MB",
					weightsMB, peakMem))
			}
		}

	case substantial:
		// Substantial declaration with too little evidence to corroborate. Unless
		// the wall-clock floor already proved impossibility, flag for review.
		if cert.TimeBoundOK {
			cert.Notes = append(cert.Notes,
				"review: a substantial model or workload was declared but there is not enough compute evidence to verify it; treat the declared figures as unverified")
		}

	default:
		// Small declared work, nothing impossible: not checkable.
		cert.Verdict = "N/A"
		cert.Notes = append(cert.Notes, "declared work below compute floor; certificate not applicable")
		return cert
	}

	switch {
	case !cert.TimeBoundOK || !cert.EnergyBoundOK:
		cert.Verdict = "FABRICATION-IMPOSSIBLE"
	case len(cert.Notes) > 0:
		cert.Verdict = "REVIEW"
	default:
		cert.Verdict = "PASS"
	}
	return cert
}

// declaredFLOPs applies the 6ND lower bound: 6 * params * tokens, tokens being
// dataset_size * epochs (times seq_len for token models). Underestimates CNN
// FLOPs, which is safe for an accusatory bound.
func declaredFLOPs(d *session.DeclaredModel) float64 {
	if d == nil || d.Params <= 0 || d.DatasetSize <= 0 || d.Epochs <= 0 {
		return 0
	}
	tokens := float64(d.DatasetSize) * d.Epochs
	if d.SeqLen > 0 {
		tokens *= float64(d.SeqLen)
	}
	return 6.0 * float64(d.Params) * tokens
}

// aggregate reduces the samples to GPU-active seconds, integrated GPU energy,
// peak GPU memory, and CPU core-seconds (the increase of the cumulative counter).
func aggregate(samples []session.HardwareSample) (activeSec, energyJ, peakMemMB, cpuCoreSec float64) {
	var firstCPU, lastCPU float64
	for i, s := range samples {
		if s.Counters.GPUMemUsedMB > peakMemMB {
			peakMemMB = s.Counters.GPUMemUsedMB
		}
		if i == 0 {
			firstCPU = s.Counters.CPUTimeSec
		}
		lastCPU = s.Counters.CPUTimeSec
		if i == 0 {
			continue
		}
		dt := s.Timestamp.Sub(samples[i-1].Timestamp).Seconds()
		if dt <= 0 {
			continue
		}
		prev := samples[i-1].Counters
		cur := s.Counters
		if prev.GPUUtilPct > utilActiveThreshold || cur.GPUUtilPct > utilActiveThreshold {
			activeSec += dt
		}
		energyJ += 0.5 * (prev.GPUPowerW + cur.GPUPowerW) * dt
	}
	if lastCPU > firstCPU {
		cpuCoreSec = lastCPU - firstCPU
	}
	return
}

// generousPeakFLOPs returns the theoretical-peak throughput summed over GPUs. It
// must be an upper bound; an achieved rate would false-accuse a fast kernel path.
func generousPeakFLOPs(hw session.HardwareInfo) float64 {
	count := hw.GPUCount
	if count < 1 {
		if len(hw.GPUNames) > 0 {
			count = len(hw.GPUNames)
		} else {
			count = 1
		}
	}
	return perGPUPeak(hw.GPUNames) * float64(count)
}

func perGPUPeak(names []string) float64 {
	name := ""
	if len(names) > 0 {
		name = strings.ToLower(names[0])
	}
	table := []struct {
		key  string
		peak float64
	}{
		{"h100", 990e12}, {"a100", 312e12}, {"v100", 125e12}, {"t4", 65e12},
		{"a6000", 310e12}, {"5090", 900e12}, {"5080", 450e12}, {"5070", 300e12},
		{"5060", 250e12}, {"4090", 660e12}, {"4080", 390e12}, {"3090", 285e12},
	}
	for _, e := range table {
		if strings.Contains(name, e.key) {
			return e.peak
		}
	}
	// Unknown GPU: generous default so the time bound never false-accuses.
	return 1e15
}
