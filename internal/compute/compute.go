// Package compute implements the compute-cost attestation certificate: a
// non-deniable check that the work declared in a run's model card was physically
// performed on the reported hardware. It compares declared FLOPs against the
// hardware evidence (GPU active time, energy, memory) using bounds set generous
// toward the author, so an honest run cannot trip the accusatory verdict.
//
// See COMPUTE_ATTESTATION_SPEC.md for the full design.
package compute

import (
	"fmt"
	"strings"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const (
	// utilActiveThreshold is the GPU utilization percent above which an interval
	// counts as GPU-active time.
	utilActiveThreshold = 5.0
	// minJoulesPerFLOP is a hard energy floor below any real device efficiency
	// (measured best on an RTX 5060 Ti was ~3.1 pJ/FLOP). Set well under that so
	// the energy bound never false-accuses a more efficient real run.
	minJoulesPerFLOP = 0.5e-12
	// computeFloorFLOPs gates the certificate: below this declared work the check
	// is not applicable (protects legitimately fast small runs).
	computeFloorFLOPs = 1e12
	// fp16BytesPerParam is the weights-only floor used for the soft memory note.
	fp16BytesPerParam = 2
	// cpuPeakFLOPSPerCore is a generous theoretical upper bound on one CPU core's
	// FP32 throughput (well above real AVX-512 FMA peaks), so the CPU time bound
	// never false-accuses an efficient real run but still catches gross overclaims.
	// The process's CPU time is already in core-seconds, so peak x core-seconds is
	// the most FLOPs the CPU could have contributed.
	cpuPeakFLOPSPerCore = 1e12
	// absolutePeakFLOPS is an upper bound on the throughput of any single machine
	// (well above an 8-GPU node), used for a telemetry-independent wall-clock floor:
	// F_declared FLOPs need at least F_declared/absolutePeakFLOPS seconds no matter
	// what hardware ran them, so a run shorter than that is impossible on its face.
	absolutePeakFLOPS = 1e16
	// largeModelParams marks a declaration substantial enough that a clean N/A would
	// be misleading: at or above this, a run with no compute evidence is flagged for
	// review rather than silently passed.
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

	// No model card was declared: the run makes no compute claim, so there is
	// nothing to attest.
	if rec.Declared == nil {
		cert.Verdict = "N/A"
		cert.Notes = append(cert.Notes, "no declared model card; compute certificate not applicable")
		return cert
	}

	// Total FLOP capacity = what the GPUs could deliver over their active time
	// plus what the CPU could deliver over its measured core-seconds. Summed so the
	// bound stays generous (never false-accuses), and applicable whether the run
	// used a GPU, only the CPU, or both.
	gpuPeak := generousPeakFLOPs(rec.Hardware)
	cpuCapacity := cpuPeakFLOPSPerCore * cpuCoreSec
	availableFLOPs := gpuPeak*active + cpuCapacity
	cert.FPeakGenerous = gpuPeak
	cert.MinPJPerFLOP = minJoulesPerFLOP * 1e12

	haveTelemetry := active > 0 || energy > 0 || peakMem > 0 || cpuCoreSec > 0
	// A declaration is substantial when its training FLOPs clear the floor, or when
	// the model itself is large (e.g. an evaluation that declares params but no
	// training workload). Below this, a fast run is legitimately not checkable.
	substantial := fDeclared >= computeFloorFLOPs || rec.Declared.Params >= largeModelParams

	// Wall-clock floor, independent of telemetry: F_declared FLOPs need at least
	// F_declared/absolutePeakFLOPS seconds on any single machine. A run shorter than
	// that is physically impossible whatever the sampler captured, so a print-and-exit
	// fake that never yields a second sample is still caught here.
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
		// Time bound (hard): declared FLOPs cannot exceed the total FLOP capacity the
		// observed hardware could physically have delivered.
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

		// Energy bound (hard): F_declared FLOPs need at least F_declared*minJoulesPerFLOP joules.
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
		// A substantial model or workload was declared, but there is not enough
		// evidence (no telemetry, or no declared training workload to bound) to
		// corroborate it. Unless the wall-clock floor already proved impossibility,
		// this must not silently pass: flag it for review as unverified.
		if cert.TimeBoundOK {
			cert.Notes = append(cert.Notes,
				"review: a substantial model or workload was declared but there is not enough compute evidence to verify it; treat the declared figures as unverified")
		}

	default:
		// Small declared work with nothing impossible about it: not checkable, which
		// protects legitimately fast small runs.
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

// declaredFLOPs applies the 6ND lower bound: 6 * params * tokens, where tokens is
// dataset_size * epochs (times seq_len for token-based models). This underestimates
// CNN FLOPs, which is safe for the accusatory bound.
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

// aggregate reduces the hardware samples to GPU-active seconds, integrated GPU
// energy, peak GPU memory, and the process's CPU core-seconds. CPU time is a
// cumulative per-process counter, so the total core-seconds is its overall
// increase across the run.
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

// generousPeakFLOPs returns an UPPER bound on device throughput, summed over GPUs.
// It must be generous (theoretical peak): using an achieved rate here would
// false-accuse a run that hits a faster kernel path.
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
	// Unknown GPU: a generous default so the time bound never false-accuses.
	return 1e15
}
