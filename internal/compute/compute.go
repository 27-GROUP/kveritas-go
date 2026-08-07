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
)

// Analyze produces the compute-cost certificate for a single run.
func Analyze(rec *session.RunRecord) session.ComputeCert {
	cert := session.ComputeCert{TimeBoundOK: true, EnergyBoundOK: true, MemoryBoundOK: true}

	active, energy, peakMem := aggregate(rec.HardwareSamples)
	cert.GPUActiveSec = active
	cert.EnergyJoules = energy
	cert.PeakGPUMemMB = peakMem

	// No GPU telemetry at all (CPU-only or no nvidia-smi): not applicable.
	if active == 0 && energy == 0 && peakMem == 0 {
		cert.Verdict = "N/A"
		cert.Notes = append(cert.Notes, "no GPU telemetry; compute certificate not applicable")
		return cert
	}

	fDeclared := declaredFLOPs(rec.Declared)
	cert.FDeclaredFLOPs = fDeclared

	// No declared model card, or declared work below the floor: not applicable.
	if rec.Declared == nil || fDeclared < computeFloorFLOPs {
		cert.Verdict = "N/A"
		cert.Notes = append(cert.Notes, "no declared model card or declared work below compute floor")
		return cert
	}

	fPeak := generousPeakFLOPs(rec.Hardware)
	cert.FPeakGenerous = fPeak
	cert.MinPJPerFLOP = minJoulesPerFLOP * 1e12

	// Time bound (hard): F_declared FLOPs cannot be done in less than
	// F_declared / F_peak seconds, even at 100% efficiency.
	if active > 0 && fPeak > 0 {
		cert.ImpliedMFU = fDeclared / (fPeak * active)
		if fDeclared > fPeak*active {
			cert.TimeBoundOK = false
			cert.Notes = append(cert.Notes, fmt.Sprintf(
				"time-impossible: %.3e declared FLOPs need >= %.1fs at peak %.2e FLOP/s, but only %.1fs GPU-active",
				fDeclared, fDeclared/fPeak, fPeak, active))
		}
	} else if active == 0 {
		cert.TimeBoundOK = false
		cert.Notes = append(cert.Notes,
			"time-impossible: heavy declared work but no GPU-active time observed")
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

// aggregate reduces the hardware samples to GPU-active seconds, integrated energy,
// and peak GPU memory.
func aggregate(samples []session.HardwareSample) (activeSec, energyJ, peakMemMB float64) {
	for i, s := range samples {
		if s.Counters.GPUMemUsedMB > peakMemMB {
			peakMemMB = s.Counters.GPUMemUsedMB
		}
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
