package compute

import (
	"fmt"
	"strings"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const (
	utilActiveThreshold = 5.0
	// Below any real device (best ~3.1 pJ/FLOP), so it never false-accuses.
	minJoulesPerFLOP    = 0.5e-12
	computeFloorFLOPs   = 1e12
	fp16BytesPerParam   = 2
	cpuPeakFLOPSPerCore = 1e12
	// F FLOPs need at least F/absolutePeakFLOPS seconds on any hardware.
	absolutePeakFLOPS = 1e16
	largeModelParams  = 1e9
)

func Analyze(rec *session.RunRecord) session.ComputeCert {
	cert := session.ComputeCert{TimeBoundOK: true, EnergyBoundOK: true, MemoryBoundOK: true}

	active, energy, peakMem, cpuCoreSec := aggregate(rec.HardwareSamples)
	gpuPeak := generousPeakFLOPs(rec.Hardware)
	availableFLOPs := gpuPeak*active + cpuPeakFLOPSPerCore*cpuCoreSec
	for _, n := range rec.Nodes {
		a, e, m, c := aggregate(n.HardwareSamples)
		p := generousPeakFLOPs(n.Hardware)
		availableFLOPs += p*a + cpuPeakFLOPSPerCore*c
		gpuPeak += p
		active += a
		energy += e
		peakMem += m
		cpuCoreSec += c
	}
	cert.GPUActiveSec = active
	cert.EnergyJoules = energy
	cert.PeakGPUMemMB = peakMem

	fDeclared := declaredFLOPs(rec.Declared)
	cert.FDeclaredFLOPs = fDeclared

	if rec.Declared == nil {
		cert.Verdict = "N/A"
		cert.Notes = append(cert.Notes, "no declared model card; compute certificate not applicable")
		return cert
	}

	cert.FPeakGenerous = gpuPeak
	cert.MinPJPerFLOP = minJoulesPerFLOP * 1e12

	haveTelemetry := active > 0 || energy > 0 || peakMem > 0 || cpuCoreSec > 0
	substantial := fDeclared >= computeFloorFLOPs || rec.Declared.Params >= largeModelParams

	// Catches a print-and-exit fake with no telemetry.
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

		if energy > 0 {
			minEnergy := fDeclared * minJoulesPerFLOP
			if energy < minEnergy {
				cert.EnergyBoundOK = false
				cert.Notes = append(cert.Notes, fmt.Sprintf(
					"energy-impossible: declared work needs >= %.1f J, but only %.1f J measured",
					minEnergy, energy))
			}
		}

		if rec.Declared.Params > 0 && peakMem > 0 {
			weightsMB := float64(rec.Declared.Params*fp16BytesPerParam) / 1e6
			if weightsMB > peakMem*1.1 {
				cert.Notes = append(cert.Notes, fmt.Sprintf(
					"memory-review: declared params need ~%.0f MB of weights, but peak GPU memory was %.0f MB",
					weightsMB, peakMem))
			}
		}

	case substantial:
		if cert.TimeBoundOK {
			cert.Notes = append(cert.Notes,
				"review: a substantial model or workload was declared but there is not enough compute evidence to verify it; treat the declared figures as unverified")
		}

	default:
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

// 6ND lower bound; underestimates CNNs, which is safe for an accusatory bound.
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

func Usage(samples []session.HardwareSample) (gpuActiveSec, energyJ, peakGPUMemMB, cpuCoreSec float64) {
	return aggregate(samples)
}

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

// Theoretical peak: an achieved rate would false-accuse a fast kernel.
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
	return 1e15
}
