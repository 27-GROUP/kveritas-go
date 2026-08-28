// Package hmca measures single-cause coherence: whether a run's telemetry
// channels co-fluctuate as shadows of one process. Genuine computation couples
// them; a fabricated, replayed, or spliced trace does not. Metric-blind.
package hmca

import (
	"fmt"
	"math"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const (
	minSamples    = 20   // below this, abstain
	minActive     = 2    // need two active channels to judge coupling
	gpuIdleRangeW = 15.0 // GPU power swing below this means the GPU did not engage
	// Coherence thresholds (0..1), calibrated on genuine vs fabricated traces.
	coherentPASS = 0.15
	coherentWARN = 0.08
)

type channel struct {
	name string
	vals []float64
}

// Analyze computes per-run coherence from each run's scoped samples and returns
// the session verdict. The samples argument is kept for signature compatibility.
func Analyze(runs []*session.RunRecord, samples []session.HardwareSample) session.HMCAResult {
	var scores []float64
	var flags []string
	judged := 0

	for i, run := range runs {
		cross, status := coherenceOne(run.HardwareSamples)
		switch status {
		case "insufficient":
			// too few samples: abstain, no accusation
		case "no_activity":
			judged++
			flags = append(flags, fmt.Sprintf("run_%d: no computational activity observed", i+1))
		default:
			judged++
			scores = append(scores, cross)
			if cross < coherentWARN {
				flags = append(flags, fmt.Sprintf("run_%d: execution channels are not coherent (%.2f); possible fabrication/replay", i+1, cross))
			} else if cross < coherentPASS {
				flags = append(flags, fmt.Sprintf("run_%d: weak execution coherence (%.2f)", i+1, cross))
			}
		}
	}

	if judged == 0 {
		// Nothing measurable: HMCA abstains; authenticity rests on the other checks.
		return session.HMCAResult{Score: 0, Verdict: "N/A", Flags: nil}
	}

	// Session score is the weakest run's coherence; no scored runs means every
	// judged run had no activity.
	score := 0.0
	verdict := "FAIL"
	if len(scores) > 0 {
		score = scores[0]
		for _, s := range scores[1:] {
			if s < score {
				score = s
			}
		}
		switch {
		case score >= coherentPASS:
			verdict = "PASS"
		case score >= coherentWARN:
			verdict = "WARN"
		default:
			verdict = "FAIL"
		}
	}
	return session.HMCAResult{Score: score, Flags: flags, Verdict: verdict}
}

// coherenceOne returns one run's coherence (0..1) and a status: "" (genuine),
// "no_activity", or "insufficient".
func coherenceOne(samples []session.HardwareSample) (float64, string) {
	n := len(samples)
	if n < minSamples {
		return 0, "insufficient"
	}

	act := activeChannels(samples)
	if len(act) < minActive {
		return 0, "no_activity"
	}

	// First-difference each channel (removes the shared trend, so a smooth ramp is
	// not read as coupling), then standardize to unit variance.
	var cols [][]float64
	for _, ch := range act {
		d := diff(ch.vals)
		z, ok := standardize(d)
		if ok {
			cols = append(cols, z)
		}
	}
	k := len(cols)
	if k < minActive {
		return 0, "no_activity"
	}

	// Largest eigenvalue of the correlation matrix, relative to k, measures how
	// much one shared component explains: ~1/k when independent, near 1 for a
	// single cause. Rescaled to 0..1.
	C := correlation(cols)
	lambda := largestEigenvalue(C)
	evr1 := lambda / float64(k)
	cross := (evr1 - 1.0/float64(k)) / (1.0 - 1.0/float64(k))
	if cross < 0 {
		cross = 0
	}
	if cross > 1 {
		cross = 1
	}
	return cross, ""
}

// activeChannels returns the channels that genuinely varied. GPU channels are
// dropped when the GPU never engaged, so idle drift does not dilute a CPU-only run.
func activeChannels(samples []session.HardwareSample) []channel {
	get := func(f func(session.HardwareCounters) float64) []float64 {
		out := make([]float64, len(samples))
		for i, s := range samples {
			out[i] = f(s.Counters)
		}
		return out
	}
	all := []channel{
		{"cpu_time", get(func(c session.HardwareCounters) float64 { return c.CPUTimeSec })},
		{"mem", get(func(c session.HardwareCounters) float64 { return c.MemUsedGB })},
		{"ctx_sw", get(func(c session.HardwareCounters) float64 { return c.CtxSwitches })},
		{"minflt", get(func(c session.HardwareCounters) float64 { return c.MinorFaults })},
		{"threads", get(func(c session.HardwareCounters) float64 { return c.Threads })},
		{"cpu_freq", get(func(c session.HardwareCounters) float64 { return c.CPUFreqMHz })},
		{"disk_r", get(func(c session.HardwareCounters) float64 { return c.DiskReadMB })},
		{"disk_w", get(func(c session.HardwareCounters) float64 { return c.DiskWriteMB })},
		{"gpu_util", get(func(c session.HardwareCounters) float64 { return c.GPUUtilPct })},
		{"gpu_mem", get(func(c session.HardwareCounters) float64 { return c.GPUMemUsedMB })},
		{"gpu_power", get(func(c session.HardwareCounters) float64 { return c.GPUPowerW })},
		{"gpu_temp", get(func(c session.HardwareCounters) float64 { return c.GPUTempC })},
	}
	gpu := map[string]bool{"gpu_util": true, "gpu_mem": true, "gpu_power": true, "gpu_temp": true}
	gpuIdle := valueRange(all[10].vals) < gpuIdleRangeW // gpu_power range

	var act []channel
	for _, ch := range all {
		if gpuIdle && gpu[ch.name] {
			continue
		}
		rng := valueRange(ch.vals)
		mean := average(ch.vals)
		// variation meaningful relative to the channel's own scale: rejects
		// constants and measurement-noise jitter alike
		if rng > 1e-9 && rng > 1e-4*(math.Abs(mean)+1e-9) {
			act = append(act, ch)
		}
	}
	return act
}

func diff(v []float64) []float64 {
	if len(v) < 2 {
		return nil
	}
	d := make([]float64, len(v)-1)
	for i := 1; i < len(v); i++ {
		d[i-1] = v[i] - v[i-1]
	}
	return d
}

func standardize(v []float64) ([]float64, bool) {
	m := average(v)
	var s float64
	for _, x := range v {
		s += (x - m) * (x - m)
	}
	s = math.Sqrt(s / float64(len(v)))
	if s < 1e-9 {
		return nil, false
	}
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = (x - m) / s
	}
	return out, true
}

// correlation builds the k x k Pearson matrix of already-standardized columns.
func correlation(cols [][]float64) [][]float64 {
	k := len(cols)
	m := len(cols[0])
	C := make([][]float64, k)
	for i := range C {
		C[i] = make([]float64, k)
	}
	for i := 0; i < k; i++ {
		for j := i; j < k; j++ {
			var dot float64
			for t := 0; t < m; t++ {
				dot += cols[i][t] * cols[j][t]
			}
			c := dot / float64(m)
			C[i][j] = c
			C[j][i] = c
		}
	}
	return C
}

// largestEigenvalue returns the dominant eigenvalue by power iteration, enough
// for a k<=12 symmetric correlation matrix.
func largestEigenvalue(C [][]float64) float64 {
	k := len(C)
	x := make([]float64, k)
	for i := range x {
		x[i] = 1.0 / math.Sqrt(float64(k))
	}
	var lambda float64
	for iter := 0; iter < 100; iter++ {
		y := make([]float64, k)
		for i := 0; i < k; i++ {
			for j := 0; j < k; j++ {
				y[i] += C[i][j] * x[j]
			}
		}
		var norm float64
		for _, v := range y {
			norm += v * v
		}
		norm = math.Sqrt(norm)
		if norm < 1e-12 {
			break
		}
		for i := range y {
			y[i] /= norm
		}
		// Rayleigh quotient x^T C x
		var l float64
		for i := 0; i < k; i++ {
			var ci float64
			for j := 0; j < k; j++ {
				ci += C[i][j] * y[j]
			}
			l += y[i] * ci
		}
		if math.Abs(l-lambda) < 1e-9 {
			lambda = l
			break
		}
		lambda = l
		x = y
	}
	return lambda
}

func average(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func valueRange(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	mn, mx := v[0], v[0]
	for _, x := range v {
		if x < mn {
			mn = x
		}
		if x > mx {
			mx = x
		}
	}
	return mx - mn
}
