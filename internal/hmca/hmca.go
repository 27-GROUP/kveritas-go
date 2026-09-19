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
	minSamplesTop2 = 150 // below this the two-cause estimator is too noisy; use one cause
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

	// How much the top components of the correlation matrix explain, relative to
	// chance (top/k). One cause is not enough for a phase-alternating run (CPU then
	// GPU), so use the top two components: near top/k when channels are independent,
	// near 1 when a few shared causes drive them. Rescaled to 0..1.
	C := correlation(cols)
	lam1, v1 := dominantEigen(C)
	top := 1
	if n >= minSamplesTop2 && k >= 4 {
		top = 2
	}
	evr := lam1 / float64(k)
	if top == 2 {
		deflate(C, lam1, v1)
		lam2, _ := dominantEigen(C)
		if lam2 < 0 {
			lam2 = 0
		}
		evr = (lam1 + lam2) / float64(k)
	}
	cross := (evr - float64(top)/float64(k)) / (1.0 - float64(top)/float64(k))
	if cross < 0 {
		cross = 0
	}
	if cross > 1 {
		cross = 1
	}
	return cross, ""
}

// activeChannels returns the per-process channels that carried real activity.
// cpu_freq and gpu_temp are deliberately excluded: they are board/system-wide, so
// an external process could drive them and inject a shared signal into a run that
// did nothing. Each channel must clear an absolute floor, so the measurement-noise
// jitter of a near-idle loop does not read as computation.
func activeChannels(samples []session.HardwareSample) []channel {
	get := func(f func(session.HardwareCounters) float64) []float64 {
		out := make([]float64, len(samples))
		for i, s := range samples {
			out[i] = f(s.Counters)
		}
		return out
	}
	gpuIdle := valueRange(get(func(c session.HardwareCounters) float64 { return c.GPUPowerW })) < gpuIdleRangeW

	type spec struct {
		name  string
		floor float64
		gpu   bool
		f     func(session.HardwareCounters) float64
	}
	// Floors are on per-interval activity (mean |first-difference|), not total range,
	// so a long idle run cannot accumulate its way past them.
	specs := []spec{
		{"cpu_time", 0.005, false, func(c session.HardwareCounters) float64 { return c.CPUTimeSec }},
		{"mem", 0.0002, false, func(c session.HardwareCounters) float64 { return c.MemUsedGB }},
		{"ctx_sw", 1.0, false, func(c session.HardwareCounters) float64 { return c.CtxSwitches }},
		{"minflt", 50, false, func(c session.HardwareCounters) float64 { return c.MinorFaults }},
		{"threads", 0.01, false, func(c session.HardwareCounters) float64 { return c.Threads }},
		{"disk_r", 0.005, false, func(c session.HardwareCounters) float64 { return c.DiskReadMB }},
		{"disk_w", 0.005, false, func(c session.HardwareCounters) float64 { return c.DiskWriteMB }},
		{"gpu_util", 0.1, true, func(c session.HardwareCounters) float64 { return c.GPUUtilPct }},
		{"gpu_mem", 0.5, true, func(c session.HardwareCounters) float64 { return c.GPUMemUsedMB }},
		{"gpu_power", 0.1, true, func(c session.HardwareCounters) float64 { return c.GPUPowerW }},
	}

	var act []channel
	for _, sp := range specs {
		if gpuIdle && sp.gpu {
			continue
		}
		vals := get(sp.f)
		if meanAbsDiff(vals) >= sp.floor {
			act = append(act, channel{sp.name, vals})
		}
	}
	return act
}

func meanAbsDiff(v []float64) float64 {
	if len(v) < 2 {
		return 0
	}
	var s float64
	for i := 1; i < len(v); i++ {
		s += math.Abs(v[i] - v[i-1])
	}
	return s / float64(len(v)-1)
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

// dominantEigen returns the largest eigenvalue and its unit eigenvector by power
// iteration, enough for a k<=10 symmetric correlation matrix.
func dominantEigen(C [][]float64) (float64, []float64) {
	k := len(C)
	x := make([]float64, k)
	for i := range x {
		x[i] = 1.0 / math.Sqrt(float64(k))
	}
	var lambda float64
	y := x
	for iter := 0; iter < 100; iter++ {
		y = make([]float64, k)
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
	return lambda, y
}

// deflate removes the component along v (eigenvalue lam) so the next power
// iteration finds the second eigenvalue.
func deflate(C [][]float64, lam float64, v []float64) {
	for i := range C {
		for j := range C[i] {
			C[i][j] -= lam * v[i] * v[j]
		}
	}
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
