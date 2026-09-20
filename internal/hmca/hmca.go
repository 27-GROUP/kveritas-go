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
	minSamples = 20 // below this, abstain
	// Two channels reduce the statistic to a single correlation coefficient,
	// which is too noisy to accuse on: tight CPU loops that move only processor
	// time and context switches swing between 0.06 and 1.00 across seeds.
	minActive      = 3
	minSamplesTop2 = 150  // below this the two-cause estimator is too noisy; use one cause
	gpuIdleRangeW  = 15.0 // GPU power swing below this means the GPU did not engage
	// Coherence thresholds (0..1), calibrated on genuine vs fabricated traces.
	coherentPASS = 0.15
	coherentWARN = 0.08
	// Real computation drives its channels in bursts, so the shared component is
	// heavy-tailed (kurtosis well above the Gaussian 3, typically tens). A duty
	// cycle that manufactures coherence by toggling load on a timer is closer to a
	// square wave and lands near 1. Only meaningful at a known sampling rate.
	analysisRateHz  = 2.0
	uniformKurtosis = 2.0
)

type channel struct {
	name string
	vals []float64
}

// The samples argument is unused; it is kept for signature compatibility.
func Analyze(runs []*session.RunRecord, samples []session.HardwareSample) session.HMCAResult {
	var scores []float64
	var flags []string
	judged := 0

	uniform := false
	for i, run := range runs {
		cross, kurt, status := coherenceOne(run.HardwareSamples)
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
			if cross >= coherentPASS && !math.IsNaN(kurt) && kurt <= uniformKurtosis {
				uniform = true
				flags = append(flags, fmt.Sprintf("run_%d: coherence is uniform rather than bursty (%.2f); consistent with load driven on a timer", i+1, kurt))
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
		// Coherence this regular is cheap to manufacture, so it is not evidence of
		// work. Withhold the pass; do not accuse, the shape alone is not proof.
		if uniform && verdict == "PASS" {
			verdict = "WARN"
		}
	}
	return session.HMCAResult{Score: score, Flags: flags, Verdict: verdict}
}

// coherenceOne returns one run's coherence (0..1), the kurtosis of its shared
// component (NaN when the trace is too coarse to judge shape), and a status:
// "" (genuine), "no_activity", or "insufficient".
func coherenceOne(samples []session.HardwareSample) (float64, float64, string) {
	n := len(samples)
	if n < minSamples {
		return 0, math.NaN(), "insufficient"
	}

	act := activeChannels(samples, sampleDt(samples))
	if len(act) == 0 {
		return 0, math.NaN(), "no_activity"
	}
	if len(act) < minActive {
		// Work is present but one channel cannot show coupling. Abstain rather
		// than accuse: a light but genuine run looks like this.
		return 0, math.NaN(), "insufficient"
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
	if k == 0 {
		return 0, math.NaN(), "no_activity"
	}
	if k < minActive {
		return 0, math.NaN(), "insufficient"
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

	// Independent channels still leave a positive residue in finite samples, and
	// it grows as the trace shortens, so a short or channel-poor run would score
	// above threshold on noise alone. Subtract that expected residue.
	null := nullCoherence(k, n, top)
	cross = (cross - null) / (1.0 - null)

	if cross < 0 {
		cross = 0
	}
	if cross > 1 {
		cross = 1
	}

	return cross, shapeKurtosis(samples), ""
}

// Burstiness of the shared component, re-derived at a fixed rate because sampling
// rate sets the scale of the statistic: judged at the raw rate, the same run would
// change shape with its duration. NaN when the trace is too coarse to reach it.
func shapeKurtosis(samples []session.HardwareSample) float64 {
	rs, rate := resample(samples, analysisRateHz)
	if rate < analysisRateHz*0.9 || len(rs) < minSamples {
		return math.NaN()
	}
	act := activeChannels(rs, 1.0/rate)
	if len(act) < minActive {
		return math.NaN()
	}
	var cols [][]float64
	for _, ch := range act {
		if z, ok := standardize(diff(ch.vals)); ok {
			cols = append(cols, z)
		}
	}
	if len(cols) < minActive {
		return math.NaN()
	}
	_, v := dominantEigen(correlation(cols))
	return kurtosis(project(cols, v))
}

func sampleDt(samples []session.HardwareSample) float64 {
	n := len(samples)
	if n < 2 {
		return 0
	}
	span := samples[n-1].Timestamp.Sub(samples[0].Timestamp).Seconds()
	if span <= 0 {
		return 0
	}
	return span / float64(n-1)
}

// resample puts the trace on a fixed-rate time grid and reports the rate achieved.
func resample(samples []session.HardwareSample, hz float64) ([]session.HardwareSample, float64) {
	n := len(samples)
	if n < 2 {
		return samples, 0
	}
	span := samples[n-1].Timestamp.Sub(samples[0].Timestamp).Seconds()
	if span <= 0 {
		return samples, 0
	}
	if have := float64(n-1) / span; have <= hz {
		return samples, have
	}
	want := int(span*hz) + 1
	out := make([]session.HardwareSample, 0, want)
	j := 0
	for i := 0; i < want; i++ {
		t := float64(i) / hz
		for j+1 < n && samples[j+1].Timestamp.Sub(samples[0].Timestamp).Seconds() <= t {
			j++
		}
		out = append(out, samples[j])
	}
	return out, hz
}

// project collapses the standardized channels onto the shared component v, giving
// the one signal every channel is a shadow of.
func project(cols [][]float64, v []float64) []float64 {
	m := len(cols[0])
	out := make([]float64, m)
	for t := 0; t < m; t++ {
		var x float64
		for i := range cols {
			x += v[i] * cols[i][t]
		}
		out[t] = x
	}
	return out
}

func kurtosis(v []float64) float64 {
	n := float64(len(v))
	if n < 4 {
		return math.NaN()
	}
	m := average(v)
	var m2, m4 float64
	for _, x := range v {
		d := x - m
		m2 += d * d
		m4 += d * d * d * d
	}
	m2 /= n
	m4 /= n
	if m2 < 1e-12 {
		return math.NaN()
	}
	return m4 / (m2 * m2)
}

// nullCoherence is the value the statistic takes when the channels are
// independent, fitted to simulated correlation matrices. It falls as 1/sqrt(n)
// and, for the two-cause form, rises as the channel count falls.
func nullCoherence(k, n, top int) float64 {
	if n < 2 {
		return 0
	}
	c := 0.80
	if top >= 2 {
		c = 0.85 + 2.4/float64(k)
	}
	null := c / math.Sqrt(float64(n))
	if null > 0.9 {
		null = 0.9
	}
	return null
}

// Channels that carried real activity, given the seconds between samples.
// cpu_freq and gpu_temp are deliberately excluded: they are board-wide, so an
// external process could drive them and inject a shared signal into a run that
// did nothing.
func activeChannels(samples []session.HardwareSample, dt float64) []channel {
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
		rate  bool
		f     func(session.HardwareCounters) float64
	}
	// Cumulative counters are gated on work per second, which means the same thing
	// at any sampling rate and cannot be accumulated past by simply running longer.
	// The rest are instantaneous levels, where coarser sampling genuinely averages
	// fluctuation away, so they keep an absolute floor on movement between samples.
	specs := []spec{
		{"cpu_time", 0.05, false, true, func(c session.HardwareCounters) float64 { return c.CPUTimeSec }},
		{"ctx_sw", 10, false, true, func(c session.HardwareCounters) float64 { return c.CtxSwitches }},
		{"minflt", 500, false, true, func(c session.HardwareCounters) float64 { return c.MinorFaults }},
		{"disk_r", 0.05, false, true, func(c session.HardwareCounters) float64 { return c.DiskReadMB }},
		{"disk_w", 0.05, false, true, func(c session.HardwareCounters) float64 { return c.DiskWriteMB }},
		{"mem", 0.0002, false, false, func(c session.HardwareCounters) float64 { return c.MemUsedGB }},
		{"threads", 0.01, false, false, func(c session.HardwareCounters) float64 { return c.Threads }},
		{"gpu_util", 0.1, true, false, func(c session.HardwareCounters) float64 { return c.GPUUtilPct }},
		{"gpu_mem", 0.5, true, false, func(c session.HardwareCounters) float64 { return c.GPUMemUsedMB }},
		{"gpu_power", 0.1, true, false, func(c session.HardwareCounters) float64 { return c.GPUPowerW }},
	}

	if dt <= 0 {
		dt = 1.0 / analysisRateHz
	}
	var act []channel
	for _, sp := range specs {
		if gpuIdle && sp.gpu {
			continue
		}
		vals := get(sp.f)
		move := meanAbsDiff(vals)
		if sp.rate {
			move /= dt
		}
		if move >= sp.floor {
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
