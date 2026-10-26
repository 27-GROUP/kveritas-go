package hmca

import (
	"fmt"
	"math"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const (
	minSamples = 20
	// Two channels are one correlation coefficient, too noisy to accuse on.
	minActive      = 3
	minSamplesTop2 = 150
	gpuIdleRangeW  = 15.0
	coherentPASS   = 0.15
	coherentWARN   = 0.08
	// Real work is bursty (kurtosis in the tens); a timer duty cycle lands near 1.
	analysisRateHz  = 2.0
	uniformKurtosis = 2.0
	windowTolerance = time.Second
	nodeClockSkew   = 5 * time.Minute
)

type channel struct {
	name string
	vals []float64
}

// The samples argument is unused; kept for signature compatibility.
func Analyze(runs []*session.RunRecord, samples []session.HardwareSample) session.HMCAResult {
	var scores []float64
	var flags []string
	judged := 0

	uniform := false
	replayed := false
	sameMachine := false
	var nodes []session.NodeCoherence
	judge := func(label string, run *session.RunRecord) (float64, string) {
		if !telemetryInWindow(run) {
			judged++
			replayed = true
			flags = append(flags, fmt.Sprintf("%s: telemetry timestamps lie outside the run; the samples describe a different execution", label))
			return 0, "FAIL"
		}
		if cpuTimeExceedsCores(run) {
			judged++
			replayed = true
			flags = append(flags, fmt.Sprintf("%s: processor time exceeds what %d cores could deliver in %.0fs", label, run.Hardware.CPUCores, run.DurationSec))
			return 0, "FAIL"
		}
		cross, kurt, status := coherenceOne(run.HardwareSamples)
		switch status {
		case "insufficient":
			return 0, "N/A"
		case "no_activity":
			judged++
			flags = append(flags, fmt.Sprintf("%s: no computational activity observed", label))
			return 0, "FAIL"
		}
		judged++
		scores = append(scores, cross)
		verdict := "PASS"
		if cross < coherentWARN {
			verdict = "FAIL"
			flags = append(flags, fmt.Sprintf("%s: execution channels are not coherent (%.2f); possible fabrication/replay", label, cross))
		} else if cross < coherentPASS {
			verdict = "WARN"
			flags = append(flags, fmt.Sprintf("%s: weak execution coherence (%.2f)", label, cross))
		}
		if cross >= coherentPASS && !math.IsNaN(kurt) && kurt <= uniformKurtosis {
			uniform = true
			verdict = "WARN"
			flags = append(flags, fmt.Sprintf("%s: coherence is uniform rather than bursty (%.2f); consistent with load driven on a timer", label, kurt))
		}
		return cross, verdict
	}
	for i, run := range runs {
		score, verdict := judge(fmt.Sprintf("run_%d", i+1), run)
		if len(run.Nodes) == 0 && run.NodesExpected < 2 {
			continue
		}
		nodes = append(nodes, session.NodeCoherence{Run: i + 1, Node: 0, Score: score, Verdict: verdict, Samples: len(run.HardwareSamples)})
		machines := map[string]int{}
		if run.Hardware.MachineID != "" {
			machines[run.Hardware.MachineID] = 0
		}
		for _, n := range run.Nodes {
			label := fmt.Sprintf("run_%d node %d", i+1, n.Node)
			nr := &session.RunRecord{StartAt: n.StartAt, EndAt: n.EndAt, DurationSec: n.DurationSec,
				Hardware: n.Hardware, HardwareSamples: n.HardwareSamples}
			score, verdict := judge(label, nr)
			if n.StartAt.After(run.EndAt.Add(nodeClockSkew)) || n.EndAt.Before(run.StartAt.Add(-nodeClockSkew)) {
				replayed = true
				verdict = "FAIL"
				flags = append(flags, fmt.Sprintf("%s: measured at a different time than the run; it describes another execution", label))
			}
			if prev, ok := machines[n.MachineID]; ok && n.MachineID != "" {
				sameMachine = true
				flags = append(flags, fmt.Sprintf("%s: same machine as node %d; the run did not span distinct machines", label, prev))
			} else {
				machines[n.MachineID] = n.Node
			}
			nodes = append(nodes, session.NodeCoherence{Run: i + 1, Node: n.Node, Score: score, Verdict: verdict, Samples: len(n.HardwareSamples)})
		}
		if measured := len(run.Nodes) + 1; run.NodesExpected > measured {
			flags = append(flags, fmt.Sprintf("run_%d: %d of %d nodes measured; the others ran without kveritas", i+1, measured, run.NodesExpected))
		}
	}

	if judged == 0 {
		if len(nodes) > 0 {
			return session.HMCAResult{Score: 0, Verdict: "N/A", Flags: flags, Nodes: nodes}
		}
		return session.HMCAResult{Score: 0, Verdict: "N/A", Flags: nil}
	}

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
		// Regular coherence is cheap to fake: withhold the pass, but do not accuse.
		if (uniform || sameMachine) && verdict == "PASS" {
			verdict = "WARN"
		}
	}
	if replayed {
		verdict = "FAIL"
	}
	return session.HMCAResult{Score: score, Flags: flags, Verdict: verdict, Nodes: nodes}
}

// CPU time above cores x wall-clock is impossible, so a replay squeezed into a shorter run trips it.
func cpuTimeExceedsCores(run *session.RunRecord) bool {
	cores := run.Hardware.CPUCores
	n := len(run.HardwareSamples)
	if cores <= 0 || n < 2 || run.DurationSec <= 0 {
		return false
	}
	used := run.HardwareSamples[n-1].Counters.CPUTimeSec - run.HardwareSamples[0].Counters.CPUTimeSec
	return used > float64(cores)*run.DurationSec*1.10
}

// A replayed trace falls outside the run's own window even when coherent.
func telemetryInWindow(run *session.RunRecord) bool {
	if run.StartAt.IsZero() || run.EndAt.IsZero() || len(run.HardwareSamples) == 0 {
		return true
	}
	lo := run.StartAt.Add(-windowTolerance)
	hi := run.EndAt.Add(windowTolerance)
	for _, s := range run.HardwareSamples {
		if s.Timestamp.Before(lo) || s.Timestamp.After(hi) {
			return false
		}
	}
	return true
}

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
		return 0, math.NaN(), "insufficient"
	}

	// First differences, so a smooth ramp is not read as coupling.
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

	// Top two components: a phase-alternating run (CPU then GPU) has two causes.
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

	// Subtract the residue independent channels leave in finite samples.
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

// At a fixed rate: at the raw rate the shape would change with duration.
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

// cpu_freq and gpu_temp are board-wide, so another process could inject a shared signal.
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
	// Cumulative counters gate on work per second; levels keep an absolute floor.
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
