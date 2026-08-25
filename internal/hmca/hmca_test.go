package hmca

import (
	"math"
	"testing"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

func makeTime(offsetSec int) time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return base.Add(time.Duration(offsetSec) * time.Second)
}

// coupledSamples builds a genuine-looking run: several channels driven by one
// shared activity signal (they co-fluctuate), plus real trend.
func coupledSamples(n int) []session.RunRecord {
	s := make([]session.HardwareSample, n)
	cpu := 0.0
	ctx := 0.0
	for i := 0; i < n; i++ {
		burst := 0.5 + 0.5*math.Sin(float64(i)*0.7) // shared activity
		cpu += 0.8 * burst
		ctx += 500 * burst
		s[i] = session.HardwareSample{
			Timestamp: makeTime(i),
			Counters: session.HardwareCounters{
				CPUTimeSec:   cpu,
				MemUsedGB:    4 + 0.3*burst,
				CtxSwitches:  ctx,
				CPUFreqMHz:   3000 + 500*burst,
				GPUUtilPct:   80 * burst,
				GPUMemUsedMB: 8000 + 400*burst,
				GPUPowerW:    40 + 120*burst,
				GPUTempC:     45 + 10*burst,
			},
		}
	}
	return []session.RunRecord{{HardwareSamples: s}}
}

// incoherentSamples builds a run where each channel is an INDEPENDENT random walk
// (fabricated/spliced): the channels share no cause, so coherence collapses.
func incoherentSamples(n int) []session.RunRecord {
	// simple deterministic per-channel PRNGs (different seeds)
	rng := func(seed uint64) func() float64 {
		st := seed
		return func() float64 {
			st = st*6364136223846793005 + 1442695040888963407
			return float64(st>>11)/float64(1<<53) - 0.5
		}
	}
	rc, rm, rx, rf, ru, rgm, rp, rt := rng(1), rng(2), rng(3), rng(4), rng(5), rng(6), rng(7), rng(8)
	s := make([]session.HardwareSample, n)
	cpu, ctx := 0.0, 0.0
	for i := 0; i < n; i++ {
		cpu += 0.8 * (rc() + 0.5)
		ctx += 500 * (rx() + 0.5)
		s[i] = session.HardwareSample{
			Timestamp: makeTime(i),
			Counters: session.HardwareCounters{
				CPUTimeSec:   cpu,
				MemUsedGB:    4 + rm(),
				CtxSwitches:  ctx,
				CPUFreqMHz:   3300 + 500*rf(),
				GPUUtilPct:   50 + 40*ru(),
				GPUMemUsedMB: 8000 + 800*rgm(),
				GPUPowerW:    100 + 100*rp(),
				GPUTempC:     50 + 10*rt(),
			},
		}
	}
	return []session.RunRecord{{HardwareSamples: s}}
}

func ptrs(runs []session.RunRecord) []*session.RunRecord {
	out := make([]*session.RunRecord, len(runs))
	for i := range runs {
		out[i] = &runs[i]
	}
	return out
}

func TestCoherentRunPasses(t *testing.T) {
	res := Analyze(ptrs(coupledSamples(60)), nil)
	if res.Verdict != "PASS" {
		t.Errorf("expected PASS for a coherent run, got %s (score %.3f, flags %v)", res.Verdict, res.Score, res.Flags)
	}
}

func TestIncoherentRunFlags(t *testing.T) {
	res := Analyze(ptrs(incoherentSamples(60)), nil)
	if res.Verdict == "PASS" {
		t.Errorf("expected a non-PASS verdict for an incoherent run, got PASS (score %.3f)", res.Score)
	}
}

func TestShortRunAbstains(t *testing.T) {
	res := Analyze(ptrs(coupledSamples(5)), nil)
	if res.Verdict != "N/A" {
		t.Errorf("expected N/A (abstain) for a too-short run, got %s", res.Verdict)
	}
}

func TestNoSamplesAbstains(t *testing.T) {
	res := Analyze([]*session.RunRecord{{}}, nil)
	if res.Verdict != "N/A" {
		t.Errorf("expected N/A when there are no samples, got %s", res.Verdict)
	}
}
