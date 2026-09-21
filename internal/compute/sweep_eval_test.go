package compute

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

type sweepTrace struct {
	CID      string                 `json:"cid"`
	Label    string                 `json:"label"`
	Family   string                 `json:"family"`
	Duration float64                `json:"duration_sec"`
	Declared *session.DeclaredModel `json:"declared"`
	Samples  []struct {
		T time.Time                `json:"t"`
		C session.HardwareCounters `json:"c"`
	} `json:"samples"`
}

func loadSweep(t *testing.T, path string) []sweepTrace {
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("corpus not present: %v", err)
	}
	defer f.Close()
	var out []sweepTrace
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	for sc.Scan() {
		var tl sweepTrace
		if err := json.Unmarshal(sc.Bytes(), &tl); err != nil {
			t.Fatalf("decode: %v", err)
		}
		out = append(out, tl)
	}
	return out
}

func (tl sweepTrace) record() *session.RunRecord {
	hs := make([]session.HardwareSample, len(tl.Samples))
	for i, s := range tl.Samples {
		hs[i] = session.HardwareSample{Timestamp: s.T, Counters: s.C}
	}
	return &session.RunRecord{
		DurationSec:     tl.Duration,
		HardwareSamples: hs,
		Hardware:        session.HardwareInfo{CPUCores: 16, GPUCount: 1, GPUNames: []string{"NVIDIA GeForce RTX 4060 Laptop GPU"}},
	}
}

// cardFor builds a model card whose 6ND product lands on the requested FLOP count.
func cardFor(flops float64) *session.DeclaredModel {
	const params = int64(1e8)
	tokens := flops / (6.0 * float64(params))
	if tokens < 1 {
		tokens = 1
	}
	return &session.DeclaredModel{Params: params, DatasetSize: int64(tokens), Epochs: 1, Arch: "transformer"}
}

// TestBoundarySweep walks the declared FLOP count across orders of magnitude on a
// real trace and reports where the verdict changes.
func TestBoundarySweep(t *testing.T) {
	traces := loadSweep(t, "/tmp/hmca_paper/kvsys.jsonl")
	var heavy sweepTrace
	for _, tl := range traces {
		if tl.Label == "genuine" && tl.Duration > heavy.Duration {
			heavy = tl
		}
	}
	if heavy.CID == "" {
		t.Skip("no genuine trace")
	}
	rec := heavy.record()
	active, energy, peakMem, cpuCoreSec := aggregate(rec.HardwareSamples)
	gpuPeak := generousPeakFLOPs(rec.Hardware)
	available := gpuPeak*active + cpuPeakFLOPSPerCore*cpuCoreSec

	t.Logf("trace %s (%s) dur=%.0fs", heavy.CID, heavy.Family, heavy.Duration)
	t.Logf("  gpu_active=%.0fs energy=%.0fJ peak_mem=%.0fMB cpu_core_sec=%.0f", active, energy, peakMem, cpuCoreSec)
	t.Logf("  hardware capacity = %.3e FLOPs   wall-clock ceiling = %.3e FLOPs", available, heavy.Duration*absolutePeakFLOPS)
	t.Logf("  energy ceiling    = %.3e FLOPs", energy/minJoulesPerFLOP)
	t.Log("")
	t.Logf("  %-12s %-24s %s", "declared", "verdict", "binding limit")

	var lastPass, firstImpossible float64
	for e := 9.0; e <= 24.0; e += 0.5 {
		f := math.Pow(10, e)
		rec.Declared = cardFor(f)
		c := Analyze(rec)
		limit := ""
		if !c.TimeBoundOK {
			limit = "time"
		}
		if !c.EnergyBoundOK {
			if limit != "" {
				limit += "+"
			}
			limit += "energy"
		}
		if e == math.Trunc(e) {
			t.Logf("  1e%-10.0f %-24s %s", e, c.Verdict, limit)
		}
		if c.Verdict == "PASS" {
			lastPass = f
		}
		if c.Verdict == "FABRICATION-IMPOSSIBLE" && firstImpossible == 0 {
			firstImpossible = f
		}
	}
	t.Log("")
	t.Logf("  highest declaration that PASSes      : %.3e", lastPass)
	t.Logf("  lowest declaration ruled IMPOSSIBLE  : %.3e", firstImpossible)
	if lastPass > 0 && firstImpossible > 0 {
		t.Logf("  gap between them                     : %.1fx", firstImpossible/lastPass)
	}
}

// TestRealDeclaredCards is the property that matters: the accusatory verdict is
// bound into the signature, so it must never fire on an honest declaration. These
// are the cards the workloads actually emitted, not synthetic ones.
func TestRealDeclaredCards(t *testing.T) {
	traces := loadSweep(t, "/tmp/hmca_paper/kvsys_cert.jsonl")
	byLabel := map[string]map[string]int{}
	accused := []string{}
	rows := []string{}
	for _, tl := range traces {
		if tl.Declared == nil {
			continue
		}
		rec := tl.record()
		rec.Declared = tl.Declared
		c := Analyze(rec)
		if byLabel[tl.Label] == nil {
			byLabel[tl.Label] = map[string]int{}
		}
		byLabel[tl.Label][c.Verdict]++
		active, energy, _, cpuCoreSec := aggregate(rec.HardwareSamples)
		capacity := generousPeakFLOPs(rec.Hardware)*active + cpuPeakFLOPSPerCore*cpuCoreSec
		rows = append(rows, fmt.Sprintf("  %-9s %-18s declared=%.2e capacity=%.2e energy_ceil=%.2e -> %s",
			tl.Label, tl.Family, c.FDeclaredFLOPs, capacity, energy/minJoulesPerFLOP, c.Verdict))
		if tl.Label == "genuine" && c.Verdict == "FABRICATION-IMPOSSIBLE" {
			accused = append(accused, fmt.Sprintf("%s %s", tl.CID, c.Notes))
		}
	}
	sort.Strings(rows)
	for _, r := range rows {
		t.Log(r)
	}
	t.Log("")
	labels := []string{}
	for k := range byLabel {
		labels = append(labels, k)
	}
	sort.Strings(labels)
	for _, l := range labels {
		t.Logf("  %-10s %v", l, byLabel[l])
	}
	for _, a := range accused {
		t.Errorf("genuine run accused: %s", a)
	}

	// How far an honest declaration sits below the bound that would accuse it.
	margins := map[string][]float64{}
	for _, tl := range traces {
		if tl.Declared == nil {
			continue
		}
		rec := tl.record()
		rec.Declared = tl.Declared
		c := Analyze(rec)
		_, energy, _, _ := aggregate(rec.HardwareSamples)
		if energy > 0 && c.FDeclaredFLOPs > 0 {
			margins[tl.Label] = append(margins[tl.Label], c.FDeclaredFLOPs/(energy/minJoulesPerFLOP))
		}
	}
	t.Log("")
	t.Log("  declared as a fraction of the energy ceiling (1.0 = accused):")
	for _, l := range labels {
		v := margins[l]
		if len(v) == 0 {
			continue
		}
		sort.Float64s(v)
		t.Logf("    %-10s n=%-3d min=%.4f med=%.4f max=%.4f", l, len(v), v[0], v[len(v)/2], v[len(v)-1])
	}
}

// TestPrintAndExit covers the fake with no telemetry at all: only the wall-clock
// floor can catch it.
func TestPrintAndExit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		dur   float64
		flops float64
	}{
		{"1e21 FLOPs claimed in 0.2s", 0.2, 1e21},
		{"1e21 FLOPs claimed in 2h", 7200, 1e21},
		{"1e18 FLOPs claimed in 0.2s", 0.2, 1e18},
		{"1e13 FLOPs claimed in 0.2s", 0.2, 1e13},
	} {
		rec := &session.RunRecord{DurationSec: tc.dur, Declared: cardFor(tc.flops)}
		c := Analyze(rec)
		t.Logf("  %-30s -> %-24s (needs >= %.1fs on any hardware)",
			tc.name, c.Verdict, tc.flops/absolutePeakFLOPS)
	}
}
