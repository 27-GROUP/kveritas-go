package hmca

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

type sweepRun struct {
	session.RunRecord
	Tag  string  `json:"_tag"`
	Duty float64 `json:"_duty"`
	Seed int     `json:"_seed"`
}

// TestAdaptiveCostCurve measures what the manufactured-coherence attack has to
// spend before it can earn a verdict, which is the only honest way to state the
// limitation: coherence is not free to fake, it costs real computation.
func TestAdaptiveCostCurve(t *testing.T) {
	dir := "/tmp/kvadaptive/runs"
	files, _ := filepath.Glob(dir + "/*.json")
	if len(files) == 0 {
		t.Skip("sweep not present")
	}

	type row struct {
		duty, cpu, score, kurt float64
		verdict                string
		channels               int
	}
	byDuty := map[float64][]row{}

	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var r sweepRun
		if json.Unmarshal(b, &r) != nil || len(r.HardwareSamples) < 2 {
			continue
		}
		rec := &r.RunRecord
		res := Analyze([]*session.RunRecord{rec}, nil)
		cross, kurt, _ := coherenceOne(r.HardwareSamples)
		// Sum the positive increments: CPU time is summed over the process tree, so a
		// child exiting drops its total out and last-minus-first can even go negative.
		cpu := 0.0
		for i := 1; i < len(r.HardwareSamples); i++ {
			if d := r.HardwareSamples[i].Counters.CPUTimeSec - r.HardwareSamples[i-1].Counters.CPUTimeSec; d > 0 {
				cpu += d
			}
		}
		act := activeChannels(r.HardwareSamples, sampleDt(r.HardwareSamples))
		byDuty[r.Duty] = append(byDuty[r.Duty], row{
			duty: r.Duty, cpu: cpu / math.Max(r.DurationSec, 1e-9), score: cross,
			kurt: kurt, verdict: res.Verdict, channels: len(act),
		})
	}

	duties := []float64{}
	for d := range byDuty {
		duties = append(duties, d)
	}
	sort.Float64s(duties)

	t.Logf("%-7s %-9s %-7s %-7s %-8s %s", "duty", "cores", "chans", "score", "kurtosis", "verdicts")
	t.Log("------------------------------------------------------------------------")
	for _, d := range duties {
		rs := byDuty[d]
		var cpu, score, kurt float64
		nk := 0
		verd := map[string]int{}
		chans := 0
		for _, r := range rs {
			cpu += r.cpu
			score += r.score
			chans += r.channels
			if !math.IsNaN(r.kurt) {
				kurt += r.kurt
				nk++
			}
			verd[r.verdict]++
		}
		n := float64(len(rs))
		ks := "n/a"
		if nk > 0 {
			ks = fmt.Sprintf("%.2f", kurt/float64(nk))
		}
		t.Logf("%-7.2f %-9.3f %-7.1f %-7.3f %-8s %v", d, cpu/n, float64(chans)/n, score/n, ks, verd)
	}

	// The cheapest budget at which the attack can earn anything better than an
	// abstention is the number the paper should quote.
	cheapest := math.Inf(1)
	for _, d := range duties {
		for _, r := range byDuty[d] {
			if r.verdict == "PASS" || r.verdict == "WARN" {
				if r.cpu < cheapest {
					cheapest = r.cpu
				}
			}
		}
	}
	t.Log("")
	if math.IsInf(cheapest, 1) {
		t.Log("no budget in this sweep earned PASS or WARN; every attempt abstained or failed")
	} else {
		t.Logf("cheapest budget earning PASS/WARN: %.3f cores sustained", cheapest)
	}
}
