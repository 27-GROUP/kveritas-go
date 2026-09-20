package hmca

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

type traceLine struct {
	CID      string  `json:"cid"`
	Label    string  `json:"label"`
	Family   string  `json:"family"`
	WType    string  `json:"wtype"`
	Duration float64 `json:"duration_sec"`
	Samples  []struct {
		T time.Time                `json:"t"`
		C session.HardwareCounters `json:"c"`
	} `json:"samples"`
}

func loadTraces(t *testing.T, path string) []traceLine {
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("corpus not present: %v", err)
	}
	defer f.Close()
	var out []traceLine
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	for sc.Scan() {
		var tl traceLine
		if err := json.Unmarshal(sc.Bytes(), &tl); err != nil {
			t.Fatalf("decode: %v", err)
		}
		out = append(out, tl)
	}
	return out
}

func (tl traceLine) records() []*session.RunRecord {
	hs := make([]session.HardwareSample, len(tl.Samples))
	for i, s := range tl.Samples {
		hs[i] = session.HardwareSample{Timestamp: s.T, Counters: s.C}
	}
	return []*session.RunRecord{{HardwareSamples: hs}}
}

// TestCorpusEval runs the shipped detector over every stored trace and prints the
// confusion table. It asserts only the property that matters: no genuine run is
// accused.
func TestCorpusEval(t *testing.T) {
	paths := []string{
		"/tmp/hmca_paper/traces.jsonl",
		"/tmp/hmca_paper/adaptive.jsonl",
		"/tmp/hmca_paper/long.jsonl",
		"/tmp/hmca_paper/defense.jsonl",
	}
	type cell struct{ pass, warn, fail, na int }
	byGroup := map[string]*cell{}
	var kurtGenuine, kurtAttack []float64
	falseAccusations := []string{}

	for _, p := range paths {
		for _, tl := range loadTraces(t, p) {
			res := Analyze(tl.records(), nil)
			grp := tl.Label + "/" + tl.Family
			if byGroup[grp] == nil {
				byGroup[grp] = &cell{}
			}
			c := byGroup[grp]
			switch res.Verdict {
			case "PASS":
				c.pass++
			case "WARN":
				c.warn++
			case "FAIL":
				c.fail++
			default:
				c.na++
			}
			if tl.Label == "genuine" && res.Verdict == "FAIL" {
				falseAccusations = append(falseAccusations,
					fmt.Sprintf("%s %s/%s score=%.3f", tl.CID, tl.Family, tl.WType, res.Score))
			}
			_, k, st := coherenceOne(tl.records()[0].HardwareSamples)
			if st == "" && !math.IsNaN(k) {
				if tl.Label == "genuine" {
					kurtGenuine = append(kurtGenuine, k)
				} else {
					kurtAttack = append(kurtAttack, k)
				}
			}
		}
	}

	keys := make([]string, 0, len(byGroup))
	for k := range byGroup {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Log("group                    PASS WARN FAIL  N/A")
	for _, k := range keys {
		c := byGroup[k]
		t.Logf("%-24s %4d %4d %4d %4d", k, c.pass, c.warn, c.fail, c.na)
	}
	pct := func(v []float64, q float64) float64 {
		if len(v) == 0 {
			return math.NaN()
		}
		s := append([]float64(nil), v...)
		sort.Float64s(s)
		return s[int(q*float64(len(s)-1))]
	}
	t.Logf("kurtosis genuine n=%d p1=%.2f p5=%.2f med=%.2f",
		len(kurtGenuine), pct(kurtGenuine, 0.01), pct(kurtGenuine, 0.05), pct(kurtGenuine, 0.5))
	t.Logf("kurtosis attack  n=%d p50=%.2f p95=%.2f",
		len(kurtAttack), pct(kurtAttack, 0.5), pct(kurtAttack, 0.95))

	if len(falseAccusations) > 0 {
		for _, f := range falseAccusations {
			t.Errorf("genuine run accused: %s", f)
		}
	}
}
