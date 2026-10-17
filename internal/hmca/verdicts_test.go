package hmca

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

type labelledRun struct {
	session.RunRecord
	Label  string `json:"_label"`
	Family string `json:"_family"`
	File   string `json:"_file"`
}

func TestCurrentVerdicts(t *testing.T) {
	f, err := os.Open("/tmp/hmca_paper/kvruns.jsonl")
	if err != nil {
		t.Skip("corpus absent")
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	counts := map[string]map[string]int{}
	var falseAcc []string
	for sc.Scan() {
		var r labelledRun
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		rec := r.RunRecord
		res := Analyze([]*session.RunRecord{&rec}, nil)
		if counts[r.Label] == nil {
			counts[r.Label] = map[string]int{}
		}
		counts[r.Label][res.Verdict]++
		if r.Label == "genuine" && res.Verdict == "FAIL" {
			falseAcc = append(falseAcc, r.File+" ("+r.Family+")")
		}
	}
	labels := []string{}
	for k := range counts {
		labels = append(labels, k)
	}
	sort.Strings(labels)
	for _, l := range labels {
		n := 0
		for _, c := range counts[l] {
			n += c
		}
		t.Logf("%-9s n=%-4d %v", l, n, counts[l])
	}
	t.Logf("genuine judged FAIL: %v", falseAcc)
}
