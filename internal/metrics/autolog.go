package metrics

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

var (
	numPat      = `[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?`
	dictPairRe  = regexp.MustCompile(`["']([A-Za-z_][\w/.-]*)["']\s*:\s*(` + numPat + `)`)
	kerasPairRe = regexp.MustCompile(`(?:^|\s-\s)([A-Za-z_][\w]*):\s*(` + numPat + `)`)
	kerasEpoch  = regexp.MustCompile(`^Epoch\s+(\d+)\s*/\s*\d+`)
	lightEpoch  = regexp.MustCompile(`^Epoch\s+(\d+)\s*:`)
	lightPairRe = regexp.MustCompile(`([A-Za-z_][\w/]*)=(` + numPat + `)`)
	xgbLineRe   = regexp.MustCompile(`^\[(\d+)\]\s+(.*)$`)
	xgbPairRe   = regexp.MustCompile(`([A-Za-z][\w-]*):(` + numPat + `)`)
	lgbPairRe   = regexp.MustCompile(`([A-Za-z][\w]*)'s\s+([\w@-]+):\s*(` + numPat + `)`)
	hfBenchRe   = regexp.MustCompile(`^Benchmark\s+(\d+):`)
	hfTimeRe    = regexp.MustCompile(`^\s*Time \(mean ± σ\):\s+(` + numPat + `)\s+(\w+)`)
	gbenchRe    = regexp.MustCompile(`^(BM_[\w/:.-]+)\s+(` + numPat + `)\s+(ns|us|ms|s)\s+(` + numPat + `)\s+(ns|us|ms|s)\s+\d+`)
	critRe      = regexp.MustCompile(`^(.*?)\s*time:\s+\[` + `(` + numPat + `)\s+(\S+)\s+(` + numPat + `)\s+(\S+)\s+(` + numPat + `)\s+(\S+)\]`)
	timeRe      = regexp.MustCompile(`^(real|user|sys)\s+(\d+)m(` + numPat + `)s$`)
	plainRe     = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9_ ()./-]{0,40}?)\s*[:=]\s*(` + numPat + `)\s*([A-Za-z%/]{1,8})?\s*$`)
	nameClean   = regexp.MustCompile(`[^a-z0-9]+`)
)

// Names that track progress or configuration rather than an outcome.
var notResults = map[string]bool{
	"epoch": true, "step": true, "steps": true, "global_step": true, "batch": true, "iter": true,
	"iteration": true, "lr": true, "learning_rate": true, "batch_size": true, "seed": true,
	"rank": true, "pid": true, "port": true, "version": true, "v_num": true, "id": true,
	"total_flos": true, "grad_norm": true, "eta": true, "it_s": true, "s_it": true,
}

// Auto reads results from the console output of common tools. Every value it returns
// is labelled with the format it came from, so it is never mistaken for a declared one.
type Auto struct {
	epoch string
	bench string
	prev  string
}

func unit(u string) string {
	switch u {
	case "µs", "μs":
		return "us"
	}
	return u
}

func cleanName(s string) string {
	return strings.Trim(nameClean.ReplaceAllString(strings.ToLower(s), "_"), "_")
}

func (a *Auto) emit(out []session.Metric, name, value, step string, line int, source string) []session.Metric {
	name = cleanName(name)
	if name == "" || notResults[name] {
		return out
	}
	v, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return out
	}
	return append(out, session.Metric{Name: name, Value: v, Step: step, Line: line, Source: "auto:" + source})
}

func (a *Auto) Line(line string, lineNum int) []session.Metric {
	defer func() {
		if t := strings.TrimSpace(line); t != "" {
			a.prev = t
		}
	}()
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "KV ") {
		return nil
	}
	var out []session.Metric

	if m := kerasEpoch.FindStringSubmatch(t); m != nil && !strings.Contains(t, " - ") {
		a.epoch = m[1]
		return nil
	}

	if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}") {
		source := "json"
		if strings.Contains(t, "'") {
			source = "trainer"
		}
		pairs := dictPairRe.FindAllStringSubmatch(t, -1)
		step := ""
		for _, p := range pairs {
			if p[1] == "step" || (p[1] == "epoch" && step == "") {
				step = p[2]
			}
		}
		for _, p := range pairs {
			out = a.emit(out, p[1], p[2], step, lineNum, source)
		}
		return out
	}

	if m := xgbLineRe.FindStringSubmatch(t); m != nil {
		if lg := lgbPairRe.FindAllStringSubmatch(m[2], -1); len(lg) > 0 {
			for _, p := range lg {
				out = a.emit(out, p[1]+"_"+p[2], p[3], m[1], lineNum, "lightgbm")
			}
			return out
		}
		for _, p := range xgbPairRe.FindAllStringSubmatch(m[2], -1) {
			out = a.emit(out, p[1], p[2], m[1], lineNum, "xgboost")
		}
		return out
	}

	if m := lightEpoch.FindStringSubmatch(t); m != nil {
		a.epoch = m[1]
		if i := strings.LastIndex(t, "["); i >= 0 {
			for _, p := range lightPairRe.FindAllStringSubmatch(t[i:], -1) {
				out = a.emit(out, p[1], p[2], a.epoch, lineNum, "lightning")
			}
		}
		return out
	}

	if strings.Contains(t, " - ") && strings.Contains(t, ":") {
		pairs := kerasPairRe.FindAllStringSubmatch(t, -1)
		if len(pairs) > 0 {
			for _, p := range pairs {
				out = a.emit(out, p[1], p[2], a.epoch, lineNum, "keras")
			}
			return out
		}
	}

	if m := hfBenchRe.FindStringSubmatch(t); m != nil {
		a.bench = "bench" + m[1]
		return nil
	}
	if m := hfTimeRe.FindStringSubmatch(line); m != nil {
		return a.emit(out, a.bench+"_time_mean_"+m[2], m[1], "", lineNum, "hyperfine")
	}
	if m := gbenchRe.FindStringSubmatch(t); m != nil {
		out = a.emit(out, m[1]+"_time_"+m[3], m[2], "", lineNum, "gbench")
		return a.emit(out, m[1]+"_cpu_"+m[5], m[4], "", lineNum, "gbench")
	}
	if m := critRe.FindStringSubmatch(t); m != nil {
		name := strings.TrimSpace(m[1])
		if name == "" {
			name = a.prev
		}
		return a.emit(out, name+"_time_"+unit(m[5]), m[4], "", lineNum, "criterion")
	}
	if m := timeRe.FindStringSubmatch(t); m != nil {
		mins, _ := strconv.ParseFloat(m[2], 64)
		secs, _ := strconv.ParseFloat(m[3], 64)
		return a.emit(out, m[1]+"_time_s", strconv.FormatFloat(mins*60+secs, 'g', -1, 64), "", lineNum, "time")
	}

	if m := plainRe.FindStringSubmatch(line); m != nil {
		name := m[1]
		if m[3] != "" {
			name += "_" + m[3]
		}
		return a.emit(out, name, m[2], a.epoch, lineNum, "line")
	}
	return nil
}
