package metrics

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	kvNameRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	kvNumberRe = regexp.MustCompile(`^[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?$`)
)

// Strict grammar, so output like "KV cache: 2 GB" is never a result.
func TranslateKV(line string) (lines []string, ok, near bool) {
	f := strings.Fields(line)
	if len(f) == 0 || f[0] != "KV" {
		return nil, false, false
	}
	if len(f) < 2 {
		return nil, false, true
	}
	switch f[1] {
	case "seed":
		if len(f) != 3 {
			return nil, false, true
		}
		return []string{"KVERITAS_INPUT src=seed:" + f[2]}, true, false
	case "phase":
		if len(f) != 3 || !kvNameRe.MatchString(f[2]) {
			return nil, false, true
		}
		return []string{"KVERITAS_PHASE name=" + f[2]}, true, false
	case "model", "workload", "artifact":
		pairs, valid := kvPairs(f[2:])
		if !valid || len(pairs) == 0 {
			return nil, false, true
		}
		return []string{"KVERITAS_" + strings.ToUpper(f[1]) + " " + strings.Join(f[2:], " ")}, true, false
	case "claim":
		pairs, valid := kvPairs(f[2:])
		if !valid {
			return nil, false, true
		}
		phase := ""
		for _, p := range pairs {
			if p[0] == "phase" {
				phase = " phase=" + p[1]
			}
		}
		for _, p := range pairs {
			if p[0] == "phase" {
				continue
			}
			if !kvNumberRe.MatchString(p[1]) {
				return nil, false, true
			}
			lines = append(lines, "KVERITAS_CLAIM metric="+p[0]+" value="+number(p[1])+phase)
		}
		if len(lines) == 0 {
			return nil, false, true
		}
		return lines, true, false
	}
	pairs, valid := kvPairs(f[1:])
	if !valid {
		return nil, false, true
	}
	step := ""
	for _, p := range pairs {
		if p[0] == "step" {
			step = " step=" + p[1]
		}
	}
	for _, p := range pairs {
		if p[0] == "step" {
			continue
		}
		if !kvNumberRe.MatchString(p[1]) {
			return nil, false, true
		}
		lines = append(lines, "KVERITAS_METRIC name="+p[0]+" value="+number(p[1])+step)
	}
	if len(lines) == 0 {
		return nil, false, true
	}
	return lines, true, false
}

func kvPairs(tokens []string) ([][2]string, bool) {
	pairs := make([][2]string, 0, len(tokens))
	for _, t := range tokens {
		k, v, found := strings.Cut(t, "=")
		if !found || v == "" || !kvNameRe.MatchString(k) {
			return nil, false
		}
		pairs = append(pairs, [2]string{k, v})
	}
	return pairs, true
}

// 1. and .5 are rewritten for the protocol regexes.
func number(v string) string {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return v
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}
