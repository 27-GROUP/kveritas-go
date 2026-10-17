// Package metrics parses the KVERITAS_* stdout protocol lines. The whole stdout
// stream is SHA-256 hashed as it runs, and each match is anchored to its line
// number, so lines cannot be inserted, removed, or reordered undetected.
package metrics

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

var (
	explicitRe = regexp.MustCompile(
		`^KVERITAS_METRIC\s+name=([a-zA-Z][a-zA-Z0-9_]*)\s+value=([+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?:\s+step=(\S+))?`,
	)

	phaseRe = regexp.MustCompile(
		`^KVERITAS_PHASE\s+name=(\S+)`,
	)

	claimRe = regexp.MustCompile(
		`^KVERITAS_CLAIM\s+metric=([a-zA-Z][a-zA-Z0-9_]*)\s+value=([+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?:\s+phase=(\S+))?`,
	)

	inputRe = regexp.MustCompile(
		`^KVERITAS_INPUT\s+src=seed:(\S+)`,
	)

	modelRe    = regexp.MustCompile(`^KVERITAS_MODEL\b`)
	workloadRe = regexp.MustCompile(`^KVERITAS_WORKLOAD\b`)

	kvTokenRe = regexp.MustCompile(`([a-zA-Z_]+)=(\S+)`)

	kerasRe = regexp.MustCompile(
		`([a-zA-Z][a-zA-Z0-9_]*):\s*([+-]?[0-9]+\.[0-9]+(?:[eE][+-]?[0-9]+)?)`,
	)

	colonKVRe = regexp.MustCompile(
		`^\s*([a-zA-Z][a-zA-Z0-9_/\-]{1,30}):\s*([+-]?[0-9]+\.[0-9]+(?:[eE][+-]?[0-9]+)?)\s*$`,
	)

	jsonMetricRe = regexp.MustCompile(
		`"metric"\s*:\s*"([^"]+)"\s*,\s*"value"\s*:\s*([+-]?[0-9]+(?:\.[0-9]+)?)`,
	)
)

var metricKeywords = map[string]bool{
	"loss": true, "acc": true, "accuracy": true, "error": true,
	"f1": true, "f1_score": true, "precision": true, "recall": true,
	"auc": true, "mse": true, "mae": true, "rmse": true,
	"bleu": true, "rouge": true, "perplexity": true, "score": true,
	"r2": true, "val_loss": true, "val_acc": true, "val_accuracy": true,
	"train_loss": true, "train_acc": true, "test_loss": true,
	"test_acc": true, "test_accuracy": true, "map": true,
}

var blocklist = map[string]bool{
	"epoch": true, "step": true, "batch": true, "iter": true,
	"lr": true, "learning_rate": true, "batch_size": true,
	"seed": true, "rank": true, "gpu_mem": true, "memory": true,
	"version": true, "time": true, "duration": true, "elapsed": true,
	"size": true, "count": true, "num": true, "n": true, "id": true,
	"pid": true, "port": true, "gpu": true, "cpu": true,
}

type Parser struct {
	explicitCount  int
	heuristicCount int
	phaseCount     int
	claimCount     int
	seedCount      int
}

func (p *Parser) Parse(line string, lineNum int) (*session.Metric, bool) {
	m := explicitRe.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	v, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return nil, false
	}
	metric := &session.Metric{
		Name:   m[1],
		Value:  v,
		Line:   lineNum,
		Source: "explicit",
	}
	if len(m) > 3 && m[3] != "" {
		metric.Step = m[3]
	}
	p.explicitCount++
	return metric, true
}

func (p *Parser) ParsePhase(line string) (string, bool) {
	m := phaseRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	p.phaseCount++
	return m[1], true
}

func (p *Parser) ParseClaim(line string, lineNum int) (*session.InlineClaim, bool) {
	m := claimRe.FindStringSubmatch(line)
	if m == nil {
		return nil, false
	}
	v, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return nil, false
	}
	claim := &session.InlineClaim{
		Metric: m[1],
		Value:  v,
		Line:   lineNum,
	}
	if len(m) > 3 && m[3] != "" {
		claim.Phase = m[3]
	}
	p.claimCount++
	return claim, true
}

type ArtifactDecl struct {
	Role       string
	Name       string
	Path       string
	Visibility string
}

func (p *Parser) ParseArtifact(line string) (*ArtifactDecl, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != "KVERITAS_ARTIFACT" {
		return nil, false
	}
	d := &ArtifactDecl{Role: "other", Visibility: "private"}
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "role":
			d.Role = v
		case "name":
			d.Name = v
		case "path":
			d.Path = v
		case "visibility":
			d.Visibility = v
		}
	}
	if d.Path == "" {
		return nil, false
	}
	return d, true
}

func (p *Parser) ParseSeed(line string) (string, bool) {
	m := inputRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	p.seedCount++
	return m[1], true
}

func (p *Parser) ParseDeclared(line string, d *session.DeclaredModel) bool {
	if !modelRe.MatchString(line) && !workloadRe.MatchString(line) {
		return false
	}
	for _, kv := range kvTokenRe.FindAllStringSubmatch(line, -1) {
		key, val := kv[1], kv[2]
		switch key {
		case "params":
			d.Params = parseCountToken(val)
		case "arch":
			d.Arch = val
		case "precision":
			d.Precision = val
		case "dataset_size":
			d.DatasetSize = parseCountToken(val)
		case "epochs":
			if f, err := strconv.ParseFloat(val, 64); err == nil {
				d.Epochs = f
			}
		case "batch_size":
			d.BatchSize = parseCountToken(val)
		case "seq_len":
			d.SeqLen = parseCountToken(val)
		}
	}
	return true
}

// parseCountToken parses an integer count that may be written in scientific or
// decimal notation (e.g. 25600000, 25.6e6). Returns 0 on failure.
func parseCountToken(v string) int64 {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return int64(f)
	}
	return 0
}

// ParseHeuristic runs best-effort detection on a line.
// These results supplement but do not replace explicit metrics.
func (p *Parser) ParseHeuristic(line string, lineNum int) []session.Metric {
	if m := jsonMetricRe.FindStringSubmatch(line); m != nil {
		name := m[1]
		if !blocklist[strings.ToLower(name)] {
			if v, err := strconv.ParseFloat(m[2], 64); err == nil {
				p.heuristicCount++
				return []session.Metric{{Name: name, Value: v, Line: lineNum, Source: "heuristic"}}
			}
		}
		return nil
	}

	// Keras/Lightning multi-metric line: "loss: 0.24 - val_acc: 0.94"
	if strings.Contains(line, " - ") && strings.Contains(line, ":") {
		var out []session.Metric
		for _, m := range kerasRe.FindAllStringSubmatch(line, -1) {
			name := m[1]
			if blocklist[strings.ToLower(name)] {
				continue
			}
			if v, err := strconv.ParseFloat(m[2], 64); err == nil {
				out = append(out, session.Metric{Name: name, Value: v, Line: lineNum, Source: "heuristic"})
				p.heuristicCount++
			}
		}
		return out
	}

	// Single "metric_name: 0.947", only when the name is a known metric keyword.
	if m := colonKVRe.FindStringSubmatch(line); m != nil {
		name := m[1]
		if !blocklist[strings.ToLower(name)] && metricKeywords[strings.ToLower(name)] {
			if v, err := strconv.ParseFloat(m[2], 64); err == nil {
				p.heuristicCount++
				return []session.Metric{{Name: name, Value: v, Line: lineNum, Source: "heuristic"}}
			}
		}
	}
	return nil
}

func (p *Parser) WarnIfEmpty() {
	if p.explicitCount == 0 {
		fmt.Fprintln(os.Stderr, "[kveritas] Warning: no results captured in this run.")
		fmt.Fprintln(os.Stderr, "[kveritas] Write one line per result to the file in $KVERITAS_OUT (or print it), from any language:")
		// WriteString, not a Print verb: keeps the literal format directives in the examples.
		os.Stderr.WriteString(`[kveritas]   Python: print(f"KV val_acc={acc:.4f} step={epoch}", file=open(os.environ.get("KVERITAS_OUT", os.devnull), "a"))` + "\n")
		os.Stderr.WriteString(`[kveritas]   R:      cat(sprintf("KV val_acc=%.4f step=%d\n", acc, epoch), file = Sys.getenv("KVERITAS_OUT", "/dev/null"), append = TRUE)` + "\n")
		os.Stderr.WriteString(`[kveritas]   Julia:  open(f -> println(f, "KV val_acc=$(acc) step=$(epoch)"), get(ENV, "KVERITAS_OUT", devnull), "a")` + "\n")
		os.Stderr.WriteString(`[kveritas]   Shell:  echo "KV val_acc=0.9471 step=100" >> "${KVERITAS_OUT:-/dev/null}"` + "\n")
		if p.heuristicCount > 0 {
			fmt.Fprintf(os.Stderr, "[kveritas] Heuristic metrics captured: %d (may be incomplete)\n", p.heuristicCount)
		}
	} else {
		if p.heuristicCount > 0 {
			fmt.Fprintf(os.Stderr, "[kveritas] Metrics captured: %d explicit, %d heuristic\n",
				p.explicitCount, p.heuristicCount)
		} else {
			fmt.Fprintf(os.Stderr, "[kveritas] Metrics captured: %d explicit\n", p.explicitCount)
		}
	}
	if p.phaseCount > 0 {
		fmt.Fprintf(os.Stderr, "[kveritas] Phase boundaries: %d\n", p.phaseCount)
	}
	if p.claimCount > 0 {
		fmt.Fprintf(os.Stderr, "[kveritas] Inline claims: %d\n", p.claimCount)
	}
	if p.seedCount > 0 {
		fmt.Fprintf(os.Stderr, "[kveritas] Seed commitments: %d\n", p.seedCount)
	}
}

func (p *Parser) ExplicitCount() int { return p.explicitCount }
