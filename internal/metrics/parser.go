// Package metrics implements the K-Veritas metric capture protocol.
//
// Primary format (guaranteed capture):
//
//	KVERITAS_METRIC name=<identifier> value=<float> [step=<value>]
//
// Additional protocol lines:
//
//	KVERITAS_PHASE name=<phase>                                    Phase boundary with hardware snapshot
//	KVERITAS_CLAIM metric=<name> value=<float> [phase=<phase>]     Inline claim committed in stdout
//	KVERITAS_INPUT src=seed:<value>                                 Seed commitment before computation
//
// The entire stdout stream is SHA-256 hashed byte-for-byte as the process runs.
// Each metric, claim, phase, and seed is anchored to its line number within
// that hash, making it impossible to insert, remove, or reorder without
// invalidating the hash.
package metrics

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/mamadouk/kveritas/internal/session"
)

var (
	// explicitRe matches the primary KVERITAS_METRIC format.
	explicitRe = regexp.MustCompile(
		`^KVERITAS_METRIC\s+name=([a-zA-Z][a-zA-Z0-9_]*)\s+value=([+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?:\s+step=(\S+))?`,
	)

	// phaseRe matches KVERITAS_PHASE name=<phase>
	phaseRe = regexp.MustCompile(
		`^KVERITAS_PHASE\s+name=(\S+)`,
	)

	// claimRe matches KVERITAS_CLAIM metric=<name> value=<float> [phase=<phase>]
	claimRe = regexp.MustCompile(
		`^KVERITAS_CLAIM\s+metric=([a-zA-Z][a-zA-Z0-9_]*)\s+value=([+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?:\s+phase=(\S+))?`,
	)

	// inputRe matches KVERITAS_INPUT src=seed:<value>
	inputRe = regexp.MustCompile(
		`^KVERITAS_INPUT\s+src=seed:(\S+)`,
	)

	// kerasRe matches Keras/PyTorch Lightning style: "loss: 0.24 - val_acc: 0.94"
	kerasRe = regexp.MustCompile(
		`([a-zA-Z][a-zA-Z0-9_]*):\s*([+-]?[0-9]+\.[0-9]+(?:[eE][+-]?[0-9]+)?)`,
	)

	// colonKVRe matches a single "metric_name: 0.947" at line start.
	colonKVRe = regexp.MustCompile(
		`^\s*([a-zA-Z][a-zA-Z0-9_/\-]{1,30}):\s*([+-]?[0-9]+\.[0-9]+(?:[eE][+-]?[0-9]+)?)\s*$`,
	)

	// jsonMetricRe matches {"metric": "name", "value": 0.947}
	jsonMetricRe = regexp.MustCompile(
		`"metric"\s*:\s*"([^"]+)"\s*,\s*"value"\s*:\s*([+-]?[0-9]+(?:\.[0-9]+)?)`,
	)
)

// metricKeywords are names that strongly imply a value is a performance metric.
var metricKeywords = map[string]bool{
	"loss": true, "acc": true, "accuracy": true, "error": true,
	"f1": true, "f1_score": true, "precision": true, "recall": true,
	"auc": true, "mse": true, "mae": true, "rmse": true,
	"bleu": true, "rouge": true, "perplexity": true, "score": true,
	"r2": true, "val_loss": true, "val_acc": true, "val_accuracy": true,
	"train_loss": true, "train_acc": true, "test_loss": true,
	"test_acc": true, "test_accuracy": true, "map": true,
}

// blocklist excludes names that are configuration or progress values, not metrics.
var blocklist = map[string]bool{
	"epoch": true, "step": true, "batch": true, "iter": true,
	"lr": true, "learning_rate": true, "batch_size": true,
	"seed": true, "rank": true, "gpu_mem": true, "memory": true,
	"version": true, "time": true, "duration": true, "elapsed": true,
	"size": true, "count": true, "num": true, "n": true, "id": true,
	"pid": true, "port": true, "gpu": true, "cpu": true,
}

// Parser accumulates metric state across a run's output lines.
type Parser struct {
	explicitCount  int
	heuristicCount int
	phaseCount     int
	claimCount     int
	seedCount      int
}

// Parse checks a line for the primary KVERITAS_METRIC format.
// Returns a metric and true only when the explicit prefix is found.
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

// ParsePhase checks a line for KVERITAS_PHASE.
// Returns the phase name and true if found.
func (p *Parser) ParsePhase(line string) (string, bool) {
	m := phaseRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	p.phaseCount++
	return m[1], true
}

// ParseClaim checks a line for KVERITAS_CLAIM.
// Returns an InlineClaim and true if found.
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

// ParseSeed checks a line for KVERITAS_INPUT src=seed:<value>.
// Returns the seed value and true if found.
func (p *Parser) ParseSeed(line string) (string, bool) {
	m := inputRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	p.seedCount++
	return m[1], true
}

// ParseHeuristic runs best-effort detection on a line.
// These results supplement but do not replace explicit metrics.
func (p *Parser) ParseHeuristic(line string, lineNum int) []session.Metric {
	// JSON metric object takes priority.
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

// WarnIfEmpty writes a guidance message when no explicit metrics were captured.
func (p *Parser) WarnIfEmpty() {
	if p.explicitCount == 0 {
		fmt.Fprintln(os.Stderr, "[kveritas] Warning: No explicit metrics captured in this run.")
		fmt.Fprintln(os.Stderr, "[kveritas] Add one line per metric to your script (any language):")
		fmt.Fprintln(os.Stderr, `[kveritas]   Python:  print(f"KVERITAS_METRIC name=val_accuracy value={acc:.4f} step={epoch}")`)
		fmt.Fprintln(os.Stderr, `[kveritas]   R:       cat(sprintf("KVERITAS_METRIC name=val_accuracy value=%.4f step=%d\n", acc, epoch))`)
		fmt.Fprintln(os.Stderr, `[kveritas]   Julia:   println("KVERITAS_METRIC name=val_accuracy value=$(acc) step=$(epoch)")`)
		fmt.Fprintln(os.Stderr, `[kveritas]   Shell:   echo "KVERITAS_METRIC name=val_accuracy value=0.9471 step=100"`)
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

// ExplicitCount returns the number of KVERITAS_METRIC lines parsed so far.
func (p *Parser) ExplicitCount() int { return p.explicitCount }
