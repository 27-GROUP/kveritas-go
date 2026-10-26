package metrics

import (
	"fmt"
	"io"
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
)

type Parser struct {
	explicitCount int
	phaseCount    int
	claimCount    int
	seedCount     int
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

func parseCountToken(v string) int64 {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return int64(f)
	}
	return 0
}

func (p *Parser) Declared() bool { return p.explicitCount+p.claimCount > 0 }

func (p *Parser) Summary(w io.Writer, auto int) {
	switch {
	case auto > 0:
		fmt.Fprintf(w, "[kveritas] Results: %d declared, %d automatic\n", p.explicitCount, auto)
	case p.explicitCount > 0:
		fmt.Fprintf(w, "[kveritas] Results: %d declared\n", p.explicitCount)
	}
	if p.phaseCount > 0 {
		fmt.Fprintf(w, "[kveritas] Phase boundaries: %d\n", p.phaseCount)
	}
	if p.claimCount > 0 {
		fmt.Fprintf(w, "[kveritas] Inline claims: %d\n", p.claimCount)
	}
	if p.seedCount > 0 {
		fmt.Fprintf(w, "[kveritas] Seed commitments: %d\n", p.seedCount)
	}
}

func DeclareHint() {
	fmt.Fprintln(os.Stderr, "[kveritas] Print one line per result, from any language:")
	// WriteString, not a Print verb: keeps the literal format directives in the examples.
	os.Stderr.WriteString(`[kveritas]   Python: print(f"KV val_acc={acc:.4f} step={epoch}")` + "\n")
	os.Stderr.WriteString(`[kveritas]   R:      cat(sprintf("KV val_acc=%.4f step=%d\n", acc, epoch))` + "\n")
	os.Stderr.WriteString(`[kveritas]   Julia:  println("KV val_acc=$(acc) step=$(epoch)")` + "\n")
	os.Stderr.WriteString(`[kveritas]   Shell:  echo "KV runtime_s=1.84"` + "\n")
}

func (p *Parser) ExplicitCount() int { return p.explicitCount }
