package pdf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/compute"
	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const (
	citeText = "M. K. Keita and C. Homan. Computer Science Conferences Should Require Nonrepudiable " +
		"Experimental Results. NeurIPS 2026 Position Paper Track. arXiv:2605.08586."
	bodySize = 10.0
	cellSize = 9.0
)

var citeBibTeX = []string{
	"@misc{keita2026computerscienceconferencesrequire,",
	"  title={Computer Science Conferences Should Require Nonrepudiable Experimental Results},",
	"  author={Mamadou K. Keita and Christopher Homan},",
	"  year={2026},",
	"  eprint={2605.08586},",
	"  archivePrefix={arXiv},",
	"  primaryClass={cs.CR},",
	"  url={https://arxiv.org/abs/2605.08586},",
	"}",
}

// Standard Type 1 metrics (per 1000 units) for ASCII 32..126, so text can be
// measured for wrapping, centering and table columns without embedding fonts.
var timesW = [95]int{
	250, 333, 408, 500, 500, 833, 778, 180, 333, 333, 500, 564, 250, 333, 250, 278,
	500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 278, 278, 564, 564, 564, 444,
	921, 722, 667, 667, 722, 611, 556, 722, 722, 333, 389, 722, 611, 889, 722, 722,
	556, 722, 667, 556, 611, 722, 722, 944, 722, 722, 611, 333, 278, 333, 469, 500,
	333, 444, 500, 444, 500, 444, 333, 500, 500, 278, 278, 500, 278, 778, 500, 500,
	500, 500, 333, 389, 278, 500, 500, 722, 500, 500, 444, 480, 200, 480, 541,
}

var timesBoldW = [95]int{
	250, 333, 555, 500, 500, 1000, 833, 278, 333, 333, 500, 570, 250, 333, 250, 278,
	500, 500, 500, 500, 500, 500, 500, 500, 500, 500, 333, 333, 570, 570, 570, 500,
	930, 722, 667, 722, 722, 667, 611, 778, 778, 389, 500, 778, 667, 944, 722, 778,
	611, 778, 722, 556, 667, 722, 722, 1000, 722, 722, 667, 333, 278, 333, 581, 500,
	333, 500, 556, 444, 556, 444, 333, 500, 556, 278, 333, 556, 278, 833, 556, 500,
	556, 556, 444, 389, 333, 556, 500, 722, 500, 500, 444, 394, 220, 394, 520,
}

func textWidth(s, font string, size float64) float64 {
	units := 0
	for _, r := range s {
		switch {
		case font == "C":
			units += 600
		case r >= 32 && r <= 126 && (font == "Tb"):
			units += timesBoldW[r-32]
		case r >= 32 && r <= 126:
			units += timesW[r-32]
		default:
			units += 500
		}
	}
	return float64(units) * size / 1000
}

func wrapToWidth(text, font string, size, maxW float64) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := ""
	for _, w := range words {
		try := w
		if cur != "" {
			try = cur + " " + w
		}
		if textWidth(try, font, size) <= maxW || cur == "" {
			cur = try
			continue
		}
		lines = append(lines, cur)
		cur = w
	}
	return append(lines, cur)
}

func fitWidth(s, font string, size, maxW float64) string {
	if textWidth(s, font, size) <= maxW {
		return s
	}
	for len(s) > 1 && textWidth(s+"...", font, size) > maxW {
		s = s[:len(s)-1]
	}
	return s + "..."
}

func (b *builder) textAt(x float64, s, font string, size float64) {
	y := pageH - b.curY - size
	b.cur.content.WriteString(fmt.Sprintf("BT /%s %.1f Tf %.2f %.2f Td (%s) Tj ET\n", font, size, x, y, pdfEscape(s)))
}

func (b *builder) line(s, font string, size, x float64) {
	b.checkSpace(lineH(size))
	b.textAt(x, s, font, size)
	b.curY += lineH(size)
}

func (b *builder) centered(s, font string, size float64) {
	b.line(s, font, size, (pageW-textWidth(s, font, size))/2)
}

func (b *builder) para(text string) {
	b.paraIn(text, "T", bodySize, mL, bodyW)
}

func (b *builder) paraIn(text, font string, size, x, w float64) {
	for _, l := range wrapToWidth(text, font, size, w) {
		b.line(l, font, size, x)
	}
}

func (b *builder) monoLines(text string) {
	for _, l := range chunkString(text, 88) {
		b.line(l, "C", 7.5, mL)
	}
}

func (b *builder) rule(y, x1, x2, width float64) {
	b.cur.content.WriteString(fmt.Sprintf("q %.2f w %.2f %.2f m %.2f %.2f l S Q\n", width, x1, pageH-y, x2, pageH-y))
}

func (b *builder) section(title string) {
	b.checkSpace(110)
	b.gap(14)
	b.line(title, "Tb", 13, mL)
	b.gap(3)
}

func (b *builder) subsection(title string) {
	b.checkSpace(70)
	b.gap(6)
	b.line(title, "Tb", bodySize, mL)
	b.gap(1)
}

// Booktabs style: heavy rules above and below, a light one under the header, no
// vertical lines. The header repeats when a table runs onto a new page.
func (b *builder) table(headers []string, widths []float64, rows [][]string) {
	const rowH = 13.0
	var total float64
	for _, w := range widths {
		total += w
	}
	scale := bodyW / total
	cols := make([]float64, len(widths))
	x := mL
	for i, w := range widths {
		cols[i] = x
		x += w * scale
	}
	drawHeader := func() {
		b.checkSpace(rowH*2 + 6)
		b.rule(b.curY, mL, pageW-mR, 0.8)
		b.curY += 3
		for i, h := range headers {
			b.textAt(cols[i]+2, fitWidth(h, "Tb", cellSize, widths[i]*scale-6), "Tb", cellSize)
		}
		b.curY += rowH
		b.rule(b.curY-2, mL, pageW-mR, 0.4)
		b.curY += 1
	}
	drawHeader()
	for _, row := range rows {
		if b.curY+rowH > pageH-mB {
			b.rule(b.curY, mL, pageW-mR, 0.8)
			b.newPage()
			drawHeader()
		}
		for i, c := range row {
			font := "T"
			if strings.HasPrefix(c, "\x00") {
				font, c = "C", c[1:]
			}
			size := cellSize
			if font == "C" {
				size = 8
			}
			b.textAt(cols[i]+2, fitWidth(c, font, size, widths[i]*scale-6), font, size)
		}
		b.curY += rowH
	}
	b.rule(b.curY, mL, pageW-mR, 0.8)
	b.curY += 6
}

func code(s string) string { return "\x00" + s }

func (b *builder) box(title string, lines []string) {
	const pad = 9.0
	inner := bodyW - 2*pad
	var wrapped []string
	for _, l := range lines {
		wrapped = append(wrapped, wrapToWidth(l, "T", 9.5, inner)...)
	}
	h := pad*2 + lineH(bodySize) + float64(len(wrapped))*lineH(9.5)
	b.checkSpace(h + 8)
	top := b.curY
	b.cur.content.WriteString(fmt.Sprintf("q 0.6 w %.2f %.2f %.2f %.2f re S Q\n", mL, pageH-top-h, bodyW, h))
	b.curY += pad
	b.line(title, "Tb", bodySize, mL+pad)
	for _, l := range wrapped {
		b.line(l, "T", 9.5, mL+pad)
	}
	b.curY = top + h + 8
}

func (b *builder) decorate(label string) {
	n := len(b.pages)
	for i, p := range b.pages {
		head := fmt.Sprintf("q 0.4 0.4 0.4 rg BT /Ti 8.5 Tf %.2f %.2f Td (%s) Tj ET Q\n", mL, pageH-40, pdfEscape(label))
		num := fmt.Sprintf("page %d of %d", i+1, n)
		head += fmt.Sprintf("q 0.4 0.4 0.4 rg BT /T 8.5 Tf %.2f %.2f Td (%s) Tj ET Q\n", pageW-mR-textWidth(num, "T", 8.5), pageH-40, num)
		head += fmt.Sprintf("q 0.75 0.75 0.75 RG 0.4 w %.2f %.2f m %.2f %.2f l S Q\n", mL, pageH-46, pageW-mR, pageH-46)
		p.content.WriteString(head)
	}
}

func short(h string, n int) string {
	if len(h) <= n {
		return h
	}
	return h[:n]
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:4] + "…" + h[len(h)-4:]
}

func runLabel(r *session.RunRecord) string {
	if strings.Contains(strings.Join(r.Command, " "), "<redacted>") {
		return ""
	}
	for i := len(r.Command) - 1; i >= 0; i-- {
		if ext := filepath.Ext(r.Command[i]); ext != "" && !strings.HasPrefix(r.Command[i], "-") {
			return filepath.Base(r.Command[i])
		}
	}
	return strings.Join(r.Command, " ")
}

func runTitle(i int, r *session.RunRecord) string {
	if l := runLabel(r); l != "" {
		return fmt.Sprintf("Run %d: %s", i, l)
	}
	return fmt.Sprintf("Run %d", i)
}

func signer(seal *session.SealRecord) string {
	if seal.ServerURL == "local" {
		return "Self-signed with a local key"
	}
	return "Signed by the K-Veritas server"
}

func finalMetrics(r *session.RunRecord) ([]session.Metric, map[string]int) {
	last := map[string]session.Metric{}
	count := map[string]int{}
	var order []string
	for _, m := range r.Metrics {
		if _, seen := last[m.Name]; !seen {
			order = append(order, m.Name)
		}
		last[m.Name] = m
		count[m.Name]++
	}
	out := make([]session.Metric, 0, len(order))
	for _, n := range order {
		out = append(out, last[n])
	}
	return out, count
}

func invocations(n int) string {
	if n == 1 {
		return "1 invocation"
	}
	return fmt.Sprintf("%d invocations", n)
}

func invocationCounts(seal *session.SealRecord) (total, failed, interrupted int) {
	total = seal.TotalRunCount
	for _, e := range seal.RunHistory {
		switch {
		case e.ExitCode == -1:
			interrupted++
		case e.ExitCode != 0:
			failed++
		}
	}
	return
}

func (b *builder) paperReport(sess *session.Session, runs []*session.RunRecord, seal *session.SealRecord, hmcaResult *session.HMCAResult) {
	b.titleBlock(sess, seal)
	b.abstract(runs, seal)
	b.box("What this record proves", []string{
		"These numbers came from the sealed code at this time, unchanged since. Whether the experiment is sound is for the reader to judge.",
		"Verify: kveritas verify <this file> or kveritas.org/verify",
	})
	b.setupSection(sess, runs)
	b.runsSection(runs, seal)
	b.resultsSection(runs)
	b.evidenceSection(runs, hmcaResult)
	b.provenanceSection(sess, runs)
	b.verificationSection(seal)
	b.section("References")
	b.paraIn("[1] "+citeText, "T", bodySize, mL, bodyW)
	b.appendix(runs, seal)
	b.decorate("Sealed Experiment Record")
}

func (b *builder) titleBlock(sess *session.Session, seal *session.SealRecord) {
	b.gap(26)
	b.centered("Sealed Experiment Record", "Tb", 20)
	b.gap(6)
	b.centered(fmt.Sprintf("Sealed %s · %s", seal.SealedAt.UTC().Format("2006-01-02"), signer(seal)), "T", bodySize+0.5)
	b.centered(fmt.Sprintf("Session %s · Data hash %s", short(sess.ID, 8), shortHash(seal.DataHash)), "C", 8.5)
	b.gap(14)
}

func (b *builder) abstract(runs []*session.RunRecord, seal *session.SealRecord) {
	var labels []string
	for _, r := range runs {
		if l := runLabel(r); l != "" {
			labels = append(labels, l)
		}
	}
	start, end := runs[0].StartAt, runs[0].EndAt
	for _, r := range runs {
		if r.StartAt.Before(start) {
			start = r.StartAt
		}
		if r.EndAt.After(end) {
			end = r.EndAt
		}
	}
	hw := runs[0].Hardware.CPUModel
	if hw == "" {
		hw = runs[0].Hardware.OS + "/" + runs[0].Hardware.Arch
	}
	plural := "s"
	if len(runs) == 1 {
		plural = ""
	}
	named := ""
	if len(labels) == len(runs) {
		named = " (" + strings.Join(labels, ", ") + ")"
	}
	text := fmt.Sprintf("This record seals %d run%s%s executed on %s between %s and %s UTC.",
		len(runs), plural, named, hw, start.UTC().Format("2006-01-02 15:04"), end.UTC().Format("15:04"))

	var results []string
	for _, r := range runs {
		for _, c := range r.Claims {
			results = append(results, fmt.Sprintf("%s %.6g", c.Metric, c.Value))
		}
	}
	if len(results) == 0 {
		fm, _ := finalMetrics(runs[len(runs)-1])
		for _, m := range fm {
			results = append(results, fmt.Sprintf("%s %.6g", m.Name, m.Value))
		}
	}
	if len(results) > 4 {
		results = results[:4]
	}
	if len(results) > 0 {
		text += " Reported results: " + strings.Join(results, ", ") + "."
	}
	if total, failed, interrupted := invocationCounts(seal); total > 0 {
		text += fmt.Sprintf(" %s in total, %d failed", invocations(total), failed)
		if interrupted > 0 {
			text += fmt.Sprintf(", %d interrupted", interrupted)
		}
		text += "."
	}
	text += " Produced with K-Veritas [1]."

	b.centered("Abstract", "Tb", bodySize+0.5)
	b.gap(2)
	b.paraIn(text, "T", bodySize, mL+28, bodyW-56)
	b.gap(10)
}

func (b *builder) setupSection(sess *session.Session, runs []*session.RunRecord) {
	b.section("1  Setup")
	hw := runs[0].Hardware
	rows := [][]string{
		{"Session", code(sess.ID)},
		{"Initialized", sess.InitAt.UTC().Format(time.RFC3339)},
		{"Machine", code(sess.MachineID)},
		{"Operating system", hw.OS + " / " + hw.Arch},
	}
	if hw.CPUModel != "" {
		rows = append(rows, []string{"CPU", fmt.Sprintf("%s, %d cores", hw.CPUModel, hw.CPUCores)})
	} else {
		rows = append(rows, []string{"CPU", fmt.Sprintf("%d cores", hw.CPUCores)})
	}
	rows = append(rows, []string{"Memory", fmt.Sprintf("%.1f GB", hw.MemGB)})
	if hw.GPUInfo != "" {
		rows = append(rows, []string{"GPU", hw.GPUInfo})
	}
	for i, r := range runs {
		if r.EnvDigest != "" {
			rows = append(rows, []string{fmt.Sprintf("Environment, run %d", i+1), code(r.EnvDigest)})
		}
	}
	for i, r := range runs {
		if d := r.Declared; d != nil {
			if d.Arch != "" || d.Params > 0 {
				rows = append(rows, []string{fmt.Sprintf("Declared model, run %d", i+1),
					fmt.Sprintf("%s, %d params, %s", d.Arch, d.Params, d.Precision)})
			}
			if d.DatasetSize > 0 {
				rows = append(rows, []string{fmt.Sprintf("Declared workload, run %d", i+1),
					fmt.Sprintf("%d samples, %g epochs, batch %d", d.DatasetSize, d.Epochs, d.BatchSize)})
			}
		}
	}
	disclosure := sess.Disclosure
	if disclosure == "" {
		disclosure = "redacted"
	}
	rows = append(rows, []string{"Disclosure", disclosure})
	for i, r := range runs {
		if r.SourceCodeHash != "" {
			rows = append(rows, []string{fmt.Sprintf("Source code, run %d", i+1), code(r.SourceCodeHash)})
		}
	}
	b.table([]string{"Item", "Value"}, []float64{1, 2.6}, rows)
}

func (b *builder) runsSection(runs []*session.RunRecord, seal *session.SealRecord) {
	b.section("2  Runs")
	byInv := map[int]session.LedgerRunEntry{}
	for _, e := range seal.RunHistory {
		if e.Invocation != nil {
			byInv[*e.Invocation] = e
		}
	}
	rows := make([][]string, 0, len(runs))
	for i, r := range runs {
		dur := r.DurationFmt
		if dur == "" {
			dur = fmt.Sprintf("%.1f s", r.DurationSec)
		}
		anchored := "not anchored"
		if r.RunDigest != "" {
			anchored = "pending"
			if e, ok := byInv[r.Invocation]; ok {
				if d, ok := e.AnchorDelay(); ok {
					anchored = session.DescribeAnchorDelay(d)
				}
			}
		}
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), code(strings.Join(r.Command, " ")), dur, fmt.Sprintf("%d", r.ExitCode), anchored})
	}
	b.table([]string{"#", "Command", "Duration", "Exit", "Anchored"}, []float64{0.3, 3.2, 1.2, 0.5, 1.6}, rows)
	if total, failed, interrupted := invocationCounts(seal); total > 0 {
		b.para(fmt.Sprintf("%s in total: %d kept in this record, %d failed, %d interrupted. "+
			"Every invocation is recorded by the server, including the ones not kept.", invocations(total), len(runs), failed, interrupted))
	}
}

func (b *builder) resultsSection(runs []*session.RunRecord) {
	b.section("3  Results")
	for i, r := range runs {
		b.subsection(runTitle(i+1, r))
		fm, count := finalMetrics(r)
		if len(fm) == 0 {
			b.para("No metrics reported.")
		} else {
			rows := make([][]string, 0, len(fm))
			for _, m := range fm {
				step := m.Step
				if count[m.Name] > 1 {
					step = fmt.Sprintf("%s (%d readings)", m.Step, count[m.Name])
				}
				rows = append(rows, []string{m.Name, fmt.Sprintf("%.6g", m.Value), step, m.Source})
			}
			b.table([]string{"Metric", "Final value", "Step", "Source"}, []float64{2, 1.2, 1.6, 1}, rows)
		}
		if len(r.Claims) > 0 {
			rows := make([][]string, 0, len(r.Claims))
			for _, c := range r.Claims {
				rows = append(rows, []string{c.Metric, fmt.Sprintf("%.6g", c.Value), c.Phase, fmt.Sprintf("%d", c.Line)})
			}
			b.table([]string{"Inline claim", "Value", "Phase", "Output line"}, []float64{2, 1.2, 1.6, 1}, rows)
		}
		for _, s := range r.Seeds {
			b.para(fmt.Sprintf("Seed committed: %s, output line %d, %s.", s.Source, s.Line, s.Timestamp.UTC().Format(time.RFC3339)))
		}
	}
}

func coherenceSentence(h *session.HMCAResult) string {
	switch h.Verdict {
	case "PASS":
		return fmt.Sprintf("Coherent (%.2f): the telemetry channels move together, as one process.", h.Score)
	case "WARN":
		return fmt.Sprintf("Weak coherence (%.2f): the channels only partly move together.", h.Score)
	case "FAIL":
		return fmt.Sprintf("Incoherent (%.2f): the channels do not move as one process.", h.Score)
	default:
		return "Not enough telemetry to judge. This says nothing against the run; the seal and anchors still hold."
	}
}

func (b *builder) evidenceSection(runs []*session.RunRecord, h *session.HMCAResult) {
	b.section("4  Execution evidence")
	if h != nil {
		b.subsection("Coherence")
		b.para(coherenceSentence(h))
		for _, f := range h.Flags {
			b.para("Flag: " + f)
		}
	}
	var certRows [][]string
	var notes []string
	for i, r := range runs {
		if r.Declared == nil {
			continue
		}
		c := compute.Analyze(r)
		flops := "n/a"
		if c.FDeclaredFLOPs > 0 {
			flops = fmt.Sprintf("%.3e", c.FDeclaredFLOPs)
		}
		mfu := "n/a"
		if c.ImpliedMFU > 0 {
			mfu = fmt.Sprintf("%.4f", c.ImpliedMFU)
		}
		certRows = append(certRows, []string{fmt.Sprintf("%d", i+1), c.Verdict, flops,
			fmt.Sprintf("%.0f s", c.GPUActiveSec), fmt.Sprintf("%.0f J", c.EnergyJoules), mfu})
		for _, n := range c.Notes {
			notes = append(notes, fmt.Sprintf("Run %d: %s", i+1, n))
		}
	}
	if len(certRows) > 0 {
		b.subsection("Compute certificate")
		b.para("Declared work is checked against what the hardware could physically deliver. It proves the declared scale was run, not that the result is correct.")
		b.table([]string{"Run", "Verdict", "Declared FLOPs", "GPU active", "Energy", "Implied MFU"}, []float64{0.5, 1.2, 1.4, 1, 1, 1}, certRows)
		for _, n := range notes {
			b.para(n)
		}
	}
	b.subsection("Telemetry")
	rows := make([][]string, 0, len(runs))
	for i, r := range runs {
		var cpu, mem, gpu float64
		for _, s := range r.HardwareSamples {
			if s.Counters.CPUTimeSec > cpu {
				cpu = s.Counters.CPUTimeSec
			}
			if s.Counters.MemUsedGB > mem {
				mem = s.Counters.MemUsedGB
			}
			if s.Counters.GPUUtilPct > gpu {
				gpu = s.Counters.GPUUtilPct
			}
		}
		rows = append(rows, []string{fmt.Sprintf("%d", i+1), fmt.Sprintf("%d", len(r.HardwareSamples)),
			fmt.Sprintf("%.1f s", cpu), fmt.Sprintf("%.2f GB", mem), fmt.Sprintf("%.0f%%", gpu)})
	}
	b.table([]string{"Run", "Samples", "CPU time", "Peak memory", "Peak GPU"}, []float64{0.5, 1, 1, 1, 1}, rows)
}

func (b *builder) provenanceSection(sess *session.Session, runs []*session.RunRecord) {
	b.section("5  Provenance")
	any := false
	for i, r := range runs {
		p := r.Provenance
		if p == nil && r.Trace == nil {
			continue
		}
		any = true
		b.subsection(runTitle(i+1, r))
		if p != nil {
			b.para(fmt.Sprintf("Disclosure %s. %d tracked files, %d snapshots. Every snapshot is bound into the signature.",
				p.Disclosure, p.FileCount, len(p.Commits)))
			rows, quiet := snapshotRows(p, true)
			b.table([]string{"#", "Snapshot", "Time", "Root", "Changed"}, []float64{0.4, 1.8, 1, 1.8, 0.8}, rows)
			if quiet > 0 {
				noun := "snapshots"
				if quiet == 1 {
					noun = "snapshot"
				}
				b.para(fmt.Sprintf("%d %s with no file change omitted here; full timeline in Appendix B.", quiet, noun))
			}
			if len(p.Withheld) > 0 {
				wr := make([][]string, 0, len(p.Withheld))
				for _, w := range p.Withheld {
					wr = append(wr, []string{w.Path, w.SizeBucket, code(short(w.Hash, 24))})
				}
				b.table([]string{"Withheld by .kveritasignore", "Size", "Hash"}, []float64{2, 0.8, 2}, wr)
			}
			if p.Truncated {
				b.para("Provenance reached its snapshot cap; later snapshots are omitted.")
			}
		}
		if t := r.Trace; t != nil {
			reads, writes := 0, 0
			for _, f := range t.Files {
				if f.Op == "write" {
					writes++
				} else {
					reads++
				}
			}
			b.para(fmt.Sprintf("Activity: %d files read, %d files written, %d subprocesses. Full list in Appendix B.", reads, writes, len(t.Procs)))
		}
	}
	if !any {
		b.para("No provenance or activity was recorded for these runs.")
	}
}

func snapshotRows(p *session.Provenance, condensed bool) ([][]string, int) {
	rows := make([][]string, 0, len(p.Commits))
	quiet := 0
	for i, c := range p.Commits {
		if condensed && len(c.Changed) == 0 && i != 0 && i != len(p.Commits)-1 {
			quiet++
			continue
		}
		ev := c.Event.Kind
		if c.Event.Name != "" {
			ev += " " + c.Event.Name
		}
		rows = append(rows, []string{fmt.Sprintf("%d", c.Index), ev, c.Timestamp.UTC().Format("15:04:05"),
			code(short(c.Root, 16)), fmt.Sprintf("%d", len(c.Changed))})
	}
	return rows, quiet
}

func (b *builder) verificationSection(seal *session.SealRecord) {
	b.section("6  Verification")
	fp := sha256.Sum256([]byte(strings.TrimSpace(seal.PublicKeyPEM)))
	rows := [][]string{
		{"Signer", signer(seal)},
		{"Signed at", seal.SignedAt},
		{"Algorithm", "RSA-PSS-SHA256, 4096-bit key"},
		{"Key fingerprint", code(hex.EncodeToString(fp[:])[:32])},
		{"Data hash", code(seal.DataHash)},
	}
	if seal.CheckoutBundleHash != "" {
		rows = append(rows, []string{"Code bundle hash", code(seal.CheckoutBundleHash)})
	}
	b.table([]string{"Field", "Value"}, []float64{1, 3.2}, rows)

	anchored, late := 0, 0
	for _, e := range seal.RunHistory {
		if e.RunDigest == "" {
			continue
		}
		if d, ok := e.AnchorDelay(); ok {
			anchored++
			if d >= time.Minute {
				late++
			}
		}
	}
	if anchored > 0 {
		s := fmt.Sprintf("Run anchors: %d invocations were anchored at the server when they ended", anchored)
		if late > 0 {
			s += fmt.Sprintf(", %d after an unwitnessed gap", late)
		}
		b.para(s + ".")
	}
	b.subsection("Checks a verifier runs")
	for i, s := range []string{
		"The stored canonical data hashes to the data hash above, and the signature verifies over data_hash:nonce:signed_at.",
		"The signing key is the K-Veritas server key, not one supplied by the author.",
		"Nothing was appended after the seal, and these pages hash to the value bound in the seal.",
		"Each run matches the digest the server received when it ended.",
		"A supplied code bundle hashes to the code bundle hash above.",
	} {
		b.paraIn(fmt.Sprintf("%d. %s", i+1, s), "T", bodySize, mL, bodyW)
	}
}

func (b *builder) appendix(runs []*session.RunRecord, seal *session.SealRecord) {
	b.newPage()
	b.line("Appendix", "Tb", 15, mL)
	b.gap(4)

	b.section("A  Full metric series")
	for i, r := range runs {
		b.subsection(runTitle(i+1, r))
		if len(r.Metrics) > 0 {
			rows := make([][]string, 0, len(r.Metrics))
			for _, m := range r.Metrics {
				rows = append(rows, []string{m.Name, fmt.Sprintf("%.6g", m.Value), m.Step, fmt.Sprintf("%d", m.Line), m.Source})
			}
			b.table([]string{"Metric", "Value", "Step", "Line", "Source"}, []float64{2, 1.2, 1, 0.6, 1}, rows)
		}
		if len(r.Phases) > 0 {
			rows := make([][]string, 0, len(r.Phases))
			for _, p := range r.Phases {
				c := p.Counters
				gpu := ""
				if c.GPUUtilPct > 0 || c.GPUMemUsedMB > 0 {
					gpu = fmt.Sprintf("%.0f%%, %.0f MB", c.GPUUtilPct, c.GPUMemUsedMB)
				}
				rows = append(rows, []string{p.Name, fmt.Sprintf("%d", p.Line), p.Timestamp.UTC().Format("15:04:05"),
					fmt.Sprintf("%.1f s", c.CPUTimeSec), fmt.Sprintf("%.2f GB", c.MemUsedGB), gpu})
			}
			b.table([]string{"Phase", "Line", "Time", "CPU time", "Memory", "GPU"}, []float64{1.6, 0.6, 1, 1, 1, 1.2}, rows)
		}
	}

	b.section("B  Provenance timeline and activity map")
	shown := false
	for i, r := range runs {
		t := r.Trace
		if t == nil && r.Provenance == nil {
			continue
		}
		shown = true
		b.subsection(runTitle(i+1, r))
		if p := r.Provenance; p != nil {
			rows, _ := snapshotRows(p, false)
			b.table([]string{"#", "Snapshot", "Time", "Root", "Changed"}, []float64{0.4, 1.8, 1, 1.8, 0.8}, rows)
		}
		if t == nil {
			continue
		}
		rows := make([][]string, 0, len(t.Files)+len(t.Procs))
		for _, f := range t.Files {
			rows = append(rows, []string{f.Op, f.Path, code(short(f.Hash, 16))})
		}
		for _, p := range t.Procs {
			cmd := p.Command
			if cmd == "" {
				cmd = fmt.Sprintf("pid %d", p.PID)
			}
			rows = append(rows, []string{"process", cmd, ""})
		}
		b.table([]string{"Event", "Path or command", "Hash"}, []float64{0.7, 3, 1.3}, rows)
		if t.Truncated {
			b.para("File capture reached its cap; some paths are omitted.")
		}
	}
	if !shown {
		b.para("No provenance or activity trace was recorded.")
	}

	b.section("C  Run history")
	if len(seal.RunHistory) == 0 {
		b.para("No server run history was attached to this record.")
	}
	for _, e := range seal.RunHistory {
		label := fmt.Sprintf("Run %d", e.RunIndex+1)
		if e.Invocation != nil {
			label = fmt.Sprintf("Invocation %d", *e.Invocation+1)
		}
		status := "OK"
		switch {
		case e.ExitCode == -1:
			status = "interrupted"
		case e.ExitCode != 0:
			status = fmt.Sprintf("exit %d", e.ExitCode)
		}
		dur := e.DurationFmt
		if dur == "" {
			dur = fmt.Sprintf("%.1f s", e.DurationSec)
		}
		b.subsection(fmt.Sprintf("%s, %s, %s, %d output lines, started %s", label, status, dur, e.StdoutLines, short(e.StartedAt, 19)))
		b.monoLines("metric_hash " + e.MetricHash)
		if e.RunDigest != "" {
			b.monoLines("run_digest  " + e.RunDigest)
			if d, ok := e.AnchorDelay(); ok {
				b.monoLines("anchored    " + session.DescribeAnchorDelay(d))
			}
		}
	}

	b.section("D  Raw seal fields and hashes")
	b.subsection("Seal")
	b.monoLines("data_hash           " + seal.DataHash)
	b.monoLines("signed_message_hash " + seal.SignedMessageHash)
	b.monoLines("nonce               " + seal.Nonce)
	b.monoLines("signed_at           " + seal.SignedAt)
	b.monoLines("sealed_at           " + seal.SealedAt.UTC().Format(time.RFC3339Nano))
	if seal.SourceBundleHash != "" {
		b.monoLines("source_bundle_hash  " + seal.SourceBundleHash)
	}
	if seal.CheckoutBundleHash != "" {
		b.monoLines("checkout_bundle     " + seal.CheckoutBundleHash)
	}
	b.subsection("Signature (base64)")
	b.monoLines(seal.Signature)
	b.subsection("Public key")
	for _, l := range strings.Split(strings.TrimSpace(seal.PublicKeyPEM), "\n") {
		b.monoLines(l)
	}
	for i, r := range runs {
		b.subsection(fmt.Sprintf("Run %d outputs", i+1))
		b.monoLines("stdout  " + r.StdoutHash)
		b.monoLines("stderr  " + r.StderrHash)
		if r.MetricHash != "" {
			b.monoLines("metrics " + r.MetricHash)
		}
		if r.RunDigest != "" {
			b.monoLines("digest  " + r.RunDigest)
		}
		paths := make([]string, 0, len(r.PreHashes))
		for p := range r.PreHashes {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			state := "unchanged"
			if r.PostHashes[p] != r.PreHashes[p] {
				state = "modified"
			}
			b.para(fmt.Sprintf("%s (%s)", p, state))
			b.monoLines("pre  " + r.PreHashes[p])
			b.monoLines("post " + r.PostHashes[p])
		}
	}

	b.section("E  BibTeX for [1]")
	for _, l := range citeBibTeX {
		b.line(l, "C", 7.5, mL)
	}
}
