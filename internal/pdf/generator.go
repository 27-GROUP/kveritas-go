// Package pdf generates K-Veritas verification reports.
//
// The report is a self-contained PDF file. Cryptographic metadata is appended
// after the PDF %%EOF marker between known delimiters so that standard PDF
// readers display the visual report while the verify command can extract and
// check the embedded attestation data without a PDF parsing library.
//
// Metadata block format (appended verbatim after %%EOF):
//
//	%%KVERITAS_SEAL_BEGIN%%
//	<JSON>
//	%%KVERITAS_SEAL_END%%
package pdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/mamadouk/kveritas/internal/session"
)

const (
	metaBegin = "%%KVERITAS_SEAL_BEGIN%%"
	metaEnd   = "%%KVERITAS_SEAL_END%%"

	pageW = 612.0
	pageH = 792.0
	mL    = 60.0
	mR    = 60.0
	mT    = 60.0
	mB    = 60.0
	bodyW = pageW - mL - mR
)

// EmbeddedData is the complete session state stored inside the PDF.
type EmbeddedData struct {
	Version string              `json:"version"`
	Session *session.Session    `json:"session"`
	Runs    []*session.RunRecord `json:"runs"`
	Seal    *session.SealRecord `json:"seal"`
}

// Generate writes a signed K-Veritas report to outPath.
func Generate(sess *session.Session, runs []*session.RunRecord, seal *session.SealRecord, hmcaResult *session.HMCAResult, outPath string) error {
	b := newBuilder()

	b.addCoverPage(sess, seal, runs)
	for i, r := range runs {
		b.addRunPage(i+1, r)
	}
	b.addRunHistoryPage(seal)
	if hmcaResult != nil {
		b.addHMCAPage(hmcaResult)
	}
	b.addCryptoPage(seal)

	pdfBytes, err := b.render()
	if err != nil {
		return err
	}

	// Hash the visual PDF content so tampering the visual pages is detectable
	pdfHash := sha256.Sum256(pdfBytes)
	seal.VisualPDFHash = hex.EncodeToString(pdfHash[:])

	meta := EmbeddedData{
		Version: "1.0",
		Session: sess,
		Runs:    runs,
		Seal:    seal,
	}

	// First pass: build the JSON without seal_block_hash
	metaJSON1, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	// Hash the entire seal block content
	blockHash := sha256.Sum256(metaJSON1)
	seal.SealBlockHash = hex.EncodeToString(blockHash[:])

	// Second pass: rebuild with the seal_block_hash included
	meta.Seal = seal
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}

	var out bytes.Buffer
	out.Write(pdfBytes)
	out.WriteString("\n" + metaBegin + "\n")
	out.Write(metaJSON)
	out.WriteString("\n" + metaEnd + "\n")

	return os.WriteFile(outPath, out.Bytes(), 0644)
}

// ExtractMetadata reads the embedded attestation data from a K-Veritas PDF.
func ExtractMetadata(pdfPath string) (*EmbeddedData, error) {
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		return nil, err
	}
	start := bytes.Index(data, []byte(metaBegin))
	end := bytes.Index(data, []byte(metaEnd))
	if start < 0 || end < 0 || end <= start {
		return nil, fmt.Errorf("no K-Veritas metadata found in %s", pdfPath)
	}
	jsonStart := start + len(metaBegin) + 1
	if jsonStart >= end {
		return nil, fmt.Errorf("metadata block is empty")
	}
	var meta EmbeddedData
	if err := json.Unmarshal(data[jsonStart:end], &meta); err != nil {
		return nil, fmt.Errorf("corrupted metadata: %w", err)
	}
	return &meta, nil
}

// --- minimal self-contained PDF builder ---

type page struct {
	content strings.Builder
}

type builder struct {
	pages []*page
	cur   *page
	curY  float64
	title string
	info  string
}

func newBuilder() *builder {
	b := &builder{}
	b.newPage()
	return b
}

func (b *builder) newPage() {
	p := &page{}
	b.pages = append(b.pages, p)
	b.cur = p
	b.curY = mT
}

func (b *builder) checkSpace(needed float64) {
	if b.curY+needed > pageH-mB {
		b.newPage()
	}
}

// lineHeight returns the line height for a given font size.
func lineH(size float64) float64 { return size * 1.4 }

func (b *builder) writeLine(text, font string, size, x float64) {
	lh := lineH(size)
	b.checkSpace(lh)
	y := pageH - b.curY - size
	b.cur.content.WriteString(fmt.Sprintf(
		"BT /%s %.1f Tf %.2f %.2f Td (%s) Tj ET\n",
		font, size, x, y, pdfEscape(text),
	))
	b.curY += lh
}

func (b *builder) hline() {
	b.checkSpace(8)
	y := pageH - b.curY
	b.cur.content.WriteString(fmt.Sprintf(
		"%.2f %.2f m %.2f %.2f l S\n",
		mL, y, pageW-mR, y,
	))
	b.curY += 6
}

func (b *builder) gap(h float64) {
	b.curY += h
}

func (b *builder) heading(text string) {
	b.gap(8)
	b.writeLine(text, "Hb", 13, mL)
	b.hline()
	b.gap(2)
}

func (b *builder) body(text string) {
	// Wrap long lines.
	for _, line := range wrapText(text, 95) {
		b.writeLine(line, "H", 9.5, mL)
	}
}

func (b *builder) mono(text string) {
	for _, line := range wrapText(text, 80) {
		b.writeLine(line, "C", 8, mL)
	}
}

func (b *builder) kv(key, val string) {
	line := key + ": " + val
	b.body(line)
}

func (b *builder) addCoverPage(sess *session.Session, seal *session.SealRecord, runs []*session.RunRecord) {
	b.gap(16)
	b.writeLine("K-Veritas Experiment Report", "Hb", 20, mL)
	b.gap(4)
	b.hline()
	b.gap(10)

	b.kv("Session ID", sess.ID)
	b.kv("Initialized", sess.InitAt.UTC().Format(time.RFC3339))
	b.kv("Machine ID", sess.MachineID)
	b.kv("Runs recorded", fmt.Sprintf("%d", len(runs)))
	b.kv("Sealed", seal.SealedAt.UTC().Format(time.RFC3339))
	b.kv("Server", seal.ServerURL)

	b.heading("Run Summary")
	for i, r := range runs {
		cmd := strings.Join(r.Command, " ")
		if len(cmd) > 70 {
			cmd = cmd[:67] + "..."
		}
		status := "OK"
		if r.ExitCode != 0 {
			status = fmt.Sprintf("EXIT %d", r.ExitCode)
		}
		b.body(fmt.Sprintf("Run %d  [%s]  %.1fs  %d metrics  %s",
			i+1, status, r.DurationSec, len(r.Metrics), cmd))
	}

	if len(runs) > 0 {
		b.heading("All Metrics (Final Values)")
		seen := map[string]bool{}
		for _, r := range runs {
			for _, m := range r.Metrics {
				if m.Source == "explicit" && !seen[m.Name] {
					seen[m.Name] = true
					b.body(fmt.Sprintf("  %-30s  %.6g", m.Name, m.Value))
				}
			}
		}
		if len(seen) == 0 {
			b.body("  (no explicit KVERITAS_METRIC lines found)")
		}
	}
}

func (b *builder) addRunPage(idx int, r *session.RunRecord) {
	b.newPage()
	b.gap(10)
	b.writeLine(fmt.Sprintf("Run %d Details", idx), "Hb", 15, mL)
	b.gap(4)
	b.hline()
	b.gap(6)

	b.kv("Command", strings.Join(r.Command, " "))
	b.kv("Start", r.StartAt.UTC().Format(time.RFC3339Nano))
	b.kv("End", r.EndAt.UTC().Format(time.RFC3339Nano))
	durStr := fmt.Sprintf("%.3f s", r.DurationSec)
	if r.DurationFmt != "" {
		durStr = r.DurationFmt
	}
	b.kv("Duration", durStr)
	b.kv("Exit code", fmt.Sprintf("%d", r.ExitCode))
	b.kv("Stdout lines", fmt.Sprintf("%d", r.StdoutLines))
	b.kv("Hardware", fmt.Sprintf("%s / %s / %d CPU / %.1f GB RAM",
		r.Hardware.OS, r.Hardware.Arch, r.Hardware.CPUCores, r.Hardware.MemGB))
	if r.Hardware.GPUInfo != "" {
		b.kv("GPU", r.Hardware.GPUInfo)
	}

	// Seed commitments
	if len(r.Seeds) > 0 {
		b.heading("Seed Commitments")
		for _, s := range r.Seeds {
			b.body(fmt.Sprintf("  %s  committed at line %d  (%s)",
				s.Source, s.Line, s.Timestamp.UTC().Format(time.RFC3339)))
		}
	}

	// Phase timeline with hardware deltas
	if len(r.Phases) > 0 {
		b.heading("Phase Timeline (Hardware Snapshots)")
		for i, p := range r.Phases {
			b.body(fmt.Sprintf("  PHASE %s  (line %d, %s)",
				p.Name, p.Line, p.Timestamp.UTC().Format(time.RFC3339)))
			c := p.Counters
			b.body(fmt.Sprintf("    CPU: %.1fs  Mem: %.2f GB  Disk R/W: %.0f/%.0f MB",
				c.CPUTimeSec, c.MemUsedGB, c.DiskReadMB, c.DiskWriteMB))
			if c.GPUUtilPct > 0 || c.GPUMemUsedMB > 0 {
				b.body(fmt.Sprintf("    GPU: %.0f%% util  %.0f MB mem  %.1fC  %.1fW",
					c.GPUUtilPct, c.GPUMemUsedMB, c.GPUTempC, c.GPUPowerW))
			}
			if c.CPUTempC > 0 {
				b.body(fmt.Sprintf("    CPU temp: %.1fC", c.CPUTempC))
			}

			// Delta from previous phase
			if i > 0 {
				prev := r.Phases[i-1]
				lines := p.Line - prev.Line
				dur := p.Timestamp.Sub(prev.Timestamp).Seconds()
				cpuDelta := p.Counters.CPUTimeSec - prev.Counters.CPUTimeSec
				diskR := p.Counters.DiskReadMB - prev.Counters.DiskReadMB
				diskW := p.Counters.DiskWriteMB - prev.Counters.DiskWriteMB
				b.body(fmt.Sprintf("    Delta from %s: %d lines, %.1fs wall, %.1fs CPU, %.0f/%.0f MB disk",
					prev.Name, lines, dur, cpuDelta, diskR, diskW))
				if p.Counters.GPUMemUsedMB > 0 && prev.Counters.GPUMemUsedMB > 0 {
					memDelta := p.Counters.GPUMemUsedMB - prev.Counters.GPUMemUsedMB
					b.body(fmt.Sprintf("    GPU mem delta: %.0f MB", memDelta))
				}
			}
		}
	}

	// Inline claims
	if len(r.Claims) > 0 {
		b.heading("Inline Claims (committed in stdout)")
		for _, c := range r.Claims {
			phase := ""
			if c.Phase != "" {
				phase = " phase=" + c.Phase
			}
			b.body(fmt.Sprintf("  %-30s  %.6g  (line %d%s)", c.Metric, c.Value, c.Line, phase))
		}
	}

	if len(r.Metrics) > 0 {
		b.heading("Metrics")
		for _, m := range r.Metrics {
			step := ""
			if m.Step != "" {
				step = " @ step=" + m.Step
			}
			src := ""
			if m.Source == "heuristic" {
				src = " (heuristic, line " + fmt.Sprintf("%d", m.Line) + ")"
			} else {
				src = fmt.Sprintf(" (line %d)", m.Line)
			}
			b.body(fmt.Sprintf("  %-30s  %.6g%s%s", m.Name, m.Value, step, src))
		}
	}

	if len(r.PreHashes) > 0 {
		b.heading("File Integrity")
		for path, pre := range r.PreHashes {
			post := r.PostHashes[path]
			status := "unchanged"
			if post != pre {
				status = "MODIFIED"
			}
			b.body(fmt.Sprintf("  %s  [%s]", path, status))
			b.mono("    pre:  " + pre)
			b.mono("    post: " + post)
		}
	}

	b.heading("Output Hashes")
	b.mono("stdout  SHA-256: " + r.StdoutHash)
	b.mono("stderr  SHA-256: " + r.StderrHash)
	if r.EnvDigest != "" {
		b.mono("env     SHA-256: " + r.EnvDigest)
	}
	if r.MetricHash != "" {
		b.mono("metrics SHA-256: " + r.MetricHash)
	}
}

func (b *builder) addRunHistoryPage(seal *session.SealRecord) {
	if seal.TotalRunCount == 0 && len(seal.RunHistory) == 0 {
		return
	}
	b.newPage()
	b.gap(10)
	b.writeLine("Run History (Multi-Run Ledger)", "Hb", 15, mL)
	b.gap(4)
	b.hline()
	b.gap(6)

	b.body(fmt.Sprintf("Total invocations for this session: %d", seal.TotalRunCount))
	b.body("The server ledger records every 'kveritas run' invocation, including failed")
	b.body("and discarded runs. Actual metric values are not stored -- only their hashes.")
	b.gap(6)

	for _, entry := range seal.RunHistory {
		status := "OK"
		if entry.ExitCode != 0 {
			status = fmt.Sprintf("EXIT %d", entry.ExitCode)
		}
		dur := entry.DurationFmt
		if dur == "" {
			dur = fmt.Sprintf("%.1fs", entry.DurationSec)
		}
		b.body(fmt.Sprintf("  Run %d  [%s]  %s  %d stdout lines  started %s",
			entry.RunIndex+1, status, dur, entry.StdoutLines, entry.StartedAt[:19]))
		b.mono(fmt.Sprintf("    metric_hash: %s", entry.MetricHash))
	}
}

func (b *builder) addHMCAPage(result *session.HMCAResult) {
	b.newPage()
	b.gap(10)
	b.writeLine("Hardware-Metric Consistency Analysis", "Hb", 15, mL)
	b.gap(4)
	b.hline()
	b.gap(6)

	b.body("The HMCA engine checks whether reported metrics are consistent with")
	b.body("observed hardware activity during experiment execution.")
	b.gap(6)

	b.kv("Score", fmt.Sprintf("%.2f / 1.00", result.Score))
	b.kv("Verdict", result.Verdict)
	b.gap(6)

	if len(result.Flags) > 0 {
		b.heading("Flags")
		for _, f := range result.Flags {
			b.body("  " + f)
		}
	} else {
		b.body("No consistency flags raised.")
	}

	b.gap(10)
	b.heading("HMCA Rules")
	b.body("ZERO_COST_METRIC: metrics reported in under 1 second of execution")
	b.body("LOW_ACTIVITY_HIGH_GAIN: high metric values with minimal CPU/memory activity")
	b.body("GPU_CLAIM_NO_GPU: GPU counters present but no GPU detected in hardware snapshot")
	b.body("IDLE_RUN: hardware remained idle for the entire run duration")
	b.body("PHASE_MISMATCH: evaluation phase used disproportionately more CPU than training")
}

func (b *builder) addCryptoPage(seal *session.SealRecord) {
	b.newPage()
	b.gap(10)
	b.writeLine("Cryptographic Attestation", "Hb", 15, mL)
	b.gap(4)
	b.hline()
	b.gap(6)

	b.kv("Protocol", "RSA-PSS-SHA256 (4096-bit key, salt=MAX)")
	b.kv("Sealed at", seal.SealedAt.UTC().Format(time.RFC3339Nano))
	b.kv("Signed at", seal.SignedAt)
	b.kv("Nonce", seal.Nonce)
	if seal.SourceBundleHash != "" {
		b.kv("Source bundle hash", seal.SourceBundleHash)
	}

	b.heading("Data Hash (SHA-256 of canonical experiment JSON)")
	b.mono(seal.DataHash)

	b.heading("Signed Message Hash (SHA-256 of data_hash:nonce:signed_at)")
	b.mono(seal.SignedMessageHash)

	b.heading("RSA-PSS Signature (base64)")
	for _, chunk := range chunkString(seal.Signature, 72) {
		b.mono(chunk)
	}

	b.heading("How to Verify")
	b.body("1. Recompute data hash from embedded session JSON.")
	b.body("2. Reconstruct payload: data_hash:nonce:signed_at")
	b.body("3. Verify SHA-256(payload) == signed_message_hash.")
	b.body("4. Verify RSA-PSS-SHA256 signature over payload using the server public key.")
	b.body("5. Upload the PDF (and optional bundle.zip) at kveritas.org/verify")
	b.body("   or run:  kveritas verify <this_file.pdf>")
}

// render produces the raw PDF bytes (through %%EOF).
func (b *builder) render() ([]byte, error) {
	var buf bytes.Buffer
	type objPos struct{ num, offset int }
	var positions []objPos
	objCount := 0

	writeObj := func(content string) int {
		objCount++
		positions = append(positions, objPos{objCount, buf.Len()})
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n\n", objCount, content)
		return objCount
	}

	buf.WriteString("%PDF-1.4\n")

	// Font objects: F1=Helvetica, F2=Helvetica-Bold, F3=Courier
	fontH := writeObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	fontHb := writeObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	fontC := writeObj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")

	fontDict := fmt.Sprintf("<< /H %d 0 R /Hb %d 0 R /C %d 0 R >>", fontH, fontHb, fontC)

	// Page content streams and page objects.
	pageNums := make([]int, 0, len(b.pages))
	for _, pg := range b.pages {
		stream := pg.content.String()
		streamObj := writeObj(fmt.Sprintf("<< /Length %d >>\nstream\n0.3 w\n%sendstream", len(stream)+6, stream))
		resourcesObj := writeObj(fmt.Sprintf("<< /Font %s >>", fontDict))
		pgObj := writeObj(fmt.Sprintf(
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.1f %.1f] /Contents %d 0 R /Resources %d 0 R >>",
			pageW, pageH, streamObj, resourcesObj,
		))
		pageNums = append(pageNums, pgObj)
	}

	// We need to write the Pages and Catalog objects. Their numbers must be
	// 1 (catalog) and 2 (pages) per PDF convention, but we wrote fonts first.
	// Instead, embed them with their actual numbers.
	kidsStr := ""
	for i, n := range pageNums {
		if i > 0 {
			kidsStr += " "
		}
		kidsStr += fmt.Sprintf("%d 0 R", n)
	}
	pagesObj := writeObj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kidsStr, len(pageNums)))
	catalogObj := writeObj(fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesObj))

	// Cross-reference table.
	xrefOffset := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", objCount+1)
	fmt.Fprintf(&buf, "0000000000 65535 f \n")

	posMap := make(map[int]int, len(positions))
	for _, p := range positions {
		posMap[p.num] = p.offset
	}
	for i := 1; i <= objCount; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", posMap[i])
	}

	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root %d 0 R >>\n", objCount+1, catalogObj)
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", xrefOffset)

	_ = pagesObj // suppress unused warning (used in kidsStr)
	return buf.Bytes(), nil
}

func pdfEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString("\\\\")
		case r == '(':
			b.WriteString("\\(")
		case r == ')':
			b.WriteString("\\)")
		case r >= 32 && r <= 126:
			b.WriteRune(r)
		case r >= 0xA0 && r <= 0xFF:
			// WinAnsiEncoding supports Latin-1 supplement directly as octal
			b.WriteString(fmt.Sprintf("\\%03o", r))
		case r == 0x2013: // en dash
			b.WriteString("\\226")
		case r == 0x2014: // em dash
			b.WriteString("\\227")
		case r == 0x2018: // left single quote
			b.WriteString("\\221")
		case r == 0x2019: // right single quote / apostrophe
			b.WriteString("\\222")
		case r == 0x201C: // left double quote
			b.WriteString("\\223")
		case r == 0x201D: // right double quote
			b.WriteString("\\224")
		case r == 0x2022: // bullet
			b.WriteString("\\225")
		case r == 0x2026: // ellipsis
			b.WriteString("\\205")
		case unicode.IsPrint(r):
			// Non-WinAnsi printable: transliterate to ASCII approximation
			b.WriteRune(transliterate(r))
		default:
			b.WriteByte(' ')
		}
	}
	return b.String()
}

func transliterate(r rune) rune {
	// Common Unicode to ASCII approximations
	switch {
	case r >= 0x0100 && r <= 0x017F: // Latin Extended-A
		base := strings.ToLower(string(r))
		if len(base) > 0 {
			first := []rune(base)[0]
			switch {
			case first >= 'a' && first <= 'z':
				return first
			}
		}
		return '?'
	default:
		return '?'
	}
}

func wrapText(text string, maxChars int) []string {
	if len(text) <= maxChars {
		return []string{text}
	}
	var lines []string
	for len(text) > maxChars {
		cut := maxChars
		// Try to break at a space.
		for i := cut; i > maxChars-20 && i >= 0; i-- {
			if text[i] == ' ' {
				cut = i
				break
			}
		}
		lines = append(lines, text[:cut])
		text = strings.TrimLeft(text[cut:], " ")
	}
	if text != "" {
		lines = append(lines, text)
	}
	return lines
}

func chunkString(s string, size int) []string {
	chunks := make([]string, 0, int(math.Ceil(float64(len(s))/float64(size))))
	for len(s) > size {
		chunks = append(chunks, s[:size])
		s = s[size:]
	}
	if s != "" {
		chunks = append(chunks, s)
	}
	return chunks
}
