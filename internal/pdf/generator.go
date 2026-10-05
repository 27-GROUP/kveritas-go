// Package pdf generates K-Veritas verification reports as self-contained PDFs.
// Attestation metadata is appended after %%EOF between delimiters, so standard
// readers show the visual report while verify extracts the seal without a PDF
// parser.
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
	"regexp"
	"strings"
	"unicode"

	"github.com/Mamadou2727/kveritas-go/internal/session"
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

type EmbeddedData struct {
	Version string                 `json:"version"`
	Kind    string                 `json:"kind,omitempty"`
	Session *session.Session       `json:"session"`
	Runs    []*session.RunRecord   `json:"runs"`
	Record  *session.ArchiveRecord `json:"record,omitempty"`
	Seal    *session.SealRecord    `json:"seal"`
}

func Generate(sess *session.Session, runs []*session.RunRecord, seal *session.SealRecord, hmcaResult *session.HMCAResult, outPath string) error {
	b := newBuilder()

	b.paperReport(sess, runs, seal, hmcaResult)

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

// Covers fields the signed canonical JSON does not, such as run_history, which verify
// prints but the signature never bound. The field is stripped before re-hashing since
// it was hashed before it contained itself.
func SealBlockHash(pdfPath string) (string, error) {
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		return "", err
	}
	start := bytes.Index(data, []byte(metaBegin))
	end := bytes.Index(data, []byte(metaEnd))
	if start < 0 || end < 0 || end <= start {
		return "", fmt.Errorf("no K-Veritas seal in %s", pdfPath)
	}
	block := data[start+len(metaBegin)+1 : end]
	if len(block) > 0 && block[len(block)-1] == '\n' {
		block = block[:len(block)-1]
	}
	stripped := sealBlockHashField.ReplaceAll(block, nil)
	sum := sha256.Sum256(stripped)
	return hex.EncodeToString(sum[:]), nil
}

var sealBlockHashField = regexp.MustCompile(`,?\s*"seal_block_hash"\s*:\s*"[a-f0-9]*"`)

// A PDF reader resolves objects through the last cross-reference table, so an update
// appended after the seal can redefine a page while every hash still matches.
func SealIsFinal(pdfPath string) (bool, error) {
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		return false, err
	}
	end := bytes.Index(data, []byte(metaEnd))
	if end < 0 {
		return false, fmt.Errorf("no K-Veritas seal in %s", pdfPath)
	}
	return len(bytes.TrimSpace(data[end+len(metaEnd):])) == 0, nil
}

// VisualPDFHash re-derives the SHA-256 of the report's visual pages (everything
// before the seal marker), so an edit to the human-readable PDF is detectable.
func VisualPDFHash(pdfPath string) (string, error) {
	data, err := os.ReadFile(pdfPath)
	if err != nil {
		return "", err
	}
	start := bytes.Index(data, []byte(metaBegin))
	if start < 0 {
		return "", fmt.Errorf("no K-Veritas seal in %s", pdfPath)
	}
	end := start
	if end > 0 && data[end-1] == '\n' {
		end--
	}
	sum := sha256.Sum256(data[:end])
	return hex.EncodeToString(sum[:]), nil
}

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

func lineH(size float64) float64 { return size * 1.4 }

func (b *builder) gap(h float64) {
	b.curY += h
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

	fontH := writeObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	fontHb := writeObj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	fontC := writeObj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")

	fontT := writeObj("<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman /Encoding /WinAnsiEncoding >>")
	fontTb := writeObj("<< /Type /Font /Subtype /Type1 /BaseFont /Times-Bold /Encoding /WinAnsiEncoding >>")
	fontTi := writeObj("<< /Type /Font /Subtype /Type1 /BaseFont /Times-Italic /Encoding /WinAnsiEncoding >>")

	fontDict := fmt.Sprintf("<< /H %d 0 R /Hb %d 0 R /C %d 0 R /T %d 0 R /Tb %d 0 R /Ti %d 0 R >>", fontH, fontHb, fontC, fontT, fontTb, fontTi)

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

	// Pages and Catalog are emitted last with their actual object numbers rather
	// than the conventional 1 and 2, since fonts were written first.
	kidsStr := ""
	for i, n := range pageNums {
		if i > 0 {
			kidsStr += " "
		}
		kidsStr += fmt.Sprintf("%d 0 R", n)
	}
	pagesObj := writeObj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kidsStr, len(pageNums)))
	catalogObj := writeObj(fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pagesObj))

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
