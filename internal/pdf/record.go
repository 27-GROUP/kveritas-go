package pdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/session"
)

const (
	RecordKind = "archive-record"
	recordsURL = "https://kveritas.org/records"
)

// The visual pages are rendered first and their hash goes into the signed record,
// so unlike a sealed report the signature itself covers what a reader sees.
func GenerateRecord(rec *session.ArchiveRecord, reports []*EmbeddedData, sign func(dataHash string) (*session.SealRecord, error), outPath string) error {
	b := newBuilder()
	b.archiveRecord(rec, reports)
	pdfBytes, err := b.render()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(pdfBytes)
	rec.VisualPDFHash = hex.EncodeToString(sum[:])

	dataHash, canonical, err := crypto.CanonicalHashWithBytes(rec)
	if err != nil {
		return err
	}
	seal, err := sign(dataHash)
	if err != nil {
		return err
	}
	seal.DataHash = dataHash
	seal.CanonicalJSON = string(canonical)
	seal.VisualPDFHash = rec.VisualPDFHash
	seal.SealedAt = time.Now().UTC()

	meta := EmbeddedData{Version: "1.0", Kind: RecordKind, Record: rec, Seal: seal}
	first, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	blockHash := sha256.Sum256(first)
	seal.SealBlockHash = hex.EncodeToString(blockHash[:])
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

func recordID(rec *session.ArchiveRecord) string {
	return strings.TrimPrefix(rec.ID, "kv:")
}

func (b *builder) archiveRecord(rec *session.ArchiveRecord, reports []*EmbeddedData) {
	b.gap(22)
	for _, l := range wrapToWidth(rec.Title, "Tb", 18, bodyW-40) {
		b.centered(l, "Tb", 18)
	}
	b.gap(8)
	names := make([]string, 0, len(rec.Authors))
	for _, a := range rec.Authors {
		if a.Affiliation != "" {
			names = append(names, fmt.Sprintf("%s (%s)", a.Name, a.Affiliation))
		} else {
			names = append(names, a.Name)
		}
	}
	for _, l := range wrapToWidth(strings.Join(names, ", "), "T", 12, bodyW-40) {
		b.centered(l, "T", 12)
	}
	b.gap(4)
	b.centered(fmt.Sprintf("%s · Published %s", rec.ID, rec.Published), "T", bodySize)
	b.gap(16)

	b.centered("Abstract", "Tb", bodySize+0.5)
	b.gap(2)
	b.paraIn(rec.Abstract, "T", bodySize, mL+28, bodyW-56)
	b.gap(10)

	refBase := 2
	cites := make([]string, len(reports))
	for i := range reports {
		cites[i] = fmt.Sprintf("[%d]", refBase+i)
	}
	b.box("About this record", []string{
		"Title, authors and abstract were provided by the authors and reviewed for completeness, not for scientific soundness. " +
			"Every number in this record is copied from the signed data of the sealed reports " + strings.Join(cites, ", ") + ", which remain authoritative.",
		"Verify: kveritas verify record.pdf, and each report with its code bundle at " + recordsURL + "/" + recordID(rec),
	})

	b.section("1  Sealed reports")
	b.para("The experiments were sealed with K-Veritas [1], which binds each result to the code, hardware and time that produced it.")
	rows := make([][]string, 0, len(reports))
	for i, rp := range reports {
		r := rec.Reports[i]
		total, failed, interrupted := invocationCounts(rp.Seal)
		inv := fmt.Sprintf("%d", total)
		if failed+interrupted > 0 {
			inv = fmt.Sprintf("%d (%d failed)", total, failed+interrupted)
		}
		rows = append(rows, []string{fmt.Sprintf("%s %s", r.ID, cites[i]), r.Label, rp.Seal.SealedAt.UTC().Format("2006-01-02"),
			fmt.Sprintf("%d", len(rp.Runs)), inv, signer(rp.Seal)})
	}
	b.table([]string{"Report", "Label", "Sealed", "Runs", "Invocations", "Signer"}, []float64{0.8, 1.8, 1, 0.5, 1, 2}, rows)

	b.section("2  Results")
	for i, rp := range reports {
		b.subsection(fmt.Sprintf("%s: %s", rec.Reports[i].ID, rec.Reports[i].Label))
		var mrows, crows [][]string
		for j, run := range rp.Runs {
			fm, _ := finalMetrics(run)
			for _, m := range fm {
				mrows = append(mrows, []string{fmt.Sprintf("%d", j+1), m.Name, fmt.Sprintf("%.6g", m.Value), m.Step})
			}
			for _, c := range run.Claims {
				crows = append(crows, []string{fmt.Sprintf("%d", j+1), c.Metric, fmt.Sprintf("%.6g", c.Value), c.Phase})
			}
		}
		if len(mrows) == 0 {
			b.para("No metrics reported.")
		} else {
			b.table([]string{"Run", "Metric", "Final value", "Step"}, []float64{0.5, 2, 1.2, 1.4}, mrows)
		}
		if len(crows) > 0 {
			b.table([]string{"Run", "Inline claim", "Value", "Phase"}, []float64{0.5, 2, 1.2, 1.4}, crows)
		}
	}

	b.section("3  Setup")
	rows = rows[:0]
	for i, rp := range reports {
		if len(rp.Runs) == 0 {
			continue
		}
		hw := rp.Runs[0].Hardware
		var dur float64
		for _, r := range rp.Runs {
			dur += r.DurationSec
		}
		id := rec.Reports[i].ID
		rows = append(rows, []string{id, "Operating system", hw.OS + " / " + hw.Arch})
		cpu := fmt.Sprintf("%d cores", hw.CPUCores)
		if hw.CPUModel != "" {
			cpu = fmt.Sprintf("%s, %d cores", hw.CPUModel, hw.CPUCores)
		}
		rows = append(rows, []string{id, "CPU", cpu})
		if hw.GPUInfo != "" {
			rows = append(rows, []string{id, "GPU", hw.GPUInfo})
		}
		rows = append(rows, []string{id, "Memory", fmt.Sprintf("%.1f GB", hw.MemGB)})
		rows = append(rows, []string{id, "Total run time", fmt.Sprintf("%.1f s", dur)})
	}
	b.table([]string{"Report", "Item", "Value"}, []float64{0.6, 1.2, 3.6}, rows)

	b.section("4  Files")
	b.para("Each report and code bundle must hash to these values. A bundle belongs to the report whose signed data names its hash.")
	rows = rows[:0]
	for _, r := range rec.Reports {
		rows = append(rows, []string{r.ID + ".pdf", code(r.ReportSHA256), formatBytes(r.ReportSize)})
		if r.BundleSHA256 != "" {
			rows = append(rows, []string{r.ID + ".kvbundle.zip", code(r.BundleSHA256), formatBytes(r.BundleSize)})
		}
	}
	b.table([]string{"File", "SHA-256", "Size"}, []float64{1.1, 4, 0.6}, rows)

	b.section("5  Licence")
	lic := "Record: CC-BY 4.0."
	if rec.License != "" {
		lic += " Code: " + rec.License + ", as declared by the authors."
	}
	if len(rec.Tags) > 0 {
		lic += " Tags: " + strings.Join(rec.Tags, ", ") + "."
	}
	b.para(lic)
	b.para("Listed, not endorsed. Review checks the artifact, never the science. Records are never edited; corrections are new versions.")

	b.section("References")
	b.paraIn("[1] "+citeText, "T", bodySize, mL, bodyW)
	for i, r := range rec.Reports {
		b.gap(2)
		b.paraIn(fmt.Sprintf("%s Sealed experiment report %s (%s), %s/%s. Data hash %s. %s/%s/%s.pdf",
			cites[i], r.ID, r.Label, rec.ID, r.ID, r.DataHash, recordsURL, recordID(rec), r.ID), "T", bodySize, mL, bodyW)
	}

	b.decorate("K-Veritas Records · " + rec.ID)
}

func formatBytes(n int64) string {
	if n < 1024*1024 {
		return fmt.Sprintf("%d KB", (n+1023)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/1024/1024)
}
