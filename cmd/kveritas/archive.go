package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/client"
	"github.com/Mamadou2727/kveritas-go/internal/crypto"
	"github.com/Mamadou2727/kveritas-go/internal/pdf"
	"github.com/Mamadou2727/kveritas-go/internal/session"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type recordFileRef struct {
	Path   string `yaml:"path"`
	SHA256 string `yaml:"sha256"`
	Size   int64  `yaml:"size"`
}

type recordMetadata struct {
	ID        string                 `yaml:"id"`
	Version   int                    `yaml:"version"`
	Title     string                 `yaml:"title"`
	Authors   []session.RecordAuthor `yaml:"authors"`
	Abstract  string                 `yaml:"abstract"`
	Tags      []string               `yaml:"tags"`
	License   string                 `yaml:"license"`
	Published string                 `yaml:"published"`
	Reports   []struct {
		ID       string `yaml:"id"`
		Label    string `yaml:"label"`
		Session  string `yaml:"session"`
		DataHash string `yaml:"data_hash"`
		Files    struct {
			Report recordFileRef  `yaml:"report"`
			Bundle *recordFileRef `yaml:"bundle"`
		} `yaml:"files"`
	} `yaml:"reports"`
}

var (
	archiveOut    string
	archiveServer string
)

var cmdArchiveRecord = &cobra.Command{
	Use:    "archive-record <metadata.yaml>",
	Short:  "Generate and sign the Archive Record for a published record (maintainers)",
	Args:   cobra.ExactArgs(1),
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		token := os.Getenv("VERITAS_SIGN_TOKEN")
		if token == "" {
			return fmt.Errorf("VERITAS_SIGN_TOKEN is not set")
		}
		raw, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		var md recordMetadata
		if err := yaml.Unmarshal(raw, &md); err != nil {
			return fmt.Errorf("reading %s: %w", args[0], err)
		}
		if md.ID == "" || md.Title == "" || len(md.Authors) == 0 || len(md.Reports) == 0 {
			return fmt.Errorf("%s needs id, title, authors and at least one report", args[0])
		}
		dir := filepath.Dir(args[0])

		rec := &session.ArchiveRecord{
			ID: md.ID, Version: md.Version, Title: md.Title, Authors: md.Authors, Abstract: md.Abstract,
			Tags: md.Tags, License: md.License, Published: md.Published,
		}
		var reports []*pdf.EmbeddedData
		for _, r := range md.Reports {
			path := filepath.Join(dir, "reports", r.ID+".pdf")
			sum, err := crypto.HashFile(path)
			if err != nil {
				return err
			}
			info, err := os.Stat(path)
			if err != nil {
				return err
			}
			if sum != r.Files.Report.SHA256 || info.Size() != r.Files.Report.Size {
				return fmt.Errorf("%s: file does not match the hash and size in the metadata", path)
			}
			meta, err := pdf.ExtractMetadata(path)
			if err != nil {
				return err
			}
			if meta.Kind != "" || meta.Session == nil || meta.Seal == nil {
				return fmt.Errorf("%s: not a sealed report", path)
			}
			if problem := sealedReportProblem(path, meta); problem != "" {
				return fmt.Errorf("%s: %s", path, problem)
			}
			if meta.Seal.DataHash != r.DataHash || meta.Session.ID != r.Session {
				return fmt.Errorf("%s: data hash or session differs from the metadata", path)
			}
			ar := session.ArchiveReport{
				ID: r.ID, Label: r.Label, SessionID: meta.Session.ID, DataHash: meta.Seal.DataHash,
				SealedAt:     meta.Seal.SealedAt.UTC().Format(time.RFC3339),
				ReportSHA256: sum, ReportSize: info.Size(),
			}
			// Pairing is by the hash the report signed, never by file name.
			if b := r.Files.Bundle; b != nil {
				if b.SHA256 != meta.Seal.CheckoutBundleHash {
					return fmt.Errorf("%s: bundle hash in the metadata is not the one this report signed", r.ID)
				}
				ar.BundleSHA256, ar.BundleSize = b.SHA256, b.Size
			}
			rec.Reports = append(rec.Reports, ar)
			reports = append(reports, meta)
		}

		c := client.New(archiveServer)
		sign := func(dataHash string) (*session.SealRecord, error) {
			resp, err := c.SignRecord(dataHash, token)
			if err != nil {
				return nil, err
			}
			payload := crypto.RecordPayload(dataHash, resp.Nonce, resp.SignedAt)
			key, err := crypto.LoadPublicKey([]byte(resp.PublicKeyPEM))
			if err != nil {
				return nil, err
			}
			if err := crypto.VerifyPSS(key, payload, resp.Signature); err != nil {
				return nil, fmt.Errorf("server returned an invalid record signature: %w", err)
			}
			return &session.SealRecord{
				Nonce: resp.Nonce, SignedAt: resp.SignedAt, Signature: resp.Signature,
				SignedMessageHash: crypto.HashBytes([]byte(payload)), PublicKeyPEM: resp.PublicKeyPEM,
				ServerURL: archiveServer,
			}, nil
		}

		out := archiveOut
		if out == "" {
			out = filepath.Join(dir, "record.pdf")
		}
		if err := pdf.GenerateRecord(rec, reports, sign, out); err != nil {
			return err
		}
		sum, err := crypto.HashFile(out)
		if err != nil {
			return err
		}
		info, err := os.Stat(out)
		if err != nil {
			return err
		}
		fmt.Printf("Archive record written: %s\n", out)
		fmt.Printf("  record: {sha256: %s, size: %d}\n", sum, info.Size())
		return nil
	},
}

func init() {
	cmdArchiveRecord.Flags().StringVarP(&archiveOut, "output", "o", "", "output path (default: record.pdf next to the metadata)")
	cmdArchiveRecord.Flags().StringVar(&archiveServer, "server", defaultServer, "signing server URL")
}

// Checks a sealed report the way verify does, without printing.
func sealedReportProblem(path string, meta *pdf.EmbeddedData) string {
	seal := meta.Seal
	signedHMCA, signedCerts, haveSigned := signedAnalysis(seal.CanonicalJSON)
	if !haveSigned {
		return "report predates stored canonical data"
	}
	computed, _, err := canonicalSessionHash(meta.Session, meta.Runs, seal.SourceBundleHash, seal.CheckoutBundleHash, signedHMCA, signedCerts)
	if err != nil || computed != seal.DataHash || crypto.HashBytes([]byte(seal.CanonicalJSON)) != seal.DataHash {
		return "embedded data does not match the signed data hash"
	}
	if final, err := pdf.SealIsFinal(path); err != nil || !final {
		return "content appended after the seal"
	}
	if seal.SealBlockHash != "" {
		if h, err := pdf.SealBlockHash(path); err != nil || h != seal.SealBlockHash {
			return "seal block modified"
		}
	}
	if seal.VisualPDFHash != "" {
		if h, err := pdf.VisualPDFHash(path); err != nil || h != seal.VisualPDFHash {
			return "visual pages modified"
		}
	}
	payload := crypto.Payload(seal.DataHash, seal.Nonce, seal.SignedAt)
	if crypto.HashBytes([]byte(payload)) != seal.SignedMessageHash {
		return "signed message hash mismatch"
	}
	key, err := crypto.LoadPublicKey([]byte(seal.PublicKeyPEM))
	if err != nil || crypto.VerifyPSS(key, payload, seal.Signature) != nil {
		return "invalid signature"
	}
	if ok, err := crypto.OriginConfirmed(seal.PublicKeyPEM, nil); err != nil || !ok {
		return "not signed by the K-Veritas server"
	}
	return ""
}

func verifyArchiveRecord(path string, meta *pdf.EmbeddedData) error {
	seal := meta.Seal
	if seal == nil || seal.CanonicalJSON == "" {
		fmt.Printf("TAMPERED\nArchive record has no signed data.\n")
		return nil
	}
	if crypto.HashBytes([]byte(seal.CanonicalJSON)) != seal.DataHash {
		fmt.Printf("TAMPERED\nStored record data does not match the signed data hash.\n")
		return nil
	}
	var rec session.ArchiveRecord
	if err := json.Unmarshal([]byte(seal.CanonicalJSON), &rec); err != nil {
		fmt.Printf("TAMPERED\nSigned record data is unreadable.\n")
		return nil
	}
	if final, err := pdf.SealIsFinal(path); err == nil && !final {
		fmt.Printf("TAMPERED\nContent was appended after the seal; a PDF reader may render it in place of the signed pages.\n")
		return nil
	}
	if seal.SealBlockHash != "" {
		if h, err := pdf.SealBlockHash(path); err == nil && h != seal.SealBlockHash {
			fmt.Printf("TAMPERED\nThe seal block was modified after signing.\n")
			return nil
		}
	}
	if h, err := pdf.VisualPDFHash(path); err != nil || h != rec.VisualPDFHash {
		fmt.Printf("TAMPERED\nThe record pages were modified after signing.\n")
		return nil
	}
	payload := crypto.RecordPayload(seal.DataHash, seal.Nonce, seal.SignedAt)
	if crypto.HashBytes([]byte(payload)) != seal.SignedMessageHash {
		fmt.Printf("TAMPERED\nSigned message hash mismatch.\n")
		return nil
	}
	key, err := crypto.LoadPublicKey([]byte(seal.PublicKeyPEM))
	if err != nil {
		return fmt.Errorf("parsing embedded public key: %w", err)
	}
	if err := crypto.VerifyPSS(key, payload, seal.Signature); err != nil {
		fmt.Printf("INVALID\nSignature verification failed: %v\n", err)
		return nil
	}
	var anchorPEM []byte
	if verifyKeyPath != "" {
		if anchorPEM, err = os.ReadFile(verifyKeyPath); err != nil {
			return fmt.Errorf("reading public key: %w", err)
		}
	}
	serverSigned, err := crypto.OriginConfirmed(seal.PublicKeyPEM, anchorPEM)
	if err != nil {
		return fmt.Errorf("checking record origin: %w", err)
	}
	if serverSigned {
		fmt.Printf("VERIFIED\n")
	} else {
		fmt.Printf("SELF-ATTESTED\nSignature valid, but not signed by K-Veritas. Not a K-Veritas record.\n")
	}
	fmt.Printf("Archive record %s\n", rec.ID)
	fmt.Printf("Title:      %s\n", rec.Title)
	fmt.Printf("Published:  %s\n", rec.Published)
	fmt.Printf("Signed at:  %s\n", seal.SignedAt)
	fmt.Printf("Reports:\n")
	for _, r := range rec.Reports {
		fmt.Printf("  %s  %s\n", r.ID, r.Label)
		fmt.Printf("      data hash  %s\n", r.DataHash)
		fmt.Printf("      report     %s\n", r.ReportSHA256)
		if r.BundleSHA256 != "" {
			fmt.Printf("      bundle     %s\n", r.BundleSHA256)
		}
	}
	fmt.Printf("\nThe sealed reports are authoritative. Verify each one with its bundle:\n")
	fmt.Printf("  kveritas verify <report.pdf> --bundle <bundle.zip>\n")
	return nil
}
