package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mamadouk/kveritas/internal/client"
	kvcrypto "github.com/mamadouk/kveritas/internal/crypto"
	"github.com/mamadouk/kveritas/internal/hardware"
	"github.com/mamadouk/kveritas/internal/pdf"
	"github.com/mamadouk/kveritas/internal/runner"
	"github.com/mamadouk/kveritas/internal/session"
	"github.com/spf13/cobra"
)

const defaultServer = "https://kveritas-api-production.up.railway.app"

var root = &cobra.Command{
	Use:   "kveritas",
	Short: "K-Veritas: tamper-evident experiment verification",
	Long: `K-Veritas cryptographically binds a published result to the exact
code, hardware, and time that produced it.

Workflow:
  kveritas init              Initialize a session in the current directory.
  kveritas run -- <cmd>      Run a monitored experiment.
  kveritas seal              Bundle and sign the session; produce a PDF report.
  kveritas verify <pdf>      Verify a signed report (no account required).
  kveritas check --claims c.json --report r.pdf
                             Check paper claims against signed results.
  kveritas generate-claims --report r.pdf
                             Generate a claims.json template from a report.
  kveritas status            Show current session state.`,
	SilenceUsage: true,
}

func main() {
	root.AddCommand(cmdInit, cmdRun, cmdSeal, cmdVerify, cmdCheck, cmdStatus, cmdGenerateClaims, cmdUpdate)
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// --- init ---

var (
	initServer   string
	initLocal    bool
	initOrgToken string
	initUser     string
)

var cmdInit = &cobra.Command{
	Use:   "init",
	Short: "Initialize a K-Veritas session in the current directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir := filepath.Join(".", session.DirName)
		if _, err := os.Stat(kvDir); err == nil {
			return fmt.Errorf("session already exists in %s; use 'kveritas status' to inspect it", kvDir)
		}

		if err := os.MkdirAll(kvDir, 0700); err != nil {
			return err
		}

		wd, err := os.Getwd()
		if err != nil {
			return err
		}

		machineID := hardware.MachineID()
		sessionID := uuid.New().String()

		var token string
		serverURL := initServer

		if !initLocal {
			c := client.New(serverURL)
			token, err = c.Init(sessionID, machineID, time.Now(), initOrgToken, initUser)
			if err != nil {
				_ = os.RemoveAll(kvDir)
				return fmt.Errorf("server registration failed: %w\n\nStart the server with: kveritas-server\nOr use --local for offline mode.", err)
			}
			fmt.Fprintf(os.Stderr, "[kveritas] Registered with server %s\n", serverURL)
		} else {
			token = "local"
			serverURL = "local"
			fmt.Fprintf(os.Stderr, "[kveritas] Local mode: no server registration\n")
		}

		sess := &session.Session{
			ID:         sessionID,
			InitAt:     time.Now().UTC(),
			ProjectDir: wd,
			MachineID:  machineID,
			Token:      token,
			ServerURL:  serverURL,
			OrgToken:   initOrgToken,
			UserEmail:  initUser,
			Runs:       []string{},
		}

		if err := sess.Save(kvDir); err != nil {
			return err
		}

		fmt.Printf("Session initialized: %s\n", sessionID)
		fmt.Printf("Directory: %s\n", kvDir)
		return nil
	},
}

func init() {
	cmdInit.Flags().StringVar(&initServer, "server", defaultServer, "attestation server URL")
	cmdInit.Flags().BoolVar(&initLocal, "local", false, "local mode: sign with a local key, no server")
	cmdInit.Flags().StringVar(&initOrgToken, "org-token", "", "organization/class token (links reports to a class or track)")
	cmdInit.Flags().StringVar(&initUser, "user", "", "user email (identifies the submitter for class-mode tokens)")
}

// --- run ---

var runFiles []string

var cmdRun = &cobra.Command{
	Use:   "run [--files f1,f2] -- <command> [args...]",
	Short: "Run a monitored experiment",
	Long: `Executes <command> as a monitored subprocess.

The stdout stream is teed to your terminal and simultaneously hashed.
Metrics printed to stdout in the KVERITAS_METRIC format are captured:

  KVERITAS_METRIC name=val_accuracy value=0.9471 step=100

Files listed with --files are hashed before and after the run.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}
		if sess.Sealed {
			return fmt.Errorf("session is already sealed; cannot add more runs")
		}

		// Heuristically detect the script file from the command if --files is empty.
		hints := runFiles
		if len(hints) == 0 {
			for _, arg := range args {
				if isSourceFile(arg) {
					hints = append(hints, arg)
				}
			}
		}

		rec, err := runner.Run(sess, args, hints)
		if err != nil {
			return err
		}

		if err := sess.SaveRun(kvDir, rec); err != nil {
			return err
		}

		sess.Runs = append(sess.Runs, rec.ID)
		if err := sess.Save(kvDir); err != nil {
			return err
		}

		fmt.Printf("Run %s recorded (%d metrics)\n", rec.ID, len(rec.Metrics))
		return nil
	},
}

func init() {
	cmdRun.Flags().StringSliceVar(&runFiles, "files", nil, "source files to hash (comma-separated)")
}

// --- seal ---

var (
	sealOutput  string
	sealKeyPath string
)

var cmdSeal = &cobra.Command{
	Use:   "seal",
	Short: "Bundle and cryptographically sign the session; produce a PDF report",
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}
		if sess.Sealed {
			return fmt.Errorf("session is already sealed")
		}
		if len(sess.Runs) == 0 {
			return fmt.Errorf("no runs recorded; use 'kveritas run' first")
		}

		runs := make([]*session.RunRecord, 0, len(sess.Runs))
		for _, id := range sess.Runs {
			r, err := session.LoadRun(kvDir, id)
			if err != nil {
				return fmt.Errorf("loading run %s: %w", id, err)
			}
			runs = append(runs, r)
		}

		dataHash, err := canonicalSessionHash(sess, runs)
		if err != nil {
			return fmt.Errorf("hashing session data: %w", err)
		}

		var seal *session.SealRecord

		if sess.ServerURL == "local" || sealKeyPath != "" {
			seal, err = localSeal(sess, runs, dataHash, sealKeyPath)
		} else {
			seal, err = serverSeal(sess, runs, dataHash)
		}
		if err != nil {
			return err
		}

		outPath := sealOutput
		if outPath == "" {
			outPath = fmt.Sprintf("kveritas-report-%s.pdf", sess.ID[:8])
		}

		if err := pdf.Generate(sess, runs, seal, outPath); err != nil {
			return fmt.Errorf("PDF generation: %w", err)
		}

		sess.Sealed = true
		if err := sess.Save(kvDir); err != nil {
			return err
		}
		if err := session.SaveSeal(kvDir, seal); err != nil {
			return err
		}

		fmt.Printf("Report sealed: %s\n", outPath)
		fmt.Printf("Data hash:     %s\n", seal.DataHash)
		return nil
	},
}

func init() {
	cmdSeal.Flags().StringVarP(&sealOutput, "output", "o", "", "output PDF path (default: kveritas-report-<id>.pdf)")
	cmdSeal.Flags().StringVar(&sealKeyPath, "local-key", "", "path to local RSA private key PEM (for offline signing)")
}

func canonicalSessionHash(sess *session.Session, runs []*session.RunRecord) (string, error) {
	type runPayload struct {
		ID          string            `json:"id"`
		Index       int               `json:"index"`
		Command     []string          `json:"command"`
		StartAt     string            `json:"start_at"`
		EndAt       string            `json:"end_at"`
		DurationSec float64           `json:"duration_sec"`
		DurationFmt string            `json:"duration_fmt,omitempty"`
		ExitCode    int               `json:"exit_code"`
		PreHashes   map[string]string `json:"pre_hashes"`
		PostHashes  map[string]string `json:"post_hashes"`
		Modified    []string          `json:"modified_files"`
		StdoutHash  string            `json:"stdout_hash"`
		StderrHash  string            `json:"stderr_hash"`
		StdoutLines int               `json:"stdout_lines"`
		Metrics     []session.Metric  `json:"metrics"`
		Phases      []session.Phase   `json:"phases,omitempty"`
		Claims      []session.Claim   `json:"claims,omitempty"`
		Seeds       []session.Seed    `json:"seeds,omitempty"`
		Hardware    session.HardwareInfo `json:"hardware"`
		EnvDigest   string            `json:"env_digest"`
	}

	runPayloads := make([]runPayload, 0, len(runs))
	for _, r := range runs {
		rp := runPayload{
			ID:          r.ID,
			Index:       r.Index,
			Command:     r.Command,
			StartAt:     r.StartAt.UTC().Format(time.RFC3339Nano),
			EndAt:       r.EndAt.UTC().Format(time.RFC3339Nano),
			DurationSec: r.DurationSec,
			DurationFmt: r.DurationFmt,
			ExitCode:    r.ExitCode,
			PreHashes:   r.PreHashes,
			PostHashes:  r.PostHashes,
			Modified:    r.Modified,
			StdoutHash:  r.StdoutHash,
			StderrHash:  r.StderrHash,
			StdoutLines: r.StdoutLines,
			Metrics:     r.Metrics,
			Phases:      r.Phases,
			Claims:      r.Claims,
			Seeds:       r.Seeds,
			Hardware:    r.Hardware,
			EnvDigest:   r.EnvDigest,
		}
		runPayloads = append(runPayloads, rp)
	}

	signingData := map[string]interface{}{
		"session_id": sess.ID,
		"init_at":    sess.InitAt.UTC().Format(time.RFC3339Nano),
		"machine_id": sess.MachineID,
		"server_url": sess.ServerURL,
		"runs":       runPayloads,
	}

	return kvcrypto.CanonicalHash(signingData)
}

func serverSeal(sess *session.Session, runs []*session.RunRecord, dataHash string) (*session.SealRecord, error) {
	c := client.New(sess.ServerURL)
	resp, err := c.Seal(sess, dataHash, len(runs))
	if err != nil {
		return nil, fmt.Errorf("server attestation failed: %w\n\nEnsure the server is running: kveritas-server", err)
	}

	return &session.SealRecord{
		SessionID:        sess.ID,
		SealedAt:         time.Now().UTC(),
		DataHash:         dataHash,
		Nonce:            resp.Nonce,
		SignedAt:         resp.SignedAt,
		Signature:        resp.Signature,
		SignedMessageHash: resp.SignedMessageHash,
		PublicKeyPEM:     resp.PublicKeyPEM,
		ServerURL:        sess.ServerURL,
	}, nil
}

func localSeal(sess *session.Session, _ []*session.RunRecord, dataHash, keyPath string) (*session.SealRecord, error) {
	if keyPath == "" {
		keyPath = "keys/private.pem"
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading private key %s: %w\n\nGenerate a key with: kveritas-server --keys keys", keyPath, err)
	}
	privKey, err := kvcrypto.LoadPrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	nonce, err := kvcrypto.RandomNonce()
	if err != nil {
		return nil, err
	}
	signedAt := time.Now().UTC().Format(time.RFC3339Nano)
	payload := kvcrypto.Payload(dataHash, nonce, signedAt)

	sig, err := kvcrypto.SignPSS(privKey, payload)
	if err != nil {
		return nil, err
	}

	pubPEM, err := kvcrypto.MarshalPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &session.SealRecord{
		SessionID:        sess.ID,
		SealedAt:         time.Now().UTC(),
		DataHash:         dataHash,
		Nonce:            nonce,
		SignedAt:         signedAt,
		Signature:        sig,
		SignedMessageHash: kvcrypto.HashBytes([]byte(payload)),
		PublicKeyPEM:     string(pubPEM),
		ServerURL:        "local",
	}, nil
}

// --- verify ---

var verifyKeyPath string

var cmdVerify = &cobra.Command{
	Use:   "verify <report.pdf>",
	Short: "Verify a signed K-Veritas report (no account required)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		reportPath := args[0]

		meta, err := pdf.ExtractMetadata(reportPath)
		if err != nil {
			return err
		}

		seal := meta.Seal
		sess := meta.Session
		runs := meta.Runs

		// Step 1: recompute and verify the data hash.
		computedHash, err := canonicalSessionHash(sess, runs)
		if err != nil {
			return fmt.Errorf("hashing session data: %w", err)
		}
		if computedHash != seal.DataHash {
			fmt.Printf("TAMPERED\nData hash mismatch.\n  Stored:   %s\n  Computed: %s\n",
				seal.DataHash, computedHash)
			return nil
		}

		// Step 2: verify the signed message hash.
		payload := kvcrypto.Payload(seal.DataHash, seal.Nonce, seal.SignedAt)
		expectedMsgHash := kvcrypto.HashBytes([]byte(payload))
		if expectedMsgHash != seal.SignedMessageHash {
			fmt.Printf("TAMPERED\nSigned message hash mismatch.\n  Stored:   %s\n  Expected: %s\n",
				seal.SignedMessageHash, expectedMsgHash)
			return nil
		}

		// Step 3: verify RSA-PSS signature.
		pubKeyPEM := []byte(seal.PublicKeyPEM)
		if verifyKeyPath != "" {
			pubKeyPEM, err = os.ReadFile(verifyKeyPath)
			if err != nil {
				return fmt.Errorf("reading public key: %w", err)
			}
		}
		pubKey, err := kvcrypto.LoadPublicKey(pubKeyPEM)
		if err != nil {
			return fmt.Errorf("parsing public key: %w", err)
		}
		if err := kvcrypto.VerifyPSS(pubKey, payload, seal.Signature); err != nil {
			fmt.Printf("INVALID\nSignature verification failed: %v\n", err)
			return nil
		}

		fmt.Printf("VERIFIED\n")
		fmt.Printf("Session:    %s\n", sess.ID)
		fmt.Printf("Sealed at:  %s\n", seal.SealedAt.UTC().Format(time.RFC3339))
		fmt.Printf("Signed at:  %s\n", seal.SignedAt)
		fmt.Printf("Machine:    %s\n", sess.MachineID)
		fmt.Printf("Runs:       %d\n", len(runs))
		fmt.Printf("Data hash:  %s\n", seal.DataHash)

		explicitCount := 0
		for _, r := range runs {
			for _, m := range r.Metrics {
				if m.Source == "explicit" {
					explicitCount++
				}
			}
		}
		fmt.Printf("Metrics:    %d explicit\n", explicitCount)
		return nil
	},
}

func init() {
	cmdVerify.Flags().StringVar(&verifyKeyPath, "public-key", "", "path to public key PEM (default: use key embedded in report)")
}

// --- check ---

type claimsFile struct {
	Claims []claim `json:"claims"`
}

type claim struct {
	Metric    string  `json:"metric"`
	Value     float64 `json:"value"`
	Tolerance float64 `json:"tolerance"`
	Run       int     `json:"run,omitempty"` // 1-indexed; 0 means any run
}

var (
	checkClaimsPath string
	checkReportPath string
)

var cmdCheck = &cobra.Command{
	Use:   "check --claims <claims.json> --report <report.pdf>",
	Short: "Check paper claims against a signed report",
	RunE: func(cmd *cobra.Command, args []string) error {
		if checkClaimsPath == "" || checkReportPath == "" {
			return fmt.Errorf("--claims and --report are both required")
		}

		meta, err := pdf.ExtractMetadata(checkReportPath)
		if err != nil {
			return err
		}

		// Verify integrity first.
		seal := meta.Seal
		sess := meta.Session
		runs := meta.Runs

		computedHash, err := canonicalSessionHash(sess, runs)
		if err != nil {
			return err
		}
		if computedHash != seal.DataHash {
			fmt.Println("TAMPERED: report data has been modified; claims check aborted")
			return nil
		}
		payload := kvcrypto.Payload(seal.DataHash, seal.Nonce, seal.SignedAt)
		if kvcrypto.HashBytes([]byte(payload)) != seal.SignedMessageHash {
			fmt.Println("TAMPERED: signature metadata has been modified; claims check aborted")
			return nil
		}
		pubKey, err := kvcrypto.LoadPublicKey([]byte(seal.PublicKeyPEM))
		if err != nil {
			return err
		}
		if err := kvcrypto.VerifyPSS(pubKey, payload, seal.Signature); err != nil {
			fmt.Printf("INVALID: signature verification failed: %v\n", err)
			return nil
		}

		// Load claims.
		claimsData, err := os.ReadFile(checkClaimsPath)
		if err != nil {
			return fmt.Errorf("reading claims file: %w", err)
		}
		var cf claimsFile
		if err := json.Unmarshal(claimsData, &cf); err != nil {
			return fmt.Errorf("parsing claims file: %w", err)
		}

		allOK := true
		for _, c := range cf.Claims {
			found, actual, ok := findMetric(runs, c.Metric, c.Run)
			if !found {
				fmt.Printf("MISSING   %s (not found in signed report)\n", c.Metric)
				allOK = false
				continue
			}
			diff := math.Abs(actual - c.Value)
			tol := c.Tolerance
			if tol == 0 {
				tol = 1e-4
			}
			if diff <= tol {
				fmt.Printf("CONSISTENT  %-30s  claimed=%.6g  signed=%.6g  diff=%.2e\n",
					c.Metric, c.Value, actual, diff)
			} else {
				fmt.Printf("INCONSISTENT %-30s  claimed=%.6g  signed=%.6g  diff=%.2e  tolerance=%.2e\n",
					c.Metric, c.Value, actual, diff, tol)
				allOK = false
				_ = ok
			}
		}

		if allOK {
			fmt.Println("\nResult: CONSISTENT")
		} else {
			fmt.Println("\nResult: INCONSISTENT")
		}
		return nil
	},
}

func init() {
	cmdCheck.Flags().StringVar(&checkClaimsPath, "claims", "", "path to claims JSON file")
	cmdCheck.Flags().StringVar(&checkReportPath, "report", "", "path to K-Veritas PDF report")
}

// findMetric searches runs for a metric by name.
// runFilter is 1-indexed; 0 means search all runs.
func findMetric(runs []*session.RunRecord, name string, runFilter int) (found bool, value float64, explicit bool) {
	for i, r := range runs {
		if runFilter > 0 && i+1 != runFilter {
			continue
		}
		for _, m := range r.Metrics {
			if strings.EqualFold(m.Name, name) {
				return true, m.Value, m.Source == "explicit"
			}
		}
	}
	return false, 0, false
}

// --- status ---

var cmdStatus = &cobra.Command{
	Use:   "status",
	Short: "Show current session state",
	RunE: func(cmd *cobra.Command, args []string) error {
		kvDir, err := session.Find()
		if err != nil {
			return err
		}
		sess, err := session.Load(kvDir)
		if err != nil {
			return err
		}

		fmt.Printf("Session ID:   %s\n", sess.ID)
		fmt.Printf("Initialized:  %s\n", sess.InitAt.UTC().Format(time.RFC3339))
		fmt.Printf("Machine ID:   %s\n", sess.MachineID)
		fmt.Printf("Server:       %s\n", sess.ServerURL)
		fmt.Printf("Sealed:       %v\n", sess.Sealed)
		fmt.Printf("Runs:         %d\n", len(sess.Runs))

		for i, id := range sess.Runs {
			r, err := session.LoadRun(kvDir, id)
			if err != nil {
				fmt.Printf("  Run %d: %s (error loading)\n", i+1, id)
				continue
			}
			statusStr := "OK"
			if r.ExitCode != 0 {
				statusStr = fmt.Sprintf("EXIT %d", r.ExitCode)
			}
			fmt.Printf("  Run %d: [%s] %s  %.1fs  %d metrics\n",
				i+1, statusStr, strings.Join(r.Command, " "), r.DurationSec, len(r.Metrics))
		}

		if sess.Sealed {
			seal, err := session.LoadSeal(kvDir)
			if err == nil {
				fmt.Printf("\nSealed at:  %s\n", seal.SealedAt.UTC().Format(time.RFC3339))
				fmt.Printf("Data hash:  %s\n", seal.DataHash)
			}
		}
		return nil
	},
}

// --- generate-claims ---

var generateClaimsReportPath string

var cmdGenerateClaims = &cobra.Command{
	Use:   "generate-claims --report <report.pdf>",
	Short: "Generate a claims.json template from a signed report",
	Long: `Extracts all final metrics and hardware info from a signed K-Veritas
PDF report and writes a claims.json template. Authors edit this file to
match the values they cite in their paper, then submit it alongside the
report for reviewer cross-referencing.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if generateClaimsReportPath == "" {
			return fmt.Errorf("--report is required")
		}

		meta, err := pdf.ExtractMetadata(generateClaimsReportPath)
		if err != nil {
			return err
		}

		type claimEntry struct {
			Metric    string  `json:"metric"`
			Value     float64 `json:"value"`
			Tolerance float64 `json:"tolerance"`
		}

		type claimsOutput struct {
			Claims []claimEntry `json:"claims"`
		}

		seen := map[string]bool{}
		var claims []claimEntry

		for _, r := range meta.Runs {
			for _, m := range r.Metrics {
				if seen[m.Name] {
					continue
				}
				seen[m.Name] = true
				claims = append(claims, claimEntry{
					Metric:    m.Name,
					Value:     m.Value,
					Tolerance: 1e-4,
				})
			}
		}

		output := claimsOutput{Claims: claims}
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return err
		}

		fmt.Println(string(data))
		return nil
	},
}

func init() {
	cmdGenerateClaims.Flags().StringVar(&generateClaimsReportPath, "report", "", "path to K-Veritas PDF report")
}

// --- update ---

var cmdUpdate = &cobra.Command{
	Use:   "update",
	Short: "Update kveritas to the latest version",
	RunE: func(cmd *cobra.Command, args []string) error {
		base := "https://github.com/27-GROUP/kveritas-releases/raw/main/bin"

		goos := strings.ToLower(runtime.GOOS)
		goarch := strings.ToLower(runtime.GOARCH)

		var fname string
		switch {
		case goos == "linux" && goarch == "amd64":
			fname = "kveritas-linux-amd64"
		case goos == "linux" && goarch == "arm64":
			fname = "kveritas-linux-arm64"
		case goos == "darwin" && goarch == "arm64":
			fname = "kveritas-darwin-arm64"
		case goos == "darwin" && goarch == "amd64":
			fname = "kveritas-darwin-amd64"
		case goos == "windows" && goarch == "amd64":
			fname = "kveritas-windows-amd64.exe"
		default:
			return fmt.Errorf("unsupported platform: %s/%s", goos, goarch)
		}

		url := base + "/" + fname

		exePath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("cannot determine executable path: %w", err)
		}
		exePath, err = filepath.EvalSymlinks(exePath)
		if err != nil {
			return fmt.Errorf("cannot resolve symlinks: %w", err)
		}

		fmt.Printf("Downloading %s...\n", fname)

		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
		}

		tmpFile := exePath + ".tmp"
		out, err := os.Create(tmpFile)
		if err != nil {
			return fmt.Errorf("cannot create temp file: %w (try running with sudo)", err)
		}

		if _, err := io.Copy(out, resp.Body); err != nil {
			out.Close()
			os.Remove(tmpFile)
			return fmt.Errorf("download interrupted: %w", err)
		}
		out.Close()

		if err := os.Chmod(tmpFile, 0755); err != nil {
			os.Remove(tmpFile)
			return err
		}

		if err := os.Rename(tmpFile, exePath); err != nil {
			os.Remove(tmpFile)
			return fmt.Errorf("cannot replace binary: %w (try running with sudo)", err)
		}

		fmt.Println("Updated successfully.")
		return nil
	},
}

// --- helpers ---

// isSourceFile returns true for file arguments that look like executable scripts.
func isSourceFile(path string) bool {
	exts := []string{".py", ".r", ".R", ".jl", ".sh", ".bash", ".rb", ".js", ".ts"}
	lower := strings.ToLower(path)
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

