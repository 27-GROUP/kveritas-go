package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// Client communicates with the K-Veritas attestation server.
type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

type initRequest struct {
	SessionID string `json:"session_id"`
	MachineID string `json:"machine_id"`
	InitAt    string `json:"init_at"`
}

type InitResponse struct {
	Token string `json:"token"`
}

type sealRequest struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	MachineID string `json:"machine_id"`
	DataHash  string `json:"data_hash"`
	RunCount  int    `json:"run_count"`
}

// SealResponse contains the server's attestation response.
type SealResponse struct {
	Nonce             string `json:"nonce"`
	SignedAt          string `json:"signed_at"`
	Signature         string `json:"signature"`
	SignedMessageHash string `json:"signed_message_hash"`
	PublicKeyPEM      string `json:"public_key_pem"`
}

type recordRunRequest struct {
	Token       string  `json:"token"`
	SessionID   string  `json:"session_id"`
	MachineID   string  `json:"machine_id"`
	RunIndex    int     `json:"run_index"`
	StartedAt   string  `json:"started_at"`
	DurationSec float64 `json:"duration_sec"`
	DurationFmt string  `json:"duration_fmt"`
	ExitCode    int     `json:"exit_code"`
	MetricHash  string  `json:"metric_hash"`
	StdoutLines int     `json:"stdout_lines"`
}

// RunHistoryResponse contains the server's run history for a session.
type RunHistoryResponse struct {
	Runs      []session.LedgerRunEntry `json:"runs"`
	TotalRuns int                      `json:"total_runs"`
}

// Init registers a new session with the server and returns the full response.
func (c *Client) Init(sessionID, machineID string, initAt time.Time) (*InitResponse, error) {
	var resp InitResponse
	err := c.post("/api/v1/init", initRequest{
		SessionID: sessionID,
		MachineID: machineID,
		InitAt:    initAt.UTC().Format(time.RFC3339Nano),
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

type harnessInitRequest struct {
	SessionID   string `json:"session_id"`
	MachineID   string `json:"machine_id"`
	InitAt      string `json:"init_at"`
	GenesisHash string `json:"genesis_hash"`
}

// GenesisResponse carries the session token and the server signature over the
// genesis hash, which binds the designation D at the start of a harness session.
type GenesisResponse struct {
	Token            string `json:"token"`
	GenesisSignature string `json:"genesis_signature"`
	GenesisNonce     string `json:"genesis_nonce"`
	GenesisSignedAt  string `json:"genesis_signed_at"`
	PublicKeyPEM     string `json:"public_key_pem"`
}

// HarnessInit registers a harness session and asks the server to sign the
// genesis hash.
func (c *Client) HarnessInit(sessionID, machineID string, initAt time.Time, genesisHash string) (*GenesisResponse, error) {
	var resp GenesisResponse
	err := c.post("/api/v1/init", harnessInitRequest{
		SessionID:   sessionID,
		MachineID:   machineID,
		InitAt:      initAt.UTC().Format(time.RFC3339Nano),
		GenesisHash: genesisHash,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// Seal submits a data hash to the server and receives a cryptographic attestation.
func (c *Client) Seal(sess *session.Session, dataHash string, runCount int) (*SealResponse, error) {
	var resp SealResponse
	err := c.post("/api/v1/seal", sealRequest{
		Token:     sess.Token,
		SessionID: sess.ID,
		MachineID: sess.MachineID,
		DataHash:  dataHash,
		RunCount:  runCount,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// RecordRun records a run invocation in the server ledger, successful or not, for
// the multi-run ledger.
func (c *Client) RecordRun(sess *session.Session, rec *session.RunRecord) error {
	var resp struct{}
	return c.post("/api/v1/record-run", recordRunRequest{
		Token:       sess.Token,
		SessionID:   sess.ID,
		MachineID:   sess.MachineID,
		RunIndex:    rec.Index,
		StartedAt:   rec.StartAt.UTC().Format(time.RFC3339Nano),
		DurationSec: rec.DurationSec,
		DurationFmt: rec.DurationFmt,
		ExitCode:    rec.ExitCode,
		MetricHash:  rec.MetricHash,
		StdoutLines: rec.StdoutLines,
	}, &resp)
}

// RunHistory retrieves the full run history for a session from the server ledger.
func (c *Client) RunHistory(sess *session.Session) (*RunHistoryResponse, error) {
	url := fmt.Sprintf("%s/api/v1/run-history?session_id=%s&token=%s",
		c.BaseURL, sess.ID, sess.Token)
	resp, err := c.HTTPClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("cannot reach server: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, body)
	}
	var result RunHistoryResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// PublicKeyPEM fetches the server's public key in PEM format.
func (c *Client) PublicKeyPEM() (string, error) {
	resp, err := c.HTTPClient.Get(c.BaseURL + "/api/v1/public-key")
	if err != nil {
		return "", fmt.Errorf("cannot reach server at %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.PublicKey, nil
}

func (c *Client) post(path string, body, out interface{}) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := c.HTTPClient.Post(c.BaseURL+path, "application/json", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("server unreachable at %s%s: %w", c.BaseURL, path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server error %d: %s", resp.StatusCode, respBody)
	}
	return json.Unmarshal(respBody, out)
}

// Anomaly is one code-audit finding.
type Anomaly struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// Mismatch is one paper-crosscheck finding.
type Mismatch struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// PaperClaim is one reconciled paper claim: its value, the matching signed value,
// and whether the two agree, disagree, or have no signed evidence.
type PaperClaim struct {
	Category    string `json:"category"`
	Label       string `json:"label"`
	PaperValue  string `json:"paper_value"`
	ReportValue string `json:"report_value"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
}

// ServerAuditResult mirrors the /api/audit response the web verifier renders:
// cryptographic status and ledger, hardware consistency, source-bundle match,
// AI code audit, and paper crosscheck.
type ServerAuditResult struct {
	CryptoStatus struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
		Ledger *struct {
			SignedAt string `json:"signed_at"`
		} `json:"ledger"`
		HMCAScore   *float64 `json:"hmca_score"`
		HMCAVerdict *string  `json:"hmca_verdict"`
		HMCAFlags   []string `json:"hmca_flags"`
	} `json:"crypto_status"`
	CodeAudit struct {
		Status    string    `json:"status"`
		Verdict   string    `json:"verdict"`
		Summary   string    `json:"summary"`
		Reason    string    `json:"reason"`
		Anomalies []Anomaly `json:"anomalies"`
	} `json:"code_audit"`
	PaperCrosscheck struct {
		Status      string       `json:"status"`
		Summary     string       `json:"summary"`
		Reason      string       `json:"reason"`
		Coverage    *float64     `json:"coverage"`
		Consistency *float64     `json:"consistency"`
		Claims      []PaperClaim `json:"claims"`
		Mismatches  []Mismatch   `json:"mismatches"`
	} `json:"paper_crosscheck"`
	BundleVerification struct {
		Match *bool `json:"match"`
	} `json:"bundle_verification"`
}

func addFilePart(w *multipart.Writer, field, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	part, err := w.CreateFormFile(field, filepath.Base(path))
	if err != nil {
		return err
	}
	_, err = io.Copy(part, f)
	return err
}

// AuditReport uploads a report (and optionally a source bundle and a manuscript)
// to the server's /api/audit endpoint, returning the same full result the web
// verifier shows for the same files.
func (c *Client) AuditReport(reportPath, bundlePath, manuscriptPath string) (*ServerAuditResult, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := addFilePart(w, "report", reportPath); err != nil {
		return nil, err
	}
	if bundlePath != "" {
		if err := addFilePart(w, "bundle", bundlePath); err != nil {
			return nil, err
		}
	}
	if manuscriptPath != "" {
		if err := addFilePart(w, "manuscript", manuscriptPath); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", c.BaseURL+"/api/audit", &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	var out ServerAuditResult
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
