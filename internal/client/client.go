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
	Token     string       `json:"token"`
	SessionID string       `json:"session_id"`
	MachineID string       `json:"machine_id"`
	DataHash  string       `json:"data_hash"`
	RunCount  int          `json:"run_count"`
	Anchors   []SealAnchor `json:"anchors,omitempty"`
}

type SealAnchor struct {
	Run        int    `json:"run"`
	Invocation int    `json:"invocation"`
	RunDigest  string `json:"run_digest"`
}

type SealResponse struct {
	Nonce             string `json:"nonce"`
	SignedAt          string `json:"signed_at"`
	Signature         string `json:"signature"`
	SignedMessageHash string `json:"signed_message_hash"`
	PublicKeyPEM      string `json:"public_key_pem"`
}

type RunAnchor struct {
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
	Invocation  int     `json:"invocation"`
	RunDigest   string  `json:"run_digest"`
	Chain       string  `json:"chain"`
	EndedAt     string  `json:"ended_at"`
}

// A reply from the server, as opposed to a network failure. A rejected anchor must
// not be retried, while an unreachable server must.
type ServerError struct {
	Status int
	Body   string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error %d: %s", e.Status, e.Body)
}

type RunHistoryResponse struct {
	Runs      []session.LedgerRunEntry `json:"runs"`
	TotalRuns int                      `json:"total_runs"`
}

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

type GenesisResponse struct {
	Token            string `json:"token"`
	GenesisSignature string `json:"genesis_signature"`
	GenesisNonce     string `json:"genesis_nonce"`
	GenesisSignedAt  string `json:"genesis_signed_at"`
	PublicKeyPEM     string `json:"public_key_pem"`
}

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

func (c *Client) Seal(sess *session.Session, dataHash string, runCount int, anchors []SealAnchor) (*SealResponse, error) {
	var resp SealResponse
	err := c.post("/api/v1/seal", sealRequest{
		Token:     sess.Token,
		SessionID: sess.ID,
		MachineID: sess.MachineID,
		DataHash:  dataHash,
		RunCount:  runCount,
		Anchors:   anchors,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func NewRunAnchor(sess *session.Session, rec *session.RunRecord, chain string) RunAnchor {
	return RunAnchor{
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
		Invocation:  rec.Invocation,
		RunDigest:   rec.RunDigest,
		Chain:       chain,
		EndedAt:     rec.EndAt.UTC().Format(time.RFC3339Nano),
	}
}

func (c *Client) SendRunAnchor(a RunAnchor) error {
	var resp struct{}
	return c.post("/api/v1/record-run", a, &resp)
}

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
		return &ServerError{Status: resp.StatusCode, Body: strings.TrimSpace(string(respBody))}
	}
	return json.Unmarshal(respBody, out)
}

type Anomaly struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type Mismatch struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type PaperClaim struct {
	Category    string `json:"category"`
	Label       string `json:"label"`
	PaperValue  string `json:"paper_value"`
	ReportValue string `json:"report_value"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
}

type AnchorCheck struct {
	Run        int      `json:"run"`
	Invocation int      `json:"invocation"`
	Status     string   `json:"status"`
	Detail     string   `json:"detail"`
	DelaySec   *float64 `json:"delay_sec"`
}

type ServerAuditResult struct {
	CryptoStatus struct {
		Valid     bool   `json:"valid"`
		Authentic *bool  `json:"authentic"`
		Origin    string `json:"origin"`
		Reason    string `json:"reason"`
		Ledger    *struct {
			SignedAt string `json:"signed_at"`
		} `json:"ledger"`
		HMCAScore        *float64      `json:"hmca_score"`
		HMCAVerdict      *string       `json:"hmca_verdict"`
		HMCAFlags        []string      `json:"hmca_flags"`
		RunAnchors       []AnchorCheck `json:"run_anchors"`
		RunAnchorSummary string        `json:"run_anchor_summary"`
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
