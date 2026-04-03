package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mamadouk/kveritas/internal/session"
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
	OrgToken  string `json:"org_token,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
}

type InitResponse struct {
	Token   string `json:"token"`
	OrgName string `json:"org_name,omitempty"`
}

type sealRequest struct {
	Token     string `json:"token"`
	SessionID string `json:"session_id"`
	MachineID string `json:"machine_id"`
	DataHash  string `json:"data_hash"`
	RunCount  int    `json:"run_count"`
	OrgToken  string `json:"org_token,omitempty"`
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
func (c *Client) Init(sessionID, machineID string, initAt time.Time, orgToken, userEmail string) (*InitResponse, error) {
	var resp InitResponse
	err := c.post("/api/v1/init", initRequest{
		SessionID: sessionID,
		MachineID: machineID,
		InitAt:    initAt.UTC().Format(time.RFC3339Nano),
		OrgToken:  orgToken,
		UserEmail: userEmail,
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
		OrgToken:  sess.OrgToken,
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// RecordRun records a run invocation in the server ledger.
// This records every invocation -- successful or not -- for the multi-run ledger.
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
