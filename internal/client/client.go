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

// Init registers a new session with the server and returns an opaque token.
func (c *Client) Init(sessionID, machineID string, initAt time.Time, orgToken string) (string, error) {
	var resp InitResponse
	err := c.post("/api/v1/init", initRequest{
		SessionID: sessionID,
		MachineID: machineID,
		InitAt:    initAt.UTC().Format(time.RFC3339Nano),
		OrgToken:  orgToken,
	}, &resp)
	if err != nil {
		return "", err
	}
	return resp.Token, nil
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
