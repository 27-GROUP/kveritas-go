package main

import (
	"io"
	"os"

	"github.com/Mamadou2727/kveritas-go/internal/client"
	"github.com/Mamadou2727/kveritas-go/internal/session"
)

// Human-readable verify output goes here; --json silences it and prints one document instead.
var out io.Writer = os.Stdout

type verifyDoc struct {
	Kind             string                    `json:"kind"`
	Status           string                    `json:"status"`
	Reason           string                    `json:"reason,omitempty"`
	SessionID        string                    `json:"session_id,omitempty"`
	SealedAt         string                    `json:"sealed_at,omitempty"`
	SignedAt         string                    `json:"signed_at,omitempty"`
	DataHash         string                    `json:"data_hash,omitempty"`
	TotalInvocations int                       `json:"total_invocations,omitempty"`
	Coherence        *session.HMCAResult       `json:"coherence,omitempty"`
	Runs             []runDoc                  `json:"runs,omitempty"`
	BundleMatch      *bool                     `json:"bundle_match,omitempty"`
	Audit            *client.ServerAuditResult `json:"server_audit,omitempty"`
	AuditError       string                    `json:"server_audit_error,omitempty"`
}

type runDoc struct {
	Index           int                      `json:"index"`
	Command         []string                 `json:"command"`
	StartAt         string                   `json:"start_at"`
	DurationSec     float64                  `json:"duration_sec"`
	ExitCode        int                      `json:"exit_code"`
	Launch          string                   `json:"launch"`
	Distributed     *session.Distributed     `json:"distributed,omitempty"`
	ChannelMessages int                      `json:"channel_messages,omitempty"`
	ChannelGaps     int                      `json:"channel_gaps,omitempty"`
	NotebookCells   int                      `json:"notebook_cells,omitempty"`
	Metrics         []session.Metric         `json:"metrics"`
	Claims          []session.InlineClaim    `json:"claims,omitempty"`
	Seeds           []session.SeedCommitment `json:"seeds,omitempty"`
	Compute         *session.ComputeCert     `json:"compute,omitempty"`
}

func (d *verifyDoc) set(status, reason string) {
	if d != nil {
		d.Status, d.Reason = status, reason
	}
}

func launchOf(r *session.RunRecord) string {
	if r.Launch != "" {
		return r.Launch
	}
	return "wrapped"
}

type sealDoc struct {
	Report           string              `json:"report"`
	Bundle           string              `json:"bundle,omitempty"`
	Keystore         string              `json:"keystore,omitempty"`
	DataHash         string              `json:"data_hash"`
	Runs             int                 `json:"runs"`
	TotalInvocations int                 `json:"total_invocations,omitempty"`
	Coherence        *session.HMCAResult `json:"coherence,omitempty"`
}

type statusDoc struct {
	SessionID     string      `json:"session_id"`
	InitAt        string      `json:"init_at"`
	Server        string      `json:"server"`
	Disclosure    string      `json:"disclosure,omitempty"`
	Type          string      `json:"type,omitempty"`
	Sealed        bool        `json:"sealed"`
	Invocations   int         `json:"invocations"`
	QueuedAnchors int         `json:"queued_anchors"`
	Runs          []statusRun `json:"runs"`
}

type statusRun struct {
	Index       int      `json:"index"`
	ID          string   `json:"id"`
	Command     []string `json:"command"`
	DurationSec float64  `json:"duration_sec"`
	ExitCode    int      `json:"exit_code"`
	Launch      string   `json:"launch"`
	Metrics     int      `json:"metrics"`
	Claims      int      `json:"claims"`
	Phases      int      `json:"phases"`
	Seeds       int      `json:"seeds"`
}
